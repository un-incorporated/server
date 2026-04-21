//! MongoDB user ID resolver.
//!
//! Extracts affected user IDs from BSON filter documents using the schema
//! configuration that maps collections to user ID fields.

use bson::{Bson, Document};
use tracing::debug;

use uninc_common::config::SchemaConfig;

/// Resolves affected user IDs from MongoDB filter documents.
pub struct MongoResolver {
    schema: SchemaConfig,
}

impl MongoResolver {
    /// Create a new resolver with the given schema configuration.
    pub fn new(schema: SchemaConfig) -> Self {
        Self { schema }
    }

    /// Resolve user IDs from a MongoDB filter document.
    ///
    /// Looks up the collection in the schema config to find user ID field names,
    /// then extracts values from the filter document.
    ///
    /// Handles:
    /// - Direct match: `{ "user_id": 42 }` -> `["42"]`
    /// - `$in` operator: `{ "user_id": { "$in": [42, 43] } }` -> `["42", "43"]`
    /// - `$eq` operator: `{ "user_id": { "$eq": 42 } }` -> `["42"]`
    /// - `ObjectId`: `{ "_id": ObjectId("...") }` -> `["..."]`
    /// - `$and` / `$or`: recursively searches nested conditions
    pub fn resolve_from_filter(
        &self,
        collection: &str,
        filter: Option<&Document>,
    ) -> Vec<String> {
        let Some(filter) = filter else {
            return Vec::new();
        };

        // Find the user ID field(s) for this collection.
        let user_id_fields = self.user_id_fields_for(collection);
        if user_id_fields.is_empty() {
            debug!(collection, "no user_id field configured, skipping resolution");
            return Vec::new();
        }

        let mut user_ids = Vec::new();

        for field in &user_id_fields {
            extract_values_for_field(filter, field, &mut user_ids);
        }

        // Deduplicate while preserving order.
        let mut seen = Vec::new();
        for id in user_ids {
            if !seen.contains(&id) {
                seen.push(id);
            }
        }

        debug!(
            collection,
            count = seen.len(),
            "resolved user IDs from filter"
        );
        seen
    }

    /// Get the user ID field names for a given collection.
    fn user_id_fields_for(&self, collection: &str) -> Vec<String> {
        for col_config in &self.schema.user_collections {
            if col_config.collection == collection {
                return col_config
                    .user_id_field
                    .columns()
                    .into_iter()
                    .map(|s| s.to_string())
                    .collect();
            }
        }

        // Fall back to user_tables config (some deployments use the same config
        // key for both SQL tables and Mongo collections).
        for table_config in &self.schema.user_tables {
            if table_config.table == collection {
                return table_config
                    .user_id_column
                    .columns()
                    .into_iter()
                    .map(|s| s.to_string())
                    .collect();
            }
        }

        Vec::new()
    }
}

/// Extract user ID values for a specific field from a filter document.
fn extract_values_for_field(filter: &Document, field: &str, out: &mut Vec<String>) {
    // Direct field match at this level.
    if let Some(value) = filter.get(field) {
        extract_from_value(value, out);
    }

    // Check $and / $or arrays for nested filters.
    for logical_op in &["$and", "$or"] {
        if let Some(Bson::Array(conditions)) = filter.get(*logical_op) {
            for condition in conditions {
                if let Bson::Document(subdoc) = condition {
                    extract_values_for_field(subdoc, field, out);
                }
            }
        }
    }
}

/// Extract string values from a BSON value that appears at a user ID field position.
fn extract_from_value(value: &Bson, out: &mut Vec<String>) {
    match value {
        // Direct equality: { "user_id": 42 }
        Bson::Int32(n) => out.push(n.to_string()),
        Bson::Int64(n) => out.push(n.to_string()),
        Bson::String(s) => out.push(s.clone()),
        Bson::ObjectId(oid) => out.push(oid.to_hex()),

        // Operator document: { "user_id": { "$in": [...], "$eq": ... } }
        Bson::Document(subdoc) => {
            // $eq operator
            if let Some(eq_val) = subdoc.get("$eq") {
                extract_from_value(eq_val, out);
            }

            // $in operator
            if let Some(Bson::Array(arr)) = subdoc.get("$in") {
                for item in arr {
                    extract_from_value(item, out);
                }
            }
        }

        // Array of values (unlikely at top level, but handle it).
        Bson::Array(arr) => {
            for item in arr {
                extract_from_value(item, out);
            }
        }

        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bson::doc;
    use uninc_common::config::{UserCollectionConfig, UserIdColumn, UserTableConfig};

    fn make_resolver() -> MongoResolver {
        MongoResolver::new(SchemaConfig {
            user_tables: vec![],
            user_collections: vec![
                UserCollectionConfig {
                    collection: "users".to_string(),
                    user_id_field: UserIdColumn::Single("_id".to_string()),
                },
                UserCollectionConfig {
                    collection: "orders".to_string(),
                    user_id_field: UserIdColumn::Single("user_id".to_string()),
                },
                UserCollectionConfig {
                    collection: "messages".to_string(),
                    user_id_field: UserIdColumn::Multiple(vec![
                        "sender_id".to_string(),
                        "recipient_id".to_string(),
                    ]),
                },
            ],
            excluded_tables: vec![],
        })
    }

    #[test]
    fn direct_match_integer() {
        let resolver = make_resolver();
        let filter = doc! { "user_id": 42 };
        let ids = resolver.resolve_from_filter("orders", Some(&filter));
        assert_eq!(ids, vec!["42"]);
    }

    #[test]
    fn direct_match_string() {
        let resolver = make_resolver();
        let filter = doc! { "user_id": "abc123" };
        let ids = resolver.resolve_from_filter("orders", Some(&filter));
        assert_eq!(ids, vec!["abc123"]);
    }

    #[test]
    fn in_operator() {
        let resolver = make_resolver();
        let filter = doc! { "user_id": { "$in": [42, 43, 44] } };
        let ids = resolver.resolve_from_filter("orders", Some(&filter));
        assert_eq!(ids, vec!["42", "43", "44"]);
    }

    #[test]
    fn eq_operator() {
        let resolver = make_resolver();
        let filter = doc! { "user_id": { "$eq": 99 } };
        let ids = resolver.resolve_from_filter("orders", Some(&filter));
        assert_eq!(ids, vec!["99"]);
    }

    #[test]
    fn object_id_field() {
        let resolver = make_resolver();
        let oid = bson::oid::ObjectId::parse_str("507f1f77bcf86cd799439011").unwrap();
        let filter = doc! { "_id": oid };
        let ids = resolver.resolve_from_filter("users", Some(&filter));
        assert_eq!(ids, vec!["507f1f77bcf86cd799439011"]);
    }

    #[test]
    fn multiple_user_id_fields() {
        let resolver = make_resolver();
        let filter = doc! { "sender_id": 1, "recipient_id": 2 };
        let ids = resolver.resolve_from_filter("messages", Some(&filter));
        assert_eq!(ids, vec!["1", "2"]);
    }

    #[test]
    fn and_operator_nested() {
        let resolver = make_resolver();
        let filter = doc! {
            "$and": [
                { "user_id": 10 },
                { "status": "active" }
            ]
        };
        let ids = resolver.resolve_from_filter("orders", Some(&filter));
        assert_eq!(ids, vec!["10"]);
    }

    #[test]
    fn or_operator_nested() {
        let resolver = make_resolver();
        let filter = doc! {
            "$or": [
                { "user_id": 10 },
                { "user_id": 20 }
            ]
        };
        let ids = resolver.resolve_from_filter("orders", Some(&filter));
        assert_eq!(ids, vec!["10", "20"]);
    }

    #[test]
    fn no_filter_returns_empty() {
        let resolver = make_resolver();
        let ids = resolver.resolve_from_filter("orders", None);
        assert!(ids.is_empty());
    }

    #[test]
    fn unknown_collection_returns_empty() {
        let resolver = make_resolver();
        let filter = doc! { "user_id": 42 };
        let ids = resolver.resolve_from_filter("unknown_collection", Some(&filter));
        assert!(ids.is_empty());
    }

    #[test]
    fn deduplication() {
        let resolver = make_resolver();
        let filter = doc! {
            "$or": [
                { "user_id": 42 },
                { "user_id": 42 }
            ]
        };
        let ids = resolver.resolve_from_filter("orders", Some(&filter));
        assert_eq!(ids, vec!["42"]);
    }

    #[test]
    fn in_with_string_ids() {
        let resolver = make_resolver();
        let filter = doc! { "user_id": { "$in": ["a", "b", "c"] } };
        let ids = resolver.resolve_from_filter("orders", Some(&filter));
        assert_eq!(ids, vec!["a", "b", "c"]);
    }

    #[test]
    fn filter_without_user_id_field() {
        let resolver = make_resolver();
        let filter = doc! { "email": "alice@example.com" };
        let ids = resolver.resolve_from_filter("orders", Some(&filter));
        assert!(ids.is_empty());
    }

    #[test]
    fn fallback_to_user_tables_config() {
        let resolver = MongoResolver::new(SchemaConfig {
            user_tables: vec![UserTableConfig {
                table: "profiles".to_string(),
                user_id_column: UserIdColumn::Single("uid".to_string()),
                sensitive_columns: vec![],
            }],
            user_collections: vec![],
            excluded_tables: vec![],
        });
        let filter = doc! { "uid": 7 };
        let ids = resolver.resolve_from_filter("profiles", Some(&filter));
        assert_eq!(ids, vec!["7"]);
    }
}

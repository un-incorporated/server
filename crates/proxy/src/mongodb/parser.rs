//! MongoDB BSON command parser.
//!
//! Converts a BSON command document into a [`ParsedOperation`] for downstream
//! processing (user resolution, fingerprinting, event emission).
//!
//! MongoDB commands use the first key as the command name and its value as the
//! target collection name.

use bson::Document;
use tracing::debug;

use uninc_common::types::{ActionType, FilterPredicate, ParsedOperation, TableRef};

/// Parse a MongoDB command document into a `ParsedOperation`.
///
/// The first key in the document is the command name (e.g. `"find"`, `"insert"`).
/// Its string value is the target collection name.
pub fn parse_command(doc: &Document) -> ParsedOperation {
    let Some((command, value)) = doc.iter().next() else {
        return ParsedOperation::default();
    };

    let collection = value.as_str().unwrap_or("unknown").to_string();

    let action = classify_action(command);

    debug!(
        command,
        collection,
        ?action,
        "parsed MongoDB command"
    );

    // Extract filter document for user resolution.
    let filter = doc.get_document("filter").ok();

    // Extract projection for scope description.
    let projection = doc.get_document("projection").ok();

    // Extract pipeline for aggregation commands.
    let pipeline = doc.get_array("pipeline").ok();

    // Build filter predicates from the filter document.
    let filters = filter
        .map(|f| extract_predicates(f))
        .unwrap_or_default();

    // Build column list from projection keys.
    let columns = projection
        .map(|p| p.keys().cloned().collect::<Vec<_>>())
        .unwrap_or_default();

    // Serialize raw BSON filter for downstream use.
    let raw_bson_filter = filter.and_then(|f| {
        let mut buf = Vec::new();
        f.to_writer(&mut buf).ok()?;
        Some(buf)
    });

    // Build a human-readable scope string.
    let _scope = build_scope(&collection, filter, projection, pipeline);

    ParsedOperation {
        tables: vec![TableRef {
            name: collection,
            alias: None,
        }],
        columns,
        filters,
        action: Some(action),
        raw_where: None,
        raw_bson_filter,
    }
}

/// Classify a MongoDB command name into an `ActionType`.
fn classify_action(command: &str) -> ActionType {
    match command {
        "find" | "aggregate" | "count" | "distinct" | "getMore" | "listCollections"
        | "listIndexes" | "collStats" | "dbStats" => ActionType::Read,
        "insert" => ActionType::Write,
        "update" | "findAndModify" => ActionType::Write,
        "delete" => ActionType::Delete,
        "drop" | "createIndexes" | "dropIndexes" | "create" | "collMod" | "renameCollection" => {
            ActionType::SchemaChange
        }
        // Default to Read for unknown commands (ping, serverStatus, etc.)
        _ => ActionType::Read,
    }
}

/// Extract filter predicates from a BSON filter document.
///
/// Handles direct equality (`{ "field": value }`) and operator expressions
/// (`{ "field": { "$gt": value } }`).
fn extract_predicates(filter: &Document) -> Vec<FilterPredicate> {
    let mut predicates = Vec::new();

    for (key, value) in filter.iter() {
        // Skip MongoDB operators at the top level ($and, $or, etc.)
        if key.starts_with('$') {
            continue;
        }

        match value {
            bson::Bson::Document(subdoc) => {
                // Operator expression: { "age": { "$gt": 25 } }
                for (op, op_val) in subdoc.iter() {
                    if op.starts_with('$') {
                        predicates.push(FilterPredicate {
                            column: key.clone(),
                            operator: op.clone(),
                            value: bson_value_to_string(op_val),
                        });
                    }
                }
            }
            _ => {
                // Direct equality: { "user_id": 42 }
                predicates.push(FilterPredicate {
                    column: key.clone(),
                    operator: "$eq".to_string(),
                    value: bson_value_to_string(value),
                });
            }
        }
    }

    predicates
}

/// Convert a BSON value to a human-readable string for predicate display.
fn bson_value_to_string(value: &bson::Bson) -> Option<String> {
    match value {
        bson::Bson::String(s) => Some(s.clone()),
        bson::Bson::Int32(n) => Some(n.to_string()),
        bson::Bson::Int64(n) => Some(n.to_string()),
        bson::Bson::Double(n) => Some(n.to_string()),
        bson::Bson::Boolean(b) => Some(b.to_string()),
        bson::Bson::ObjectId(oid) => Some(oid.to_hex()),
        bson::Bson::Null => Some("null".to_string()),
        bson::Bson::Array(arr) => {
            let items: Vec<String> = arr
                .iter()
                .filter_map(|v| bson_value_to_string(v))
                .collect();
            Some(format!("[{}]", items.join(", ")))
        }
        _ => None,
    }
}

/// Build a human-readable scope string for the AccessEvent.
fn build_scope(
    collection: &str,
    filter: Option<&Document>,
    projection: Option<&Document>,
    pipeline: Option<&bson::Array>,
) -> String {
    let mut parts = vec![format!("collection: {collection}")];

    if let Some(proj) = projection {
        let cols: Vec<&str> = proj.keys().map(|k| k.as_str()).collect();
        if !cols.is_empty() {
            parts.push(format!("fields: {}", cols.join(", ")));
        }
    }

    if let Some(f) = filter {
        let filter_keys: Vec<&str> = f.keys().map(|k| k.as_str()).collect();
        if !filter_keys.is_empty() {
            parts.push(format!("filter: {}", filter_keys.join(", ")));
        }
    }

    if let Some(pipe) = pipeline {
        let stages: Vec<String> = pipe
            .iter()
            .filter_map(|stage| {
                if let bson::Bson::Document(d) = stage {
                    d.keys().next().cloned()
                } else {
                    None
                }
            })
            .collect();
        if !stages.is_empty() {
            parts.push(format!("pipeline: {}", stages.join(" | ")));
        }
    }

    parts.join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use bson::doc;

    #[test]
    fn parse_find_command() {
        let doc = doc! {
            "find": "users",
            "filter": { "age": { "$gt": 25 } },
            "projection": { "email": 1, "name": 1 },
            "$db": "mydb"
        };
        let op = parse_command(&doc);
        assert_eq!(op.tables.len(), 1);
        assert_eq!(op.tables[0].name, "users");
        assert_eq!(op.action, Some(ActionType::Read));
        assert_eq!(op.columns, vec!["email", "name"]);
        assert_eq!(op.filters.len(), 1);
        assert_eq!(op.filters[0].column, "age");
        assert_eq!(op.filters[0].operator, "$gt");
    }

    #[test]
    fn parse_insert_command() {
        let doc = doc! {
            "insert": "orders",
            "documents": [{ "item": "widget", "qty": 10 }],
            "$db": "shop"
        };
        let op = parse_command(&doc);
        assert_eq!(op.tables[0].name, "orders");
        assert_eq!(op.action, Some(ActionType::Write));
    }

    #[test]
    fn parse_update_command() {
        let doc = doc! {
            "update": "users",
            "updates": [{
                "q": { "user_id": 42 },
                "u": { "$set": { "name": "Bob" } }
            }],
            "$db": "mydb"
        };
        let op = parse_command(&doc);
        assert_eq!(op.tables[0].name, "users");
        assert_eq!(op.action, Some(ActionType::Write));
    }

    #[test]
    fn parse_delete_command() {
        let doc = doc! {
            "delete": "sessions",
            "deletes": [{ "q": { "expired": true }, "limit": 0 }],
            "filter": { "user_id": 99 },
            "$db": "mydb"
        };
        let op = parse_command(&doc);
        assert_eq!(op.tables[0].name, "sessions");
        assert_eq!(op.action, Some(ActionType::Delete));
        assert_eq!(op.filters.len(), 1);
        assert_eq!(op.filters[0].column, "user_id");
        assert_eq!(op.filters[0].operator, "$eq");
        assert_eq!(op.filters[0].value, Some("99".to_string()));
    }

    #[test]
    fn parse_aggregate_command() {
        let doc = doc! {
            "aggregate": "events",
            "pipeline": [
                { "$match": { "type": "click" } },
                { "$group": { "_id": "$user_id", "count": { "$sum": 1 } } }
            ],
            "cursor": {},
            "$db": "analytics"
        };
        let op = parse_command(&doc);
        assert_eq!(op.tables[0].name, "events");
        assert_eq!(op.action, Some(ActionType::Read));
    }

    #[test]
    fn parse_schema_change_commands() {
        for (cmd, col) in [
            ("drop", "old_table"),
            ("create", "new_table"),
            ("createIndexes", "users"),
            ("dropIndexes", "users"),
        ] {
            let doc = doc! { cmd: col, "$db": "mydb" };
            let op = parse_command(&doc);
            assert_eq!(op.action, Some(ActionType::SchemaChange), "failed for {cmd}");
            assert_eq!(op.tables[0].name, col);
        }
    }

    #[test]
    fn parse_empty_document_returns_default() {
        let doc = doc! {};
        let op = parse_command(&doc);
        assert!(op.tables.is_empty());
        assert_eq!(op.action, None);
    }

    #[test]
    fn filter_with_in_operator() {
        let doc = doc! {
            "find": "users",
            "filter": { "user_id": { "$in": [1, 2, 3] } },
            "$db": "mydb"
        };
        let op = parse_command(&doc);
        assert_eq!(op.filters.len(), 1);
        assert_eq!(op.filters[0].operator, "$in");
        assert_eq!(op.filters[0].value, Some("[1, 2, 3]".to_string()));
    }

    #[test]
    fn filter_with_direct_equality() {
        let doc = doc! {
            "find": "users",
            "filter": { "email": "alice@example.com" },
            "$db": "mydb"
        };
        let op = parse_command(&doc);
        assert_eq!(op.filters.len(), 1);
        assert_eq!(op.filters[0].column, "email");
        assert_eq!(op.filters[0].operator, "$eq");
        assert_eq!(
            op.filters[0].value,
            Some("alice@example.com".to_string())
        );
    }

    #[test]
    fn build_scope_with_all_parts() {
        let filter = doc! { "age": { "$gt": 25 } };
        let projection = doc! { "name": 1, "email": 1 };
        let scope = build_scope("users", Some(&filter), Some(&projection), None);
        assert!(scope.contains("collection: users"));
        assert!(scope.contains("fields: name, email"));
        assert!(scope.contains("filter: age"));
    }

    #[test]
    fn build_scope_with_pipeline() {
        let pipeline = bson::bson!([
            { "$match": { "type": "click" } },
            { "$group": { "_id": "$user_id" } }
        ]);
        let arr = pipeline.as_array().unwrap();
        let scope = build_scope("events", None, None, Some(arr));
        assert!(scope.contains("pipeline: $match | $group"));
    }

    #[test]
    fn unknown_command_defaults_to_read() {
        let doc = doc! { "ping": 1, "$db": "admin" };
        let op = parse_command(&doc);
        assert_eq!(op.action, Some(ActionType::Read));
    }
}

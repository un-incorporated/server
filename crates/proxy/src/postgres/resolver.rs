//! Affected user resolution from SQL WHERE clauses.
//!
//! For V1 this performs static resolution only: it examines the parsed WHERE
//! clause filters to find direct equality matches on configured user_id columns.
//! No runtime queries are issued against the database.
//!
//! Example: if the schema config says `users.user_id_column = "id"` and the
//! query is `SELECT * FROM users WHERE id = 42`, we resolve `["42"]`.

use uninc_common::config::SchemaConfig;
use uninc_common::types::{ParsedOperation, TableRef};

/// Resolves affected user IDs from parsed SQL operations using schema config.
pub struct PostgresResolver {
    schema: SchemaConfig,
}

impl PostgresResolver {
    pub fn new(schema: SchemaConfig) -> Self {
        Self { schema }
    }

    /// Given a parsed operation, determine affected user IDs by static analysis
    /// of the WHERE clause filters.
    ///
    /// Rules:
    /// - Looks at each table referenced in the operation
    /// - If the table matches a configured `user_table`, checks the WHERE filters
    ///   for direct equality (`=`) or `IN` matches on the user_id_column(s)
    /// - Returns the matched literal values as user IDs
    /// - If no direct match is found, returns empty (deferred to runtime)
    pub fn resolve_from_where(&self, operation: &ParsedOperation) -> Vec<String> {
        let mut user_ids = Vec::new();

        for table in &operation.tables {
            let user_id_columns = self.user_id_columns_for_table(table);
            if user_id_columns.is_empty() {
                continue;
            }

            for filter in &operation.filters {
                let filter_col = normalize_column_name(&filter.column, table);
                if user_id_columns.contains(&filter_col.as_str()) {
                    if let Some(ref value) = filter.value {
                        match filter.operator.as_str() {
                            "=" => {
                                let cleaned = clean_literal(value);
                                if !cleaned.is_empty() && !user_ids.contains(&cleaned) {
                                    user_ids.push(cleaned);
                                }
                            }
                            "IN" => {
                                // Value looks like "(1, 2, 3)" — parse individual values
                                let inner = value
                                    .trim_start_matches('(')
                                    .trim_end_matches(')');
                                for part in inner.split(',') {
                                    let cleaned = clean_literal(part.trim());
                                    if !cleaned.is_empty() && !user_ids.contains(&cleaned) {
                                        user_ids.push(cleaned);
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        user_ids
    }

    /// Look up which user_id column(s) are configured for a given table.
    fn user_id_columns_for_table<'a>(&'a self, table: &TableRef) -> Vec<&'a str> {
        for ut in &self.schema.user_tables {
            if table_name_matches(&ut.table, &table.name) {
                return ut.user_id_column.columns();
            }
        }
        Vec::new()
    }
}

/// Check if a configured table name matches a parsed table reference.
/// Handles schema-qualified names (e.g., "public.users" matches "users").
fn table_name_matches(configured: &str, parsed: &str) -> bool {
    if configured == parsed {
        return true;
    }
    // Strip schema prefix from parsed name
    if let Some((_schema, table)) = parsed.rsplit_once('.') {
        return configured == table;
    }
    // Strip schema prefix from configured name
    if let Some((_schema, table)) = configured.rsplit_once('.') {
        return table == parsed;
    }
    false
}

/// Normalize a column name by stripping table alias prefixes.
/// e.g., "u.id" with table alias "u" becomes "id".
fn normalize_column_name(column: &str, table: &TableRef) -> String {
    if let Some(ref alias) = table.alias {
        if let Some(stripped) = column.strip_prefix(&format!("{alias}.")) {
            return stripped.to_string();
        }
    }
    // Also strip the table name prefix
    if let Some(stripped) = column.strip_prefix(&format!("{}.", table.name)) {
        return stripped.to_string();
    }
    column.to_string()
}

/// Clean a literal value string: strip quotes, whitespace.
fn clean_literal(value: &str) -> String {
    value
        .trim()
        .trim_matches('\'')
        .trim_matches('"')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use uninc_common::config::{UserIdColumn, UserTableConfig};
    use uninc_common::types::FilterPredicate;

    fn make_schema() -> SchemaConfig {
        SchemaConfig {
            user_tables: vec![
                UserTableConfig {
                    table: "users".to_string(),
                    user_id_column: UserIdColumn::Single("id".to_string()),
                    sensitive_columns: vec!["email".to_string(), "phone".to_string()],
                },
                UserTableConfig {
                    table: "messages".to_string(),
                    user_id_column: UserIdColumn::Multiple(vec![
                        "sender_id".to_string(),
                        "recipient_id".to_string(),
                    ]),
                    sensitive_columns: vec![],
                },
            ],
            user_collections: vec![],
            excluded_tables: vec!["migrations".to_string()],
        }
    }

    fn make_resolver() -> PostgresResolver {
        PostgresResolver::new(make_schema())
    }

    #[test]
    fn resolve_direct_equality() {
        let resolver = make_resolver();
        let op = ParsedOperation {
            tables: vec![TableRef {
                name: "users".to_string(),
                alias: None,
            }],
            columns: vec!["email".to_string()],
            filters: vec![FilterPredicate {
                column: "id".to_string(),
                operator: "=".to_string(),
                value: Some("42".to_string()),
            }],
            action: None,
            raw_where: Some("id = 42".to_string()),
            raw_bson_filter: None,
        };
        let ids = resolver.resolve_from_where(&op);
        assert_eq!(ids, vec!["42"]);
    }

    #[test]
    fn resolve_string_literal() {
        let resolver = make_resolver();
        let op = ParsedOperation {
            tables: vec![TableRef {
                name: "users".to_string(),
                alias: None,
            }],
            filters: vec![FilterPredicate {
                column: "id".to_string(),
                operator: "=".to_string(),
                value: Some("'user_abc'".to_string()),
            }],
            action: None,
            columns: vec![],
            raw_where: None,
            raw_bson_filter: None,
        };
        let ids = resolver.resolve_from_where(&op);
        assert_eq!(ids, vec!["user_abc"]);
    }

    #[test]
    fn resolve_in_list() {
        let resolver = make_resolver();
        let op = ParsedOperation {
            tables: vec![TableRef {
                name: "users".to_string(),
                alias: None,
            }],
            filters: vec![FilterPredicate {
                column: "id".to_string(),
                operator: "IN".to_string(),
                value: Some("(1, 2, 3)".to_string()),
            }],
            action: None,
            columns: vec![],
            raw_where: None,
            raw_bson_filter: None,
        };
        let ids = resolver.resolve_from_where(&op);
        assert_eq!(ids, vec!["1", "2", "3"]);
    }

    #[test]
    fn resolve_no_match_returns_empty() {
        let resolver = make_resolver();
        let op = ParsedOperation {
            tables: vec![TableRef {
                name: "users".to_string(),
                alias: None,
            }],
            filters: vec![FilterPredicate {
                column: "status".to_string(),
                operator: "=".to_string(),
                value: Some("'active'".to_string()),
            }],
            action: None,
            columns: vec![],
            raw_where: None,
            raw_bson_filter: None,
        };
        let ids = resolver.resolve_from_where(&op);
        assert!(ids.is_empty());
    }

    #[test]
    fn resolve_unknown_table_returns_empty() {
        let resolver = make_resolver();
        let op = ParsedOperation {
            tables: vec![TableRef {
                name: "audit_log".to_string(),
                alias: None,
            }],
            filters: vec![FilterPredicate {
                column: "id".to_string(),
                operator: "=".to_string(),
                value: Some("42".to_string()),
            }],
            action: None,
            columns: vec![],
            raw_where: None,
            raw_bson_filter: None,
        };
        let ids = resolver.resolve_from_where(&op);
        assert!(ids.is_empty());
    }

    #[test]
    fn resolve_multi_column_user_id() {
        let resolver = make_resolver();
        let op = ParsedOperation {
            tables: vec![TableRef {
                name: "messages".to_string(),
                alias: None,
            }],
            filters: vec![
                FilterPredicate {
                    column: "sender_id".to_string(),
                    operator: "=".to_string(),
                    value: Some("10".to_string()),
                },
                FilterPredicate {
                    column: "recipient_id".to_string(),
                    operator: "=".to_string(),
                    value: Some("20".to_string()),
                },
            ],
            action: None,
            columns: vec![],
            raw_where: None,
            raw_bson_filter: None,
        };
        let ids = resolver.resolve_from_where(&op);
        assert_eq!(ids, vec!["10", "20"]);
    }

    #[test]
    fn resolve_with_table_alias() {
        let resolver = make_resolver();
        let op = ParsedOperation {
            tables: vec![TableRef {
                name: "users".to_string(),
                alias: Some("u".to_string()),
            }],
            filters: vec![FilterPredicate {
                column: "u.id".to_string(),
                operator: "=".to_string(),
                value: Some("42".to_string()),
            }],
            action: None,
            columns: vec![],
            raw_where: None,
            raw_bson_filter: None,
        };
        let ids = resolver.resolve_from_where(&op);
        assert_eq!(ids, vec!["42"]);
    }

    #[test]
    fn resolve_deduplicates() {
        let resolver = make_resolver();
        let op = ParsedOperation {
            tables: vec![TableRef {
                name: "users".to_string(),
                alias: None,
            }],
            filters: vec![
                FilterPredicate {
                    column: "id".to_string(),
                    operator: "=".to_string(),
                    value: Some("42".to_string()),
                },
                FilterPredicate {
                    column: "id".to_string(),
                    operator: "=".to_string(),
                    value: Some("42".to_string()),
                },
            ],
            action: None,
            columns: vec![],
            raw_where: None,
            raw_bson_filter: None,
        };
        let ids = resolver.resolve_from_where(&op);
        assert_eq!(ids, vec!["42"]);
    }

    #[test]
    fn table_name_matches_schema_qualified() {
        assert!(table_name_matches("users", "public.users"));
        assert!(table_name_matches("public.users", "users"));
        assert!(!table_name_matches("users", "orders"));
    }

    #[test]
    fn resolve_greater_than_ignored() {
        let resolver = make_resolver();
        let op = ParsedOperation {
            tables: vec![TableRef {
                name: "users".to_string(),
                alias: None,
            }],
            filters: vec![FilterPredicate {
                column: "id".to_string(),
                operator: ">".to_string(),
                value: Some("0".to_string()),
            }],
            action: None,
            columns: vec![],
            raw_where: None,
            raw_bson_filter: None,
        };
        let ids = resolver.resolve_from_where(&op);
        // > is not = or IN, so no resolution
        assert!(ids.is_empty());
    }
}

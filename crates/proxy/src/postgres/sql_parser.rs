//! SQL parsing using sqlparser-rs.
//!
//! Extracts tables, columns, filters, and action type from SQL statements
//! to produce a `ParsedOperation` for downstream user resolution and logging.

use sqlparser::ast::{
    Expr, FromTable, Query, SelectItem, SetExpr, Statement, TableFactor,
    TableWithJoins,
};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;
use tracing::debug;

use uninc_common::types::{ActionType, FilterPredicate, ParsedOperation, TableRef};

/// Parse a SQL statement and extract tables, columns, filters, and action type.
///
/// On parse failure, returns a default (empty) `ParsedOperation` — we never
/// block a query just because we can't parse it.
pub fn parse_sql(sql: &str) -> ParsedOperation {
    let dialect = PostgreSqlDialect {};
    let statements = match Parser::parse_sql(&dialect, sql) {
        Ok(stmts) => stmts,
        Err(e) => {
            debug!(sql, error = %e, "failed to parse SQL");
            return ParsedOperation::default();
        }
    };

    if statements.is_empty() {
        return ParsedOperation::default();
    }

    // We only look at the first statement (most common case).
    parse_statement(&statements[0])
}

fn parse_statement(stmt: &Statement) -> ParsedOperation {
    match stmt {
        Statement::Query(query) => parse_query(query),

        Statement::Insert(insert) => {
            let mut op = ParsedOperation {
                action: Some(ActionType::Write),
                ..Default::default()
            };
            // Extract target table
            let table_name = insert.table_name.to_string();
            op.tables.push(TableRef {
                name: table_name,
                alias: None,
            });
            // Extract column names
            for col in &insert.columns {
                op.columns.push(col.value.clone());
            }
            op
        }

        Statement::Update { table, assignments, selection, .. } => {
            let mut op = ParsedOperation {
                action: Some(ActionType::Write),
                ..Default::default()
            };
            // Extract table from the relation
            extract_table_from_table_with_joins(table, &mut op.tables);
            // Extract assigned columns
            for assignment in assignments {
                // Extract column names from the assignment target.
                let target_str = assignment.target.to_string();
                op.columns.push(target_str);
            }
            // Extract WHERE
            if let Some(where_expr) = selection {
                op.raw_where = Some(where_expr.to_string());
                extract_filters(where_expr, &mut op.filters);
            }
            op
        }

        Statement::Delete(delete) => {
            let mut op = ParsedOperation {
                action: Some(ActionType::Delete),
                ..Default::default()
            };
            // Extract table
            match &delete.from {
                FromTable::WithFromKeyword(tables) | FromTable::WithoutKeyword(tables) => {
                    for twj in tables {
                        extract_table_from_table_with_joins(twj, &mut op.tables);
                    }
                }
            }
            // Extract WHERE
            if let Some(where_expr) = &delete.selection {
                op.raw_where = Some(where_expr.to_string());
                extract_filters(where_expr, &mut op.filters);
            }
            op
        }

        Statement::CreateTable(create) => {
            let mut op = ParsedOperation {
                action: Some(ActionType::SchemaChange),
                ..Default::default()
            };
            op.tables.push(TableRef {
                name: create.name.to_string(),
                alias: None,
            });
            for col_def in &create.columns {
                op.columns.push(col_def.name.value.clone());
            }
            op
        }

        Statement::AlterTable { name, .. } => ParsedOperation {
            action: Some(ActionType::SchemaChange),
            tables: vec![TableRef {
                name: name.to_string(),
                alias: None,
            }],
            ..Default::default()
        },

        Statement::Drop { names, .. } => {
            let mut op = ParsedOperation {
                action: Some(ActionType::SchemaChange),
                ..Default::default()
            };
            for name in names {
                op.tables.push(TableRef {
                    name: name.to_string(),
                    alias: None,
                });
            }
            op
        }

        _ => {
            debug!("unhandled SQL statement type: {stmt}");
            ParsedOperation::default()
        }
    }
}

fn parse_query(query: &Query) -> ParsedOperation {
    let mut op = ParsedOperation {
        action: Some(ActionType::Read),
        ..Default::default()
    };

    if let SetExpr::Select(select) = query.body.as_ref() {
        extract_select_items(&select.projection, &mut op.columns);
        extract_tables_from_from(&select.from, &mut op.tables);

        if let Some(where_expr) = &select.selection {
            op.raw_where = Some(where_expr.to_string());
            extract_filters(where_expr, &mut op.filters);
        }
    }

    op
}

/// Extract column names from SELECT items.
fn extract_select_items(items: &[SelectItem], columns: &mut Vec<String>) {
    for item in items {
        match item {
            SelectItem::UnnamedExpr(Expr::Identifier(ident)) => {
                columns.push(ident.value.clone());
            }
            SelectItem::ExprWithAlias { expr, alias } => {
                // Use the alias if present, otherwise the expression
                let _ = alias;
                if let Expr::Identifier(ident) = expr {
                    columns.push(ident.value.clone());
                } else {
                    columns.push(expr.to_string());
                }
            }
            SelectItem::UnnamedExpr(Expr::CompoundIdentifier(idents)) => {
                // e.g., t.column_name — take the last part
                if let Some(last) = idents.last() {
                    columns.push(last.value.clone());
                }
            }
            SelectItem::Wildcard(_) => {
                columns.push("*".to_string());
            }
            SelectItem::QualifiedWildcard(name, _) => {
                columns.push(format!("{}.*", name));
            }
            _ => {}
        }
    }
}

/// Extract table references from FROM clauses.
fn extract_tables_from_from(from: &[TableWithJoins], tables: &mut Vec<TableRef>) {
    for twj in from {
        extract_table_from_table_with_joins(twj, tables);
    }
}

fn extract_table_from_table_with_joins(twj: &TableWithJoins, tables: &mut Vec<TableRef>) {
    extract_table_from_factor(&twj.relation, tables);
    for join in &twj.joins {
        extract_table_from_factor(&join.relation, tables);
    }
}

fn extract_table_from_factor(factor: &TableFactor, tables: &mut Vec<TableRef>) {
    match factor {
        TableFactor::Table { name, alias, .. } => {
            tables.push(TableRef {
                name: name.to_string(),
                alias: alias.as_ref().map(|a| a.name.value.clone()),
            });
        }
        TableFactor::Derived { alias, .. } => {
            if let Some(a) = alias {
                tables.push(TableRef {
                    name: "(subquery)".to_string(),
                    alias: Some(a.name.value.clone()),
                });
            }
        }
        TableFactor::NestedJoin { table_with_joins, .. } => {
            extract_table_from_table_with_joins(table_with_joins, tables);
        }
        _ => {}
    }
}

/// Extract filter predicates from a WHERE expression.
fn extract_filters(expr: &Expr, filters: &mut Vec<FilterPredicate>) {
    match expr {
        Expr::BinaryOp { left, op, right } => {
            let op_str = op.to_string();
            match op_str.as_str() {
                "AND" | "OR" => {
                    extract_filters(left, filters);
                    extract_filters(right, filters);
                }
                _ => {
                    // Try to extract column = value pattern
                    let column = extract_column_name(left);
                    let value = extract_literal_value(right);
                    if let Some(col) = column {
                        filters.push(FilterPredicate {
                            column: col,
                            operator: op_str,
                            value,
                        });
                    }
                }
            }
        }
        Expr::InList { expr, list, .. } => {
            if let Some(col) = extract_column_name(expr) {
                let values: Vec<String> = list
                    .iter()
                    .filter_map(extract_literal_value_from_expr)
                    .collect();
                filters.push(FilterPredicate {
                    column: col,
                    operator: "IN".to_string(),
                    value: Some(format!("({})", values.join(", "))),
                });
            }
        }
        Expr::IsNull(inner) => {
            if let Some(col) = extract_column_name(inner) {
                filters.push(FilterPredicate {
                    column: col,
                    operator: "IS NULL".to_string(),
                    value: None,
                });
            }
        }
        Expr::IsNotNull(inner) => {
            if let Some(col) = extract_column_name(inner) {
                filters.push(FilterPredicate {
                    column: col,
                    operator: "IS NOT NULL".to_string(),
                    value: None,
                });
            }
        }
        Expr::Nested(inner) => {
            extract_filters(inner, filters);
        }
        _ => {}
    }
}

fn extract_column_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Identifier(ident) => Some(ident.value.clone()),
        Expr::CompoundIdentifier(idents) => {
            Some(idents.iter().map(|i| i.value.as_str()).collect::<Vec<_>>().join("."))
        }
        _ => None,
    }
}

fn extract_literal_value(expr: &Expr) -> Option<String> {
    extract_literal_value_from_expr(expr)
}

fn extract_literal_value_from_expr(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Value(v) => Some(v.to_string()),
        Expr::UnaryOp { op, expr } => {
            // Handle negative numbers: -42
            let inner = extract_literal_value_from_expr(expr)?;
            Some(format!("{op}{inner}"))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_select() {
        let op = parse_sql("SELECT name, email FROM users WHERE id = 42");
        assert_eq!(op.action, Some(ActionType::Read));
        assert_eq!(op.tables.len(), 1);
        assert_eq!(op.tables[0].name, "users");
        assert!(op.columns.contains(&"name".to_string()));
        assert!(op.columns.contains(&"email".to_string()));
        assert_eq!(op.filters.len(), 1);
        assert_eq!(op.filters[0].column, "id");
        assert_eq!(op.filters[0].operator, "=");
    }

    #[test]
    fn parse_select_star() {
        let op = parse_sql("SELECT * FROM users");
        assert_eq!(op.action, Some(ActionType::Read));
        assert!(op.columns.contains(&"*".to_string()));
    }

    #[test]
    fn parse_insert() {
        let op = parse_sql("INSERT INTO users (name, email) VALUES ('Alice', 'a@b.com')");
        assert_eq!(op.action, Some(ActionType::Write));
        assert_eq!(op.tables[0].name, "users");
        assert!(op.columns.contains(&"name".to_string()));
        assert!(op.columns.contains(&"email".to_string()));
    }

    #[test]
    fn parse_update() {
        let op = parse_sql("UPDATE users SET email = 'new@email.com' WHERE id = 42");
        assert_eq!(op.action, Some(ActionType::Write));
        assert_eq!(op.tables[0].name, "users");
        assert!(op.columns.contains(&"email".to_string()));
        assert_eq!(op.filters[0].column, "id");
    }

    #[test]
    fn parse_delete() {
        let op = parse_sql("DELETE FROM users WHERE id = 42 AND status = 'inactive'");
        assert_eq!(op.action, Some(ActionType::Delete));
        assert_eq!(op.tables[0].name, "users");
        assert_eq!(op.filters.len(), 2);
    }

    #[test]
    fn parse_join() {
        let op = parse_sql(
            "SELECT u.name, o.total FROM users u JOIN orders o ON u.id = o.user_id WHERE u.id = 1",
        );
        assert_eq!(op.action, Some(ActionType::Read));
        assert_eq!(op.tables.len(), 2);
        assert_eq!(op.tables[0].name, "users");
        assert_eq!(op.tables[0].alias, Some("u".to_string()));
        assert_eq!(op.tables[1].name, "orders");
        assert_eq!(op.tables[1].alias, Some("o".to_string()));
    }

    #[test]
    fn parse_create_table() {
        let op = parse_sql(
            "CREATE TABLE users (id SERIAL PRIMARY KEY, name TEXT NOT NULL, email TEXT)",
        );
        assert_eq!(op.action, Some(ActionType::SchemaChange));
        assert_eq!(op.tables[0].name, "users");
        assert!(op.columns.contains(&"id".to_string()));
        assert!(op.columns.contains(&"name".to_string()));
        assert!(op.columns.contains(&"email".to_string()));
    }

    #[test]
    fn parse_drop_table() {
        let op = parse_sql("DROP TABLE users");
        assert_eq!(op.action, Some(ActionType::SchemaChange));
        assert_eq!(op.tables[0].name, "users");
    }

    #[test]
    fn parse_alter_table() {
        let op = parse_sql("ALTER TABLE users ADD COLUMN phone TEXT");
        assert_eq!(op.action, Some(ActionType::SchemaChange));
        assert_eq!(op.tables[0].name, "users");
    }

    #[test]
    fn parse_invalid_sql_returns_default() {
        let op = parse_sql("THIS IS NOT SQL AT ALL %%% !!!");
        assert_eq!(op.action, None);
        assert!(op.tables.is_empty());
    }

    #[test]
    fn parse_select_with_in_list() {
        let op = parse_sql("SELECT * FROM users WHERE id IN (1, 2, 3)");
        assert_eq!(op.filters.len(), 1);
        assert_eq!(op.filters[0].column, "id");
        assert_eq!(op.filters[0].operator, "IN");
    }

    #[test]
    fn parse_select_with_multiple_where_conditions() {
        let op =
            parse_sql("SELECT * FROM users WHERE age > 18 AND status = 'active' AND city = 'NYC'");
        assert_eq!(op.action, Some(ActionType::Read));
        assert_eq!(op.filters.len(), 3);
    }
}

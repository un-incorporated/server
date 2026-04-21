//! SQL normalization and fingerprinting.
//!
//! Normalizes SQL by replacing all literal values with `?` placeholders,
//! lowercasing, then computing a SHA-256 hash. This groups structurally
//! identical queries regardless of the specific parameter values used.
//!
//! Example:
//! ```text
//! "SELECT name, email FROM users WHERE id = 42 AND status = 'active'"
//! → "select name, email from users where id = ? and status = ?"
//! → SHA-256(...)
//! ```

use sha2::{Digest, Sha256};
use sqlparser::ast::{Expr, Value, VisitMut, VisitorMut};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;

/// Compute a SHA-256 fingerprint of a normalized SQL query.
///
/// All literal values are replaced with `?`, the entire query is lowercased,
/// and the result is hashed. If the SQL fails to parse, we fall back to
/// hashing the lowercased raw string.
pub fn fingerprint_sql(sql: &str) -> [u8; 32] {
    let normalized = normalize_sql(sql);
    let mut hasher = Sha256::new();
    hasher.update(normalized.as_bytes());
    hasher.finalize().into()
}

/// Normalize a SQL string by replacing all literal values with `?` and lowercasing.
pub fn normalize_sql(sql: &str) -> String {
    let dialect = PostgreSqlDialect {};
    match Parser::parse_sql(&dialect, sql) {
        Ok(mut statements) if !statements.is_empty() => {
            // Walk the AST and replace all literal values with placeholder `?`
            let mut replacer = LiteralReplacer;
            for stmt in &mut statements {
                let _ = stmt.visit(&mut replacer);
            }

            // Re-serialize and lowercase
            let normalized = statements
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .join("; ");
            normalized.to_lowercase()
        }
        _ => {
            // Fallback: just lowercase the raw SQL
            sql.to_lowercase()
        }
    }
}

/// AST visitor that replaces all literal values with a `?` placeholder.
struct LiteralReplacer;

impl VisitorMut for LiteralReplacer {
    type Break = ();

    fn post_visit_expr(&mut self, expr: &mut Expr) -> std::ops::ControlFlow<Self::Break> {
        let should_replace = match expr {
            Expr::Value(v) => {
                let val: &Value = v;
                !matches!(val, Value::Null)
                    && matches!(
                        val,
                        Value::Number(_, _)
                            | Value::SingleQuotedString(_)
                            | Value::DoubleQuotedString(_)
                            | Value::EscapedStringLiteral(_)
                            | Value::HexStringLiteral(_)
                            | Value::Boolean(_)
                    )
            }
            _ => false,
        };
        if should_replace {
            *expr = Expr::Value(Value::Placeholder("?".to_string()).into());
        }
        std::ops::ControlFlow::Continue(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_replaces_numbers() {
        let norm = normalize_sql("SELECT * FROM users WHERE id = 42");
        assert!(norm.contains("?"));
        assert!(!norm.contains("42"));
    }

    #[test]
    fn normalize_replaces_strings() {
        let norm = normalize_sql("SELECT * FROM users WHERE status = 'active'");
        assert!(norm.contains("?"));
        assert!(!norm.contains("active"));
    }

    #[test]
    fn normalize_replaces_multiple_literals() {
        let norm =
            normalize_sql("SELECT name, email FROM users WHERE id = 42 AND status = 'active'");
        assert!(!norm.contains("42"));
        assert!(!norm.contains("active"));
        // Should have two ? placeholders
        assert_eq!(norm.matches('?').count(), 2);
    }

    #[test]
    fn normalize_preserves_null() {
        let norm = normalize_sql("SELECT * FROM users WHERE deleted_at IS NULL");
        assert!(norm.contains("null"));
    }

    #[test]
    fn normalize_is_lowercased() {
        let norm = normalize_sql("SELECT Name FROM Users WHERE ID = 1");
        // The output should be entirely lowercase
        assert_eq!(norm, norm.to_lowercase());
    }

    #[test]
    fn fingerprint_same_structure_same_hash() {
        let fp1 = fingerprint_sql("SELECT * FROM users WHERE id = 1");
        let fp2 = fingerprint_sql("SELECT * FROM users WHERE id = 999");
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn fingerprint_different_structure_different_hash() {
        let fp1 = fingerprint_sql("SELECT * FROM users WHERE id = 1");
        let fp2 = fingerprint_sql("SELECT * FROM orders WHERE id = 1");
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn fingerprint_case_insensitive() {
        let fp1 = fingerprint_sql("SELECT * FROM users WHERE id = 1");
        let fp2 = fingerprint_sql("select * from users where id = 1");
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn fingerprint_invalid_sql_falls_back() {
        // Should not panic, just hash the lowercased raw string
        let fp = fingerprint_sql("NOT VALID SQL %%%");
        assert_ne!(fp, [0u8; 32]);
    }

    #[test]
    fn normalize_insert_replaces_values() {
        let norm = normalize_sql("INSERT INTO users (name, email) VALUES ('Alice', 'a@b.com')");
        assert!(!norm.contains("Alice"));
        assert!(!norm.contains("a@b.com"));
        assert_eq!(norm.matches('?').count(), 2);
    }

    #[test]
    fn normalize_update_replaces_set_and_where() {
        let norm =
            normalize_sql("UPDATE users SET email = 'new@example.com' WHERE id = 42");
        assert!(!norm.contains("new@example.com"));
        assert!(!norm.contains("42"));
    }
}

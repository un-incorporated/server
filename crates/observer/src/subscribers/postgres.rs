//! Postgres WAL subscriber — logical replication via SQL polling.
//!
//! Connects to the DB primary using `tokio-postgres` and polls the
//! logical replication slot using `pg_logical_slot_get_changes()`. Each
//! change row is parsed from the pgoutput text representation and
//! converted to a `ChainEntry` appended to the observer's deployment
//! chain.
//!
//! # Why SQL polling, not the streaming replication protocol
//!
//! The streaming replication protocol (`START_REPLICATION` via CopyBoth)
//! requires a specialized client that speaks the binary pgoutput format.
//! The `pgwire-replication` crate handles this, but it's a newer dep
//! and the SQL polling approach via `pg_logical_slot_get_changes()` is:
//! - Simpler (standard SQL, no binary protocol parsing)
//! - Uses the existing `tokio-postgres` dep (already in workspace)
//! - Captures the same set of DML changes (insert, update, delete)
//! - Sufficient for v1's operation-level comparison
//!
//! v1.1 may upgrade to streaming replication for lower latency if
//! the polling interval (1s) proves too coarse for real-time verification.
//!
//! # Independence from the proxy
//!
//! This connection uses a standard Postgres connection with replication
//! credentials — NOT the proxy. The proxy has no path to modify what
//! the observer sees, because it's a direct DB connection.

use crate::chain::ObserverChain;
use crate::config::PostgresSubscriberConfig;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio_postgres::{NoTls};
use tracing::{debug, error, info, warn};
use uninc_common::ActionType;

/// Sentinel table the proxy's `PgActorMarker` sidechannel writes to
/// before each admin query. INSERTs against this table appear in WAL
/// ahead of the forwarded real op; we parse the actor id out and use
/// it to attribute the following CRUD op. MUST stay in sync with the
/// proxy-side constant in `crates/proxy/src/postgres/actor_marker.rs`.
const MARKER_TABLE: &str = "uninc_audit_marker";

pub struct PostgresSubscriber {
    cfg: PostgresSubscriberConfig,
    chain: Arc<ObserverChain>,
}

impl PostgresSubscriber {
    pub fn new(cfg: PostgresSubscriberConfig, chain: Arc<ObserverChain>) -> Self {
        Self { cfg, chain }
    }

    /// Long-running subscriber loop. Reconnects on failure with
    /// exponential backoff, bounded at 60 seconds.
    pub async fn run(self) {
        let slot = self
            .cfg
            .replication_slot
            .clone()
            .unwrap_or_else(|| "uninc_observer".to_string());

        info!(
            host = self.cfg.host.as_str(),
            port = self.cfg.port,
            database = self.cfg.database.as_str(),
            publication = self.cfg.publication.as_str(),
            slot = slot.as_str(),
            "postgres subscriber starting"
        );

        let mut backoff_secs = 1u64;
        loop {
            match self.connect_and_stream(&slot).await {
                Ok(()) => {
                    backoff_secs = 1;
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                Err(e) => {
                    error!(
                        error = %e,
                        next_retry_secs = backoff_secs,
                        "postgres subscriber errored, backing off"
                    );
                    tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                    backoff_secs = (backoff_secs * 2).min(60);
                }
            }
        }
    }

    /// Connect to the DB primary, ensure the replication slot exists,
    /// then poll for logical decoding changes in a loop.
    async fn connect_and_stream(&self, slot: &str) -> anyhow::Result<()> {
        let chain = Arc::clone(&self.chain);

        let connstr = format!(
            "host={} port={} user={} password={} dbname={}",
            self.cfg.host, self.cfg.port, self.cfg.user, self.cfg.password, self.cfg.database,
        );
        let (client, connection) = tokio_postgres::connect(&connstr, NoTls).await?;

        // Spawn the connection driver.
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                warn!(error = %e, "postgres connection closed");
            }
        });

        info!("postgres connection established, ensuring replication slot");

        // Ensure the logical replication slot exists. This uses the SQL
        // function, not the replication protocol command.
        let create_result = client.execute(
            &format!(
                "SELECT pg_create_logical_replication_slot('{}', 'pgoutput') WHERE NOT EXISTS (SELECT 1 FROM pg_replication_slots WHERE slot_name = '{}')",
                slot, slot
            ),
            &[],
        ).await;

        match create_result {
            Ok(_) => info!(slot, "replication slot ready"),
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("already exists") {
                    debug!(slot, "replication slot already exists");
                } else {
                    return Err(e.into());
                }
            }
        }

        info!(slot, "polling replication slot for changes");
        let mut total_changes: u64 = 0;
        // Most-recent actor id recovered from the sentinel
        // `uninc_audit_marker` table. The proxy writes one marker row
        // via its sidechannel ahead of each forwarded admin query; we
        // read those INSERTs out of WAL and attribute the next CRUD op
        // on a different table to this actor. Concurrent admin
        // sessions race here — see server/SPEC-DELTA.md §"Actor
        // identity" for the interleave limit.
        let mut last_actor: Option<String> = None;

        // Poll loop: fetch pending changes from the replication slot every
        // second. Each call advances the slot's confirmed position, so
        // changes are consumed exactly once.
        loop {
            // pg_logical_slot_get_changes consumes and returns pending changes.
            // Returns rows of (lsn, xid, data) where data is the plugin's
            // text representation of the change. See:
            //   https://www.postgresql.org/docs/current/logicaldecoding-example.html
            let rows = client.query(
                &format!(
                    "SELECT lsn, xid, data FROM pg_logical_slot_get_changes('{}', NULL, NULL, 'proto_version', '1', 'publication_names', '{}')",
                    slot, self.cfg.publication
                ),
                &[],
            ).await?;

            for row in &rows {
                let data: &str = row.get(2);

                // Marker-table INSERTs come through as normal table
                // rows; parse them separately and update `last_actor`
                // without emitting an observer chain entry (the
                // marker is infrastructure, not a data op).
                if let Some(actor) = parse_marker_row(data) {
                    debug!(actor, "postgres sentinel marker observed");
                    last_actor = Some(actor);
                    continue;
                }

                // pgoutput text format: "table <schema>.<table>: <operation> ..."
                // Parse the operation type and table name.
                let (action, table_name, op_label) = if let Some(parsed) = parse_pgoutput_text(data) {
                    parsed
                } else {
                    debug!(data, "skipping unparseable pgoutput record");
                    continue;
                };

                // Defensive: if the parser ever mis-classifies the
                // marker table, treat it as a marker rather than a
                // user-data event.
                if table_name == MARKER_TABLE {
                    continue;
                }

                let scope = format!("{}:{}", op_label, table_name);
                let fingerprint = {
                    let mut h = Sha256::new();
                    h.update(scope.as_bytes());
                    let result: [u8; 32] = h.finalize().into();
                    result
                };

                let metadata = Some(HashMap::from([
                    ("source".to_string(), "postgres_wal".to_string()),
                    ("msg_type".to_string(), op_label.to_string()),
                ]));

                // Attribution: prefer the most-recent sentinel actor;
                // fall back to a placeholder that HMACs to a well-
                // formed but non-matching `actor_id_hash`. The fallback
                // deliberately won't byte-match the proxy's projection
                // so §5.5 surfaces the gap as a real divergence signal
                // rather than a silent pass.
                let actor_pre_hash = last_actor
                    .clone()
                    .unwrap_or_else(|| "observer:postgres".to_string());

                if let Err(e) = chain.append(
                    "_deployment",
                    actor_pre_hash,
                    action,
                    table_name,
                    scope,
                    fingerprint,
                    metadata,
                ).await {
                    warn!(error = %e, "failed to append observer chain entry");
                }

                total_changes += 1;
            }

            if !rows.is_empty() {
                debug!(batch_size = rows.len(), total_changes, "processed WAL changes");
            }

            // Poll interval: 1 second. This balances latency (changes are
            // detected within 1s) against DB load (one query per second when
            // idle). v1.1 may switch to streaming replication for sub-second
            // latency if needed.
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
}

/// Parse a sentinel-table INSERT line. Returns `Some(actor_id)` if
/// the line is a WAL INSERT on `uninc_audit_marker`, otherwise `None`.
///
/// Expected test_decoding-style input:
///
/// ```text
/// table public.uninc_audit_marker: INSERT: id[bigint]:42 \
///   actor_id[text]:'alice' session_id[uuid]:'...' \
///   at[timestamp with time zone]:'2026-04-21 00:00:00+00'
/// ```
///
/// We find the `actor_id[text]:'...'` fragment and extract the quoted
/// value. This is deliberately forgiving of column-order changes;
/// it only requires the `actor_id[text]:'<value>'` substring.
fn parse_marker_row(data: &str) -> Option<String> {
    // The WAL text format is `"table <schema>.<table>: <op>:"`. Match
    // `.uninc_audit_marker: INSERT:` so the schema prefix is
    // schema-agnostic (`public`, `audit`, etc).
    let marker_fragment = format!(".{MARKER_TABLE}: INSERT:");
    if !data.contains(&marker_fragment) {
        return None;
    }
    let needle = "actor_id[text]:'";
    let start = data.find(needle)? + needle.len();
    let tail = &data[start..];

    // SQL string-literal scan: find the CLOSING single quote, treating
    // `''` as an embedded `'`. Without this pass, an actor id like
    // `alice's admin` — legally quoted in CREATE USER "alice's admin"
    // or originating from an email local part per RFC 5321 §4.1.2 —
    // would emit `actor_id[text]:'alice''s admin'` in the WAL, and a
    // naive `find('\'')` would stop at the first of the doubled pair,
    // yielding `alice` and silently mis-attributing every subsequent
    // CRUD op on this session. Spec §3.1.2 makes actor identity the
    // core of observer-side witnessing, so a wrong `actor_id_hash` is
    // worse than the placeholder fallback.
    let mut out = String::new();
    let mut chars = tail.char_indices().peekable();
    while let Some((_, c)) = chars.next() {
        if c == '\'' {
            // Peek at the next char to disambiguate terminator vs escape.
            match chars.peek() {
                Some(&(_, '\'')) => {
                    // Escaped `''` → single `'` in the value.
                    out.push('\'');
                    chars.next();
                }
                _ => {
                    // Unescaped `'` → end of the quoted value.
                    return Some(out);
                }
            }
        } else {
            out.push(c);
        }
    }
    // Ran off the end without finding a closing quote — malformed line.
    None
}

/// Parse pgoutput text representation to extract (action, table_name, op_label).
///
/// pgoutput text format examples:
///   "table public.users: INSERT: id[integer]:42 email[text]:'jane@example.com'"
///   "table public.users: UPDATE: id[integer]:42 email[text]:'new@example.com'"
///   "table public.users: DELETE: id[integer]:42"
///   "BEGIN 12345"
///   "COMMIT 12345"
fn parse_pgoutput_text(data: &str) -> Option<(ActionType, String, String)> {
    // Skip transaction boundary markers.
    if data.starts_with("BEGIN") || data.starts_with("COMMIT") {
        return None;
    }

    // Expected format: "table <schema>.<table>: <OP>: ..."
    if !data.starts_with("table ") {
        return None;
    }

    let after_table = &data["table ".len()..];
    let colon_pos = after_table.find(':')?;
    let full_table_name = &after_table[..colon_pos].trim();

    // Strip schema prefix (e.g. "public.users" → "users")
    let table_name = full_table_name
        .rsplit('.')
        .next()
        .unwrap_or(full_table_name)
        .to_string();

    let rest = after_table[colon_pos + 1..].trim();
    let op = rest.split(':').next()?.trim();

    let (action, label) = match op {
        "INSERT" => (ActionType::Write, "insert"),
        "UPDATE" => (ActionType::Write, "update"),
        "DELETE" => (ActionType::Delete, "delete"),
        "TRUNCATE" => (ActionType::Delete, "truncate"),
        _ => return None,
    };

    Some((action, table_name, label.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_marker_row_extracts_actor() {
        let line = "table public.uninc_audit_marker: INSERT: id[bigint]:42 \
                    actor_id[text]:'alice' \
                    session_id[uuid]:'e3b0c442-98fc-1c14-9afb-f4c8996fb924' \
                    at[timestamp with time zone]:'2026-04-21 00:00:00+00'";
        assert_eq!(parse_marker_row(line), Some("alice".to_string()));
    }

    #[test]
    fn parse_marker_row_ignores_other_tables() {
        let line = "table public.users: INSERT: id[integer]:1 email[text]:'bob@example.com'";
        assert_eq!(parse_marker_row(line), None);
    }

    #[test]
    fn parse_marker_row_ignores_begin_commit() {
        assert_eq!(parse_marker_row("BEGIN 12345"), None);
        assert_eq!(parse_marker_row("COMMIT 12345"), None);
    }

    #[test]
    fn parse_marker_row_handles_non_public_schema() {
        // Unlikely but possible if a customer moves the table.
        let line = "table audit.uninc_audit_marker: INSERT: id[bigint]:1 \
                    actor_id[text]:'carol' session_id[uuid]:'x' at[timestamptz]:'t'";
        assert_eq!(parse_marker_row(line), Some("carol".to_string()));
    }

    #[test]
    fn parse_marker_row_unescapes_doubled_single_quotes() {
        // Postgres' test_decoding output encodes embedded `'` in a text
        // value as `''` (standard SQL string-literal escaping). A naive
        // `find('\'')` truncates at the first inner quote, silently
        // mis-attributing every CRUD op that follows. The unescape pass
        // in parse_marker_row recovers the correct actor_id.
        let line = "table public.uninc_audit_marker: INSERT: id[bigint]:42 \
                    actor_id[text]:'alice''s admin' session_id[uuid]:'x' at[timestamptz]:'t'";
        assert_eq!(
            parse_marker_row(line),
            Some("alice's admin".to_string()),
            "embedded `''` must unescape to a single `'` per SQL string-literal rules"
        );
    }

    #[test]
    fn parse_marker_row_handles_multiple_embedded_quotes() {
        // Belt-and-suspenders: actor IDs with multiple `'` (say, a
        // nested-quote email like `a''b's user`) still recover.
        let line = "table public.uninc_audit_marker: INSERT: id[bigint]:1 \
                    actor_id[text]:'a''b''c' session_id[uuid]:'x' at[timestamptz]:'t'";
        assert_eq!(parse_marker_row(line), Some("a'b'c".to_string()));
    }

    #[test]
    fn parse_marker_row_returns_none_on_unterminated_quote() {
        // Malformed WAL line — no closing quote. Returning None (rather
        // than a partial string or a panic) lets the observer fall back
        // to the placeholder actor and continue processing.
        let line = "table public.uninc_audit_marker: INSERT: id[bigint]:1 actor_id[text]:'unterminated";
        assert_eq!(parse_marker_row(line), None);
    }

    #[test]
    fn parse_pgoutput_text_identifies_marker_table() {
        // Ensures the main parser still routes the marker table
        // through — the observer's run loop uses `table_name ==
        // MARKER_TABLE` as a defensive filter.
        let line = "table public.uninc_audit_marker: INSERT: id[bigint]:1 \
                    actor_id[text]:'dan' session_id[uuid]:'x' at[timestamptz]:'t'";
        let (_, table, _) = parse_pgoutput_text(line).unwrap();
        assert_eq!(table, "uninc_audit_marker");
    }
}

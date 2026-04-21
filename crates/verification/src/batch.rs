//! Batch operation summarization with before/after checksums.

use sha2::{Digest, Sha256};

/// Summary of a batch operation for efficient verification.
///
/// Instead of replaying every row change, we store a before/after checksum
/// pair so the verifier replica can compare states cheaply.
#[derive(Debug, Clone)]
pub struct BatchSummary {
    /// The normalized query template (parameters replaced with placeholders).
    pub query_template: String,
    /// Total number of rows affected by the batch.
    pub affected_row_count: u64,
    /// SHA-256 checksum of the relevant state before the operation.
    pub checksum_before: [u8; 32],
    /// SHA-256 checksum of the relevant state after the operation.
    pub checksum_after: [u8; 32],
}

/// Summarize a batch operation for efficient verification.
///
/// `query` is the SQL or command template.
/// `affected_rows` is how many rows were changed.
/// `before_state` and `after_state` are raw byte representations of the
/// relevant database state (e.g., a sorted dump of affected rows).
pub fn summarize_batch(
    query: &str,
    affected_rows: u64,
    before_state: &[u8],
    after_state: &[u8],
) -> BatchSummary {
    let mut before_hasher = Sha256::new();
    before_hasher.update(before_state);
    let checksum_before: [u8; 32] = before_hasher.finalize().into();

    let mut after_hasher = Sha256::new();
    after_hasher.update(after_state);
    let checksum_after: [u8; 32] = after_hasher.finalize().into();

    BatchSummary {
        query_template: query.to_string(),
        affected_row_count: affected_rows,
        checksum_before,
        checksum_after,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summarize_produces_valid_checksums() {
        let before = b"row1,row2,row3";
        let after = b"row1,row2_modified,row3";
        let summary = summarize_batch("UPDATE users SET name = $1 WHERE id = $2", 1, before, after);

        assert_eq!(summary.affected_row_count, 1);
        assert_ne!(summary.checksum_before, summary.checksum_after);
        assert_eq!(summary.query_template, "UPDATE users SET name = $1 WHERE id = $2");
    }

    #[test]
    fn identical_state_produces_matching_checksums() {
        let state = b"identical state data";
        let summary = summarize_batch("SELECT 1", 0, state, state);
        assert_eq!(summary.checksum_before, summary.checksum_after);
    }

    #[test]
    fn empty_state_is_valid() {
        let summary = summarize_batch("DELETE FROM temp", 5, &[], &[]);
        assert_eq!(summary.checksum_before, summary.checksum_after);
        assert_eq!(summary.affected_row_count, 5);
    }

    #[test]
    fn checksums_are_deterministic() {
        let before = b"some state";
        let after = b"other state";
        let s1 = summarize_batch("Q", 1, before, after);
        let s2 = summarize_batch("Q", 1, before, after);
        assert_eq!(s1.checksum_before, s2.checksum_before);
        assert_eq!(s1.checksum_after, s2.checksum_after);
    }
}

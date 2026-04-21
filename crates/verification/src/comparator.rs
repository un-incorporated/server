//! State comparison: checksums, row-level diffs between replicas.

/// Result of comparing two replica states.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComparisonResult {
    /// The two states are identical.
    Match,
    /// The states have diverged.
    Divergence {
        /// Hex-encoded checksum from the access (Set 0) replica.
        access: String,
        /// Hex-encoded checksum from the verifier (Set 2) replica.
        verifier: String,
    },
}

/// Compare two database states represented as SHA-256 checksums.
///
/// `access_state` is the checksum from the access replica (Set 0).
/// `verifier_state` is the checksum from the verifier replica (Set 2).
pub fn compare_states(
    access_state: &[u8; 32],
    verifier_state: &[u8; 32],
) -> ComparisonResult {
    if access_state == verifier_state {
        ComparisonResult::Match
    } else {
        ComparisonResult::Divergence {
            access: hex::encode(access_state),
            verifier: hex::encode(verifier_state),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_states_match() {
        let state = [0xab; 32];
        assert_eq!(compare_states(&state, &state), ComparisonResult::Match);
    }

    #[test]
    fn different_states_diverge() {
        let access = [0x11; 32];
        let verifier = [0x22; 32];
        let result = compare_states(&access, &verifier);
        match result {
            ComparisonResult::Divergence { access, verifier } => {
                assert_eq!(access, hex::encode([0x11; 32]));
                assert_eq!(verifier, hex::encode([0x22; 32]));
            }
            ComparisonResult::Match => panic!("expected divergence"),
        }
    }

    #[test]
    fn single_bit_difference_detected() {
        let mut access = [0x00; 32];
        let mut verifier = [0x00; 32];
        verifier[31] = 0x01;
        assert!(matches!(
            compare_states(&access, &verifier),
            ComparisonResult::Divergence { .. }
        ));

        // Fix the bit — should match now
        access[31] = 0x01;
        assert_eq!(compare_states(&access, &verifier), ComparisonResult::Match);
    }

    #[test]
    fn zero_checksums_match() {
        let zero = [0u8; 32];
        assert_eq!(compare_states(&zero, &zero), ComparisonResult::Match);
    }
}

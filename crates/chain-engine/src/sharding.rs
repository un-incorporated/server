//! Chain file sharding at configurable boundaries (default: 10,000 entries).
//!
//! For V1, sharding is not yet implemented. Chains use a single chain.dat file.
//! This module provides the shard boundary calculation for future use.

/// Calculate which shard file an entry belongs to.
pub fn shard_index(entry_index: u64, shard_size: u64) -> u64 {
    entry_index / shard_size
}

/// Calculate the entry range for a given shard.
pub fn shard_range(shard: u64, shard_size: u64) -> (u64, u64) {
    let start = shard * shard_size;
    let end = start + shard_size;
    (start, end)
}

/// Generate the shard filename.
pub fn shard_filename(shard: u64) -> String {
    format!("chain_{:04}.dat", shard)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shard_calculation() {
        assert_eq!(shard_index(0, 10_000), 0);
        assert_eq!(shard_index(9_999, 10_000), 0);
        assert_eq!(shard_index(10_000, 10_000), 1);
        assert_eq!(shard_index(25_000, 10_000), 2);
    }

    #[test]
    fn shard_range_correct() {
        assert_eq!(shard_range(0, 10_000), (0, 10_000));
        assert_eq!(shard_range(1, 10_000), (10_000, 20_000));
    }

    #[test]
    fn shard_filename_format() {
        assert_eq!(shard_filename(0), "chain_0000.dat");
        assert_eq!(shard_filename(1), "chain_0001.dat");
        assert_eq!(shard_filename(99), "chain_0099.dat");
    }
}

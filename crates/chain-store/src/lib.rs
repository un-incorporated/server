//! Per-user and deployment-wide hash-chain storage and hashing for
//! Uninc Access Transparency v1 (see `protocol/draft-wang-data-access-transparency-00.md`).
//!
//! This crate is the shared data layer for the transparency chain: the
//! writer (`chain-engine`, consuming NATS access events), the reader
//! (the proxy's `chain_api` module serving `:9091/api/v1/chain/*`), and
//! the client-side WASM verifier (`chain-verifier-wasm`) all link against
//! the single `ChainEntry` + `compute_hash` defined here. Because every
//! party uses the same `serialize` function, the hash inputs are
//! byte-identical by construction.
//!
//! The `storage` feature (default-on) adds the on-disk read/write layer
//! plus user-hashing. Consumers that only need the hash algorithm (e.g.
//! the WASM verifier) build with `default-features = false` to skip the
//! native-only transitive dependencies of `uninc-common` and `chrono`.

pub mod entry;

#[cfg(feature = "storage")]
pub mod storage;

// Conversions between the application-layer enums in `uninc-common` and
// the wire-level enums in `entry`. Gated behind `storage` because
// uninc-common is a storage-only dep (the WASM verifier doesn't have it).
// These are identity maps today; the impls exist so callers can write
// `.into()` rather than `match` ladders, and so the two sides stay in
// sync — adding a variant to either side without the other flags a
// compile error here.
#[cfg(feature = "storage")]
mod from_uninc_common {
    use crate::entry::{DeploymentActorType, DeploymentCategory};

    impl From<uninc_common::DeploymentCategory> for DeploymentCategory {
        fn from(c: uninc_common::DeploymentCategory) -> Self {
            use uninc_common::DeploymentCategory as U;
            match c {
                U::AdminAccess => Self::AdminAccess,
                U::AdminLifecycle => Self::AdminLifecycle,
                U::Config => Self::Config,
                U::Deploy => Self::Deploy,
                U::Schema => Self::Schema,
                U::System => Self::System,
                U::ApprovedAccess => Self::ApprovedAccess,
                U::Egress => Self::Egress,
                U::UserErasureRequested => Self::UserErasureRequested,
                U::RetentionSweep => Self::RetentionSweep,
                U::ReplicaReshuffle => Self::ReplicaReshuffle,
                U::VerificationFailure => Self::VerificationFailure,
                U::NightlyVerification => Self::NightlyVerification,
            }
        }
    }

    impl From<uninc_common::ActorType> for DeploymentActorType {
        fn from(a: uninc_common::ActorType) -> Self {
            use uninc_common::ActorType as U;
            match a {
                U::Admin => Self::Admin,
                U::System => Self::System,
                U::CiCd => Self::Cicd,
                U::Operator => Self::Operator,
            }
        }
    }
}

pub use entry::{
    AccessAction, AccessActorType, AccessEvent, AccessScope, ChainEntry, EntryError, EventPayload,
    DeploymentActorType, DeploymentCategory, DeploymentEvent, MAX_PAYLOAD_LEN, ObservedAction,
    ObservedDeploymentEvent, PAYLOAD_TYPE_ACCESS_EVENT, PAYLOAD_TYPE_DEPLOYMENT_EVENT,
    PAYLOAD_TYPE_OBSERVED_DEPLOYMENT_EVENT, Protocol,
    UAT_VERSION_OCTET, canonicalize_payload, compute_hash, serialize,
};

#[cfg(feature = "storage")]
pub use storage::{ChainMeta, ChainStore, StorageError, list_chain_dirs};

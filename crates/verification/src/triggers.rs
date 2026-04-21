//! v1 trigger model: **only T3 (scheduled cross-replica comparison)**.
//!
//! Earlier drafts of this file held four trigger loops — T1 (session end),
//! T2 (periodic hourly), T3 (daily full comparison), and T4 (randomized
//! role reshuffle). For v1 we ship only T3: a single background task
//! that wakes up on a schedule and runs the full cross-replica check.
//!
//! The other triggers are deferred.
//! The T3 scheduled run is sufficient for v1 because:
//!
//!   1. A cross-replica state comparison running at least once per day
//!      catches any divergence within 24 hours — well inside the window
//!      an auditor or breach investigator would care about.
//!   2. The replicas are already independent (no SSH, no public IPs,
//!      firewall-limited), so the attack surface between scheduled
//!      runs is small.
//!   3. Running fewer triggers means less code, fewer places for bugs,
//!      and a simpler operational story for the first customer cohort.
//!
//! The scheduling loop itself lives in `task.rs`
//! (`run_scheduled_verification` + `start_scheduled_verification_task`).
//! This file just re-exports the entry point under its canonical name.
//!
//! Cadence note: the current default window is nightly (02:00–04:00 UTC
//! jittered), but the code is named `scheduled_*` rather than `nightly_*`
//! so that retuning the cadence — e.g. to hourly or every-four-hours to
//! match tighter tamper-detection SLOs — is a config change, not a
//! code-rename.

pub use crate::task::start_scheduled_verification_task;

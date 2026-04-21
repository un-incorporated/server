//! Erasure request handler — serves `ERASURE_NATS_SUBJECT` (core NATS
//! request/reply) and implements the full §7.3.1 / §8.1 flow:
//!
//!   1. commit a `UserErasureRequested` tombstone to the deployment chain
//!   2. delete the per-user chain from local fs + durable replicas
//!   3. reply with the tombstone receipt
//!
//! Topology:
//!
//! ```text
//!   proxy DELETE handler
//!       │  (core NATS request/reply, 5s timeout)
//!       ▼
//!   uninc.control.erasure  ──► this handler
//!                                  │
//!                                  ├──► DeploymentChainManager::append_deployment_event
//!                                  │       (commit tombstone, get index + entry_hash)
//!                                  │
//!                                  └──► ChainManager::delete_chain_by_hash
//!                                          (local fs + durable replicas, quorum)
//!                                  │
//!                                  ▼
//!                       receipt (or partial-failure envelope) → reply to proxy
//! ```
//!
//! Tombstone-first ordering. Physical delete runs only after the tombstone
//! has durably committed. If the delete fails AFTER that, the reply carries
//! the receipt plus a `partial_failure` string so the proxy surfaces a 503
//! that names the tombstone — an operator can then re-run the durable-tier
//! sweep without double-tombstoning.
//!
//! Runs alongside the JetStream `run_consumer` loop. Both share the NATS
//! cluster but different subjects — the JetStream stream is durable and
//! at-least-once; this handler is ephemeral and exactly-once-per-request
//! (the caller retries on timeout; duplicates would produce two tombstones,
//! which is acceptable per §7.3.1's "MUST record" semantics).

use crate::chain::ChainManager;
use crate::deployment_chain::DeploymentChainManager;
use anyhow::Result;
use async_nats::Client;
use futures::StreamExt;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{error, info, warn};
use uninc_common::types::{
    ActionType, ActorType, DeploymentCategory, ERASURE_NATS_SUBJECT, ErasureReceipt,
    ErasureRequest,
};

pub async fn run_erasure_handler(
    nats_url: &str,
    deployment_chain_manager: Arc<DeploymentChainManager>,
    chain_manager: Arc<ChainManager>,
) -> Result<()> {
    let client = async_nats::connect(nats_url).await?;
    let mut subscriber = client.subscribe(ERASURE_NATS_SUBJECT).await?;

    info!(
        subject = ERASURE_NATS_SUBJECT,
        "erasure request handler started"
    );

    while let Some(msg) = subscriber.next().await {
        let Some(reply_to) = msg.reply.clone() else {
            warn!(
                subject = %msg.subject,
                "erasure message had no reply subject — ignoring"
            );
            continue;
        };

        let req: ErasureRequest = match serde_json::from_slice(&msg.payload) {
            Ok(r) => r,
            Err(e) => {
                error!(error = %e, "failed to deserialize ErasureRequest");
                reply_error(&client, &reply_to, &format!("decode: {e}")).await;
                continue;
            }
        };

        // Step 1: commit tombstone.
        let receipt = match commit_tombstone(&deployment_chain_manager, &req).await {
            Ok(r) => r,
            Err(e) => {
                error!(error = %e, "failed to commit erasure tombstone");
                reply_error(&client, &reply_to, &e.to_string()).await;
                continue;
            }
        };

        // Step 2: physical delete (local fs + durable replicas). Only after
        // the tombstone is durably committed.
        if let Err(e) = chain_manager
            .delete_chain_by_hash(&req.user_id_hash)
            .await
        {
            error!(
                user_id_hash = %req.user_id_hash,
                tombstone_index = receipt.tombstone_deployment_chain_index,
                error = %e,
                "partial erasure: tombstone committed but physical delete failed"
            );
            reply_partial_failure(&client, &reply_to, &receipt, &e.to_string()).await;
            continue;
        }

        info!(
            user_id_hash = %req.user_id_hash,
            index = receipt.tombstone_deployment_chain_index,
            "erasure complete (tombstone + local + durable)"
        );
        reply_receipt(&client, &reply_to, &receipt).await;
    }

    warn!("erasure handler subscriber stream ended");
    Ok(())
}

async fn commit_tombstone(
    manager: &DeploymentChainManager,
    req: &ErasureRequest,
) -> Result<ErasureReceipt> {
    // Per §4.11.1 / §7.3.1 the tombstone is an DeploymentEvent with:
    //   - actor_id   = user's hashed id (we never relearn the plaintext here).
    //                  This makes every tombstone deterministic for the same
    //                  (salt, user_id) pair without reintroducing the id.
    //   - actor_type = System — the server committed the erasure; the user
    //                  requested it. `details.requested_by = "data_subject"`
    //                  captures who asked for it.
    //   - category   = UserErasureRequested
    //   - action     = Delete
    //   - resource   = "user_chain"
    //   - scope      = short human summary.
    //   - details    = { user_id_hash, source_ip, requested_at, requested_by }
    let mut details = HashMap::new();
    details.insert("user_id_hash".to_string(), req.user_id_hash.clone());
    details.insert("source_ip".to_string(), req.source_ip.clone());
    details.insert("requested_at".to_string(), req.requested_at.to_string());
    details.insert("requested_by".to_string(), "data_subject".to_string());

    let scope = format!("user_chain erasure for {}", req.user_id_hash);

    let (index, entry_hash) = manager
        .append_deployment_event(
            &req.user_id_hash,
            ActorType::System,
            DeploymentCategory::UserErasureRequested,
            ActionType::Delete,
            "user_chain",
            &scope,
            Some(details),
            None,
            req.session_id,
            Some(&req.source_ip),
        )
        .await?;

    Ok(ErasureReceipt {
        tombstone_entry_id: hex::encode(entry_hash),
        tombstone_deployment_chain_index: index,
    })
}

async fn reply_receipt(client: &Client, reply_to: &async_nats::Subject, receipt: &ErasureReceipt) {
    let bytes = match serde_json::to_vec(receipt) {
        Ok(b) => b,
        Err(e) => {
            error!(error = %e, "failed to serialize ErasureReceipt");
            reply_error(client, reply_to, &format!("encode: {e}")).await;
            return;
        }
    };
    if let Err(e) = client.publish(reply_to.clone(), bytes.into()).await {
        error!(error = %e, "failed to publish tombstone reply");
    }
}

/// Reply with `{"receipt": ErasureReceipt, "partial_failure": "<message>"}`.
/// The proxy decodes this into `TombstoneError::PartialErasure` and returns
/// 503 to the caller with the tombstone id named so an operator can finish
/// the durable-tier cleanup by hand. Matches the wire contract documented
/// in `uninc_common::nats_client::request_erasure_tombstone`.
async fn reply_partial_failure(
    client: &Client,
    reply_to: &async_nats::Subject,
    receipt: &ErasureReceipt,
    message: &str,
) {
    let body = serde_json::json!({
        "receipt": receipt,
        "partial_failure": message,
    });
    let bytes = match serde_json::to_vec(&body) {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, "failed to serialize partial_failure reply");
            return;
        }
    };
    if let Err(e) = client.publish(reply_to.clone(), bytes.into()).await {
        warn!(error = %e, "failed to deliver partial_failure reply");
    }
}

async fn reply_error(client: &Client, reply_to: &async_nats::Subject, message: &str) {
    let body = serde_json::json!({ "error": message });
    let bytes = match serde_json::to_vec(&body) {
        Ok(b) => b,
        Err(_) => return,
    };
    if let Err(e) = client.publish(reply_to.clone(), bytes.into()).await {
        warn!(error = %e, "failed to deliver erasure error reply");
    }
}

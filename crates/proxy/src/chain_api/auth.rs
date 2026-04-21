//! JWT auth for `/api/v1/chain/*` — implements §6 (Authentication) of
//! the protocol spec, gating the endpoints defined in §7 (HTTP API). See
//! `protocol/draft-wang-data-access-transparency-00.md`.
//!
//! Customers hold `JWT_SECRET` (provisioned per-deployment by the www
//! control plane, stored in GCP Secret Manager as `dep-{id}-jwt`, and
//! injected into the proxy VM's env). They sign short-lived HS256 tokens
//! from their own backend and send them in `Authorization: Bearer ...`.
//!
//! Token format (spec §6.1, required claims per that clause):
//!   header:  { alg: "HS256", typ: "JWT" }
//!   payload: { iss, sub, aud, exp, jti }   // `iat` is OPTIONAL and ignored
//!
//! `iss`  — Opaque customer identifier. Recorded in audit logs; the proxy
//!          does not enforce a specific value but rejects empty/missing.
//! `sub`  — User id (bound to the URL path `:user_id` per §6.3's subject
//!          binding) OR the literal "operator" for admin-scoped calls.
//! `aud`  — "chain-api-user" (user-scoped reads) or "chain-api-admin"
//!          (operator).
//! `exp`  — Unix seconds. Spec §6.1 recommends `exp` no more than 3600
//!          seconds beyond the moment of issue.
//! `iat`  — OPTIONAL per §6.1. v1 does not require or act on `iat`; tokens
//!          omitting it are accepted, and its value is ignored when present.
//!          Decoded here only because the jwt crate deserializes it for
//!          diagnostic display.
//! `jti`  — Unique token identifier. Required per §6.1 / §10.5. The proxy
//!          records each accepted `jti` in the in-process replay
//!          deny-list (see `crate::jwt_replay`) and rejects any repeat
//!          within the token's `exp` window.
//!
//! Subject binding (§6.3): the predicate is plain string equality
//! `claims.sub == url_user_id`. Per-user storage lookup hashes the URL id
//! internally to `HMAC-SHA-256(deployment_salt, user_id)` so
//! `deployment_salt` remains operator-private; the JWT issuer never
//! needs to know it.

use axum::{
    extract::FromRequestParts,
    http::{header::AUTHORIZATION, request::Parts},
};
use jsonwebtoken::{DecodingKey, Validation, decode};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use super::ChainApiState;
use super::errors::ApiError;
use crate::jwt_replay::JtiAdmit;

/// Valid `aud` values the chain API accepts. `chain-api-user` is for
/// user-scoped endpoints (`/u/:id/*`); `chain-api-admin` is for operator-
/// scoped endpoints like `/deployment/summary`. The two audiences match
/// §6.2 of protocol/draft-wang-data-access-transparency-00.md exactly. Tokens for one
/// audience cannot be used on the other.
pub const AUD_USER: &str = "chain-api-user";
pub const AUD_ADMIN: &str = "chain-api-admin";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    pub sub: String,
    pub aud: String,
    pub exp: usize,
    /// Issued-at. OPTIONAL in v1 (§6.1): the jti deny-list plus `exp`
    /// already carry single-use + freshness. Reserved for future minor
    /// versions; accepted but not required or acted upon.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iat: Option<usize>,
    /// Customer identifier (§6.1). Required. Empty strings are rejected
    /// at the extractor layer.
    pub iss: String,
    /// Unique token identifier (§6.1). Required for §10.5 replay
    /// prevention; a request whose token omits or empties this field
    /// is rejected at the extractor layer.
    pub jti: String,
}

impl FromRequestParts<Arc<ChainApiState>> for JwtClaims {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<ChainApiState>,
    ) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.strip_prefix("Bearer "))
            .ok_or_else(|| ApiError::Unauthorized("missing bearer token".into()))?;

        let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.set_audience(&[AUD_USER, AUD_ADMIN]);
        // §6.1 requires iss, sub, aud, exp, jti. v1 does not use `iat` —
        // the jti deny-list (§10.5) plus a capped `exp` window already
        // carry the single-use + freshness contract. `nbf` is OPTIONAL.
        // `jti` is a custom string validated below (the crate doesn't
        // treat it as a spec-presence claim).
        validation.set_required_spec_claims(&["iss", "sub", "aud", "exp"]);
        validation.validate_exp = true;
        validation.leeway = 5;

        let data = decode::<JwtClaims>(
            token,
            &DecodingKey::from_secret(&state.jwt_secret),
            &validation,
        )
        .map_err(|e| ApiError::Unauthorized(format!("invalid jwt: {e}")))?;

        let claims = data.claims;
        if claims.iss.trim().is_empty() {
            return Err(ApiError::Unauthorized(
                "jwt missing required iss claim".into(),
            ));
        }
        if claims.jti.trim().is_empty() {
            return Err(ApiError::Unauthorized(
                "jwt missing required jti claim".into(),
            ));
        }

        match state.jti_deny.admit(&claims.jti, claims.exp as u64) {
            JtiAdmit::Fresh => Ok(claims),
            JtiAdmit::Replayed => Err(ApiError::Unauthorized(
                "jwt jti already used (replay rejected)".into(),
            )),
            // Normal exp validation above should have caught this; belt and
            // suspenders in case clock skew leeway lets an expired token
            // through the jwt crate's own exp check.
            JtiAdmit::Expired => Err(ApiError::Unauthorized("jwt expired".into())),
        }
    }
}

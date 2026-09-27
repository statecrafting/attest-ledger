// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Bartek Kus
//
// Relicensed from the Open Agentic Platform (crates/policy-kernel:
// proof_chain.rs and the pure subset of audit.rs, AGPL-3.0-or-later) to
// Apache-2.0 by the sole copyright holder. See NOTICE.

//! `attest-ledger-core`: a tamper-evident record ledger.
//!
//! Two hash-linked chains share one linkage primitive:
//!
//! - **Record chain** ([`RecordChain`]): individual [`LedgerRecord`]s, each
//!   hashing the canonical JSON of the prior record's hash into its own. A
//!   signed [`ChainAnchor`] pins the chain to a root and is Ed25519-signed, so
//!   an external verifier has a trust root beyond the chain's own hashes.
//! - **Audit-segment chain** ([`AuditChain`]): a content-agnostic, hash-chained
//!   segment log for higher-volume append, closed with a size-anchoring segment
//!   head, verified by [`verify_audit_chain`].
//!
//! # Determinism
//!
//! The core takes **all** hash inputs (including `timestamp`) as arguments: no
//! wall clock, no `Date.now()`. [`compute_record_hash`] is therefore a pure
//! function of its inputs and the verifier is reproducible byte-for-byte across
//! platforms. Reproducible hashing rests on [`canonical_keysort_json`], which
//! guarantees key-sorted serialization regardless of `serde_json`'s
//! `preserve_order` feature state anywhere in the dependency graph.
//!
//! # Storage is not here
//!
//! This crate produces and verifies records; it owns no persistence. Writing
//! records to JSONL files, rotating them, or committing them to a database is
//! the consumer's concern.
//!
//! # Completeness and freshness
//!
//! The original verifiers prove integrity only for the sequence presented.
//! [`verify_chain_with_head`] and [`verify_audit_chain_with_head`] additionally
//! require exact agreement with a [`HeadCommitmentV1`] obtained through a
//! separately trusted channel. A commitment stored and rolled back with the
//! ledger is not a freshness authority.

use sha2::{Digest, Sha256};

mod audit;
mod head_commitment;
mod record_chain;
mod signing;

pub use attest_ledger_types::{
    AuditHeadVerifyError, AuditVerifyError, ChainAnchor, GenesisAttestation,
    GenesisAttestationKind, HEAD_COMMITMENT_SCHEMA_V1, HeadCommitmentKind, HeadCommitmentV1,
    HeadVerifyError, LedgerRecord, VerifyError,
};

pub use audit::{AuditChain, verify_audit_chain};
pub use head_commitment::{
    build_audit_head_commitment, build_record_head_commitment, chain_anchor_identity,
    head_commitment_canonical_bytes, head_commitment_digest, verify_audit_chain_with_head,
    verify_chain_with_head,
};
pub use record_chain::{
    DEFAULT_MAX_RECORD_BYTES, RecordChain, compute_record_hash, record_payload_bytes, verify_chain,
    verify_chain_with_anchor,
};
pub use signing::{
    ENV_SIGNING_KEY, ENV_SIGNING_KEY_PATH, resolve_signing_material, sign_anchor, verify_anchor,
};

/// `sha256:<hex>` over `bytes`.
///
/// The `sha256:` prefix is carried from OAP so the hash is self-describing and
/// existing OAP chains verify byte-identically under this core.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

/// Hash a JSON value with `hash_field` removed, over its canonical (key-sorted)
/// serialization.
///
/// This is the single linkage primitive shared by the record chain and the
/// audit chain: both compute their record hash through this one function,
/// differing only in the record body and the hash field name. Reusing one
/// linkage discipline is deliberate: there is exactly one chain shape to reason
/// about.
pub fn link_record_hash(mut value: serde_json::Value, hash_field: &str) -> String {
    if let serde_json::Value::Object(ref mut m) = value {
        m.remove(hash_field);
    }
    sha256_hex(canonical_keysort_json::to_canonical_string(&value).as_bytes())
}

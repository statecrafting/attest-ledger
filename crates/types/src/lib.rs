// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Bartek Kus
//
// Relicensed from the Open Agentic Platform (crates/policy-kernel/proof_chain.rs,
// AGPL-3.0-or-later) to Apache-2.0 by the sole copyright holder. See NOTICE.

//! Data types for `attest-ledger`: the tamper-evident record chain envelope,
//! the signed genesis anchor, the attestation taxonomy, and the verification
//! error enums.
//!
//! This crate holds only the shapes and errors; the hashing, signing, and
//! verification logic lives in `attest-ledger-core`. Depending on this crate
//! alone gets a consumer the on-the-wire structs without pulling in the crypto
//! stack.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// One append-only ledger record.
///
/// `record_hash` is the SHA-256 (carrying a `sha256:` prefix) over the
/// canonical, key-sorted JSON of this record **with the `record_hash` field
/// removed**, so a record never hashes its own hash.
/// `previous_record_hash` binds the predecessor record, or, for the genesis
/// record, the chain anchor hash.
///
/// The envelope is domain-neutral: every field except `payload` is chain
/// mechanism. `payload` carries the consumer's opaque domain content (a
/// governance decision, a message-send record, anything). The ledger core
/// never inspects it; it is hashed as-is, key-sorted, so two producers emitting
/// the same logical payload produce the same record hash regardless of key
/// insertion order.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LedgerRecord {
    pub id: String,
    /// Caller-supplied timestamp (any string; RFC 3339 by convention). The core
    /// takes it as an argument and never reads a wall clock, so `record_hash`
    /// stays a pure function of its inputs and the verifier is reproducible.
    pub timestamp: String,
    pub previous_record_hash: String,
    pub record_hash: String,
    pub payload: Value,
}

/// Trust posture recorded for a chain's genesis signing key. Structural mirror
/// of a certificate-side attestation taxonomy so an auditor reads one story
/// across the ledger side and the certificate side.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum GenesisAttestationKind {
    /// No genesis signature was set: an unsigned writer.
    #[default]
    Unsigned,
    /// Key generated for this writer's lifetime only. Local-dev posture.
    Ephemeral,
    /// Operator-supplied key via env var or file. Out of agent write scope.
    Operator,
    /// Sigstore Fulcio + Rekor anchored. The strongest posture (consumer wires
    /// the actual Sigstore flow; this crate only records the claim).
    SigstoreRekor,
}

/// The attestation attached to a [`ChainAnchor`]: what kind of key signed the
/// genesis, plus an optional human note on its provenance.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct GenesisAttestation {
    pub kind: GenesisAttestationKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Signed chain-genesis anchor.
///
/// Pins the chain's starting point to a signing key so an external verifier has
/// a trust root beyond the chain's own self-referential hashes. The signature
/// covers the canonical JSON of the anchor with `genesis_signature` zeroed.
/// The genesis record's `previous_record_hash` must equal `anchor_hash`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChainAnchor {
    pub chain_id: String,
    /// The pinned root hash (the generic form of OAP's `policy_bundle_hash`).
    /// The genesis record links to this.
    pub anchor_hash: String,
    pub genesis_timestamp: String,
    /// Base64 Ed25519 public key (32 bytes). Empty for unsigned chains;
    /// signature verification rejects empty.
    #[serde(default)]
    pub genesis_public_key: String,
    /// Base64 Ed25519 signature (64 bytes) over canonical JSON of the anchor
    /// with `genesis_signature` zeroed.
    #[serde(default)]
    pub genesis_signature: String,
    #[serde(default)]
    pub genesis_attestation: GenesisAttestation,
}

/// Record-chain verification failure (the generic form of OAP's
/// `ProofChainError`), naming the first broken record where applicable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// The chain has no records.
    EmptyChain,
    /// Record `index`'s stored `record_hash` does not match a recompute: the
    /// record's content was altered.
    RecordHashMismatch { index: usize },
    /// Record `index`'s `previous_record_hash` does not bind its predecessor:
    /// a record was deleted, reordered, or spliced.
    BrokenLink { index: usize },
    /// The genesis anchor signature did not verify, or the anchor is unsigned
    /// when a signature was required. The string carries the specific
    /// diagnostic distinguishing the two.
    AnchorSignature(String),
    /// The signed anchor's `anchor_hash` does not match the genesis record's
    /// `previous_record_hash`: the anchor and the chain disagree on the root.
    GenesisLinkMismatch { expected: String, found: String },
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyChain => write!(f, "empty chain"),
            Self::RecordHashMismatch { index } => {
                write!(
                    f,
                    "record {index}: record_hash mismatch (content was altered)"
                )
            }
            Self::BrokenLink { index } => write!(
                f,
                "record {index}: broken chain link (predecessor deleted or reordered)"
            ),
            Self::AnchorSignature(diag) => write!(f, "chain anchor signature: {diag}"),
            Self::GenesisLinkMismatch { expected, found } => write!(
                f,
                "genesis record links {found} but the anchor pins {expected}"
            ),
        }
    }
}

impl std::error::Error for VerifyError {}

/// Audit-segment verification failure (the generic form of OAP's
/// `AuditChainError`), naming the first broken record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditVerifyError {
    EmptyChain,
    MissingField {
        index: usize,
        field: &'static str,
    },
    RecordHashMismatch {
        index: usize,
    },
    BrokenLink {
        index: usize,
    },
    GenesisMismatch {
        expected: String,
        found: String,
    },
    /// A trailing segment head's `record_count` disagrees with the number of
    /// data records before it (closed-segment tail truncation).
    CountMismatch {
        expected: u64,
        found: u64,
    },
    /// A segment head appeared before the final position.
    MisplacedHead {
        index: usize,
    },
}

impl std::fmt::Display for AuditVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyChain => write!(f, "empty chain"),
            Self::MissingField { index, field } => {
                write!(f, "record {index}: missing required field `{field}`")
            }
            Self::RecordHashMismatch { index } => {
                write!(
                    f,
                    "record {index}: record_hash mismatch (content was altered)"
                )
            }
            Self::BrokenLink { index } => write!(
                f,
                "record {index}: broken chain link (predecessor deleted or reordered)"
            ),
            Self::GenesisMismatch { expected, found } => write!(
                f,
                "record 0: genesis link {found} does not bind expected anchor {expected}"
            ),
            Self::CountMismatch { expected, found } => write!(
                f,
                "segment head record_count {expected} != {found} data records (tail truncated)"
            ),
            Self::MisplacedHead { index } => {
                write!(f, "record {index}: segment head before end of segment")
            }
        }
    }
}

impl std::error::Error for AuditVerifyError {}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ledger_record_round_trips() {
        let rec = LedgerRecord {
            id: "r1".into(),
            timestamp: "2026-07-13T00:00:00Z".into(),
            previous_record_hash: "sha256:aa".into(),
            record_hash: "sha256:bb".into(),
            payload: json!({ "kind": "demo", "n": 1 }),
        };
        let s = serde_json::to_string(&rec).unwrap();
        let back: LedgerRecord = serde_json::from_str(&s).unwrap();
        assert_eq!(rec, back);
    }

    #[test]
    fn attestation_kind_serializes_kebab_case() {
        assert_eq!(
            serde_json::to_string(&GenesisAttestationKind::SigstoreRekor).unwrap(),
            "\"sigstore-rekor\""
        );
        assert_eq!(
            GenesisAttestationKind::default(),
            GenesisAttestationKind::Unsigned
        );
    }
}

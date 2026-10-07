//! Pinned trust roots: the verifier's own statement of which Ed25519 keys may
//! sign a chain's genesis anchor.
//!
//! [`TrustRootsV1`] is the wire shape only. Construction, canonical bytes, the
//! digest and the key-id derivation live in `attest-ledger-core`, which owns the
//! hashing and Ed25519 stack; this crate stays serde-only.

use serde::{Deserialize, Serialize};

use crate::{HeadVerifyError, VerifyError};

/// The only schema identity a v1 verifier accepts.
pub const TRUST_ROOTS_SCHEMA_V1: &str = "attest-ledger/trust-roots/v1";

/// The only key algorithm a v1 root set may name.
pub const TRUST_ROOT_ALGORITHM_ED25519: &str = "ed25519";

/// A pinned set of accepted anchor-signing keys.
///
/// A valid set is non-empty and canonical: entries strictly ascending by
/// `key_id` (so no duplicates), and each entry's `chain_ids`, when present,
/// non-empty and strictly ascending. A set that is not canonical is refused,
/// so one logical set has exactly one digest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrustRootsV1 {
    pub schema_identity: String,
    pub roots: Vec<TrustRootV1>,
}

/// One accepted signing key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrustRootV1 {
    /// `sha256:<hex>` over the domain-separated key-id preimage of
    /// `public_key`. Carried so a pin is readable; always recomputed and
    /// compared, never trusted.
    pub key_id: String,
    /// Always [`TRUST_ROOT_ALGORITHM_ED25519`] in v1.
    pub algorithm: String,
    /// Base64 (standard alphabet, padded) of the 32-byte Ed25519 public key,
    /// the same encoding as `ChainAnchor.genesis_public_key`.
    pub public_key: String,
    /// The chain ids this key may sign for. Absent means any chain id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_ids: Option<Vec<String>>,
}

/// Why a root set is not a valid v1 set. `index` names the offending entry.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TrustRootsError {
    UnsupportedSchema {
        expected: String,
        found: String,
    },
    EmptySet,
    UnsupportedAlgorithm {
        index: usize,
        found: String,
    },
    MalformedPublicKey {
        index: usize,
    },
    /// A small-order (weak) Ed25519 key, which strict verification refuses.
    WeakPublicKey {
        index: usize,
    },
    KeyIdMismatch {
        index: usize,
        expected: String,
        found: String,
    },
    /// Entries are not strictly ascending by `key_id` (unsorted or duplicate).
    NotCanonicalOrder {
        index: usize,
    },
    /// `chain_ids` is present but empty.
    EmptyScope {
        index: usize,
    },
    /// `chain_ids` holds an empty string or is not strictly ascending.
    NotCanonicalScope {
        index: usize,
    },
}

impl std::fmt::Display for TrustRootsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedSchema { expected, found } => {
                write!(f, "trust roots schema {found} is not {expected}")
            }
            Self::EmptySet => write!(f, "trust roots name no key"),
            Self::UnsupportedAlgorithm { index, found } => {
                write!(f, "trust root {index}: unsupported algorithm {found}")
            }
            Self::MalformedPublicKey { index } => write!(
                f,
                "trust root {index}: public_key is not a base64 Ed25519 point"
            ),
            Self::WeakPublicKey { index } => {
                write!(f, "trust root {index}: public_key is a weak Ed25519 key")
            }
            Self::KeyIdMismatch {
                index,
                expected,
                found,
            } => write!(
                f,
                "trust root {index}: key_id {found} does not match its public_key ({expected})"
            ),
            Self::NotCanonicalOrder { index } => write!(
                f,
                "trust root {index}: roots are not strictly ascending by key_id"
            ),
            Self::EmptyScope { index } => {
                write!(f, "trust root {index}: chain_ids is present but empty")
            }
            Self::NotCanonicalScope { index } => write!(
                f,
                "trust root {index}: chain_ids must be non-empty strings, strictly ascending"
            ),
        }
    }
}

impl std::error::Error for TrustRootsError {}

/// Which required anchor field was empty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorField {
    GenesisPublicKey,
    GenesisSignature,
}

impl AnchorField {
    pub fn name(self) -> &'static str {
        match self {
            Self::GenesisPublicKey => "genesis_public_key",
            Self::GenesisSignature => "genesis_signature",
        }
    }
}

/// Root-pinned verification failure.
///
/// The anchor checks run in the order the variants are listed, and every one
/// of them runs before any record is read.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RootVerifyError {
    /// The supplied root set is not a valid canonical v1 set.
    InvalidRoots(TrustRootsError),
    /// The anchor carries no key or no signature.
    Unsigned { field: AnchorField },
    /// The anchor's key or signature is not decodable as Ed25519.
    MalformedAnchor { field: AnchorField },
    /// The anchor's key is not in the pinned roots.
    UnknownKey { key_id: String },
    /// The anchor's key is pinned, but not for this anchor's `chain_id`.
    OutOfScope { key_id: String, chain_id: String },
    /// The anchor's key is pinned and in scope, but the signature does not
    /// verify under strict Ed25519 rules.
    BadSignature { key_id: String },
    /// The anchor is authenticated; the record chain then failed.
    Chain(VerifyError),
    /// The anchor is authenticated; the trusted-head check then failed.
    Head(HeadVerifyError),
}

impl std::fmt::Display for RootVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRoots(e) => write!(f, "invalid trust roots: {e}"),
            Self::Unsigned { field } => {
                write!(f, "chain genesis is unsigned ({} empty)", field.name())
            }
            Self::MalformedAnchor { field } => {
                write!(f, "anchor {} is not a valid Ed25519 value", field.name())
            }
            Self::UnknownKey { key_id } => {
                write!(f, "anchor key {key_id} is not a pinned trust root")
            }
            Self::OutOfScope { key_id, chain_id } => write!(
                f,
                "anchor key {key_id} is pinned but not for chain_id {chain_id}"
            ),
            Self::BadSignature { key_id } => write!(
                f,
                "anchor signature by pinned key {key_id} fails strict Ed25519 verification"
            ),
            Self::Chain(e) => write!(f, "{e}"),
            Self::Head(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for RootVerifyError {}

impl RootVerifyError {
    /// True for the refusals that say only "this key is not authorised":
    /// the anchor may still be intact. A caller (the CLI) uses this to tell an
    /// integrity-only result apart from tampering.
    pub fn is_authorisation_refusal(&self) -> bool {
        matches!(
            self,
            Self::Unsigned { .. } | Self::UnknownKey { .. } | Self::OutOfScope { .. }
        )
    }
}

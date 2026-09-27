//! Versioned, domain-neutral commitments to a verified chain head.

use serde::{Deserialize, Serialize};

use crate::{AuditVerifyError, VerifyError};

/// The exact schema identity of [`HeadCommitmentV1`].
pub const HEAD_COMMITMENT_SCHEMA_V1: &str = "attest-ledger/head-commitment/v1";

/// Which attest-ledger chain shape a head commitment closes.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum HeadCommitmentKind {
    RecordChain,
    AuditSegment,
}

impl std::fmt::Display for HeadCommitmentKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RecordChain => f.write_str("record-chain"),
            Self::AuditSegment => f.write_str("audit-segment"),
        }
    }
}

/// An externally transportable statement of the expected complete chain head.
///
/// This value becomes trusted only when the caller obtains it through a
/// channel outside the rollback domain of the ledger being verified.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HeadCommitmentV1 {
    pub schema_identity: String,
    pub chain_kind: HeadCommitmentKind,
    pub chain_identity: String,
    pub anchor_identity: String,
    pub expected_record_count: u64,
    pub terminal_record_hash: String,
}

/// Failure to verify a record chain against an expected head commitment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeadVerifyError {
    Integrity(VerifyError),
    UnsupportedSchema {
        expected: String,
        found: String,
    },
    KindMismatch {
        expected: HeadCommitmentKind,
        found: HeadCommitmentKind,
    },
    ChainIdentityMismatch {
        expected: String,
        found: String,
    },
    AnchorIdentityMismatch {
        expected: String,
        found: String,
    },
    RecordCountMismatch {
        expected: u64,
        found: u64,
    },
    TerminalHashMismatch {
        expected: String,
        found: String,
    },
}

impl std::fmt::Display for HeadVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Integrity(err) => write!(f, "chain integrity: {err}"),
            Self::UnsupportedSchema { expected, found } => {
                write!(
                    f,
                    "schema_identity mismatch: expected {expected}, found {found}"
                )
            }
            Self::KindMismatch { expected, found } => {
                write!(f, "chain_kind mismatch: expected {expected}, found {found}")
            }
            Self::ChainIdentityMismatch { expected, found } => {
                write!(
                    f,
                    "chain_identity mismatch: expected {expected}, found {found}"
                )
            }
            Self::AnchorIdentityMismatch { expected, found } => {
                write!(
                    f,
                    "anchor_identity mismatch: expected {expected}, found {found}"
                )
            }
            Self::RecordCountMismatch { expected, found } => {
                write!(
                    f,
                    "expected_record_count mismatch: expected {expected}, found {found}"
                )
            }
            Self::TerminalHashMismatch { expected, found } => {
                write!(
                    f,
                    "terminal_record_hash mismatch: expected {expected}, found {found}"
                )
            }
        }
    }
}

impl std::error::Error for HeadVerifyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Integrity(err) => Some(err),
            _ => None,
        }
    }
}

/// Failure to verify a closed audit segment against an expected head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditHeadVerifyError {
    Integrity(AuditVerifyError),
    UnsupportedSchema {
        expected: String,
        found: String,
    },
    KindMismatch {
        expected: HeadCommitmentKind,
        found: HeadCommitmentKind,
    },
    MissingSegmentHead,
    MissingHeadField {
        field: &'static str,
    },
    ChainIdentityMismatch {
        expected: String,
        found: String,
    },
    AnchorIdentityMismatch {
        expected: String,
        found: String,
    },
    RecordCountMismatch {
        expected: u64,
        found: u64,
    },
    TerminalHashMismatch {
        expected: String,
        found: String,
    },
}

impl std::fmt::Display for AuditHeadVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Integrity(err) => write!(f, "audit integrity: {err}"),
            Self::UnsupportedSchema { expected, found } => {
                write!(
                    f,
                    "schema_identity mismatch: expected {expected}, found {found}"
                )
            }
            Self::KindMismatch { expected, found } => {
                write!(f, "chain_kind mismatch: expected {expected}, found {found}")
            }
            Self::MissingSegmentHead => f.write_str("closed audit segment has no trailing head"),
            Self::MissingHeadField { field } => {
                write!(
                    f,
                    "trailing segment head is missing required field `{field}`"
                )
            }
            Self::ChainIdentityMismatch { expected, found } => {
                write!(
                    f,
                    "chain_identity mismatch: expected {expected}, found {found}"
                )
            }
            Self::AnchorIdentityMismatch { expected, found } => {
                write!(
                    f,
                    "anchor_identity mismatch: expected {expected}, found {found}"
                )
            }
            Self::RecordCountMismatch { expected, found } => {
                write!(
                    f,
                    "expected_record_count mismatch: expected {expected}, found {found}"
                )
            }
            Self::TerminalHashMismatch { expected, found } => {
                write!(
                    f,
                    "terminal_record_hash mismatch: expected {expected}, found {found}"
                )
            }
        }
    }
}

impl std::error::Error for AuditHeadVerifyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Integrity(err) => Some(err),
            _ => None,
        }
    }
}

//! Construction and verification of externally trusted chain heads.

use attest_ledger_types::{
    AuditHeadVerifyError, ChainAnchor, HEAD_COMMITMENT_SCHEMA_V1, HeadCommitmentKind,
    HeadCommitmentV1, HeadVerifyError, LedgerRecord,
};
use serde_json::Value;

use crate::{sha256_hex, verify_audit_chain, verify_chain_with_anchor};

/// The canonical UTF-8 bytes committed by [`head_commitment_digest`].
pub fn head_commitment_canonical_bytes(commitment: &HeadCommitmentV1) -> Vec<u8> {
    canonical_keysort_json::to_canonical_string(
        &serde_json::to_value(commitment).expect("head commitment serialises to JSON"),
    )
    .into_bytes()
}

/// SHA-256 identity of the complete canonical head commitment.
pub fn head_commitment_digest(commitment: &HeadCommitmentV1) -> String {
    sha256_hex(&head_commitment_canonical_bytes(commitment))
}

/// SHA-256 identity of the complete signed chain anchor.
///
/// Unlike the existing anchor signature boundary, this includes the signature
/// itself. It therefore identifies the exact signed anchor supplied to a head
/// verifier.
pub fn chain_anchor_identity(anchor: &ChainAnchor) -> String {
    let canonical = canonical_keysort_json::to_canonical_string(
        &serde_json::to_value(anchor).expect("chain anchor serialises to JSON"),
    );
    sha256_hex(canonical.as_bytes())
}

/// Build a commitment only after the complete presented record chain verifies.
pub fn build_record_head_commitment(
    anchor: &ChainAnchor,
    records: &[LedgerRecord],
) -> Result<HeadCommitmentV1, HeadVerifyError> {
    verify_chain_with_anchor(anchor, records).map_err(HeadVerifyError::Integrity)?;
    require_nonempty_chain_identity(&anchor.chain_id)?;
    let last = records.last().expect("verified record chain is non-empty");
    Ok(HeadCommitmentV1 {
        schema_identity: HEAD_COMMITMENT_SCHEMA_V1.to_owned(),
        chain_kind: HeadCommitmentKind::RecordChain,
        chain_identity: anchor.chain_id.clone(),
        anchor_identity: chain_anchor_identity(anchor),
        expected_record_count: record_count(records.len()),
        terminal_record_hash: last.record_hash.clone(),
    })
}

/// Verify a record chain against an independently trusted expected head.
pub fn verify_chain_with_head(
    anchor: &ChainAnchor,
    records: &[LedgerRecord],
    expected_head: &HeadCommitmentV1,
) -> Result<(), HeadVerifyError> {
    verify_chain_with_anchor(anchor, records).map_err(HeadVerifyError::Integrity)?;
    require_record_schema_and_kind(expected_head)?;
    require_nonempty_chain_identity(&anchor.chain_id)?;
    if expected_head.chain_identity != anchor.chain_id {
        return Err(HeadVerifyError::ChainIdentityMismatch {
            expected: expected_head.chain_identity.clone(),
            found: anchor.chain_id.clone(),
        });
    }
    let found_anchor = chain_anchor_identity(anchor);
    if expected_head.anchor_identity != found_anchor {
        return Err(HeadVerifyError::AnchorIdentityMismatch {
            expected: expected_head.anchor_identity.clone(),
            found: found_anchor,
        });
    }
    let found_count = record_count(records.len());
    if expected_head.expected_record_count != found_count {
        return Err(HeadVerifyError::RecordCountMismatch {
            expected: expected_head.expected_record_count,
            found: found_count,
        });
    }
    let found_terminal = records
        .last()
        .expect("verified record chain is non-empty")
        .record_hash
        .clone();
    if expected_head.terminal_record_hash != found_terminal {
        return Err(HeadVerifyError::TerminalHashMismatch {
            expected: expected_head.terminal_record_hash.clone(),
            found: found_terminal,
        });
    }
    Ok(())
}

/// Build a commitment only after a closed audit segment verifies.
pub fn build_audit_head_commitment(
    records: &[Value],
    expected_genesis: &str,
) -> Result<HeadCommitmentV1, AuditHeadVerifyError> {
    verify_audit_chain(records, Some(expected_genesis)).map_err(AuditHeadVerifyError::Integrity)?;
    require_nonempty_anchor_identity(expected_genesis)?;
    let (head, chain_identity, head_count, terminal_hash) = audit_head_fields(records)?;
    let found_count = audit_data_count(records.len());
    if head_count != found_count {
        return Err(AuditHeadVerifyError::RecordCountMismatch {
            expected: head_count,
            found: found_count,
        });
    }
    debug_assert_eq!(
        head.get("segment_head").and_then(Value::as_bool),
        Some(true)
    );
    Ok(HeadCommitmentV1 {
        schema_identity: HEAD_COMMITMENT_SCHEMA_V1.to_owned(),
        chain_kind: HeadCommitmentKind::AuditSegment,
        chain_identity,
        anchor_identity: expected_genesis.to_owned(),
        expected_record_count: head_count,
        terminal_record_hash: terminal_hash,
    })
}

/// Verify a closed audit segment against an independently trusted head.
pub fn verify_audit_chain_with_head(
    records: &[Value],
    expected_genesis: &str,
    expected_head: &HeadCommitmentV1,
) -> Result<(), AuditHeadVerifyError> {
    verify_audit_chain(records, Some(expected_genesis)).map_err(AuditHeadVerifyError::Integrity)?;
    require_audit_schema_and_kind(expected_head)?;
    require_nonempty_anchor_identity(expected_genesis)?;
    let (_, found_chain, head_count, found_terminal) = audit_head_fields(records)?;
    if expected_head.chain_identity != found_chain {
        return Err(AuditHeadVerifyError::ChainIdentityMismatch {
            expected: expected_head.chain_identity.clone(),
            found: found_chain,
        });
    }
    if expected_head.anchor_identity != expected_genesis {
        return Err(AuditHeadVerifyError::AnchorIdentityMismatch {
            expected: expected_head.anchor_identity.clone(),
            found: expected_genesis.to_owned(),
        });
    }
    let found_count = audit_data_count(records.len());
    if head_count != found_count {
        return Err(AuditHeadVerifyError::RecordCountMismatch {
            expected: head_count,
            found: found_count,
        });
    }
    if expected_head.expected_record_count != found_count {
        return Err(AuditHeadVerifyError::RecordCountMismatch {
            expected: expected_head.expected_record_count,
            found: found_count,
        });
    }
    if expected_head.terminal_record_hash != found_terminal {
        return Err(AuditHeadVerifyError::TerminalHashMismatch {
            expected: expected_head.terminal_record_hash.clone(),
            found: found_terminal,
        });
    }
    Ok(())
}

fn require_record_schema_and_kind(head: &HeadCommitmentV1) -> Result<(), HeadVerifyError> {
    if head.schema_identity != HEAD_COMMITMENT_SCHEMA_V1 {
        return Err(HeadVerifyError::UnsupportedSchema {
            expected: HEAD_COMMITMENT_SCHEMA_V1.to_owned(),
            found: head.schema_identity.clone(),
        });
    }
    if head.chain_kind != HeadCommitmentKind::RecordChain {
        return Err(HeadVerifyError::KindMismatch {
            expected: HeadCommitmentKind::RecordChain,
            found: head.chain_kind,
        });
    }
    Ok(())
}

fn require_audit_schema_and_kind(head: &HeadCommitmentV1) -> Result<(), AuditHeadVerifyError> {
    if head.schema_identity != HEAD_COMMITMENT_SCHEMA_V1 {
        return Err(AuditHeadVerifyError::UnsupportedSchema {
            expected: HEAD_COMMITMENT_SCHEMA_V1.to_owned(),
            found: head.schema_identity.clone(),
        });
    }
    if head.chain_kind != HeadCommitmentKind::AuditSegment {
        return Err(AuditHeadVerifyError::KindMismatch {
            expected: HeadCommitmentKind::AuditSegment,
            found: head.chain_kind,
        });
    }
    Ok(())
}

fn require_nonempty_chain_identity(identity: &str) -> Result<(), HeadVerifyError> {
    if identity.is_empty() {
        return Err(HeadVerifyError::ChainIdentityMismatch {
            expected: "non-empty chain_identity".to_owned(),
            found: String::new(),
        });
    }
    Ok(())
}

fn require_nonempty_anchor_identity(identity: &str) -> Result<(), AuditHeadVerifyError> {
    if identity.is_empty() {
        return Err(AuditHeadVerifyError::AnchorIdentityMismatch {
            expected: "non-empty anchor_identity".to_owned(),
            found: String::new(),
        });
    }
    Ok(())
}

fn audit_head_fields(
    records: &[Value],
) -> Result<(&Value, String, u64, String), AuditHeadVerifyError> {
    let head = records
        .last()
        .filter(|value| value.get("segment_head").and_then(Value::as_bool) == Some(true))
        .ok_or(AuditHeadVerifyError::MissingSegmentHead)?;
    let chain_identity = head
        .get("segment_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(AuditHeadVerifyError::MissingHeadField {
            field: "segment_id",
        })?
        .to_owned();
    let head_count = head.get("record_count").and_then(Value::as_u64).ok_or(
        AuditHeadVerifyError::MissingHeadField {
            field: "record_count",
        },
    )?;
    let terminal_hash = head
        .get("record_hash")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(AuditHeadVerifyError::MissingHeadField {
            field: "record_hash",
        })?
        .to_owned();
    Ok((head, chain_identity, head_count, terminal_hash))
}

fn record_count(len: usize) -> u64 {
    u64::try_from(len).expect("a Rust slice length fits in u64")
}

fn audit_data_count(len: usize) -> u64 {
    record_count(len.saturating_sub(1))
}

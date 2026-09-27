use attest_ledger_core::{
    AuditChain, AuditHeadVerifyError, AuditVerifyError, GenesisAttestation, GenesisAttestationKind,
    HeadCommitmentKind, HeadVerifyError, RecordChain, build_audit_head_commitment,
    build_record_head_commitment, head_commitment_canonical_bytes, head_commitment_digest,
    link_record_hash, verify_audit_chain_with_head, verify_chain_with_head,
};
use attest_ledger_types::HeadCommitmentV1;
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};

const ROOT: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const GENESIS: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn record_fixture(
    seed: u8,
    chain_id: &str,
) -> (
    attest_ledger_core::ChainAnchor,
    Vec<attest_ledger_core::LedgerRecord>,
) {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let mut writer = RecordChain::new(ROOT.to_owned());
    let anchor = writer.build_anchor_with_key(
        chain_id.to_owned(),
        "2026-09-26T00:00:00Z".to_owned(),
        &key,
        GenesisAttestation {
            kind: GenesisAttestationKind::Operator,
            note: Some("test key".to_owned()),
        },
    );
    let records = vec![
        writer.append("one".to_owned(), "t1".to_owned(), json!({"n": 1})),
        writer.append("two".to_owned(), "t2".to_owned(), json!({"n": 2})),
    ];
    (anchor, records)
}

fn audit_fixture() -> Vec<Value> {
    let mut writer = AuditChain::new(GENESIS.to_owned(), "segment-001".to_owned());
    let mut records = vec![
        writer.append("t1".to_owned(), json!({"n": 1})).unwrap(),
        writer.append("t2".to_owned(), json!({"n": 2})).unwrap(),
    ];
    records.push(writer.close_segment());
    records
}

#[test]
fn canonical_bytes_and_digest_are_pinned() {
    let commitment = HeadCommitmentV1 {
        schema_identity: "attest-ledger/head-commitment/v1".to_owned(),
        chain_kind: HeadCommitmentKind::RecordChain,
        chain_identity: "chain-001".to_owned(),
        anchor_identity: "sha256:aa".to_owned(),
        expected_record_count: 2,
        terminal_record_hash: "sha256:bb".to_owned(),
    };
    assert_eq!(
        String::from_utf8(head_commitment_canonical_bytes(&commitment)).unwrap(),
        r#"{"anchor_identity":"sha256:aa","chain_identity":"chain-001","chain_kind":"record-chain","expected_record_count":2,"schema_identity":"attest-ledger/head-commitment/v1","terminal_record_hash":"sha256:bb"}"#
    );
    assert_eq!(
        head_commitment_digest(&commitment),
        "sha256:005e40407d2b6f30b22c513df8199a3e5d1021a29920f3f77b9ce720015a8400"
    );
}

#[test]
fn clean_record_chain_matches_trusted_head() {
    let (anchor, records) = record_fixture(7, "chain-001");
    let head = build_record_head_commitment(&anchor, &records).unwrap();
    verify_chain_with_head(&anchor, &records, &head).unwrap();
}

#[test]
fn one_record_prefix_of_two_is_refused() {
    let (anchor, records) = record_fixture(7, "chain-001");
    let head = build_record_head_commitment(&anchor, &records).unwrap();
    assert_eq!(
        verify_chain_with_head(&anchor, &records[..1], &head).unwrap_err(),
        HeadVerifyError::RecordCountMismatch {
            expected: 2,
            found: 1,
        }
    );
}

#[test]
fn record_head_refuses_schema_kind_count_and_terminal_mismatches() {
    let (anchor, records) = record_fixture(7, "chain-001");
    let head = build_record_head_commitment(&anchor, &records).unwrap();

    let mut wrong = head.clone();
    wrong.schema_identity = "attest-ledger/head-commitment/v2".to_owned();
    assert!(matches!(
        verify_chain_with_head(&anchor, &records, &wrong).unwrap_err(),
        HeadVerifyError::UnsupportedSchema { .. }
    ));

    let mut wrong = head.clone();
    wrong.chain_kind = HeadCommitmentKind::AuditSegment;
    assert!(matches!(
        verify_chain_with_head(&anchor, &records, &wrong).unwrap_err(),
        HeadVerifyError::KindMismatch { .. }
    ));

    let mut wrong = head.clone();
    wrong.expected_record_count = 3;
    assert_eq!(
        verify_chain_with_head(&anchor, &records, &wrong).unwrap_err(),
        HeadVerifyError::RecordCountMismatch {
            expected: 3,
            found: 2,
        }
    );

    let mut wrong = head;
    wrong.terminal_record_hash = "sha256:wrong".to_owned();
    assert!(matches!(
        verify_chain_with_head(&anchor, &records, &wrong).unwrap_err(),
        HeadVerifyError::TerminalHashMismatch { .. }
    ));
}

#[test]
fn record_head_refuses_another_chain_and_another_anchor() {
    let (anchor, records) = record_fixture(7, "chain-001");
    let (other_chain_anchor, other_chain_records) = record_fixture(8, "chain-002");
    let other_chain_head =
        build_record_head_commitment(&other_chain_anchor, &other_chain_records).unwrap();
    assert!(matches!(
        verify_chain_with_head(&anchor, &records, &other_chain_head).unwrap_err(),
        HeadVerifyError::ChainIdentityMismatch { .. }
    ));

    let (other_anchor, _) = record_fixture(9, "chain-001");
    assert!(matches!(
        verify_chain_with_head(
            &other_anchor,
            &records,
            &build_record_head_commitment(&anchor, &records).unwrap()
        )
        .unwrap_err(),
        HeadVerifyError::AnchorIdentityMismatch { .. }
    ));
}

#[test]
fn clean_closed_audit_segment_matches_trusted_head() {
    let records = audit_fixture();
    let head = build_audit_head_commitment(&records, GENESIS).unwrap();
    verify_audit_chain_with_head(&records, GENESIS, &head).unwrap();
}

#[test]
fn removing_audit_head_is_refused() {
    let records = audit_fixture();
    let head = build_audit_head_commitment(&records, GENESIS).unwrap();
    assert_eq!(
        verify_audit_chain_with_head(&records[..2], GENESIS, &head).unwrap_err(),
        AuditHeadVerifyError::MissingSegmentHead
    );
}

#[test]
fn removing_audit_data_before_head_is_refused() {
    let records = audit_fixture();
    let head = build_audit_head_commitment(&records, GENESIS).unwrap();
    let truncated = vec![records[0].clone(), records[2].clone()];
    assert!(matches!(
        verify_audit_chain_with_head(&truncated, GENESIS, &head).unwrap_err(),
        AuditHeadVerifyError::Integrity(AuditVerifyError::BrokenLink { .. })
            | AuditHeadVerifyError::Integrity(AuditVerifyError::CountMismatch { .. })
    ));
}

#[test]
fn audit_head_refuses_wrong_count_terminal_chain_and_anchor() {
    let records = audit_fixture();
    let head = build_audit_head_commitment(&records, GENESIS).unwrap();

    let mut wrong = head.clone();
    wrong.expected_record_count = 3;
    assert_eq!(
        verify_audit_chain_with_head(&records, GENESIS, &wrong).unwrap_err(),
        AuditHeadVerifyError::RecordCountMismatch {
            expected: 3,
            found: 2,
        }
    );

    let mut wrong = head.clone();
    wrong.terminal_record_hash = "sha256:wrong".to_owned();
    assert!(matches!(
        verify_audit_chain_with_head(&records, GENESIS, &wrong).unwrap_err(),
        AuditHeadVerifyError::TerminalHashMismatch { .. }
    ));

    let mut wrong = head.clone();
    wrong.chain_identity = "segment-002".to_owned();
    assert!(matches!(
        verify_audit_chain_with_head(&records, GENESIS, &wrong).unwrap_err(),
        AuditHeadVerifyError::ChainIdentityMismatch { .. }
    ));

    let mut wrong = head;
    wrong.anchor_identity = "sha256:wrong".to_owned();
    assert!(matches!(
        verify_audit_chain_with_head(&records, GENESIS, &wrong).unwrap_err(),
        AuditHeadVerifyError::AnchorIdentityMismatch { .. }
    ));
}

#[test]
fn audit_head_refuses_wrong_genesis_and_missing_segment_id() {
    let records = audit_fixture();
    let head = build_audit_head_commitment(&records, GENESIS).unwrap();
    assert!(matches!(
        verify_audit_chain_with_head(&records, "sha256:wrong", &head).unwrap_err(),
        AuditHeadVerifyError::Integrity(AuditVerifyError::GenesisMismatch { .. })
    ));

    let mut missing = records;
    missing[2].as_object_mut().unwrap().remove("segment_id");
    let hash = link_record_hash(missing[2].clone(), "record_hash");
    missing[2]["record_hash"] = Value::String(hash);
    assert_eq!(
        verify_audit_chain_with_head(&missing, GENESIS, &head).unwrap_err(),
        AuditHeadVerifyError::MissingHeadField {
            field: "segment_id"
        }
    );
}

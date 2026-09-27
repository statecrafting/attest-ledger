use attest_ledger_core::{
    AuditChain, AuditHeadVerifyError, HeadVerifyError, RecordChain,
    build_audit_head_commitment, build_record_head_commitment, verify_audit_chain_with_head,
    verify_chain_with_head,
};
use serde_json::json;

const ROOT: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const GENESIS: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn main() {
    let mut writer = RecordChain::new(ROOT.to_owned());
    let anchor = writer.build_anchor("consumer-chain".to_owned(), "t0".to_owned());
    let records = vec![
        writer.append("one".to_owned(), "t1".to_owned(), json!({"n": 1})),
        writer.append("two".to_owned(), "t2".to_owned(), json!({"n": 2})),
    ];
    let head = build_record_head_commitment(&anchor, &records).unwrap();
    verify_chain_with_head(&anchor, &records, &head).unwrap();

    assert_eq!(
        verify_chain_with_head(&anchor, &records[..1], &head).unwrap_err(),
        HeadVerifyError::RecordCountMismatch {
            expected: 2,
            found: 1,
        }
    );

    let mut wrong_count = head.clone();
    wrong_count.expected_record_count = 3;
    assert!(matches!(
        verify_chain_with_head(&anchor, &records, &wrong_count).unwrap_err(),
        HeadVerifyError::RecordCountMismatch { .. }
    ));

    let mut wrong_terminal = head.clone();
    wrong_terminal.terminal_record_hash = "sha256:wrong".to_owned();
    assert!(matches!(
        verify_chain_with_head(&anchor, &records, &wrong_terminal).unwrap_err(),
        HeadVerifyError::TerminalHashMismatch { .. }
    ));

    let mut other_chain_writer = RecordChain::new(ROOT.to_owned());
    let other_chain_anchor =
        other_chain_writer.build_anchor("other-chain".to_owned(), "t0".to_owned());
    let other_chain_records = vec![
        other_chain_writer.append("one".to_owned(), "t1".to_owned(), json!({"n": 1})),
        other_chain_writer.append("two".to_owned(), "t2".to_owned(), json!({"n": 2})),
    ];
    let other_chain_head =
        build_record_head_commitment(&other_chain_anchor, &other_chain_records).unwrap();
    assert!(matches!(
        verify_chain_with_head(&anchor, &records, &other_chain_head).unwrap_err(),
        HeadVerifyError::ChainIdentityMismatch { .. }
    ));

    let other_anchor_writer = RecordChain::new(ROOT.to_owned());
    let other_anchor =
        other_anchor_writer.build_anchor("consumer-chain".to_owned(), "t0".to_owned());
    assert!(matches!(
        verify_chain_with_head(&other_anchor, &records, &head).unwrap_err(),
        HeadVerifyError::AnchorIdentityMismatch { .. }
    ));

    let mut audit_writer = AuditChain::new(GENESIS.to_owned(), "segment-001".to_owned());
    let mut audit = vec![
        audit_writer
            .append("t1".to_owned(), json!({"n": 1}))
            .unwrap(),
        audit_writer
            .append("t2".to_owned(), json!({"n": 2}))
            .unwrap(),
    ];
    audit.push(audit_writer.close_segment());
    let audit_head = build_audit_head_commitment(&audit, GENESIS).unwrap();
    verify_audit_chain_with_head(&audit, GENESIS, &audit_head).unwrap();
    assert_eq!(
        verify_audit_chain_with_head(&audit[..2], GENESIS, &audit_head).unwrap_err(),
        AuditHeadVerifyError::MissingSegmentHead
    );
    assert!(matches!(
        verify_audit_chain_with_head(&audit, "sha256:wrong", &audit_head).unwrap_err(),
        AuditHeadVerifyError::Integrity(_)
    ));

    println!("attest-ledger 0.1.1 registry consumer qualified");
}

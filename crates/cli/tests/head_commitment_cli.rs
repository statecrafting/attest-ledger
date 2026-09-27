use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use attest_ledger_core::{
    AuditChain, RecordChain, build_audit_head_commitment, build_record_head_commitment,
};
use serde::Serialize;
use serde_json::{Value, json};

const GENESIS: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "attest-ledger-cli-head-{}-{serial}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_attest-ledger"))
        .args(args)
        .output()
        .unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).unwrap()
}

fn write_json(path: &Path, value: &impl Serialize) {
    fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
}

fn write_jsonl(path: &Path, values: &[impl Serialize]) {
    let mut bytes = Vec::new();
    for value in values {
        serde_json::to_writer(&mut bytes, value).unwrap();
        bytes.push(b'\n');
    }
    fs::write(path, bytes).unwrap();
}

#[test]
fn record_require_head_refuses_before_reading() {
    let output = cli(&["verify", "/path/that/does/not/exist", "--require-head"]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        text(&output.stderr),
        "--require-head was set but --head and --anchor were not both supplied: cannot verify record-chain completeness\n"
    );
}

#[test]
fn record_head_without_anchor_refuses_before_reading() {
    let output = cli(&[
        "verify",
        "/path/that/does/not/exist",
        "--head",
        "/also/missing",
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        text(&output.stderr),
        "--head was supplied without --anchor: a record-chain head must bind a verified signed anchor\n"
    );
}

#[test]
fn record_complete_success_and_tail_refusal_have_exact_modes() {
    let dir = TestDir::new();
    let mut writer = RecordChain::new(GENESIS.to_owned());
    let anchor = writer.build_anchor("chain-cli".to_owned(), "2026-09-26T00:00:00Z".to_owned());
    let records = vec![
        writer.append("one".to_owned(), "t1".to_owned(), json!({"n": 1})),
        writer.append("two".to_owned(), "t2".to_owned(), json!({"n": 2})),
    ];
    let head = build_record_head_commitment(&anchor, &records).unwrap();
    let chain_path = dir.path("chain.jsonl");
    let prefix_path = dir.path("prefix.jsonl");
    let anchor_path = dir.path("anchor.json");
    let head_path = dir.path("head.json");
    write_jsonl(&chain_path, &records);
    write_jsonl(&prefix_path, &records[..1]);
    write_json(&anchor_path, &anchor);
    write_json(&head_path, &head);

    let output = cli(&[
        "verify",
        chain_path.to_str().unwrap(),
        "--anchor",
        anchor_path.to_str().unwrap(),
        "--head",
        head_path.to_str().unwrap(),
        "--require-head",
    ]);
    assert_eq!(output.status.code(), Some(0));
    assert!(text(&output.stdout).contains("trusted head matched"));

    let output = cli(&[
        "verify",
        prefix_path.to_str().unwrap(),
        "--anchor",
        anchor_path.to_str().unwrap(),
        "--head",
        head_path.to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert!(text(&output.stderr).starts_with("chain INVALID:"));
    assert!(text(&output.stderr).contains("expected_record_count mismatch"));

    let output = cli(&["verify", chain_path.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(0));
    assert!(text(&output.stdout).contains("integrity only"));
}

fn audit_values() -> Vec<Value> {
    let mut writer = AuditChain::new(GENESIS.to_owned(), "segment-cli".to_owned());
    let mut values = vec![
        writer.append("t1".to_owned(), json!({"n": 1})).unwrap(),
        writer.append("t2".to_owned(), json!({"n": 2})).unwrap(),
    ];
    values.push(writer.close_segment());
    values
}

#[test]
fn audit_complete_success_and_missing_head_refusal_have_exact_modes() {
    let dir = TestDir::new();
    let records = audit_values();
    let head = build_audit_head_commitment(&records, GENESIS).unwrap();
    let segment_path = dir.path("segment.jsonl");
    let open_path = dir.path("open.jsonl");
    let head_path = dir.path("head.json");
    write_jsonl(&segment_path, &records);
    write_jsonl(&open_path, &records[..2]);
    write_json(&head_path, &head);

    let output = cli(&[
        "verify-audit",
        segment_path.to_str().unwrap(),
        "--head",
        head_path.to_str().unwrap(),
        "--require-head",
    ]);
    assert_eq!(output.status.code(), Some(0));
    assert!(text(&output.stdout).contains("trusted head matched"));

    let output = cli(&[
        "verify-audit",
        open_path.to_str().unwrap(),
        "--head",
        head_path.to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert!(text(&output.stderr).starts_with("audit segment INVALID:"));
    assert!(text(&output.stderr).contains("no trailing head"));

    let output = cli(&["verify-audit", open_path.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(0));
    assert!(text(&output.stdout).contains("integrity only"));
}

#[test]
fn audit_require_head_refuses_before_reading() {
    let output = cli(&[
        "verify-audit",
        "/path/that/does/not/exist",
        "--require-head",
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        text(&output.stderr),
        "--require-head was set but no --head was supplied: cannot verify closed audit-segment completeness\n"
    );
}

#[test]
fn malformed_head_is_invalid_and_clap_syntax_is_exit_two() {
    let dir = TestDir::new();
    let chain_path = dir.path("chain.jsonl");
    let anchor_path = dir.path("anchor.json");
    let head_path = dir.path("bad-head.json");
    let mut writer = RecordChain::new(GENESIS.to_owned());
    let anchor = writer.build_anchor("chain-cli".to_owned(), "t0".to_owned());
    let records = vec![writer.append("one".to_owned(), "t1".to_owned(), json!({}))];
    write_jsonl(&chain_path, &records);
    write_json(&anchor_path, &anchor);
    fs::write(&head_path, b"not json").unwrap();

    let output = cli(&[
        "verify",
        chain_path.to_str().unwrap(),
        "--anchor",
        anchor_path.to_str().unwrap(),
        "--head",
        head_path.to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert!(text(&output.stderr).starts_with("chain INVALID:"));

    let output = cli(&["--not-a-real-option"]);
    assert_eq!(output.status.code(), Some(2));
}

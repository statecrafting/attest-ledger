use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use attest_ledger_core::{
    ChainAnchor, GenesisAttestation, GenesisAttestationKind, LedgerRecord, RecordChain,
    build_record_head_commitment, build_trust_roots, trust_roots_digest,
};
use ed25519_dalek::SigningKey;
use serde::Serialize;
use serde_json::json;

const ROOT: &str = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const NOTE: &str = "note: integrity only (the anchor was verified against its embedded key, not authenticated); pass --roots to authenticate its signer\n";
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "attest-ledger-cli-roots-{}-{serial}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn path(&self, name: &str) -> String {
        self.0.join(name).to_str().unwrap().to_owned()
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

fn write_json(path: &str, value: &impl Serialize) {
    fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// A two-record chain whose anchor is signed by `signer`, plus a root set
/// pinning key 1 for `chain-a`.
fn fixture(dir: &TestDir, signer: &SigningKey) -> (ChainAnchor, Vec<LedgerRecord>) {
    let mut chain = RecordChain::new(ROOT.into());
    let records: Vec<LedgerRecord> = (0..2)
        .map(|i| chain.append(format!("r{i}"), format!("t{i}"), json!({ "n": i })))
        .collect();
    let anchor = chain.build_anchor_with_key(
        "chain-a".into(),
        "2026-10-07T00:00:00Z".into(),
        signer,
        GenesisAttestation {
            kind: GenesisAttestationKind::Operator,
            note: None,
        },
    );
    let mut lines = Vec::new();
    for r in &records {
        serde_json::to_writer(&mut lines, r).unwrap();
        lines.push(b'\n');
    }
    fs::write(dir.path("chain.jsonl"), lines).unwrap();
    write_json(&dir.path("anchor.json"), &anchor);
    let roots =
        build_trust_roots([(key(1).verifying_key(), Some(vec!["chain-a".to_owned()]))]).unwrap();
    write_json(&dir.path("roots.json"), &roots);
    (anchor, records)
}

fn verify(dir: &TestDir, extra: &[&str]) -> Output {
    let chain = dir.path("chain.jsonl");
    let anchor = dir.path("anchor.json");
    let mut args = vec!["verify", chain.as_str(), "--anchor", anchor.as_str()];
    args.extend_from_slice(extra);
    cli(&args)
}

#[test]
fn without_roots_stdout_and_exit_are_unchanged_and_a_note_says_embedded_key_only() {
    let dir = TestDir::new();
    fixture(&dir, &key(1));
    let output = verify(&dir, &[]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        text(&output.stdout),
        "chain VERIFIED: 2 record(s), anchor signature valid, integrity only (no trusted head supplied)\n"
    );
    assert_eq!(text(&output.stderr), NOTE);
}

#[test]
fn without_roots_a_trusted_head_keeps_stdout_and_still_labels_integrity_only() {
    let dir = TestDir::new();
    let (anchor, records) = fixture(&dir, &key(1));
    let head = build_record_head_commitment(&anchor, &records).unwrap();
    write_json(&dir.path("head.json"), &head);
    let head_path = dir.path("head.json");
    let output = verify(&dir, &["--head", &head_path, "--require-head"]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        text(&output.stdout),
        "chain VERIFIED: 2 record(s), anchor signature valid, trusted head matched\n"
    );
    assert_eq!(text(&output.stderr), NOTE);
}

#[test]
fn pinned_signer_is_authenticated_with_exit_0() {
    let dir = TestDir::new();
    let (anchor, records) = fixture(&dir, &key(1));
    let roots = dir.path("roots.json");
    let output = verify(&dir, &["--roots", &roots, "--require-roots"]);
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    let stdout = text(&output.stdout);
    assert!(stdout.contains("signer authenticated by pinned root sha256:"));
    assert!(stdout.ends_with("integrity only (no trusted head supplied)\n"));
    assert_eq!(text(&output.stderr), "");

    let head = build_record_head_commitment(&anchor, &records).unwrap();
    write_json(&dir.path("head.json"), &head);
    let head_path = dir.path("head.json");
    let output = verify(&dir, &["--roots", &roots, "--head", &head_path]);
    assert_eq!(output.status.code(), Some(0));
    assert!(text(&output.stdout).ends_with("trusted head matched\n"));
}

#[test]
fn intact_chain_from_an_unpinned_signer_exits_3() {
    let dir = TestDir::new();
    fixture(&dir, &key(9));
    let roots = dir.path("roots.json");
    // The embedded-key verifier accepts the forged signer...
    assert_eq!(verify(&dir, &[]).status.code(), Some(0));
    // ...the pinned verifier does not.
    let output = verify(&dir, &["--roots", &roots]);
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(text(&output.stdout), "");
    let stderr = text(&output.stderr);
    assert!(stderr.starts_with("chain NOT AUTHENTICATED: 2 record(s) intact"));
    assert!(stderr.contains("is not a pinned trust root"));
}

#[test]
fn out_of_scope_signer_exits_3() {
    let dir = TestDir::new();
    fixture(&dir, &key(1));
    let roots =
        build_trust_roots([(key(1).verifying_key(), Some(vec!["chain-b".to_owned()]))]).unwrap();
    write_json(&dir.path("roots.json"), &roots);
    let output = verify(&dir, &["--roots", &dir.path("roots.json")]);
    assert_eq!(output.status.code(), Some(3));
    assert!(text(&output.stderr).contains("not for chain_id chain-a"));
}

#[test]
fn tampered_chain_under_unpinned_signer_is_invalid_not_unauthenticated() {
    let dir = TestDir::new();
    fixture(&dir, &key(9));
    let chain = dir.path("chain.jsonl");
    let tampered = fs::read_to_string(&chain)
        .unwrap()
        .replace("\"n\":1", "\"n\":7");
    fs::write(&chain, tampered).unwrap();
    let output = verify(&dir, &["--roots", &dir.path("roots.json")]);
    assert_eq!(output.status.code(), Some(1));
    assert!(text(&output.stderr).starts_with("chain INVALID:"));
}

#[test]
fn bad_signature_by_pinned_key_exits_1() {
    let dir = TestDir::new();
    let (mut anchor, _) = fixture(&dir, &key(1));
    anchor.genesis_timestamp = "2026-10-08T00:00:00Z".into();
    write_json(&dir.path("anchor.json"), &anchor);
    let output = verify(&dir, &["--roots", &dir.path("roots.json")]);
    assert_eq!(output.status.code(), Some(1));
    assert!(text(&output.stderr).contains("fails strict Ed25519 verification"));
}

#[test]
fn roots_digest_pins_the_set() {
    let dir = TestDir::new();
    fixture(&dir, &key(1));
    let roots_path = dir.path("roots.json");
    let roots = serde_json::from_str(&fs::read_to_string(&roots_path).unwrap()).unwrap();
    let digest = trust_roots_digest(&roots);
    let ok = verify(&dir, &["--roots", &roots_path, "--roots-digest", &digest]);
    assert_eq!(ok.status.code(), Some(0));
    let wrong = format!("sha256:{}", "0".repeat(64));
    let output = verify(&dir, &["--roots", &roots_path, "--roots-digest", &wrong]);
    assert_eq!(output.status.code(), Some(1));
    assert!(text(&output.stderr).contains("does not match --roots-digest"));
}

#[test]
fn invalid_roots_file_exits_1() {
    let dir = TestDir::new();
    fixture(&dir, &key(1));
    write_json(
        &dir.path("roots.json"),
        &json!({ "schema_identity": "attest-ledger/trust-roots/v1", "roots": [] }),
    );
    let output = verify(&dir, &["--roots", &dir.path("roots.json")]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        text(&output.stderr),
        "chain INVALID: invalid trust roots: trust roots name no key\n"
    );
}

#[test]
fn roots_flags_refuse_before_reading() {
    let output = cli(&["verify", "/missing", "--require-roots"]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        text(&output.stderr),
        "--require-roots was set but no --roots was supplied: cannot authenticate the anchor's signer\n"
    );
    let output = cli(&["verify", "/missing", "--roots", "/also/missing"]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        text(&output.stderr),
        "--roots was supplied without --anchor: trust roots authenticate a signed anchor\n"
    );
    // --roots-digest without --roots is a syntax error.
    let output = cli(&["verify", "/missing", "--roots-digest", "sha256:00"]);
    assert_eq!(output.status.code(), Some(2));
}

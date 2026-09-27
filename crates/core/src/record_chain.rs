//! The append-only, hash-linked record chain and its verifiers.

use attest_ledger_types::{ChainAnchor, GenesisAttestation, LedgerRecord, VerifyError};
use ed25519_dalek::SigningKey;
use serde_json::Value;

use crate::{link_record_hash, signing};

/// A conservative default budget, in bytes, for a record's fixed envelope
/// (everything except `payload`).
///
/// This is the generic descendant of OAP's `NF004_MAX_BYTES_EXCLUDING_CONTEXT`.
/// It is **not** enforced by [`verify_chain`]: a per-record size budget is a
/// domain policy, not a ledger-integrity property, so it is offered as an
/// opt-in check via [`record_payload_bytes`] for consumers that want it.
pub const DEFAULT_MAX_RECORD_BYTES: usize = 1024;

/// The serialized byte size of `record`'s fixed envelope, measured with
/// `payload` nulled out.
///
/// `payload` is the variable, caller-owned part of a record (the analog of
/// OAP's variable-sized context hash), so nulling it isolates the fixed-field
/// overhead a consumer might want to bound. Compare against
/// [`DEFAULT_MAX_RECORD_BYTES`] or a consumer-chosen budget.
pub fn record_payload_bytes(record: &LedgerRecord) -> usize {
    let mut r = record.clone();
    r.payload = Value::Null;
    serde_json::to_string(&r)
        .expect("ledger record serialises to JSON")
        .len()
}

/// `record_hash = sha256:<hex>` over the canonical JSON of `record` with its
/// `record_hash` field removed.
pub fn compute_record_hash(record: &LedgerRecord) -> String {
    link_record_hash(
        serde_json::to_value(record).expect("ledger record serialises to JSON"),
        "record_hash",
    )
}

/// Append-only, in-memory chain writer.
///
/// Produces [`LedgerRecord`]s; persistence is the caller's concern (write the
/// returned record to JSONL, Postgres, or anywhere). The first record's
/// `previous_record_hash` is the anchor hash (the genesis link); each
/// subsequent record links the prior record's hash.
pub struct RecordChain {
    anchor_hash: String,
    last_link_hash: String,
}

impl RecordChain {
    /// Start a chain rooted at `anchor_hash`. The genesis record will link to
    /// it, and a signed [`ChainAnchor`] built via [`RecordChain::build_anchor`]
    /// pins the same hash.
    pub fn new(anchor_hash: String) -> Self {
        Self {
            last_link_hash: anchor_hash.clone(),
            anchor_hash,
        }
    }

    /// The root this chain is pinned to.
    pub fn anchor_hash(&self) -> &str {
        &self.anchor_hash
    }

    /// The hash of the last record written (or the anchor hash for a fresh
    /// chain): the next record's `previous_record_hash`.
    pub fn last_link_hash(&self) -> &str {
        &self.last_link_hash
    }

    /// Append a record carrying `payload`. `timestamp` is caller-supplied so
    /// the record hash is reproducible.
    pub fn append(&mut self, id: String, timestamp: String, payload: Value) -> LedgerRecord {
        let mut record = LedgerRecord {
            id,
            timestamp,
            previous_record_hash: self.last_link_hash.clone(),
            record_hash: String::new(),
            payload,
        };
        record.record_hash = compute_record_hash(&record);
        self.last_link_hash.clone_from(&record.record_hash);
        record
    }

    /// Build a signed genesis anchor for this chain, resolving the signing key
    /// from the environment (ephemeral fallback). For a caller-supplied key,
    /// use [`RecordChain::build_anchor_with_key`].
    pub fn build_anchor(&self, chain_id: String, genesis_timestamp: String) -> ChainAnchor {
        let (key, attestation) = signing::resolve_signing_material();
        self.build_anchor_with_key(chain_id, genesis_timestamp, &key, attestation)
    }

    /// Build a signed genesis anchor with an explicit `key` and `attestation`.
    /// Keeps key custody out of the core: the caller decides where the key
    /// comes from.
    pub fn build_anchor_with_key(
        &self,
        chain_id: String,
        genesis_timestamp: String,
        key: &SigningKey,
        attestation: GenesisAttestation,
    ) -> ChainAnchor {
        let mut anchor = ChainAnchor {
            chain_id,
            anchor_hash: self.anchor_hash.clone(),
            genesis_timestamp,
            genesis_public_key: String::new(),
            genesis_signature: String::new(),
            genesis_attestation: attestation,
        };
        signing::sign_anchor(&mut anchor, key);
        anchor
    }
}

/// Verify the integrity of the presented chain: non-empty, every `record_hash`
/// recomputes, and every record binds its predecessor.
///
/// The genesis record's `previous_record_hash` is accepted as the declared
/// anchor link (there is no external root to check it against here); use
/// [`verify_chain_with_anchor`] to check it against a signed anchor.
/// Neither function proves the presented sequence is latest or complete. Use
/// [`crate::verify_chain_with_head`] with an independently trusted expected
/// head when tail completeness is required.
pub fn verify_chain(records: &[LedgerRecord]) -> Result<(), VerifyError> {
    if records.is_empty() {
        return Err(VerifyError::EmptyChain);
    }
    for (i, rec) in records.iter().enumerate() {
        if compute_record_hash(rec) != rec.record_hash {
            return Err(VerifyError::RecordHashMismatch { index: i });
        }
        if i > 0 && rec.previous_record_hash != records[i - 1].record_hash {
            return Err(VerifyError::BrokenLink { index: i });
        }
    }
    Ok(())
}

/// Verify the anchor signature FIRST, then that the genesis record binds the
/// anchor, then the integrity of the presented chain.
///
/// The anchor is the authoritative external trust root: a chain rooted in an
/// unsigned or forged anchor is untrusted regardless of how well its per-record
/// hashes line up, so the signature check gates everything.
/// This does not prove the sequence is latest or complete; use
/// [`crate::verify_chain_with_head`] with an independently trusted expected
/// head for that property.
pub fn verify_chain_with_anchor(
    anchor: &ChainAnchor,
    records: &[LedgerRecord],
) -> Result<(), VerifyError> {
    signing::verify_anchor(anchor).map_err(VerifyError::AnchorSignature)?;
    match records.first() {
        None => Err(VerifyError::EmptyChain),
        Some(first) => {
            if first.previous_record_hash != anchor.anchor_hash {
                return Err(VerifyError::GenesisLinkMismatch {
                    expected: anchor.anchor_hash.clone(),
                    found: first.previous_record_hash.clone(),
                });
            }
            verify_chain(records)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use attest_ledger_types::GenesisAttestationKind;
    use serde_json::json;

    fn sample_anchor_hash() -> String {
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into()
    }

    fn payload(rule: &str) -> Value {
        json!({ "decision": "allow", "rule_ids": [rule] })
    }

    #[test]
    fn hundred_record_chain_verifies() {
        let anchor = sample_anchor_hash();
        let mut w = RecordChain::new(anchor.clone());
        let mut chain = Vec::new();
        for i in 0..100 {
            let id = format!("{:08x}-0000-4000-8000-{:012x}", i, i);
            chain.push(w.append(
                id,
                format!("2026-07-13T12:{:02}:00Z", i % 60),
                payload("R-001"),
            ));
        }
        verify_chain(&chain).expect("clean 100-record chain verifies");
    }

    #[test]
    fn genesis_previous_is_anchor_hash() {
        let anchor = sample_anchor_hash();
        let mut w = RecordChain::new(anchor.clone());
        let r = w.append("r1".into(), "2026-07-13T12:00:00Z".into(), payload("R-1"));
        assert_eq!(r.previous_record_hash, anchor);
        verify_chain(&[r]).unwrap();
    }

    #[test]
    fn record_hash_tamper_detected() {
        let anchor = sample_anchor_hash();
        let mut w = RecordChain::new(anchor);
        let mut chain: Vec<LedgerRecord> = (0..4)
            .map(|i| w.append(format!("r{i}"), "t".into(), payload("R")))
            .collect();
        // Alter record 2's payload without recomputing its hash.
        chain[2].payload = json!({ "decision": "deny" });
        assert_eq!(
            verify_chain(&chain).unwrap_err(),
            VerifyError::RecordHashMismatch { index: 2 }
        );
    }

    #[test]
    fn broken_link_fails() {
        let anchor = sample_anchor_hash();
        let mut w = RecordChain::new(anchor);
        let a = w.append("a".into(), "t".into(), payload("R"));
        let mut b = w.append("b".into(), "t".into(), payload("R"));
        b.previous_record_hash = "sha256:deadbeef".into();
        b.record_hash = compute_record_hash(&b); // re-hash so only the link is wrong
        assert_eq!(
            verify_chain(&[a, b]).unwrap_err(),
            VerifyError::BrokenLink { index: 1 }
        );
    }

    #[test]
    fn empty_chain_is_error() {
        assert_eq!(verify_chain(&[]).unwrap_err(), VerifyError::EmptyChain);
    }

    #[test]
    fn signed_anchor_chain_verifies() {
        let anchor_hash = sample_anchor_hash();
        let mut w = RecordChain::new(anchor_hash.clone());
        let anchor = w.build_anchor("chain-001".into(), "2026-07-13T00:00:00Z".into());
        let r = w.append("r1".into(), "2026-07-13T00:00:01Z".into(), payload("R-1"));

        assert!(!anchor.genesis_public_key.is_empty());
        assert!(!anchor.genesis_signature.is_empty());
        assert_eq!(
            anchor.genesis_attestation.kind,
            GenesisAttestationKind::Ephemeral,
            "no env key set: ephemeral fallback"
        );
        verify_chain_with_anchor(&anchor, &[r]).expect("signed anchor + clean chain verifies");
    }

    #[test]
    fn tamper_anchor_fails_signature() {
        let anchor_hash = sample_anchor_hash();
        let w = RecordChain::new(anchor_hash);
        let anchor = w.build_anchor("chain-002".into(), "2026-07-13T00:00:00Z".into());

        // Adversary edits a field but cannot mint a fresh signature.
        let mut tampered = anchor.clone();
        tampered.chain_id = "ADVERSARY-INJECTED".into();
        assert!(super::signing::verify_anchor(&tampered).is_err());

        let err = verify_chain_with_anchor(&tampered, &[]).unwrap_err();
        assert!(matches!(err, VerifyError::AnchorSignature(_)));
    }

    #[test]
    fn anchor_hash_mismatch_fails() {
        // Anchor pins root A; the chain's genesis links to root B.
        let wa = RecordChain::new(sample_anchor_hash());
        let anchor = wa.build_anchor("chain-003".into(), "2026-07-13T00:00:00Z".into());

        let root_b = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let mut wb = RecordChain::new(root_b.into());
        let r = wb.append("r1".into(), "2026-07-13T00:00:01Z".into(), payload("R-1"));

        let err = verify_chain_with_anchor(&anchor, &[r]).unwrap_err();
        assert!(matches!(err, VerifyError::GenesisLinkMismatch { .. }));
    }

    #[test]
    fn unsigned_anchor_is_rejected() {
        let anchor = ChainAnchor {
            chain_id: "chain-unsigned".into(),
            anchor_hash: sample_anchor_hash(),
            genesis_timestamp: "2026-07-13T00:00:00Z".into(),
            genesis_public_key: String::new(),
            genesis_signature: String::new(),
            genesis_attestation: GenesisAttestation::default(),
        };
        assert!(
            super::signing::verify_anchor(&anchor)
                .unwrap_err()
                .contains("unsigned")
        );
    }

    #[test]
    fn payload_budget_helper() {
        let mut w = RecordChain::new(sample_anchor_hash());
        let r = w.append("id".into(), "2026-07-13T00:00:00Z".into(), payload("R-1"));
        // The fixed envelope (payload nulled) is well under the default budget,
        // regardless of how large the real payload is.
        assert!(record_payload_bytes(&r) <= DEFAULT_MAX_RECORD_BYTES);
    }

    // --- determinism gate ---

    #[test]
    fn record_hash_is_byte_stable_across_payload_key_order() {
        // Two logically-equal payloads built with different key insertion order
        // must produce identical record hashes. This is the property the whole
        // ecosystem's tamper-evidence rests on.
        let mut w1 = RecordChain::new(sample_anchor_hash());
        let a = w1.append(
            "id".into(),
            "2026-07-13T00:00:00Z".into(),
            json!({ "z": 1, "a": { "n": 2, "b": 3 }, "m": [ { "y": 4, "x": 5 } ] }),
        );
        let mut w2 = RecordChain::new(sample_anchor_hash());
        let b = w2.append(
            "id".into(),
            "2026-07-13T00:00:00Z".into(),
            json!({ "a": { "b": 3, "n": 2 }, "m": [ { "x": 5, "y": 4 } ], "z": 1 }),
        );
        assert_eq!(a.record_hash, b.record_hash);
        assert!(a.record_hash.starts_with("sha256:"));
    }

    #[test]
    fn record_hash_golden_value() {
        // Fixed inputs must hash to a fixed value on every platform. If this
        // constant ever changes, canonicalization or the hash construction
        // drifted and every existing chain would fail to verify.
        let mut w = RecordChain::new(
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".into(),
        );
        let r = w.append(
            "00000000-0000-4000-8000-000000000001".into(),
            "2026-07-13T00:00:00Z".into(),
            json!({ "decision": "allow", "rule_ids": ["R-1"] }),
        );
        assert_eq!(
            r.record_hash,
            "sha256:60a00b99cdf2994bbe07647022b763fe80e6f04c689cbf4cccff20d8daa49b27",
            "record hash drifted from the committed golden value"
        );
    }
}

//! The audit-segment chain: a content-agnostic, hash-linked segment log with a
//! size-anchoring segment head, plus an independent verifier.
//!
//! This is the pure subset of OAP's `audit.rs`. The rotating **file writer**
//! (open/append/rotate/recover) is deliberately not extracted: persistence and
//! rotation are the consumer's concern. [`AuditChain`] produces the hash-linked
//! records in memory; the consumer writes them wherever it keeps them (JSONL,
//! Postgres, an object store) and feeds them back to [`verify_audit_chain`].

use attest_ledger_types::AuditVerifyError;
use serde_json::{Value, json};

use crate::link_record_hash;

/// In-memory audit-segment chain builder.
///
/// Appends content-agnostic JSON records (each gaining `timestamp`,
/// `previous_record_hash`, and `record_hash`) and can close a segment with a
/// head record capturing `{segment_id, record_count, first/last timestamp}`.
/// The head's hash anchors the closed segment; feed it as the next segment's
/// genesis for cross-segment continuity.
pub struct AuditChain {
    last_hash: String,
    segment_id: String,
    record_count: u64,
    first_ts: Option<String>,
    last_ts: Option<String>,
}

impl AuditChain {
    /// Start a segment whose genesis binds `genesis`.
    ///
    /// `genesis` is a prior segment's head hash (for continuity across a
    /// rotation) or a fresh `genesis:<id>` marker for a first segment.
    /// `segment_id` is cosmetic: it is stamped into the segment head but records
    /// link by hash, so it is not chain-load-bearing.
    pub fn new(genesis: String, segment_id: String) -> Self {
        Self {
            last_hash: genesis,
            segment_id,
            record_count: 0,
            first_ts: None,
            last_ts: None,
        }
    }

    /// The current chain head: the next record's `previous_record_hash`.
    pub fn last_hash(&self) -> &str {
        &self.last_hash
    }

    /// The number of data records appended to the open segment so far.
    pub fn record_count(&self) -> u64 {
        self.record_count
    }

    /// Append an arbitrary JSON object as a chained record. `timestamp` is
    /// caller-supplied.
    ///
    /// Returns the fully-formed record (carrying its chain fields) on success.
    /// A non-object value cannot carry chain fields, so it is dropped and
    /// `None` is returned with the chain head unchanged (auditing must never
    /// panic the host).
    pub fn append(&mut self, timestamp: String, mut record: Value) -> Option<Value> {
        match record {
            Value::Object(ref mut m) => {
                m.insert("timestamp".into(), Value::String(timestamp.clone()));
                m.insert(
                    "previous_record_hash".into(),
                    Value::String(self.last_hash.clone()),
                );
            }
            _ => return None,
        }
        let record_hash = link_record_hash(record.clone(), "record_hash");
        if let Value::Object(ref mut m) = record {
            m.insert("record_hash".into(), Value::String(record_hash.clone()));
        }
        self.last_hash = record_hash;
        self.record_count += 1;
        if self.first_ts.is_none() {
            self.first_ts = Some(timestamp.clone());
        }
        self.last_ts = Some(timestamp);
        Some(record)
    }

    /// Close the segment with a head record capturing its accounting.
    ///
    /// The head's `record_count` is the closed-segment truncation tripwire; its
    /// hash anchors the segment and becomes the new chain head, so a following
    /// segment's genesis can bind it.
    pub fn close_segment(&mut self) -> Value {
        let mut head = json!({
            "segment_head": true,
            "segment_id": self.segment_id,
            "record_count": self.record_count,
            "first_timestamp": self.first_ts.clone().unwrap_or_default(),
            "last_timestamp": self.last_ts.clone().unwrap_or_default(),
            "previous_record_hash": self.last_hash,
        });
        let head_hash = link_record_hash(head.clone(), "record_hash");
        if let Value::Object(ref mut m) = head {
            m.insert("record_hash".into(), Value::String(head_hash.clone()));
        }
        self.last_hash = head_hash;
        head
    }
}

/// Walk the presented audit segment chain for integrity only.
///
/// Recomputes each record's hash, checks each `previous_record_hash` binds its
/// predecessor, and, if the final record is a segment head, checks its
/// `record_count` against the number of data records. When `expected_genesis`
/// is given, the first record's `previous_record_hash` must equal it
/// (cross-segment continuity); otherwise the first record's predecessor link is
/// the segment boundary and is not failed. Shares no state with the writer and
/// runs offline.
///
/// This accepts an intact open segment and does not prove that the trailing
/// head is present or latest. Use [`crate::verify_audit_chain_with_head`] with
/// an independently trusted expected head to require closed-segment
/// completeness.
pub fn verify_audit_chain(
    records: &[Value],
    expected_genesis: Option<&str>,
) -> Result<(), AuditVerifyError> {
    if records.is_empty() {
        return Err(AuditVerifyError::EmptyChain);
    }

    let last = records.len() - 1;
    for (i, rec) in records.iter().enumerate() {
        let is_head = rec.get("segment_head").and_then(Value::as_bool) == Some(true);
        if is_head && i != last {
            return Err(AuditVerifyError::MisplacedHead { index: i });
        }

        let stored = rec.get("record_hash").and_then(Value::as_str).ok_or(
            AuditVerifyError::MissingField {
                index: i,
                field: "record_hash",
            },
        )?;
        if link_record_hash(rec.clone(), "record_hash") != stored {
            return Err(AuditVerifyError::RecordHashMismatch { index: i });
        }

        let prev = rec
            .get("previous_record_hash")
            .and_then(Value::as_str)
            .ok_or(AuditVerifyError::MissingField {
                index: i,
                field: "previous_record_hash",
            })?;
        if i == 0 {
            if let Some(g) = expected_genesis
                && prev != g
            {
                return Err(AuditVerifyError::GenesisMismatch {
                    expected: g.to_string(),
                    found: prev.to_string(),
                });
            }
        } else {
            let prior = records[i - 1]
                .get("record_hash")
                .and_then(Value::as_str)
                .unwrap_or("");
            if prev != prior {
                return Err(AuditVerifyError::BrokenLink { index: i });
            }
        }
    }

    // Closed-segment truncation tripwire: a trailing head's stated record_count
    // must equal the data records preceding it.
    let trailing_head = records
        .last()
        .filter(|h| h.get("segment_head").and_then(Value::as_bool) == Some(true));
    if let Some(head) = trailing_head {
        let expected = head.get("record_count").and_then(Value::as_u64).ok_or(
            AuditVerifyError::MissingField {
                index: last,
                field: "record_count",
            },
        )?;
        let found = last as u64; // every record except the head is a data record
        if expected != found {
            return Err(AuditVerifyError::CountMismatch { expected, found });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(cmd: &str) -> Value {
        json!({ "tool_name": "Bash", "command": cmd, "decision": "Allow" })
    }

    #[test]
    fn appends_and_chains() {
        let mut w = AuditChain::new("genesis:seg".into(), "seg".into());
        let a = w
            .append("2026-07-13T00:00:00Z".into(), entry("cargo test"))
            .unwrap();
        let b = w
            .append("2026-07-13T00:00:01Z".into(), entry("cargo build"))
            .unwrap();
        assert!(
            a["previous_record_hash"]
                .as_str()
                .unwrap()
                .starts_with("genesis:")
        );
        assert_eq!(b["previous_record_hash"], a["record_hash"]);
        verify_audit_chain(&[a, b], None).expect("clean chain verifies");
    }

    #[test]
    fn non_object_is_dropped_without_advancing() {
        let mut w = AuditChain::new("genesis:seg".into(), "seg".into());
        assert!(w.append("t".into(), json!("not-an-object")).is_none());
        let a = w.append("t".into(), entry("x")).unwrap();
        // The scalar did not advance the head, so the object still binds genesis.
        assert!(
            a["previous_record_hash"]
                .as_str()
                .unwrap()
                .starts_with("genesis:")
        );
        verify_audit_chain(&[a], None).expect("chain intact after dropped scalar");
    }

    #[test]
    fn byte_flip_detected() {
        let mut w = AuditChain::new("genesis:seg".into(), "seg".into());
        let mut recs: Vec<Value> = (0..5)
            .map(|i| w.append("t".into(), entry(&format!("cmd-{i}"))).unwrap())
            .collect();
        recs[2]["command"] = Value::String("TAMPERED".into());
        assert_eq!(
            verify_audit_chain(&recs, None).unwrap_err(),
            AuditVerifyError::RecordHashMismatch { index: 2 }
        );
    }

    #[test]
    fn mid_segment_deletion_detected() {
        let mut w = AuditChain::new("genesis:seg".into(), "seg".into());
        let mut recs: Vec<Value> = (0..5)
            .map(|i| w.append("t".into(), entry(&format!("cmd-{i}"))).unwrap())
            .collect();
        recs.remove(2);
        assert_eq!(
            verify_audit_chain(&recs, None).unwrap_err(),
            AuditVerifyError::BrokenLink { index: 2 }
        );
    }

    #[test]
    fn closed_segment_truncation_detected() {
        let mut w = AuditChain::new("genesis:seg".into(), "seg".into());
        let mut recs: Vec<Value> = (0..4)
            .map(|i| w.append("t".into(), entry(&format!("c{i}"))).unwrap())
            .collect();
        recs.push(w.close_segment());
        verify_audit_chain(&recs, None).expect("intact closed segment verifies");

        // Drop one data record and re-link the head to the new tail, so only
        // the count is wrong (proves count, not linkage, catches it).
        let mut truncated = recs.clone();
        truncated.remove(3);
        let new_prev = truncated[2]["record_hash"].as_str().unwrap().to_string();
        truncated[3]["previous_record_hash"] = Value::String(new_prev);
        let relinked = link_record_hash(truncated[3].clone(), "record_hash");
        truncated[3]["record_hash"] = Value::String(relinked);
        assert_eq!(
            verify_audit_chain(&truncated, None).unwrap_err(),
            AuditVerifyError::CountMismatch {
                expected: 4,
                found: 3
            }
        );
    }

    #[test]
    fn rotation_continuity() {
        let mut w = AuditChain::new("genesis:seg-n".into(), "seg-n".into());
        let mut seg_n: Vec<Value> = (0..3)
            .map(|i| w.append("t".into(), entry(&format!("n{i}"))).unwrap())
            .collect();
        let head = w.close_segment();
        let head_hash = head["record_hash"].as_str().unwrap().to_string();
        seg_n.push(head);
        verify_audit_chain(&seg_n, None).expect("segment N verifies");

        // Segment N+1 genesis must bind segment N's head hash.
        let mut w2 = AuditChain::new(head_hash.clone(), "seg-n1".into());
        let seg_n1: Vec<Value> = (0..2)
            .map(|i| w2.append("t".into(), entry(&format!("m{i}"))).unwrap())
            .collect();
        verify_audit_chain(&seg_n1, Some(&head_hash)).expect("segment N+1 binds N's head");
        assert!(matches!(
            verify_audit_chain(&seg_n1, Some("sha256:wrong")).unwrap_err(),
            AuditVerifyError::GenesisMismatch { .. }
        ));
    }

    #[test]
    fn misplaced_head_detected() {
        let mut w = AuditChain::new("genesis:seg".into(), "seg".into());
        let a = w.append("t".into(), entry("a")).unwrap();
        let head = w.close_segment();
        let b = w.append("t".into(), entry("b")).unwrap();
        assert_eq!(
            verify_audit_chain(&[a, head, b], None).unwrap_err(),
            AuditVerifyError::MisplacedHead { index: 1 }
        );
    }

    #[test]
    fn empty_chain_is_error() {
        assert_eq!(
            verify_audit_chain(&[], None).unwrap_err(),
            AuditVerifyError::EmptyChain
        );
    }
}

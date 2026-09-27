# attest-ledger

A tamper-evident record ledger: append-only, hash-linked, Ed25519-signed, with
an independent verifier that does not trust the producer. It is the **run-time**
counterpart to a build-time registry: the same primitive (typed, hash-verified,
append-only), a different clock.

```rust
use attest_ledger_core::{
    RecordChain, build_record_head_commitment, verify_chain_with_head,
};
use serde_json::json;

// Root the chain at some pinned hash (a bundle hash, a context hash, anything).
let mut chain = RecordChain::new("sha256:0000...".into());

// A signed genesis anchor gives an external verifier a trust root beyond the
// chain's own hashes. The key resolves from ATTEST_LEDGER_SIGNING_KEY, or an
// ephemeral key is generated for this writer.
let anchor = chain.build_anchor("chain-001".into(), "2026-07-13T00:00:00Z".into());

// Every append hashes the prior record's hash into its own. The payload is
// opaque: put whatever domain content you want in it.
let r0 = chain.append("r0".into(), "2026-07-13T00:00:01Z".into(),
    json!({ "decision": "allow", "rule_ids": ["R-1"] }));

// A commitment becomes trusted only after it is carried through a channel
// outside the ledger's rollback domain.
let head = build_record_head_commitment(&anchor, &[r0.clone()]).unwrap();

// Verify offline against that independently trusted expected head.
verify_chain_with_head(&anchor, &[r0], &head).unwrap();
```

## The two chains

- **Record chain** (`RecordChain` + `verify_chain` / `verify_chain_with_anchor`):
  individual `LedgerRecord`s, each hashing the canonical JSON of the prior
  record's hash into its own. A signed `ChainAnchor` pins the chain to a root.
  These APIs verify the integrity of the presented sequence. Add
  `HeadCommitmentV1` plus `verify_chain_with_head` to prove tail completeness
  against an independently trusted expected head.
- **Audit-segment chain** (`AuditChain` + `verify_audit_chain`): a
  content-agnostic, hash-chained segment log for higher-volume append, closed
  with a size-anchoring segment head, verified with cross-segment continuity.
  Open-segment verification is integrity-only. Use
  `verify_audit_chain_with_head` to require a complete closed segment.

## Design commitments

- **Domain-neutral envelope.** A record's `payload` is an opaque
  `serde_json::Value`; the ledger core never inspects it. Consumers put their
  decision, provenance, or message record in the payload and get tamper-evidence
  for free.
- **Determinism.** The core takes every hash input, including the timestamp, as
  an argument: no wall clock, no `Date.now()`. `compute_record_hash` is a pure
  function of its inputs and the verifier reproduces byte-for-byte across
  platforms. Reproducible hashing rests on
  [`canonical-keysort-json`](https://crates.io/crates/canonical-keysort-json),
  which guarantees key-sorted serialization regardless of `serde_json`'s
  `preserve_order` feature state anywhere in the dependency graph. (Hashed
  payloads should stay integer/string/bool: cross-language float formatting
  differs, so a float payload is not portable across a Rust/JS/Python verify.)
- **Storage is not here.** The core produces and verifies records; it owns no
  persistence. Writing records to JSONL files, rotating them, or committing them
  to a database is the consumer's concern. The `attest-ledger` CLI does the file
  I/O at the edge.
- **Freshness is external.** A trusted head binds schema, chain, signed anchor,
  expected count, and terminal hash. The caller must obtain it through a
  separately trusted channel. A head stored and rolled back with the ledger is
  not a freshness authority, so attest-ledger does not claim rollback
  resistance for that arrangement.

## Crates

| Crate | What it is |
|---|---|
| `attest-ledger-types` | The on-the-wire shapes and error taxonomy. Serde only. |
| `attest-ledger-core` | Hashing, Ed25519 anchor signing, and the two verifiers. |
| `attest-ledger-cli` | The `attest-ledger` binary: `verify` and `verify-audit`. |

## CLI

```console
$ attest-ledger verify chain.jsonl --anchor anchor.json
chain VERIFIED: 12 record(s), anchor signature valid, integrity only (no trusted head supplied)

$ attest-ledger verify chain.jsonl --anchor anchor.json --head head.json --require-head
chain VERIFIED: 12 record(s), anchor signature valid, trusted head matched

$ attest-ledger verify-audit segment.jsonl --genesis sha256:abc...
audit segment VERIFIED: 8 record(s), integrity only (no trusted head supplied)

$ attest-ledger verify-audit segment.jsonl --head audit-head.json --require-head
audit segment VERIFIED: 8 record(s), trusted head matched
```

Exit 0 on a clean verify, exit 1 with a specific diagnostic naming the first
broken record or head mismatch. `--require-head` exits 1 rather than silently
falling back when its trusted head input is absent.

## Ecosystem

Part of the `statecrafting` reusable-primitive family, extracted from the Open
Agentic Platform and relicensed Apache-2.0 by the sole copyright holder (see
`NOTICE`). It depends on `canonical-keysort-json` (the leaf). This repo is
self-governed by its own `specs/` corpus, compiled by the pinned `spec-spine`
library.

Licensed under Apache-2.0.

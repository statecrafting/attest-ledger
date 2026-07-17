# attest-ledger

A tamper-evident record ledger: append-only, hash-linked, Ed25519-signed, with
an independent verifier that does not trust the producer. It is the **run-time**
counterpart to a build-time registry: the same primitive (typed, hash-verified,
append-only), a different clock.

```rust
use attest_ledger_core::{RecordChain, verify_chain_with_anchor};
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

// Verify offline. The verifier recomputes every hash and checks the anchor
// signature first; it shares no state with the writer.
verify_chain_with_anchor(&anchor, &[r0]).unwrap();
```

## The two chains

- **Record chain** (`RecordChain` + `verify_chain` / `verify_chain_with_anchor`):
  individual `LedgerRecord`s, each hashing the canonical JSON of the prior
  record's hash into its own. A signed `ChainAnchor` pins the chain to a root.
- **Audit-segment chain** (`AuditChain` + `verify_audit_chain`): a
  content-agnostic, hash-chained segment log for higher-volume append, closed
  with a size-anchoring segment head, verified with cross-segment continuity.

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

## Crates

| Crate | What it is |
|---|---|
| `attest-ledger-types` | The on-the-wire shapes and error taxonomy. Serde only. |
| `attest-ledger-core` | Hashing, Ed25519 anchor signing, and the two verifiers. |
| `attest-ledger-cli` | The `attest-ledger` binary: `verify` and `verify-audit`. |

## CLI

```console
$ attest-ledger verify chain.jsonl --anchor anchor.json
chain VERIFIED: 12 record(s), anchor signature valid

$ attest-ledger verify-audit segment.jsonl --genesis sha256:abc...
audit segment VERIFIED: 8 record(s)
```

Exit 0 on a clean verify, exit 1 with a specific diagnostic naming the first
broken record on tamper.

## Ecosystem

Part of the `statecrafting` reusable-primitive family, extracted from the Open
Agentic Platform and relicensed Apache-2.0 by the sole copyright holder (see
`NOTICE`). It depends on `canonical-keysort-json` (the leaf). This repo is
self-governed by its own `specs/` corpus, compiled by the pinned `spec-spine`
library.

Licensed under Apache-2.0.

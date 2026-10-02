---
id: "000-attest-ledger-bootstrap"
title: "attest-ledger bootstrap (tamper-evident record ledger)"
status: approved
created: "2026-07-13"
authors: ["attest-ledger"]
kind: tooling
implementation: pending
risk: low
summary: >
  Bootstrap spec for the attest-ledger repository: a three-crate workspace
  vending a tamper-evident record ledger (append-only, hash-linked,
  Ed25519-signed) with an independent verifier. Extracted (relicensed Apache-2.0
  by the sole copyright holder) from the Open Agentic Platform's
  crates/policy-kernel (proof_chain.rs and the pure subset of audit.rs). It
  depends on canonical-keysort-json for reproducible hashing. This spec
  establishes the workspace skeleton and seeds this repo's own spec corpus,
  which is governed by the pinned spec-spine library.
depends_on: []
establishes:
  - { kind: directory, path: "standards/spec/" }
  - { kind: file, path: "spec-spine.toml" }
  - { kind: file, path: "AGENTS.md" }
  - { kind: file, path: "Makefile" }
  - { kind: file, path: ".github/CODEOWNERS" }
  - { kind: file, path: ".github/workflows/statecraft-ai-review.yml" }
  - { kind: file, path: ".github/workflows/statecraft-ci.yml" }
  - { kind: directory, path: ".statecraft/" }
  - { kind: directory, path: "scripts/statecraft/" }
  - { kind: file, path: "Cargo.toml" }
  - { kind: file, path: "crates/types/Cargo.toml" }
  - { kind: file, path: "crates/types/src/lib.rs" }
  - { kind: file, path: "crates/core/Cargo.toml" }
  - { kind: file, path: "crates/core/src/lib.rs" }
  - { kind: file, path: "crates/core/src/record_chain.rs" }
  - { kind: file, path: "crates/core/src/audit.rs" }
  - { kind: file, path: "crates/core/src/signing.rs" }
  - { kind: file, path: "crates/cli/Cargo.toml" }
  - { kind: file, path: "crates/cli/src/main.rs" }
references:
  - { unit: { kind: file, path: "README.md" }, role: context }
  - { unit: { kind: file, path: "NOTICE" }, role: context }
---

# 000: attest-ledger bootstrap

## 1. Purpose

attest-ledger is the run-time tamper-evidence primitive of the `statecrafting`
reusable-primitive family. It guarantees that a sequence of records is
append-only and hash-linked, so any edit, deletion, reorder, or splice is
detectable, and that the chain is pinned to a signing key an external verifier
can trust without trusting the producer.

It is the run-time counterpart to a build-time registry: the same discipline
(typed, hash-verified, append-only) applied to records emitted while a system
runs rather than facts frozen at build time. A consumer's decision, provenance,
or message-send record is one `LedgerRecord`; the ledger core never inspects the
payload, only chains and verifies it.

This bootstrap spec exists so the repository has a governed seed: the workspace
compiles, this corpus is non-empty, and spec-spine can dogfood it.

## 2. Scope

In scope, established here:

- The **record chain**: `RecordChain` (append-only in-memory writer),
  `compute_record_hash`, `verify_chain`, `verify_chain_with_anchor`, and the
  signed `ChainAnchor` with Ed25519 `sign_anchor` / `verify_anchor`.
- The **audit-segment chain**: the storage-agnostic `AuditChain` builder,
  segment-head construction, and `verify_audit_chain` with cross-segment
  continuity.
- The **verifier CLI** `attest-ledger` (`verify`, `verify-audit`).
- The **determinism gate**: byte-stable record hashes across payload key order,
  plus a golden-value test pinning a fixed hash for fixed inputs.

Out of scope:

- **Persistence.** The core produces and verifies records; it owns no storage.
  The rotating file writer OAP uses is a persistence choice and is not extracted.
- **The OAP-specific proof-record fields.** `policy_bundle_hash`, `rule_ids`,
  `decision`, and `privilege_level` are not part of the envelope; they move into
  the opaque `payload` of consumers that want them.
- **Hashing internals beyond canonicalization**, which are owned by
  `canonical-keysort-json` (the leaf dependency).

## 3. Provenance

Extracted from OAP `crates/policy-kernel` (`proof_chain.rs` and the pure subset
of `audit.rs`, AGPL-3.0-or-later there), relicensed Apache-2.0 by the sole
copyright holder. The signing key resolution was generalized (OAP's
`OAP_SIGNING_KEY` becomes `ATTEST_LEDGER_SIGNING_KEY`), the OAP-specific record
fields moved into the opaque payload, and the file writer / rotation dropped in
favor of a storage-agnostic in-memory builder. The interim extraction record is
`chancery/docs/preliminary/00-extraction-overview.md` and `01-attest-ledger.md`;
a forthcoming OAP extraction spec formalizes the vend.

## 4. Established units

- `Cargo.toml`: the workspace manifest (three members, Apache-2.0, edition 2024,
  forbid-unsafe), pinning the crypto stack to OAP's versions so the extracted
  proof-chain code compiles identically.
- `crates/types`: `LedgerRecord`, `ChainAnchor`, `GenesisAttestation(Kind)`,
  `VerifyError`, `AuditVerifyError`.
- `crates/core`: hashing, the record chain, anchor signing, and the audit chain,
  each with its verifier.
- `crates/cli`: the `attest-ledger` verifier binary.

## 5. Notes on the generalization

OAP's `verify_proof_chain(records, expected_bundle_hash)` required an external
bundle hash. The generic `verify_chain(records)` checks internal integrity only
(hashes + links); the external trust root is checked by
`verify_chain_with_anchor(anchor, records)`, which verifies the anchor signature
first and then that the genesis record binds the anchor. OAP's
`NF004_MAX_BYTES_EXCLUDING_CONTEXT` per-record budget is a domain policy, not a
ledger-integrity property, so it is offered as an opt-in helper
(`record_payload_bytes` against `DEFAULT_MAX_RECORD_BYTES`) rather than enforced
by the verifier.

## Owner ratification

2026-10-02: Ratified under the owner's explicit fleet-upgrade instruction.
Implementation lifecycle is unchanged by this approval.

## Managed governance enrollment (2026-10-02)

The owner requested enrollment on spec-spine =0.28.0 and the Statecraft
github-actions-rust profile revision 13. The adopted pin remains the single
version authority. The managed profile installs .bin/spec-spine, preserves
signed commits, checks every commit, enforces source coverage and ratified
path ownership, and requires owner review for authority changes.

The constitution template uses section authority claims for amendments, matching
the managed constitution. The `amends` relationship continues to target spec ids.

The authored constitution retains corpus principles I through V and the
amendment contract. Template authoring instructions are not part of the live
constitution. This enrollment adds no unratified product principles.

## Managed governance refresh (2026-10-02)

The owner approved Statecraft profile revision 14 and fleet convergence after
the revision-13 enrollment. This amendment adopts revision 14 with the
existing exact spec-spine =0.28.0 pin and preserves the actual Rust code
checks, all current governance parameters, and protected owner review.
The revision-13 enrollment above remains the historical adoption record.
The managed installer remains at .bin/spec-spine.
The corrected constitution template is an authored customization. Its
per-path managed-to-user ownership transfer is recorded by the Statecraft
CLI with owner-delegated consent; its bytes are preserved, and init apply
never silently overwrites that corrected amendment guidance.

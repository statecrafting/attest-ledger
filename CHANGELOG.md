# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-09-26

### Added

- `HeadCommitmentV1`, a versioned domain-neutral commitment to chain identity,
  signed anchor identity, expected record count, and terminal record hash.
- Opt-in `verify_chain_with_head` and `verify_audit_chain_with_head` APIs with
  typed refusals for valid prefixes, substituted chains or anchors, wrong
  counts, and wrong terminal hashes.
- CLI `--head` and `--require-head` modes for complete record chains and closed
  audit segments. Required-head mode never falls back to integrity-only
  verification.

### Changed

- Documentation now states that the 0.1.0 verifiers prove integrity only for
  the sequence presented. Tail completeness requires an independently trusted
  expected head. A commitment rolled back with the ledger is not a freshness
  authority and does not provide rollback resistance.

## [0.1.0] - 2026-07-13

### Added

- Initial release of the three-crate workspace.
  - `attest-ledger-types`: the `LedgerRecord` envelope (domain payload kept
    opaque), the signed `ChainAnchor`, the `GenesisAttestation` taxonomy, and
    the `VerifyError` / `AuditVerifyError` enums.
  - `attest-ledger-core`: `sha256_hex` and `link_record_hash` over
    `canonical-keysort-json`; the append-only `RecordChain` writer;
    Ed25519 anchor signing (`sign_anchor` / `verify_anchor` /
    `resolve_signing_material`); `verify_chain` and `verify_chain_with_anchor`;
    and the storage-agnostic `AuditChain` segment builder with
    `verify_audit_chain`.
  - `attest-ledger-cli`: the `attest-ledger` binary with `verify` (optional
    `--anchor`, `--require-signed`) and `verify-audit` (optional `--genesis`).
- Determinism gate: record hashes are byte-stable across payload key-insertion
  order, and a golden-value test pins a fixed hash for fixed inputs so
  cross-platform drift fails loudly.
- Extracted and relicensed Apache-2.0 (by the sole copyright holder) from the
  Open Agentic Platform's `crates/policy-kernel` (`proof_chain.rs` and the pure
  subset of `audit.rs`). The OAP-specific proof-record fields move into the
  opaque `payload`; the OAP file writer / rotation is not extracted (storage is
  the consumer's concern). See `NOTICE`.

[0.1.0]: https://github.com/statecrafting/attest-ledger/releases/tag/v0.1.0
[0.1.1]: https://github.com/statecrafting/attest-ledger/compare/v0.1.0...v0.1.1

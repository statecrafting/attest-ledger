# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.1.0]: https://github.com/stagecraft-ing/attest-ledger/releases/tag/v0.1.0

---
id: "001-tail-completeness-and-head-commitment"
title: "Tail completeness and trusted head commitments"
status: approved
created: "2026-09-26"
authors: ["attest-ledger"]
kind: tooling
implementation: complete
risk: high
summary: >
  Amend spec 000's unqualified deletion claim. Existing verifiers prove the
  integrity of the sequence presented to them, not that it is the latest or
  complete sequence. Add a versioned, domain-neutral head commitment and
  opt-in record-chain and closed-audit-segment verifiers for callers that
  obtain the expected head through a separately trusted channel. Preserve all
  0.1.0 APIs and release the additive contract as 0.1.1.
depends_on:
  - "000-attest-ledger-bootstrap"
amends:
  - "000-attest-ledger-bootstrap"
amends_sections:
  - "1-purpose"
establishes:
  - { kind: file, path: "crates/types/src/head_commitment.rs" }
  - { kind: file, path: "crates/core/src/head_commitment.rs" }
  - { kind: file, path: "crates/core/tests/head_commitment.rs" }
  - { kind: file, path: "crates/cli/tests/head_commitment_cli.rs" }
  - { kind: file, path: "tests/registry-consumer/Cargo.toml" }
  - { kind: file, path: "tests/registry-consumer/src/main.rs" }
extends:
  - { spec: "000-attest-ledger-bootstrap", unit: { kind: section, file: "Cargo.toml", anchor: "workspace.package" }, nature: additive }
  - { spec: "000-attest-ledger-bootstrap", unit: { kind: section, file: "Cargo.toml", anchor: "workspace.dependencies" }, nature: additive }
  - { spec: "000-attest-ledger-bootstrap", unit: "Cargo.lock", nature: additive }
  - { spec: "000-attest-ledger-bootstrap", unit: "crates/types/Cargo.toml", nature: additive }
  - { spec: "000-attest-ledger-bootstrap", unit: "crates/types/src/lib.rs", nature: additive }
  - { spec: "000-attest-ledger-bootstrap", unit: "crates/core/Cargo.toml", nature: additive }
  - { spec: "000-attest-ledger-bootstrap", unit: "crates/core/src/lib.rs", nature: additive }
  - { spec: "000-attest-ledger-bootstrap", unit: "crates/core/src/record_chain.rs", nature: additive }
  - { spec: "000-attest-ledger-bootstrap", unit: "crates/core/src/audit.rs", nature: additive }
  - { spec: "000-attest-ledger-bootstrap", unit: "crates/cli/Cargo.toml", nature: additive }
  - { spec: "000-attest-ledger-bootstrap", unit: "crates/cli/src/main.rs", nature: additive }
  - { spec: "000-attest-ledger-bootstrap", unit: "README.md", nature: corrective }
  - { spec: "000-attest-ledger-bootstrap", unit: "CHANGELOG.md", nature: additive }
references:
  - { unit: { kind: file, path: ".github/workflows/ci.yml" }, role: constraint }
  - { unit: { kind: file, path: ".github/workflows/release.yml" }, role: constraint }
  - { unit: { kind: file, path: ".github/publish-crate.sh" }, role: constraint }
---

# 001: Tail completeness and trusted head commitments

Ratified by Bart on 2026-09-26. The same owner instruction authorized the
separate implementation, review, merge, and governed public 0.1.1 release
sequence after all declared gates pass.

## 1. Purpose and amendment

Spec `000-attest-ledger-bootstrap` section 1 says that any deletion is
detectable. That statement is too broad. The released 0.1.0 verifiers detect
an edit, reorder, splice, broken link, or non-tail deletion within the sequence
presented to them. They accept a valid non-empty prefix because they have no
independently trusted statement of how many records should exist or which hash
should be terminal. Removing an audit segment's trailing head likewise turns a
closed segment into a valid open segment.

This spec amends only that deletion claim. In the amended contract:

1. `verify_chain`, `verify_chain_with_anchor`, and `verify_audit_chain` are
   integrity verifiers for the sequence presented to them.
2. Those functions do not establish that the sequence is latest, complete, or
   immune to rollback.
3. Tail completeness is established only when an opt-in verifier compares the
   presented sequence with an independently trusted `HeadCommitmentV1`.

Spec 000 remains a historical bootstrap with `status: draft` and
`implementation: pending` until Bart separately corrects or ratifies its
lifecycle metadata. This draft does not change that metadata. The signed
`v0.1.0` tag, GitHub release, and published 0.1.0 crates remain immutable.

## 2. Scope, compatibility, and claimed units

The 0.1.1 change is additive. These 0.1.0 public functions retain their exact
signatures, return types, validation order, and integrity semantics:

- `verify_chain(&[LedgerRecord]) -> Result<(), VerifyError>`;
- `verify_chain_with_anchor(&ChainAnchor, &[LedgerRecord]) -> Result<(), VerifyError>`;
- `verify_audit_chain(&[serde_json::Value], Option<&str>) -> Result<(), AuditVerifyError>`.

Existing public types and error enums are not given new required fields or new
variants. In particular, the new refusal cases use new error enums so an
existing exhaustive match over `VerifyError` or `AuditVerifyError` continues
to compile. Existing callers get no completeness check unless they call a new
API or select a new CLI option.

The later implementation owns exactly these changes:

| Unit | Required change |
|---|---|
| `crates/types/src/head_commitment.rs` | Define `HeadCommitmentKind`, `HeadCommitmentV1`, `HeadVerifyError`, and `AuditHeadVerifyError`. |
| `crates/types/src/lib.rs` | Export the four new public types without changing existing exports. |
| `crates/types/Cargo.toml` | Keep the wire-types crate serde-only and update package metadata or description if needed. |
| `crates/core/src/head_commitment.rs` | Implement canonical commitment and anchor identities, builders, and both complete verification APIs. |
| `crates/core/src/lib.rs` | Export the new constants and functions. |
| `crates/core/src/record_chain.rs` | Correct integrity-only documentation without changing the existing verifier implementation. |
| `crates/core/src/audit.rs` | Label open-segment verification as integrity-only without changing `verify_audit_chain`. |
| `crates/core/tests/head_commitment.rs` | Cover canonical bytes and every record and audit refusal in this spec. |
| `crates/cli/src/main.rs` | Add `--head` and `--require-head`, preserve old modes, and implement the exact refusal behavior in section 7. |
| `crates/cli/tests/head_commitment_cli.rs` | Cover required-head success, refusal text, and exit codes. |
| `crates/cli/Cargo.toml` | Add only the dev dependencies required by the CLI integration test. |
| `tests/registry-consumer/Cargo.toml` | Define a standalone fixture with exact registry `=0.1.1` dependencies, its own empty `[workspace]`, and no path, Git, or patch source. |
| `tests/registry-consumer/src/main.rs` | Implement the nine post-publication assertions in section 8.3. |
| `Cargo.toml`, `Cargo.lock`, and all three crate manifests | Set and resolve all three public crates at 0.1.1 with matching internal dependency requirements. |
| `README.md` | Qualify integrity-only claims, document external trust, and show complete record and audit CLI examples. |
| `CHANGELOG.md` | Add a 0.1.1 entry naming the fixed claim, the opt-in APIs, compatibility, and trust limitation. |

No persistence, remote witness, key service, network protocol, or automatic
checkpoint transport is added. Rahi and travel-memory are outside this spec.

## 3. The versioned commitment

### 3.1 Public wire shape

`attest-ledger-types` adds this domain-neutral public shape. Names below are
normative Rust and JSON names:

```rust
pub const HEAD_COMMITMENT_SCHEMA_V1: &str =
    "attest-ledger/head-commitment/v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum HeadCommitmentKind {
    RecordChain,
    AuditSegment,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HeadCommitmentV1 {
    pub schema_identity: String,
    pub chain_kind: HeadCommitmentKind,
    pub chain_identity: String,
    pub anchor_identity: String,
    pub expected_record_count: u64,
    pub terminal_record_hash: String,
}
```

No field has a serde default and no field may be omitted. A verifier accepts
only the literal `HEAD_COMMITMENT_SCHEMA_V1`; another value returns the typed
unsupported-schema refusal. `chain_identity`, `anchor_identity`, and
`terminal_record_hash` must be non-empty. Hash identities created by this
library use the existing lower-case `sha256:<64 hex digits>` representation.

The fields mean:

- `schema_identity`: the exact wire and digest schema above;
- `chain_kind`: whether the commitment closes a record chain or an audit
  segment;
- `chain_identity`: `ChainAnchor.chain_id` for a record chain, or the trailing
  audit head's `segment_id` for an audit segment;
- `anchor_identity`: the signed chain-anchor identity defined in section 3.2
  for a record chain, or the exact expected genesis string for an audit
  segment;
- `expected_record_count`: every `LedgerRecord` for a record chain, or data
  records excluding the required trailing segment-head record for an audit
  segment;
- `terminal_record_hash`: the last `LedgerRecord.record_hash` for a record
  chain, or the required trailing segment head's `record_hash` for an audit
  segment.

### 3.2 Canonical bytes and identities

Canonical bytes are exact and cross-platform:

1. Serialize the value to `serde_json::Value` with its public JSON field and
   enum names.
2. Serialize that value with
   `canonical_keysort_json::to_canonical_string`.
3. Take the UTF-8 bytes of that string, with no newline, byte-order mark, or
   surrounding whitespace.

`head_commitment_digest(&HeadCommitmentV1)` returns the existing
`sha256:<lower-case hex>` encoding of SHA-256 over those canonical bytes.

`chain_anchor_identity(&ChainAnchor)` applies the same three steps to the
complete serialized `ChainAnchor`, including `chain_id`, `anchor_hash`,
`genesis_timestamp`, `genesis_public_key`, `genesis_signature`, and
`genesis_attestation`, then returns the same SHA-256 encoding. It does not zero
the signature. This is distinct from the bytes signed by `sign_anchor`, which
continue to zero `genesis_signature` under spec 000. Binding the complete
signed anchor prevents substitution of another chain id, root, signing key,
signature, timestamp, or attestation.

`HeadCommitmentV1` has no embedded signature in 0.1.1. The digest boundary is
the whole canonical commitment. A caller may pin that object or digest, carry
it in authenticated configuration, or sign those canonical bytes in a
separate protocol. Attest-ledger does not declare any one transport or signer
authoritative.

### 3.3 Construction

The core exports:

```rust
pub fn build_record_head_commitment(
    anchor: &ChainAnchor,
    records: &[LedgerRecord],
) -> Result<HeadCommitmentV1, HeadVerifyError>;

pub fn build_audit_head_commitment(
    records: &[serde_json::Value],
    expected_genesis: &str,
) -> Result<HeadCommitmentV1, AuditHeadVerifyError>;
```

The record builder first runs `verify_chain_with_anchor`, then uses the anchor
and verified terminal record to fill the fields. The audit builder first runs
`verify_audit_chain(records, Some(expected_genesis))`, then requires the final
record to be a segment head with a string `segment_id`, a `u64` record count
equal to the number of preceding data records, and a string `record_hash`.
Builders never label unchecked input trusted. Constructing a commitment does
not make it an external freshness authority.

## 4. Complete record-chain verification

The core adds:

```rust
pub fn verify_chain_with_head(
    anchor: &ChainAnchor,
    records: &[LedgerRecord],
    expected_head: &HeadCommitmentV1,
) -> Result<(), HeadVerifyError>;
```

It performs checks in this fixed order:

1. Run `verify_chain_with_anchor(anchor, records)` and wrap any failure as
   `HeadVerifyError::Integrity`.
2. Require the v1 schema identity and `record-chain` kind.
3. Require `expected_head.chain_identity == anchor.chain_id`.
4. Require `expected_head.anchor_identity == chain_anchor_identity(anchor)`.
5. Require `expected_head.expected_record_count == records.len()` after a
   checked `usize` to `u64` conversion.
6. Require `expected_head.terminal_record_hash` to equal the final record hash.

The new error type is exactly:

```rust
pub enum HeadVerifyError {
    Integrity(VerifyError),
    UnsupportedSchema { expected: String, found: String },
    KindMismatch { expected: HeadCommitmentKind, found: HeadCommitmentKind },
    ChainIdentityMismatch { expected: String, found: String },
    AnchorIdentityMismatch { expected: String, found: String },
    RecordCountMismatch { expected: u64, found: u64 },
    TerminalHashMismatch { expected: String, found: String },
}
```

Here `expected` is the value supplied by the trusted commitment and `found` is
the value derived from the anchor and records, except the schema and kind
variants, where `expected` is the library's required value. Display text must
name the mismatched field and both values without printing payloads.

A one-record prefix of a committed two-record chain therefore returns
`RecordCountMismatch`. Even if a caller changes the count in an untrusted copy,
the terminal hash disagrees. A commitment from another signed chain returns
`ChainIdentityMismatch` or `AnchorIdentityMismatch`; another anchor on a chain
with the same id still returns `AnchorIdentityMismatch`. Wrong count and wrong
terminal hash return their specific variants.

## 5. Complete audit-segment verification

The core adds:

```rust
pub fn verify_audit_chain_with_head(
    records: &[serde_json::Value],
    expected_genesis: &str,
    expected_head: &HeadCommitmentV1,
) -> Result<(), AuditHeadVerifyError>;
```

It performs checks in this fixed order:

1. Run `verify_audit_chain(records, Some(expected_genesis))` and wrap any
   failure as `AuditHeadVerifyError::Integrity`.
2. Require the v1 schema and `audit-segment` kind.
3. Require the final record to have `segment_head: true`, a string
   `segment_id`, a `u64` `record_count`, and a string `record_hash`.
4. Require the commitment's `chain_identity` to equal the final head's
   `segment_id`.
5. Require the commitment's `anchor_identity` to equal `expected_genesis`.
6. Require the commitment count, the final head's `record_count`, and the
   number of data records before the head to agree exactly.
7. Require the commitment terminal hash to equal the trailing head's
   `record_hash`.

The new audit error type is exactly:

```rust
pub enum AuditHeadVerifyError {
    Integrity(AuditVerifyError),
    UnsupportedSchema { expected: String, found: String },
    KindMismatch { expected: HeadCommitmentKind, found: HeadCommitmentKind },
    MissingSegmentHead,
    MissingHeadField { field: &'static str },
    ChainIdentityMismatch { expected: String, found: String },
    AnchorIdentityMismatch { expected: String, found: String },
    RecordCountMismatch { expected: u64, found: u64 },
    TerminalHashMismatch { expected: String, found: String },
}
```

Removing the trailing segment head returns `MissingSegmentHead`. Removing data
while retaining the head is refused by existing linkage or count checks.
Removing data and honestly rebuilding a shorter closed segment is refused by
the external count or terminal hash. Substituting another segment, genesis, or
head is refused by a typed mismatch.

`verify_audit_chain` remains available for open segments. Its documentation
and CLI output must call that mode `integrity only`; the mere presence of a
locally stored segment head does not turn it into a trusted completeness input.

## 6. Trust and rollback boundary

Trust is external to the ledger being verified. The expected commitment, or
its digest, must come from a channel the caller trusts independently of the
records under test. Examples include pinned deployment configuration, a
separately administered transparency system, or an authenticated remote
witness. Choosing and operating that channel belongs to the caller.

A commitment stored in the same database, directory, snapshot, backup, or
rollback domain as the ledger is useful internal consistency metadata but is
not a freshness authority. An attacker or restore operation that rolls back
both the records and that commitment can still present a mutually consistent
older state. Neither the library nor CLI may describe such a check as rollback
resistant.

The 0.1.1 claim is therefore precise: given an independently trusted expected
head, the new verifier rejects a presented valid prefix or substituted chain.
It does not prove that a caller obtained the latest head, that a head was
durably witnessed, or that two external witnesses agree.

## 7. CLI contract

### 7.1 Record chains

The complete form is:

```text
attest-ledger verify <CHAIN.jsonl> --anchor <ANCHOR.json> \
  --head <HEAD.json> [--require-signed] [--require-head]
```

`--head` reads one `HeadCommitmentV1` JSON document and requires `--anchor`.
With both present the CLI calls `verify_chain_with_head`. `--require-head`
requires both `--head` and `--anchor`; if either is absent, the CLI returns exit
1 before reading or verifying the chain and writes:

```text
--require-head was set but --head and --anchor were not both supplied: cannot verify record-chain completeness
```

Supplying `--head` without `--anchor` also returns exit 1 with:

```text
--head was supplied without --anchor: a record-chain head must bind a verified signed anchor
```

`--require-head` never falls back to `verify_chain` or
`verify_chain_with_anchor`. Without `--head`, existing verification behavior
and `--require-signed` behavior remain, but the success line ends with
`integrity only (no trusted head supplied)`. With a complete check it ends with
`trusted head matched`. A read, parse, integrity, or head mismatch returns exit
1 and begins `chain INVALID:`. Command-line syntax errors produced by clap
remain exit 2. Success remains exit 0.

### 7.2 Audit segments

The complete form is:

```text
attest-ledger verify-audit <SEGMENT.jsonl> --head <HEAD.json> \
  [--genesis <HASH>] [--require-head]
```

With `--head`, the CLI parses `HeadCommitmentV1`. If `--genesis` is present it
is the `expected_genesis` argument. Otherwise the commitment's
`anchor_identity` is that argument. The complete verifier still compares it
back to the commitment. With `--require-head` and no `--head`, the CLI returns
exit 1 before verification and writes:

```text
--require-head was set but no --head was supplied: cannot verify closed audit-segment completeness
```

`--require-head` never runs the open verifier. Without `--head`, the existing
`verify_audit_chain` path remains and the success line ends with
`integrity only (no trusted head supplied)`, even if the final local record
looks like a segment head. Complete success ends with `trusted head matched`.
Audit read, parse, integrity, or head mismatch returns exit 1 and begins
`audit segment INVALID:`. Syntax errors remain exit 2; success remains exit 0.

## 8. Functional requirements and acceptance

### 8.1 Required behavior

- **FR-001.** Existing verifiers remain source-compatible and integrity-only.
- **FR-002.** Canonical commitment bytes and both digest helpers are stable
  across JSON object insertion order and platforms.
- **FR-003.** Record completeness verification rejects a valid proper prefix,
  wrong schema, wrong kind, wrong chain, wrong anchor, wrong count, and wrong
  terminal hash with the typed variants in section 4.
- **FR-004.** Closed audit verification rejects a missing trailing head, data
  removed before the head, wrong segment, wrong genesis, wrong count, and
  wrong terminal head hash with the typed variants in section 5 or a wrapped
  existing integrity error where that check runs first.
- **FR-005.** Required-head CLI modes cannot silently downgrade and return the
  exact exit codes and diagnostic prefixes in section 7.
- **FR-006.** README and rustdoc distinguish integrity, completeness, external
  freshness authority, and rollback resistance.
- **FR-007.** All three crates and their internal requirements agree on 0.1.1.
- **FR-008.** A fresh registry-only consumer proves the published behavior with
  no path, Git, or Cargo patch override.

### 8.2 Future implementation commands

After ratification and implementation, run these repository gates separately:

```sh
cargo fmt --all --check
cargo clippy --all-targets --locked -- -D warnings
cargo build --workspace --locked
cargo test --workspace --locked
cargo test -p attest-ledger-core --test head_commitment --locked
cargo test -p attest-ledger-cli --test head_commitment_cli --locked
```

The focused core test must independently assert clean record and audit success,
one-of-two record-tail deletion, missing audit head, audit data removal, wrong
schema, wrong kind, wrong count, wrong terminal hash, wrong chain identity,
wrong record anchor, and wrong audit genesis. The CLI test must cover both
commands with and without a trusted head, `--require-head` with missing inputs,
no downgrade, malformed commitment input, mismatch exit 1, syntax exit 2, and
success exit 0.

Check versions and package contents before tagging:

```sh
cargo metadata --no-deps --format-version 1 \
  | jq -e '[.packages[] | select(.name | startswith("attest-ledger-")) | .version] == ["0.1.1", "0.1.1", "0.1.1"]'
cargo package --locked --list -p attest-ledger-types
cargo package --locked --list -p attest-ledger-core
cargo package --locked --list -p attest-ledger-cli
cargo package --locked --no-verify -p attest-ledger-types
cargo package --locked --no-verify -p attest-ledger-core
cargo package --locked --no-verify -p attest-ledger-cli
```

The lists must contain the public source, README, license and manifest required
by each package, and must not contain tests, credentials, worktree state, or
session artifacts. Inspect each generated manifest and require internal
dependencies `attest-ledger-types = "0.1.1"` and
`attest-ledger-core = "0.1.1"` where applicable.

Check release workflow and tag-to-version agreement without publishing:

```sh
test "$(grep -m1 '^version = ' Cargo.toml | tr -d '" ' | cut -d= -f2)" = "0.1.1"
rg -n 'Publish attest-ledger-types|Publish attest-ledger-core|Publish attest-ledger-cli' .github/workflows/release.yml
test "$(git tag --points-at HEAD --list 'v0.1.1')" = "v0.1.1"
git tag -v v0.1.1
```

The workflow review must confirm tag `vX.Y.Z` gating, exact tag-to-workspace
version refusal, and publication in `types`, `core`, `cli` dependency order.
The last two tag commands run only after the owner-authorized signed tag exists.

Check authored content for credential material and prohibited session links:

```sh
session_host='https://Codex.ai/code/'
session_path='session_'
session_trailer='Codex-'"Session:"
! git grep -nF -e "${session_host}${session_path}" -e "$session_trailer"
! git grep -nE -- '-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{20,}'
```

The literal workflow reference `${{ secrets.CARGO_REGISTRY_TOKEN }}` is a
secret name, not a value, and remains permitted. No check reads the secret.

### 8.3 Registry-only consumer qualification

After all three 0.1.1 packages are visible on crates.io, create a new temporary
binary outside this repository with only these dependency forms:

```toml
[dependencies]
attest-ledger-types = "=0.1.1"
attest-ledger-core = "=0.1.1"
serde_json = "1"
```

Its manifest and resolved metadata must contain no `path`, `git`, or
`[patch.crates-io]` entry. Run the committed fixture only after all three
packages are visible, using these exact commands from the repository root:

```sh
consumer_dir="$(mktemp -d "${TMPDIR:-/tmp}/attest-ledger-0.1.1-consumer.XXXXXX")"
consumer_cargo_home="$(mktemp -d "${TMPDIR:-/tmp}/attest-ledger-0.1.1-cargo-home.XXXXXX")"
cp -R tests/registry-consumer/. "$consumer_dir/"
! rg -n '(^|[[:space:]])(path|git)[[:space:]]*=|\[patch\.crates-io\]' "$consumer_dir/Cargo.toml"
CARGO_HOME="$consumer_cargo_home" cargo generate-lockfile --manifest-path "$consumer_dir/Cargo.toml"
CARGO_HOME="$consumer_cargo_home" cargo metadata --locked --format-version 1 \
  --manifest-path "$consumer_dir/Cargo.toml" > "$consumer_dir/metadata.json"
jq -e '[.packages[] | select(.name == "attest-ledger-types" or .name == "attest-ledger-core") | .source] | length == 2 and all(. == "registry+https://github.com/rust-lang/crates.io-index")' "$consumer_dir/metadata.json"
CARGO_HOME="$consumer_cargo_home" cargo run --locked --manifest-path "$consumer_dir/Cargo.toml"
```

Do not delete either temporary directory until its evidence has been retained.
The consumer program must exit successfully only after asserting:

1. clean two-record verification against a trusted head succeeds;
2. the one-record prefix returns `RecordCountMismatch`;
3. a clean closed audit segment succeeds;
4. removing its trailing audit head returns `MissingSegmentHead`;
5. wrong count returns `RecordCountMismatch`;
6. wrong terminal hash returns `TerminalHashMismatch`;
7. another chain returns `ChainIdentityMismatch`;
8. another signed anchor returns `AnchorIdentityMismatch`;
9. another audit genesis is refused.

Retain the consumer `Cargo.toml`, lockfile, source, metadata, stdout, stderr,
package checksums, and command transcript as release evidence outside Git.
This is consumer qualification, not merely package publication.

## 9. Release contract

The target is an additive 0.1.1 release of `attest-ledger-types`,
`attest-ledger-core`, and `attest-ledger-cli`. The release sequence is fixed:

1. Bart ratifies this spec in a separate owner action.
2. A later implementation unit changes only the claimed units, sets the
   workspace and internal crate dependency versions to 0.1.1, and passes
   section 8 acceptance.
3. Review, repository gates, and pull-request CI pass. The implementation is
   merged before any release identity is created.
4. Under the recorded public-release authority, create and locally verify a
   signed annotated `v0.1.1` tag at the exact merged commit, then push that tag.
5. The existing release workflow verifies tag-to-version agreement, publishes
   `attest-ledger-types`, then `attest-ledger-core`, then
   `attest-ledger-cli`, and creates the non-draft, non-prerelease GitHub
   release only after publication succeeds.
6. Verify the tag signature, peeled commit, GitHub release, successful release
   run, crates.io checksums and non-yanked state. Then run the fresh
   registry-only consumer proof in section 8.3.

Passing local tests or CI is not publication. A GitHub release is not crates.io
publication. Publication is not registry-only consumer qualification. A
failed or partial release is reported as such and is not rerun merely to turn
the same identity into apparent success.

## 10. Downstream and lifecycle boundaries

Rahi adoption is downstream and separate. This spec does not modify Rahi,
promise Rahi 0.4.1, change travel-memory dependencies, or claim that local Rahi
accounting is an external freshness witness. In particular, it does not claim
protection when ledger data and its local accounting or commitment are rolled
back together. Rahi needs its own ratified storage contract before it can
adopt and operate an external head authority.

This draft grants no authority to implement, approve, merge, tag, publish, or
release. Bart's ratification is the next action. The recorded public-release
authority applies only after ratification, implementation, acceptance, review,
repository gates, and CI have all passed.

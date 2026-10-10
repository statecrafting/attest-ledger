---
id: "002-pinned-trust-roots"
title: "Pinned trust roots for anchor verification"
status: approved
created: "2026-10-07"
authors: ["attest-ledger"]
kind: tooling
implementation: complete
risk: high
summary: >
  The released anchor verifier checks a chain anchor's Ed25519 signature
  against the public key the anchor itself carries, so anyone can mint a
  self-consistent chain. That proves integrity, not authorship. Add a pinned
  trust-root input: a canonical, digestible set of accepted Ed25519 keys, each
  with a key id derived from its bytes and an optional chain-id scope, and
  root-pinned variants of the anchor, anchor-chain and head verifiers that
  pass only when the anchor's key is pinned, in scope, and produced a
  signature that verifies under strict Ed25519 rules. Add the matching CLI
  input and exit code. Existing APIs, hashes, signatures, head commitments and
  CLI stdout and exit codes are unchanged. Release as an additive 0.2.0.
depends_on:
  - "000-attest-ledger-bootstrap"
  - "001-tail-completeness-and-head-commitment"
establishes:
  - { kind: file, path: "crates/types/src/trust_roots.rs" }
  - { kind: file, path: "crates/core/src/trust_roots.rs" }
  - { kind: file, path: "crates/cli/tests/trust_roots_cli.rs" }
  - { kind: symbol, id: "attest_ledger_types::trust_roots::TrustRootsV1" }
  - { kind: symbol, id: "attest_ledger_core::trust_roots::verify_anchor_with_roots" }
extends:
  - { spec: "000-attest-ledger-bootstrap", unit: { kind: section, file: "Cargo.toml", anchor: "workspace.package" }, nature: additive }
  - { spec: "000-attest-ledger-bootstrap", unit: { kind: section, file: "Cargo.toml", anchor: "workspace.dependencies" }, nature: additive }
  - { spec: "000-attest-ledger-bootstrap", unit: "Cargo.lock", nature: additive }
  - { spec: "000-attest-ledger-bootstrap", unit: "crates/types/src/lib.rs", nature: additive }
  - { spec: "000-attest-ledger-bootstrap", unit: "crates/core/src/lib.rs", nature: additive }
  - { spec: "000-attest-ledger-bootstrap", unit: "crates/core/src/signing.rs", nature: corrective }
  - { spec: "000-attest-ledger-bootstrap", unit: "crates/core/src/record_chain.rs", nature: corrective }
  - { spec: "000-attest-ledger-bootstrap", unit: "crates/cli/Cargo.toml", nature: additive }
  - { spec: "000-attest-ledger-bootstrap", unit: "crates/cli/src/main.rs", nature: additive }
  - { spec: "000-attest-ledger-bootstrap", unit: "README.md", nature: corrective }
  - { spec: "000-attest-ledger-bootstrap", unit: "CHANGELOG.md", nature: additive }
  - { spec: "000-attest-ledger-bootstrap", unit: "spec-spine.toml", nature: additive }
references:
  - { unit: { kind: file, path: ".github/workflows/release.yml" }, role: constraint }
---

# 002: Pinned trust roots for anchor verification

Ratified by Bart on 2026-10-07, together with the implementation in the same
pull request and its merge. Ratification does not authorize a tag, a GitHub
release or a crates.io publication (section 9).

## 1. Purpose

`verify_anchor` checks `ChainAnchor.genesis_signature` against
`ChainAnchor.genesis_public_key`, the key embedded in the anchor. A producer
who rewrites a chain can generate a fresh key, re-sign the anchor with it, and
pass. The check proves that the anchor was not altered after signing. It does
not prove who signed it, so it is not a trust root, although spec 000 section
1 and the 0.1.x rustdoc describe it as one.

This spec makes authorship a verifier decision. The verifier supplies a set of
keys it accepts, pinned independently of the chain under test, and the
root-pinned verifiers refuse an anchor signed by any other key.

This is step 1 of a larger direction (bringing attest-ledger closer to the
evidence DAG in `statecraft-envelope` while keeping the two chains separate).
Later steps are out of scope here: per-entry domain-separated signatures,
multi-parent linking, head commitments generic over codec and hash, and a
generic DAG module. Section 7 records what this step leaves room for.

## 2. Scope, compatibility, and claimed units

The change is additive. These keep their signatures, semantics, and output
bytes exactly:

- `sign_anchor`, `verify_anchor`, `verify_chain`, `verify_chain_with_anchor`,
  `verify_chain_with_head`, `compute_record_hash`, `sha256_hex`,
  `chain_anchor_identity`, `head_commitment_digest`, and both audit verifiers;
- the anchor signing preimage (the anchor with `genesis_signature` zeroed,
  canonical key-sorted JSON), so every 0.1.x anchor verifies under pinned
  roots once its key is pinned, with no re-signing;
- `VerifyError`, `HeadVerifyError`, `AuditVerifyError` and
  `AuditHeadVerifyError`, which gain no variants;
- CLI stdout and exit codes for every 0.1.1 invocation.

The one observable CLI change for an existing invocation is a new stderr note
(section 5.2).

| Unit | Change |
|---|---|
| `attest_ledger_types::trust_roots` | `TrustRootsV1`, `TrustRootV1`, the two constants, `TrustRootsError`, `AnchorField`, `RootVerifyError`. |
| `attest_ledger_core::trust_roots` | Key-id derivation, construction, validation, canonical bytes, digest, the three root-pinned verifiers, and their unit tests and golden vectors. |
| `crates/types/src/lib.rs`, `crates/core/src/lib.rs` | Export the new items; correct the crate doc's trust-root claim. |
| `crates/core/src/signing.rs` | Document `verify_anchor` as self-attesting; expose the existing preimage function within the crate. No behaviour change. |
| `crates/core/src/record_chain.rs` | Correct `verify_chain_with_anchor`'s documentation. No behaviour change. |
| `crates/cli/src/main.rs` | `--roots`, `--roots-digest`, `--require-roots`, the stderr note, and exit 3. |
| `crates/cli/tests/trust_roots_cli.rs` | CLI behaviour and exit codes in section 5. |
| `crates/cli/Cargo.toml` | `ed25519-dalek` as a dev dependency for the CLI test. |
| `Cargo.toml`, `Cargo.lock` | Workspace and internal requirements at 0.2.0. |
| `README.md`, `CHANGELOG.md` | Document the trust model, the CLI, the exit codes, and the 0.2.0 entry. |
| `spec-spine.toml` | Add `crates/cli/tests/trust_roots_cli.rs` to `[lint] unwitnessed_allowed`. |

The two new source modules are witnessed through symbol claims. The CLI
integration test lives under `tests/`, which spec-spine's symbol index does
not read, so, like spec 001's `head_commitment_cli.rs`, it is a whole-file
claim on the unwitnessed allowlist. The owner decides at ratification whether
to accept that entry or require a different witness.

`attest-ledger-types` stays serde-only: it holds the shapes, and everything
that hashes or touches Ed25519 is in core, as with `HeadCommitmentV1`.

## 3. The trust-root set

### 3.1 Wire shape

```rust
pub const TRUST_ROOTS_SCHEMA_V1: &str = "attest-ledger/trust-roots/v1";
pub const TRUST_ROOT_ALGORITHM_ED25519: &str = "ed25519";

#[serde(deny_unknown_fields)]
pub struct TrustRootsV1 {
    pub schema_identity: String,
    pub roots: Vec<TrustRootV1>,
}

#[serde(deny_unknown_fields)]
pub struct TrustRootV1 {
    pub key_id: String,
    pub algorithm: String,
    pub public_key: String,              // base64, 32 bytes
    pub chain_ids: Option<Vec<String>>,  // absent: any chain id
}
```

`public_key` uses the same base64 encoding as `ChainAnchor.genesis_public_key`.
`chain_ids`, when absent, is omitted from the serialized form.

### 3.2 Key id

`key_id` is `sha256:<lower-case hex>` over the bytes

```text
"attest-ledger/key-id/v1" || 0x0A || "ed25519" || 0x0A || public key (32 bytes)
```

The domain prefix keeps a key id from ever equalling a record, anchor,
commitment or root-set hash this crate computes, and naming the algorithm
leaves room for another key type without a collision. A verifier always
recomputes the key id; the stored one is there so a pin is readable.

### 3.3 Validity and canonical form

A set is valid only if, in this order of checks:

1. `schema_identity` is exactly `TRUST_ROOTS_SCHEMA_V1`;
2. `roots` is non-empty;
3. for each entry: `algorithm` is `ed25519`; `public_key` decodes to 32 bytes
   that are a valid Ed25519 point; the key is not weak (small order); `key_id`
   equals its recomputation; the entry's `key_id` is strictly greater than the
   previous entry's; and `chain_ids`, if present, is non-empty, holds no empty
   string, and is strictly ascending.

Strict ordering makes duplicates invalid and gives one logical set exactly one
encoding. A non-canonical set is refused rather than normalized, so the digest
a deployment pinned is the digest of the set that was used.

`build_trust_roots(entries)` is the pure constructor. It takes
`(VerifyingKey, Option<Vec<String>>)` pairs, derives key ids, sorts entries by
key id, sorts and de-duplicates each scope, refuses a repeated key, an empty
scope, an empty chain id or a weak key, and returns a set that passes
validation. It reads no environment, clock or network.

### 3.4 Canonical bytes and digest

`trust_roots_canonical_bytes` serializes the set to `serde_json::Value`, then
with `canonical_keysort_json::to_canonical_string`, and takes the UTF-8 bytes
with no trailing newline. `trust_roots_digest` is `sha256_hex` over those bytes.
A consumer pins a root set by this digest. Golden vectors for two fixed keys
pin the key ids, the canonical string and the digest, cross-checked by an
independent SHA-256.

### 3.5 Errors

```rust
#[non_exhaustive]
pub enum TrustRootsError {
    UnsupportedSchema { expected: String, found: String },
    EmptySet,
    UnsupportedAlgorithm { index: usize, found: String },
    MalformedPublicKey { index: usize },
    WeakPublicKey { index: usize },
    KeyIdMismatch { index: usize, expected: String, found: String },
    NotCanonicalOrder { index: usize },
    EmptyScope { index: usize },
    NotCanonicalScope { index: usize },
}
```

## 4. Root-pinned verification

### 4.1 Functions

```rust
pub fn verify_anchor_with_roots(
    anchor: &ChainAnchor, roots: &TrustRootsV1,
) -> Result<String, RootVerifyError>;

pub fn verify_chain_with_anchor_and_roots(
    anchor: &ChainAnchor, records: &[LedgerRecord], roots: &TrustRootsV1,
) -> Result<String, RootVerifyError>;

pub fn verify_chain_with_head_and_roots(
    anchor: &ChainAnchor, records: &[LedgerRecord],
    expected_head: &HeadCommitmentV1, roots: &TrustRootsV1,
) -> Result<String, RootVerifyError>;
```

Each returns the key id of the root that authenticated the anchor.

### 4.2 Order of checks

`verify_anchor_with_roots` runs, stopping at the first failure:

1. the root set is valid (section 3.3), else `InvalidRoots`;
2. `genesis_public_key`, then `genesis_signature`, is non-empty, else
   `Unsigned { field }`;
3. `genesis_public_key` decodes to 32 bytes, else
   `MalformedAnchor { field: GenesisPublicKey }`;
4. those bytes equal a pinned root's key, else `UnknownKey { key_id }`;
5. that root is unscoped, or its `chain_ids` contains `anchor.chain_id`, else
   `OutOfScope { key_id, chain_id }`;
6. `genesis_signature` decodes to 64 bytes, else
   `MalformedAnchor { field: GenesisSignature }`;
7. the signature's `S` is below the group order, and the signature verifies
   with `verify_strict` over the existing anchor preimage, else
   `BadSignature { key_id }`.

The chain variants authenticate the anchor first, then run the existing
`verify_chain_with_anchor` or `verify_chain_with_head`, wrapping a failure as
`Chain(VerifyError)` or `Head(HeadVerifyError)`. No record is read before the
anchor is authenticated.

```rust
#[non_exhaustive]
pub enum RootVerifyError {
    InvalidRoots(TrustRootsError),
    Unsigned { field: AnchorField },
    MalformedAnchor { field: AnchorField },
    UnknownKey { key_id: String },
    OutOfScope { key_id: String, chain_id: String },
    BadSignature { key_id: String },
    Chain(VerifyError),
    Head(HeadVerifyError),
}
```

`RootVerifyError::is_authorisation_refusal` is true for `Unsigned`,
`UnknownKey` and `OutOfScope`: refusals that say the key is not authorised,
not that anything was altered.

### 4.3 Strict Ed25519 only

Root-pinned verification uses `VerifyingKey::verify_strict`, refuses weak
root keys, and checks itself that `S` is canonical. Non-strict verification
accepts a small-order public key or `R` component. With a small-order key, one
signature verifies for many messages, so a root that holds such a key
authorizes bytes nobody signed. `ed25519-dalek` rejects a non-canonical `S` by
default, but its `legacy_compatibility` feature, which Cargo feature
unification can switch on from anywhere in a consumer's build, relaxes that
for both `verify` and `verify_strict`. A malleable signature lets two
different encodings authenticate one anchor. The explicit check keeps the
refusal independent of the build. A trust-root decision that can pass for
bytes the key holder never signed is not a trust-root decision, and two
verifiers that disagree on one signature cannot both be the authority.
`ed25519-dalek` signing always produces strict-valid signatures, so every
honest 0.1.x anchor passes. The legacy `verify_anchor` keeps its existing
non-strict check, unchanged.

## 5. CLI contract

### 5.1 Root-pinned verification

```text
attest-ledger verify <CHAIN.jsonl> --anchor <ANCHOR.json> --roots <ROOTS.json> \
  [--roots-digest <sha256:...>] [--head <HEAD.json>] [--require-roots] [--require-head]
```

`--roots` reads one `TrustRootsV1` and requires `--anchor`. The set is
validated, and compared with `--roots-digest` when given, before any chain is
verified. `--roots-digest` without `--roots` is a syntax error.
`--require-roots` without `--roots` refuses before reading anything. With
`--head`, the CLI calls `verify_chain_with_head_and_roots`; otherwise
`verify_chain_with_anchor_and_roots`.

Success writes to stdout:

```text
chain VERIFIED: <n> record(s), anchor signature valid, signer authenticated by pinned root <key_id> (roots <digest>), <tail>
```

where `<tail>` is `trusted head matched` or
`integrity only (no trusted head supplied)`.

When the roots refuse the signer as not authorised (`Unsigned`, `UnknownKey`
or `OutOfScope`), the CLI also runs the embedded-key verifier the same
invocation would have run without `--roots`. If that passes, it writes
`chain NOT AUTHENTICATED: <n> record(s) intact under the anchor's embedded key only: ...`
to stderr and exits 3. Otherwise it reports `chain INVALID:` and exits 1, so
tampering is never reported as a mere authorisation gap. An unsigned anchor
fails the embedded-key verifier and therefore exits 1.

### 5.2 Without roots

Without `--roots`, `verify` keeps its 0.1.1 stdout and exit codes. When
`--anchor` is supplied and the chain verifies, it also writes to stderr:

```text
note: the anchor was verified against its embedded key only (integrity, not authenticity); pass --roots to authenticate its signer
```

### 5.3 Exit codes

| Exit | Meaning |
|---|---|
| 0 | Verified. Authenticated when `--roots` was supplied; otherwise integrity only, as in 0.1.1. |
| 1 | Invalid input, failed integrity or head check, bad or malformed signature, invalid root set, digest mismatch, unreadable input, or a missing required input. |
| 2 | Command-line syntax error (clap). |
| 3 | `--roots` only: intact under the anchor's embedded key, but the roots do not authorise that key. |

A caller who needs authentication passes `--roots` and treats only exit 0 as
success; `--require-roots` makes a configuration that forgot `--roots` fail.
`verify-audit` has no anchor and takes no roots.

## 6. Deprecation decision

`verify_anchor` is not marked `#[deprecated]` in 0.2.0. Rahi, the main
downstream, runs `cargo clippy --workspace --all-targets --locked -- -D warnings`
with no allowance for the `deprecated` lint, so its gate does not tolerate
deprecation warnings. Rahi does not call `verify_anchor` today, so the
attribute would not break it now, but the condition for deprecating was that
downstream gates tolerate it, and they do not. `verify_chain_with_anchor` and
the approved `verify_chain_with_head` also call `verify_anchor` and are equally
self-attesting; deprecating one of the three alone would be inconsistent.
Rustdoc and the README describe all of them as integrity-only and point to the
root-pinned variants. Deprecation can be reconsidered in a later minor once
downstream gates allow it.

## 7. Room for later steps

- Key ids name their algorithm in the preimage, and the root schema is
  versioned, so another key type or a per-key domain scope (chain kind, format
  id) can be added as a new schema without changing v1 digests.
- The anchor preimage is unchanged here. A later step can introduce a
  domain-separated preimage carrying a chain-kind marker and a format id
  (for example `attest-ledger/<chain-kind>/<format-id>`), selected by an
  explicit anchor version, and verify it against the same `TrustRootsV1`.
  `RootVerifyError` and `TrustRootsError` are `#[non_exhaustive]` so such
  refusals can be added without a breaking release.
- The root set is a pin, not an issuer history. Rotation, revocation and
  validity windows (as in `statecraft-envelope`'s `RootSetV2`) are out of
  scope; a deployment rotates by pinning a new set and digest.

## 8. Functional requirements and acceptance

- **FR-001.** Every unchanged API in section 2 keeps its output bytes. A test
  pins record hashes, anchor public key and signature, anchor identity and
  head digest to values produced by the published `attest-ledger-core =0.1.1`
  for the same inputs, and authenticates that 0.1.1-signed anchor under pinned
  roots.
- **FR-002.** Each `RootVerifyError` variant and each `TrustRootsError`
  variant is produced by a unit test.
- **FR-003.** Across 64 seeded cases, a chain re-signed with a non-root key
  passes `verify_anchor` and `verify_chain_with_anchor` and is refused by
  `verify_chain_with_anchor_and_roots` with `UnknownKey`.
- **FR-004.** A signature malleated by adding the group order to `S` is
  refused with `BadSignature` by the explicit canonical-`S` check, and that
  check's boundary is unit tested.
- **FR-005.** Golden vectors pin the key ids, canonical form and digest of a
  fixed two-key set, and the canonical form round-trips.
- **FR-006.** The CLI tests cover exit 0 with and without a head, exit 3 for
  an unknown and an out-of-scope signer, exit 1 for tampering under an
  unpinned signer, a bad signature, an invalid set and a digest mismatch, the
  refusals before reading, exit 2 for `--roots-digest` alone, and unchanged
  stdout plus the stderr note without `--roots`.
- **FR-007.** All three crates and internal requirements are 0.2.0.

Run the repository gates:

```sh
make gate
make code
```

`make code` runs build, test, clippy with `-D warnings` and fmt check.

## 9. Release boundary

This spec does not authorize a tag, a GitHub release or a crates.io
publication. Publication of 0.2.0 needs a separate owner instruction after
ratification and merge, following the release sequence in spec 001 section 9.

## 10. Verifier trust policy (2026-10-10)

Adopted by the owner on 2026-10-10. This section records deployment policy;
it changes no requirement in sections 1 to 9.

Pinned trust roots are required wherever the verifier is not the signer:
receipts verified by another party, exported or backed-up chains, and anything
that crosses a repository or tenant boundary. Those callers use the
root-pinned verifiers in section 4, or `verify --roots` in section 5.1, and
treat only exit 0 as success.

The self-attesting `verify_anchor` and `verify_chain_with_anchor` (and, per
section 6, `verify_chain_with_head`) stay supported for local integrity only.
Documentation labels them "integrity only".

## 11. Decision entries

### 2026-10-10: "integrity only" output label conflicts with section 5 (open)

The 2026-10-10 policy requires the self-attesting verifiers to be labelled
"integrity only" in output as well as in docs. The approved CLI contract does
not allow that label in every self-attesting path without a requirement change:

- `verify --anchor <A> --head <H>` without `--roots` prints
  `chain VERIFIED: <n> record(s), anchor signature valid, trusted head matched`.
  Section 2 freezes 0.1.1 stdout for this invocation, so "integrity only"
  cannot be added there.
- The stderr note for that path and for `--anchor` alone is fixed verbatim in
  section 5.2 and reads "(integrity, not authenticity)", not "integrity only".
- `verify --anchor <A>` without `--head` already prints "integrity only", but
  as the no-trusted-head tail, not as a label on the anchor check.

Options for the owner:

1. Accept the section 5.2 stderr note as the output label, and release 0.2.0
   with the contract unchanged.
2. Amend section 5.2 so the note reads "integrity only" (stderr only; stdout
   and exit codes stay as section 2 requires), implement it, and release.
3. Amend section 2 to allow a stdout change in the self-attesting paths, which
   breaks the 0.1.1 stdout guarantee for existing callers.

Until the owner chooses, the 0.2.0 release (section 9) is held.

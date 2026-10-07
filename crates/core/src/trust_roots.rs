//! Root-pinned anchor verification.
//!
//! [`verify_anchor`](crate::verify_anchor) checks an anchor's signature against
//! the key the anchor itself carries, so anyone can mint a self-consistent
//! chain: it proves integrity, not authorship. The verifiers here take a
//! [`TrustRootsV1`] the caller pins, and pass only when the anchor's key is in
//! that set, is in scope for the anchor's `chain_id`, and produced a signature
//! that verifies under strict Ed25519 rules.
//!
//! The signed bytes are the existing anchor preimage, unchanged, so every
//! anchor signed by 0.1.x verifies here once its key is pinned.

use attest_ledger_types::{
    AnchorField, ChainAnchor, HeadCommitmentV1, LedgerRecord, RootVerifyError,
    TRUST_ROOT_ALGORITHM_ED25519, TRUST_ROOTS_SCHEMA_V1, TrustRootV1, TrustRootsError,
    TrustRootsV1,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use ed25519_dalek::{Signature, VerifyingKey};

use crate::{sha256_hex, signing, verify_chain_with_anchor, verify_chain_with_head};

/// Domain separator for key ids, so a key id can never collide with a record,
/// anchor, commitment or root-set hash computed by this crate.
pub const TRUST_ROOT_KEY_ID_DOMAIN_V1: &str = "attest-ledger/key-id/v1";

/// The stable key id of an Ed25519 public key: `sha256:<hex>` over
/// `TRUST_ROOT_KEY_ID_DOMAIN_V1 || 0x0A || "ed25519" || 0x0A || key bytes`.
pub fn trust_root_key_id(key: &VerifyingKey) -> String {
    key_id_of(key.as_bytes())
}

fn key_id_of(key_bytes: &[u8; 32]) -> String {
    let mut preimage = Vec::with_capacity(TRUST_ROOT_KEY_ID_DOMAIN_V1.len() + 9 + 32);
    preimage.extend_from_slice(TRUST_ROOT_KEY_ID_DOMAIN_V1.as_bytes());
    preimage.push(b'\n');
    preimage.extend_from_slice(TRUST_ROOT_ALGORITHM_ED25519.as_bytes());
    preimage.push(b'\n');
    preimage.extend_from_slice(key_bytes);
    sha256_hex(&preimage)
}

/// Build a canonical v1 root set from keys and optional chain-id scopes.
///
/// Pure: no environment, clock or network read. Entries are ordered by key id
/// and each scope is sorted and de-duplicated. The same key given twice, an
/// empty scope, an empty chain id, or a weak key is refused.
pub fn build_trust_roots<I>(entries: I) -> Result<TrustRootsV1, TrustRootsError>
where
    I: IntoIterator<Item = (VerifyingKey, Option<Vec<String>>)>,
{
    let mut roots = Vec::new();
    for (index, (key, scope)) in entries.into_iter().enumerate() {
        if key.is_weak() {
            return Err(TrustRootsError::WeakPublicKey { index });
        }
        let chain_ids = match scope {
            None => None,
            Some(mut ids) => {
                if ids.is_empty() {
                    return Err(TrustRootsError::EmptyScope { index });
                }
                if ids.iter().any(String::is_empty) {
                    return Err(TrustRootsError::NotCanonicalScope { index });
                }
                ids.sort();
                ids.dedup();
                Some(ids)
            }
        };
        roots.push(TrustRootV1 {
            key_id: trust_root_key_id(&key),
            algorithm: TRUST_ROOT_ALGORITHM_ED25519.to_owned(),
            public_key: B64.encode(key.as_bytes()),
            chain_ids,
        });
    }
    roots.sort_by(|a, b| a.key_id.cmp(&b.key_id));
    let set = TrustRootsV1 {
        schema_identity: TRUST_ROOTS_SCHEMA_V1.to_owned(),
        roots,
    };
    validate_trust_roots(&set)?;
    Ok(set)
}

/// Check that `roots` is a valid canonical v1 set. Every root-pinned verifier
/// runs this first, so a hand-written or altered set fails closed.
pub fn validate_trust_roots(roots: &TrustRootsV1) -> Result<(), TrustRootsError> {
    validated_keys(roots).map(|_| ())
}

fn validated_keys(roots: &TrustRootsV1) -> Result<Vec<[u8; 32]>, TrustRootsError> {
    if roots.schema_identity != TRUST_ROOTS_SCHEMA_V1 {
        return Err(TrustRootsError::UnsupportedSchema {
            expected: TRUST_ROOTS_SCHEMA_V1.to_owned(),
            found: roots.schema_identity.clone(),
        });
    }
    if roots.roots.is_empty() {
        return Err(TrustRootsError::EmptySet);
    }
    let mut keys = Vec::with_capacity(roots.roots.len());
    for (index, root) in roots.roots.iter().enumerate() {
        if root.algorithm != TRUST_ROOT_ALGORITHM_ED25519 {
            return Err(TrustRootsError::UnsupportedAlgorithm {
                index,
                found: root.algorithm.clone(),
            });
        }
        let bytes = decode_fixed::<32>(&root.public_key)
            .ok_or(TrustRootsError::MalformedPublicKey { index })?;
        let key = VerifyingKey::from_bytes(&bytes)
            .map_err(|_| TrustRootsError::MalformedPublicKey { index })?;
        if key.is_weak() {
            return Err(TrustRootsError::WeakPublicKey { index });
        }
        let expected = key_id_of(&bytes);
        if root.key_id != expected {
            return Err(TrustRootsError::KeyIdMismatch {
                index,
                expected,
                found: root.key_id.clone(),
            });
        }
        if index > 0 && roots.roots[index - 1].key_id >= root.key_id {
            return Err(TrustRootsError::NotCanonicalOrder { index });
        }
        if let Some(ids) = &root.chain_ids {
            if ids.is_empty() {
                return Err(TrustRootsError::EmptyScope { index });
            }
            if ids.iter().any(String::is_empty) || ids.windows(2).any(|w| w[0] >= w[1]) {
                return Err(TrustRootsError::NotCanonicalScope { index });
            }
        }
        keys.push(bytes);
    }
    Ok(keys)
}

/// The canonical UTF-8 bytes of a root set: its JSON value serialized by
/// `canonical_keysort_json`, with no trailing newline.
pub fn trust_roots_canonical_bytes(roots: &TrustRootsV1) -> Vec<u8> {
    canonical_keysort_json::to_canonical_string(
        &serde_json::to_value(roots).expect("trust roots serialise to JSON"),
    )
    .into_bytes()
}

/// `sha256:<hex>` over [`trust_roots_canonical_bytes`]: the value a consumer
/// pins to mean "this root set".
pub fn trust_roots_digest(roots: &TrustRootsV1) -> String {
    sha256_hex(&trust_roots_canonical_bytes(roots))
}

/// Authenticate `anchor` against pinned `roots`.
///
/// Checks, in order: the root set is valid; the anchor carries a key and a
/// signature; the key decodes; the key is pinned; the key is in scope for
/// `anchor.chain_id`; the signature decodes and verifies under
/// `verify_strict`. Returns the authenticating root's key id.
pub fn verify_anchor_with_roots(
    anchor: &ChainAnchor,
    roots: &TrustRootsV1,
) -> Result<String, RootVerifyError> {
    let keys = validated_keys(roots).map_err(RootVerifyError::InvalidRoots)?;
    if anchor.genesis_public_key.is_empty() {
        return Err(RootVerifyError::Unsigned {
            field: AnchorField::GenesisPublicKey,
        });
    }
    if anchor.genesis_signature.is_empty() {
        return Err(RootVerifyError::Unsigned {
            field: AnchorField::GenesisSignature,
        });
    }
    let key_bytes =
        decode_fixed::<32>(&anchor.genesis_public_key).ok_or(RootVerifyError::MalformedAnchor {
            field: AnchorField::GenesisPublicKey,
        })?;
    let key_id = key_id_of(&key_bytes);
    let Some(position) = keys.iter().position(|k| *k == key_bytes) else {
        return Err(RootVerifyError::UnknownKey { key_id });
    };
    if let Some(ids) = &roots.roots[position].chain_ids {
        if ids.binary_search(&anchor.chain_id).is_err() {
            return Err(RootVerifyError::OutOfScope {
                key_id,
                chain_id: anchor.chain_id.clone(),
            });
        }
    }
    let key = VerifyingKey::from_bytes(&key_bytes).expect("a validated root decodes");
    let sig_bytes =
        decode_fixed::<64>(&anchor.genesis_signature).ok_or(RootVerifyError::MalformedAnchor {
            field: AnchorField::GenesisSignature,
        })?;
    let bad_signature = || RootVerifyError::BadSignature {
        key_id: key_id.clone(),
    };
    // Refuse a non-canonical S here rather than rely on ed25519-dalek's
    // default, which a `legacy_compatibility` feature elsewhere in the build
    // would relax.
    let s: [u8; 32] = sig_bytes[32..].try_into().expect("64-byte signature");
    if !scalar_is_canonical(&s) {
        return Err(bad_signature());
    }
    let signature = Signature::from_bytes(&sig_bytes);
    key.verify_strict(signing::anchor_signing_bytes(anchor).as_bytes(), &signature)
        .map_err(|_| bad_signature())?;
    Ok(key_id)
}

/// [`verify_chain_with_anchor`] with the anchor authenticated against pinned
/// `roots` first. Returns the authenticating root's key id.
pub fn verify_chain_with_anchor_and_roots(
    anchor: &ChainAnchor,
    records: &[LedgerRecord],
    roots: &TrustRootsV1,
) -> Result<String, RootVerifyError> {
    let key_id = verify_anchor_with_roots(anchor, roots)?;
    verify_chain_with_anchor(anchor, records).map_err(RootVerifyError::Chain)?;
    Ok(key_id)
}

/// [`verify_chain_with_head`] with the anchor authenticated against pinned
/// `roots` first. Returns the authenticating root's key id.
pub fn verify_chain_with_head_and_roots(
    anchor: &ChainAnchor,
    records: &[LedgerRecord],
    expected_head: &HeadCommitmentV1,
    roots: &TrustRootsV1,
) -> Result<String, RootVerifyError> {
    let key_id = verify_anchor_with_roots(anchor, roots)?;
    verify_chain_with_head(anchor, records, expected_head).map_err(RootVerifyError::Head)?;
    Ok(key_id)
}

/// The Ed25519 group order L, little-endian.
const GROUP_ORDER: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

/// True when the little-endian scalar `s` is below the group order.
fn scalar_is_canonical(s: &[u8; 32]) -> bool {
    for i in (0..32).rev() {
        if s[i] != GROUP_ORDER[i] {
            return s[i] < GROUP_ORDER[i];
        }
    }
    false
}

fn decode_fixed<const N: usize>(b64: &str) -> Option<[u8; N]> {
    B64.decode(b64).ok()?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RecordChain, sign_anchor, verify_anchor};
    use attest_ledger_types::{GenesisAttestation, GenesisAttestationKind, VerifyError};
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    const ANCHOR_HASH: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn anchor(chain_id: &str, signer: &SigningKey) -> ChainAnchor {
        let mut a = ChainAnchor {
            chain_id: chain_id.into(),
            anchor_hash: ANCHOR_HASH.into(),
            genesis_timestamp: "2026-10-07T00:00:00Z".into(),
            genesis_public_key: String::new(),
            genesis_signature: String::new(),
            genesis_attestation: GenesisAttestation {
                kind: GenesisAttestationKind::Operator,
                note: None,
            },
        };
        sign_anchor(&mut a, signer);
        a
    }

    fn records(n: usize, salt: u64) -> Vec<LedgerRecord> {
        let mut chain = RecordChain::new(ANCHOR_HASH.into());
        (0..n)
            .map(|i| {
                chain.append(
                    format!("r{i}"),
                    format!("2026-10-07T00:00:{i:02}Z"),
                    json!({ "n": i, "salt": salt }),
                )
            })
            .collect()
    }

    fn roots_of(keys: &[(u8, Option<Vec<&str>>)]) -> TrustRootsV1 {
        build_trust_roots(keys.iter().map(|(seed, scope)| {
            (
                key(*seed).verifying_key(),
                scope
                    .as_ref()
                    .map(|ids| ids.iter().map(|s| s.to_string()).collect()),
            )
        }))
        .unwrap()
    }

    #[test]
    fn pinned_in_scope_key_authenticates() {
        let roots = roots_of(&[(1, Some(vec!["chain-a"])), (2, None)]);
        let a = anchor("chain-a", &key(1));
        let id = verify_anchor_with_roots(&a, &roots).unwrap();
        assert_eq!(id, trust_root_key_id(&key(1).verifying_key()));
        verify_chain_with_anchor_and_roots(&a, &records(3, 0), &roots).unwrap();
        // An unscoped root signs for any chain id.
        verify_anchor_with_roots(&anchor("anything", &key(2)), &roots).unwrap();
    }

    #[test]
    fn unsigned_anchor_names_the_empty_field() {
        let roots = roots_of(&[(1, None)]);
        let mut a = anchor("c", &key(1));
        a.genesis_signature.clear();
        assert_eq!(
            verify_anchor_with_roots(&a, &roots),
            Err(RootVerifyError::Unsigned {
                field: AnchorField::GenesisSignature
            })
        );
        a.genesis_public_key.clear();
        assert_eq!(
            verify_anchor_with_roots(&a, &roots),
            Err(RootVerifyError::Unsigned {
                field: AnchorField::GenesisPublicKey
            })
        );
    }

    #[test]
    fn malformed_anchor_fields_are_refused() {
        let roots = roots_of(&[(1, None)]);
        let mut a = anchor("c", &key(1));
        a.genesis_public_key = "not base64!".into();
        assert_eq!(
            verify_anchor_with_roots(&a, &roots),
            Err(RootVerifyError::MalformedAnchor {
                field: AnchorField::GenesisPublicKey
            })
        );
        let mut a = anchor("c", &key(1));
        a.genesis_signature = B64.encode([0u8; 10]);
        assert_eq!(
            verify_anchor_with_roots(&a, &roots),
            Err(RootVerifyError::MalformedAnchor {
                field: AnchorField::GenesisSignature
            })
        );
    }

    #[test]
    fn unknown_key_is_refused() {
        let roots = roots_of(&[(1, None)]);
        let a = anchor("c", &key(9));
        assert_eq!(
            verify_anchor_with_roots(&a, &roots),
            Err(RootVerifyError::UnknownKey {
                key_id: trust_root_key_id(&key(9).verifying_key())
            })
        );
    }

    #[test]
    fn out_of_scope_key_is_refused() {
        let roots = roots_of(&[(1, Some(vec!["chain-a", "chain-b"]))]);
        let a = anchor("chain-c", &key(1));
        assert_eq!(
            verify_anchor_with_roots(&a, &roots),
            Err(RootVerifyError::OutOfScope {
                key_id: trust_root_key_id(&key(1).verifying_key()),
                chain_id: "chain-c".into()
            })
        );
    }

    #[test]
    fn bad_signature_by_pinned_key_is_refused() {
        let roots = roots_of(&[(1, None)]);
        let mut a = anchor("c", &key(1));
        a.genesis_timestamp = "2026-10-08T00:00:00Z".into();
        assert_eq!(
            verify_anchor_with_roots(&a, &roots),
            Err(RootVerifyError::BadSignature {
                key_id: trust_root_key_id(&key(1).verifying_key())
            })
        );
    }

    #[test]
    fn non_canonical_signature_is_refused() {
        // Add the group order L to S: the same signature, malleated.
        let roots = roots_of(&[(1, None)]);
        let mut a = anchor("c", &key(1));
        let mut sig: [u8; 64] = B64
            .decode(&a.genesis_signature)
            .unwrap()
            .try_into()
            .unwrap();
        let mut carry = 0u16;
        for i in 0..32 {
            let sum = sig[32 + i] as u16 + GROUP_ORDER[i] as u16 + carry;
            sig[32 + i] = sum as u8;
            carry = sum >> 8;
        }
        assert_eq!(carry, 0, "S + L still fits in 32 bytes");
        assert!(!scalar_is_canonical(sig[32..].try_into().unwrap()));
        a.genesis_signature = B64.encode(sig);
        assert!(matches!(
            verify_anchor_with_roots(&a, &roots),
            Err(RootVerifyError::BadSignature { .. })
        ));
    }

    #[test]
    fn scalar_canonicality_boundary() {
        let mut below = GROUP_ORDER;
        below[0] -= 1;
        assert!(scalar_is_canonical(&below));
        assert!(!scalar_is_canonical(&GROUP_ORDER));
        assert!(scalar_is_canonical(&[0; 32]));
        assert!(!scalar_is_canonical(&[0xff; 32]));
    }

    #[test]
    fn invalid_roots_fail_closed() {
        let a = anchor("c", &key(1));
        let mut roots = roots_of(&[(1, None)]);
        roots.schema_identity = "attest-ledger/trust-roots/v0".into();
        assert!(matches!(
            verify_anchor_with_roots(&a, &roots),
            Err(RootVerifyError::InvalidRoots(
                TrustRootsError::UnsupportedSchema { .. }
            ))
        ));
    }

    #[test]
    fn chain_and_head_failures_after_authentication_are_wrapped() {
        let roots = roots_of(&[(1, None)]);
        let a = anchor("c", &key(1));
        let mut recs = records(3, 0);
        recs.remove(1);
        assert_eq!(
            verify_chain_with_anchor_and_roots(&a, &recs, &roots),
            Err(RootVerifyError::Chain(VerifyError::BrokenLink { index: 1 }))
        );
        let full = records(3, 0);
        let head = crate::build_record_head_commitment(&a, &full).unwrap();
        verify_chain_with_head_and_roots(&a, &full, &head, &roots).unwrap();
        assert!(matches!(
            verify_chain_with_head_and_roots(&a, &full[..2], &head, &roots),
            Err(RootVerifyError::Head(
                attest_ledger_types::HeadVerifyError::RecordCountMismatch { .. }
            ))
        ));
        // Roots are checked before the head: an unpinned signer never reaches it.
        let other = anchor("c", &key(2));
        assert!(matches!(
            verify_chain_with_head_and_roots(&other, &full, &head, &roots),
            Err(RootVerifyError::UnknownKey { .. })
        ));
    }

    /// The gap this change closes: an attacker who rewrites a chain and
    /// re-signs its anchor with their own key passes the embedded-key verifier
    /// every time, and the root-pinned verifier refuses it every time.
    #[test]
    fn chain_resigned_with_non_root_key_is_refused_while_embedded_key_accepts() {
        let roots = roots_of(&[(1, None)]);
        for case in 0u64..64 {
            let mut seed = [0u8; 32];
            seed[..8].copy_from_slice(&(case.wrapping_mul(0x9e37_79b9_7f4a_7c15)).to_le_bytes());
            seed[31] = 0xa5;
            let forger = SigningKey::from_bytes(&seed);
            let chain_id = format!("chain-{case}");
            let genuine = anchor(&chain_id, &key(1));
            let recs = records(1 + (case as usize % 5), case);
            verify_chain_with_anchor_and_roots(&genuine, &recs, &roots).unwrap();

            let mut forged_anchor = genuine.clone();
            sign_anchor(&mut forged_anchor, &forger);
            let mut chain = RecordChain::new(ANCHOR_HASH.into());
            let forged = vec![chain.append(
                "forged".into(),
                "2026-10-07T00:00:00Z".into(),
                json!({ "case": case }),
            )];

            verify_anchor(&forged_anchor).unwrap();
            crate::verify_chain_with_anchor(&forged_anchor, &forged).unwrap();
            assert_eq!(
                verify_chain_with_anchor_and_roots(&forged_anchor, &forged, &roots),
                Err(RootVerifyError::UnknownKey {
                    key_id: trust_root_key_id(&forger.verifying_key())
                }),
                "case {case}"
            );
        }
    }

    #[test]
    fn build_canonicalises_order_and_scope() {
        let a = build_trust_roots([
            (
                key(2).verifying_key(),
                Some(vec!["z".into(), "a".into(), "a".into()]),
            ),
            (key(1).verifying_key(), None),
        ])
        .unwrap();
        let b = build_trust_roots([
            (key(1).verifying_key(), None),
            (key(2).verifying_key(), Some(vec!["a".into(), "z".into()])),
        ])
        .unwrap();
        assert_eq!(a, b);
        assert_eq!(trust_roots_digest(&a), trust_roots_digest(&b));
    }

    #[test]
    fn build_refuses_duplicates_empty_scope_and_empty_chain_id() {
        let k = key(1).verifying_key();
        assert!(matches!(
            build_trust_roots([(k, None), (k, None)]),
            Err(TrustRootsError::NotCanonicalOrder { index: 1 })
        ));
        assert_eq!(
            build_trust_roots([(k, Some(vec![]))]),
            Err(TrustRootsError::EmptyScope { index: 0 })
        );
        assert_eq!(
            build_trust_roots([(k, Some(vec![String::new()]))]),
            Err(TrustRootsError::NotCanonicalScope { index: 0 })
        );
        assert_eq!(
            build_trust_roots(std::iter::empty()),
            Err(TrustRootsError::EmptySet)
        );
    }

    #[test]
    fn validation_refuses_every_malformed_set() {
        let good = roots_of(&[(1, Some(vec!["a", "b"])), (2, None)]);
        let check = |f: &dyn Fn(&mut TrustRootsV1)| {
            let mut r = good.clone();
            f(&mut r);
            validate_trust_roots(&r)
        };
        assert!(matches!(
            check(&|r| r.roots[0].algorithm = "rsa".into()),
            Err(TrustRootsError::UnsupportedAlgorithm { index: 0, .. })
        ));
        assert_eq!(
            check(&|r| r.roots[0].public_key = "AAAA".into()),
            Err(TrustRootsError::MalformedPublicKey { index: 0 })
        );
        // The identity point is a valid encoding of a small-order (weak) key.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        assert_eq!(
            check(&|r| r.roots[0].public_key = B64.encode(identity)),
            Err(TrustRootsError::WeakPublicKey { index: 0 })
        );
        assert!(matches!(
            check(&|r| r.roots[0].key_id = "sha256:00".into()),
            Err(TrustRootsError::KeyIdMismatch { index: 0, .. })
        ));
        assert_eq!(
            check(&|r| r.roots.swap(0, 1)),
            Err(TrustRootsError::NotCanonicalOrder { index: 1 })
        );
        let scoped = good
            .roots
            .iter()
            .position(|r| r.chain_ids.is_some())
            .unwrap();
        assert_eq!(
            check(&|r| r.roots[scoped].chain_ids = Some(vec![])),
            Err(TrustRootsError::EmptyScope { index: scoped })
        );
        assert_eq!(
            check(&|r| r.roots[scoped].chain_ids = Some(vec!["b".into(), "a".into()])),
            Err(TrustRootsError::NotCanonicalScope { index: scoped })
        );
        assert_eq!(check(&|r| r.roots.clear()), Err(TrustRootsError::EmptySet));
        validate_trust_roots(&good).unwrap();
    }

    #[test]
    fn a_strict_signature_from_a_pinned_key_over_other_bytes_is_bad() {
        let roots = roots_of(&[(1, None)]);
        let mut a = anchor("c", &key(1));
        a.genesis_signature = B64.encode(key(1).sign(b"other bytes").to_bytes());
        assert!(matches!(
            verify_anchor_with_roots(&a, &roots),
            Err(RootVerifyError::BadSignature { .. })
        ));
    }

    /// Byte identity with the published 0.1.1 crates: these values were
    /// produced by `attest-ledger-core = "=0.1.1"` from crates.io for the same
    /// inputs. Record hashes, anchor signature bytes, the anchor identity and
    /// the head-commitment digest are unchanged, and an anchor signed by 0.1.1
    /// authenticates under pinned roots with no re-signing.
    #[test]
    fn existing_outputs_match_the_0_1_1_release() {
        let recs = records(3, 0);
        let hashes: Vec<&str> = recs.iter().map(|r| r.record_hash.as_str()).collect();
        assert_eq!(
            hashes,
            [
                "sha256:7d5fc597b98c7c6cae0fcc696ffeea156fdff58465bd770448f732872792cc84",
                "sha256:f161f6b5b4fec7c2a20c2b222882c85eb630278db020bcedd45889a366271aba",
                "sha256:86dd76377acef37623fbc1ec4e52b13d6e5befff3319ca48da80f0f68c3c20fc",
            ]
        );
        let a = anchor("chain-a", &key(1));
        assert_eq!(
            a.genesis_public_key,
            "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w="
        );
        assert_eq!(
            a.genesis_signature,
            "aDnni8Ve2QImhPZAncqtREfzC+hIjuBT9t1OvgtZTvX6TLvfcIWEAzA6rsofh1QdmvWY7bhzREih8L73l0CgDQ=="
        );
        assert_eq!(
            crate::chain_anchor_identity(&a),
            "sha256:8512278695ea74482953bb9f79d0e981ba10f4be9a43ebb78ad6216944c6a82a"
        );
        let head = crate::build_record_head_commitment(&a, &recs).unwrap();
        assert_eq!(
            crate::head_commitment_digest(&head),
            "sha256:50d5eda38d90706f980e2c5c741b2bc8c6e060ee0bc399073bf3df352b36c9a1"
        );
        verify_anchor(&a).unwrap();
        let roots = roots_of(&[(1, Some(vec!["chain-a"]))]);
        verify_chain_with_head_and_roots(&a, &recs, &head, &roots).unwrap();
    }

    /// Golden vectors: the key-id derivation, the canonical form and the
    /// digest of a fixed root set. Any change here is a wire break.
    #[test]
    fn golden_trust_roots_canonical_form_and_digest() {
        let roots = roots_of(&[(1, Some(vec!["chain-b", "chain-a"])), (2, None)]);
        let canonical = String::from_utf8(trust_roots_canonical_bytes(&roots)).unwrap();
        assert_eq!(trust_root_key_id(&key(1).verifying_key()), GOLDEN_KEY_ID_1);
        assert_eq!(trust_root_key_id(&key(2).verifying_key()), GOLDEN_KEY_ID_2);
        assert_eq!(canonical, GOLDEN_CANONICAL);
        assert_eq!(trust_roots_digest(&roots), GOLDEN_DIGEST);
        let parsed: TrustRootsV1 = serde_json::from_str(GOLDEN_CANONICAL).unwrap();
        assert_eq!(parsed, roots);
    }

    // Cross-checked outside Rust: key id = sha256 of
    // b"attest-ledger/key-id/v1\ned25519\n" || key bytes; digest = sha256 of
    // GOLDEN_CANONICAL's UTF-8 bytes.
    const GOLDEN_KEY_ID_1: &str =
        "sha256:fbc57299fd371a070e079473961e694b1290419d1637fa7431669b4be4e206af";
    const GOLDEN_KEY_ID_2: &str =
        "sha256:77d588152d5c46b73afa23228719ddc6b264dd07fed3ec1e6b8bebec5dc2e0e1";
    const GOLDEN_CANONICAL: &str = concat!(
        r#"{"roots":[{"algorithm":"ed25519","#,
        r#""key_id":"sha256:77d588152d5c46b73afa23228719ddc6b264dd07fed3ec1e6b8bebec5dc2e0e1","#,
        r#""public_key":"gTl3Dqh9F19Wo1Rmw0x+zMuNipG07jeiXfYPW4/Js5Q="},"#,
        r#"{"algorithm":"ed25519","chain_ids":["chain-a","chain-b"],"#,
        r#""key_id":"sha256:fbc57299fd371a070e079473961e694b1290419d1637fa7431669b4be4e206af","#,
        r#""public_key":"iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w="}],"#,
        r#""schema_identity":"attest-ledger/trust-roots/v1"}"#
    );
    const GOLDEN_DIGEST: &str =
        "sha256:188308067b34baee45dcede2a91d9aa333c8a68deafb7b91de4cb09fe79040e0";
}

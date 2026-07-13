//! Ed25519 signing and verification for the chain genesis anchor.
//!
//! The anchor signature is the chain-side external trust root: without it, an
//! adversary who can regenerate the chain produces a consistent-looking hash
//! sequence with no anchor to a real key. Verifiers check the anchor signature
//! FIRST, before walking record hashes.

use attest_ledger_types::{ChainAnchor, GenesisAttestation, GenesisAttestationKind};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// Environment variable carrying a base64-encoded 32-byte Ed25519 seed.
pub const ENV_SIGNING_KEY: &str = "ATTEST_LEDGER_SIGNING_KEY";

/// Environment variable carrying a file path to the base64-encoded seed.
pub const ENV_SIGNING_KEY_PATH: &str = "ATTEST_LEDGER_SIGNING_KEY_PATH";

/// The canonical bytes an anchor signature covers: the anchor with
/// `genesis_signature` zeroed, serialized canonically (key-sorted). Sign and
/// verify both route through this, so the field naming convention and key order
/// cannot desynchronize the two sides.
fn anchor_signing_bytes(anchor: &ChainAnchor) -> String {
    let mut a = anchor.clone();
    a.genesis_signature = String::new();
    canonical_keysort_json::to_canonical_string(
        &serde_json::to_value(&a).expect("anchor serialises to JSON"),
    )
}

/// Sign `anchor` in place with `key`: sets `genesis_public_key` and
/// `genesis_signature`. Pure with respect to the environment and the clock; the
/// only non-determinism is `key` itself.
pub fn sign_anchor(anchor: &mut ChainAnchor, key: &SigningKey) {
    anchor.genesis_public_key = B64.encode(key.verifying_key().to_bytes());
    anchor.genesis_signature = String::new();
    let sig: Signature = key.sign(anchor_signing_bytes(anchor).as_bytes());
    anchor.genesis_signature = B64.encode(sig.to_bytes());
}

/// Verify an anchor's Ed25519 signature against its embedded public key.
///
/// Returns `Err` with a specific diagnostic distinguishing "unsigned" (empty
/// public key or signature) from "invalid" (signature does not verify).
pub fn verify_anchor(anchor: &ChainAnchor) -> Result<(), String> {
    if anchor.genesis_public_key.is_empty() {
        return Err("chain genesis is unsigned (genesis_public_key empty)".into());
    }
    if anchor.genesis_signature.is_empty() {
        return Err("chain genesis is unsigned (genesis_signature empty)".into());
    }
    let pk_bytes: [u8; 32] = B64
        .decode(&anchor.genesis_public_key)
        .map_err(|e| format!("genesis_public_key base64 decode: {e}"))?
        .try_into()
        .map_err(|v: Vec<u8>| format!("genesis_public_key length {} != 32", v.len()))?;
    let verifying_key = VerifyingKey::from_bytes(&pk_bytes)
        .map_err(|e| format!("genesis_public_key not a valid Ed25519 point: {e}"))?;
    let sig_bytes: [u8; 64] = B64
        .decode(&anchor.genesis_signature)
        .map_err(|e| format!("genesis_signature base64 decode: {e}"))?
        .try_into()
        .map_err(|v: Vec<u8>| format!("genesis_signature length {} != 64", v.len()))?;
    let sig = Signature::from_bytes(&sig_bytes);
    verifying_key
        .verify(anchor_signing_bytes(anchor).as_bytes(), &sig)
        .map_err(|e| format!("Ed25519 chain genesis signature verification failed: {e}"))
}

/// Resolve a signing key + attestation from the environment.
///
/// An operator key is read from [`ENV_SIGNING_KEY`] (base64 seed) or
/// [`ENV_SIGNING_KEY_PATH`] (path to a base64 seed); with neither set, an
/// ephemeral key is generated for this writer's lifetime. This is the one
/// convenience in the crate that touches the environment; the hashing and
/// verification paths stay pure.
pub fn resolve_signing_material() -> (SigningKey, GenesisAttestation) {
    if let Ok(b64) = std::env::var(ENV_SIGNING_KEY) {
        let seed = decode_seed(&b64)
            .unwrap_or_else(|e| panic!("{ENV_SIGNING_KEY} is set but malformed: {e}"));
        return (
            SigningKey::from_bytes(&seed),
            GenesisAttestation {
                kind: GenesisAttestationKind::Operator,
                note: Some(format!("source={ENV_SIGNING_KEY}")),
            },
        );
    }
    if let Ok(path) = std::env::var(ENV_SIGNING_KEY_PATH) {
        let contents = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{ENV_SIGNING_KEY_PATH}={path} unreadable: {e}"));
        let seed = decode_seed(contents.trim())
            .unwrap_or_else(|e| panic!("{ENV_SIGNING_KEY_PATH}={path} content malformed: {e}"));
        return (
            SigningKey::from_bytes(&seed),
            GenesisAttestation {
                kind: GenesisAttestationKind::Operator,
                note: Some(format!("source={ENV_SIGNING_KEY_PATH}:{path}")),
            },
        );
    }
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("OS RNG unavailable");
    (
        SigningKey::from_bytes(&seed),
        GenesisAttestation {
            kind: GenesisAttestationKind::Ephemeral,
            note: Some("auto-generated for chain lifetime".into()),
        },
    )
}

fn decode_seed(s: &str) -> Result<[u8; 32], String> {
    B64.decode(s.trim())
        .map_err(|e| format!("base64: {e}"))?
        .try_into()
        .map_err(|v: Vec<u8>| format!("seed length {} != 32", v.len()))
}

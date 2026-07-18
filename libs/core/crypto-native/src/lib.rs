//! Native ML-DSA-65 (FIPS 204) signing backend over `aws-lc-rs` (ADR-005, #244).
//!
//! The napi-rs performance backend, ships second behind the pure-TS
//! `@noble/post-quantum` backend (#243). It is byte-for-byte interoperable with
//! the noble backend: both key off the same 32-byte seed (ξ), and FIPS 204
//! keys expand deterministically, so a signature produced here verifies under
//! the noble backend and vice versa.
//!
//! The addon exposes exactly the primitives the `SignatureBackend` seam needs;
//! all higher-level shaping (MlDsaKey, base64url, error normalization) stays in
//! TypeScript so both backends present an identical interface.

use aws_lc_rs::signature::{KeyPair, UnparsedPublicKey};
use aws_lc_rs::unstable::signature::{PqdsaKeyPair, ML_DSA_65, ML_DSA_65_SIGNING};
use napi::bindgen_prelude::{Error, Result, Uint8Array};
use napi_derive::napi;

/// FIPS 204 ML-DSA-65 seed length (bytes).
const SEED_LEN: usize = 32;
/// Upper bound for an ML-DSA-65 signature (actual is 3309 B); a scratch buffer.
const SIG_MAX_LEN: usize = 4096;

fn to_err(context: &str) -> Error {
    Error::from_reason(format!("ML-DSA-65 native: {context}"))
}

/// Expand a 32-byte seed into the raw public key bytes (1952 B). Deterministic
/// — the same seed yields the same key as the noble backend.
#[napi]
pub fn mldsa65_public_key_from_seed(seed: Uint8Array) -> Result<Uint8Array> {
    if seed.len() != SEED_LEN {
        return Err(to_err("seed must be exactly 32 bytes"));
    }
    let kp = PqdsaKeyPair::from_seed(&ML_DSA_65_SIGNING, seed.as_ref())
        .map_err(|_| to_err("seed rejected by aws-lc-rs"))?;
    Ok(Uint8Array::new(kp.public_key().as_ref().to_vec()))
}

/// Sign `message` with the key expanded from `seed`. aws-lc-rs uses FIPS 204's
/// hedged (randomized) signing by default, matching noble — signatures are not
/// byte-reproducible, but always verifiable.
#[napi]
pub fn mldsa65_sign(seed: Uint8Array, message: Uint8Array) -> Result<Uint8Array> {
    if seed.len() != SEED_LEN {
        return Err(to_err("seed must be exactly 32 bytes"));
    }
    let kp = PqdsaKeyPair::from_seed(&ML_DSA_65_SIGNING, seed.as_ref())
        .map_err(|_| to_err("seed rejected by aws-lc-rs"))?;
    let mut sig = vec![0u8; SIG_MAX_LEN];
    let n = kp
        .sign(message.as_ref(), &mut sig)
        .map_err(|_| to_err("signing failed"))?;
    sig.truncate(n);
    Ok(Uint8Array::new(sig))
}

/// Verify `signature` over `message` under the raw public key. Returns `false`
/// for a forged/mismatched signature; errors only on a malformed public key.
#[napi]
pub fn mldsa65_verify(
    public_key: Uint8Array,
    message: Uint8Array,
    signature: Uint8Array,
) -> Result<bool> {
    let upk = UnparsedPublicKey::new(&ML_DSA_65, public_key.as_ref());
    Ok(upk.verify(message.as_ref(), signature.as_ref()).is_ok())
}

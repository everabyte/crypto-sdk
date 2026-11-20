//! Client-only opaque backup metadata shared by the WASM and Dart bindings.
//!
//! These domains match the desktop agent's existing `evb-agent-metadata-v1`
//! construction. Keep the labels and the `v1:` wire encoding stable.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{E2eeError, Result};
use crate::keys::{UmkSecrets, NONCE_LEN};
use crate::wrap::{b64_decode, b64_encode, hkdf_sha256_32, GcmBox};

type HmacSha256 = Hmac<Sha256>;

const KDF_PREFIX: &str = "evb-agent-metadata-v1:";
const PATH_ALIAS: &str = "manifest-path-index";
const CONTENT_EQUALITY: &str = "content-equality";
const PATH_CIPHER: &str = "manifest-path-cipher";
const CONTENT_HASH_CIPHER: &str = "manifest-content-hash-cipher";
const PATH_AAD: &[u8] = b"evb-agent-manifest-path-v1";
const CONTENT_HASH_AAD: &[u8] = b"evb-agent-manifest-content-hash-v1";

fn derive_key(umk: &UmkSecrets, purpose: &str) -> Result<Zeroizing<[u8; 32]>> {
    let mut ikm = Vec::with_capacity(umk.private_key_x25519.len() + umk.seed_mlkem.len());
    ikm.extend_from_slice(&umk.private_key_x25519);
    ikm.extend_from_slice(&umk.seed_mlkem);
    let key = hkdf_sha256_32(&ikm, format!("{KDF_PREFIX}{purpose}").as_bytes());
    ikm.zeroize();
    key.map(Zeroizing::new)
}

fn hmac_hex(key: &[u8; 32], value: &[u8]) -> Result<String> {
    let mut mac =
        HmacSha256::new_from_slice(key).map_err(|_| E2eeError::InvalidInput("bad metadata key"))?;
    mac.update(value);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn validate_relative_path(path: &str) -> Result<()> {
    if path.is_empty()
        || path.len() > 4096
        || path.starts_with('/')
        || path.contains('\\')
        || path.split('/').count() > 512
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(E2eeError::InvalidInput(
            "path must be normalized and relative",
        ));
    }
    Ok(())
}

fn validate_sha256_hex(hash: &str) -> Result<()> {
    if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(E2eeError::InvalidInput(
            "content hash must be 64 hex characters",
        ));
    }
    Ok(())
}

fn encrypt_text(umk: &UmkSecrets, text: &str, purpose: &str, aad: &[u8]) -> Result<String> {
    let key = derive_key(umk, purpose)?;
    let nonce = crate::keys::generate_nonce()?;
    let ciphertext_and_tag = GcmBox::seal(&key[..], &nonce, text.as_bytes(), aad)?;
    let mut blob = Vec::with_capacity(NONCE_LEN + ciphertext_and_tag.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext_and_tag);
    Ok(format!("v1:{}", b64_encode(&blob)))
}

fn decrypt_text(umk: &UmkSecrets, blob: &str, purpose: &str, aad: &[u8]) -> Result<String> {
    let encoded = blob.strip_prefix("v1:").ok_or(E2eeError::InvalidPayload(
        "unsupported encrypted metadata version",
    ))?;
    let data = b64_decode(encoded)?;
    if data.len() < NONCE_LEN + 16 {
        return Err(E2eeError::InvalidPayload("encrypted metadata is truncated"));
    }
    let (nonce, ciphertext_and_tag) = data.split_at(NONCE_LEN);
    let key = derive_key(umk, purpose)?;
    let plaintext = GcmBox::open(&key[..], nonce, ciphertext_and_tag, aad)?;
    String::from_utf8(plaintext).map_err(|_| E2eeError::InvalidPayload("metadata utf8"))
}

/// Stable HMAC alias of one normalized relative path: `evb-` + lowercase hex.
pub fn derive_opaque_manifest_path(umk: &UmkSecrets, path: &str) -> Result<String> {
    validate_relative_path(path)?;
    let key = derive_key(umk, PATH_ALIAS)?;
    Ok(format!("evb-{}", hmac_hex(&key, path.as_bytes())?))
}

/// HMAC aliases for each path prefix, in root-to-leaf order.
pub fn derive_opaque_path_ancestors(umk: &UmkSecrets, path: &str) -> Result<Vec<String>> {
    validate_relative_path(path)?;
    let mut ancestors = Vec::new();
    let mut prefix = String::new();
    for component in path.split('/') {
        if !prefix.is_empty() {
            prefix.push('/');
        }
        prefix.push_str(component);
        ancestors.push(derive_opaque_manifest_path(umk, &prefix)?);
    }
    Ok(ancestors)
}

/// Deterministic content-equality token for a SHA-256 digest; raw digest stays local.
pub fn derive_opaque_content_hash(umk: &UmkSecrets, sha256_hex: &str) -> Result<String> {
    validate_sha256_hex(sha256_hex)?;
    let key = derive_key(umk, CONTENT_EQUALITY)?;
    hmac_hex(&key, sha256_hex.to_ascii_lowercase().as_bytes())
}

/// Encrypts a normalized path as `v1:base64(nonce12 || ciphertext || tag16)`.
pub fn encrypt_manifest_path(umk: &UmkSecrets, path: &str) -> Result<String> {
    validate_relative_path(path)?;
    encrypt_text(umk, path, PATH_CIPHER, PATH_AAD)
}

/// Authenticates and decrypts a path produced by [`encrypt_manifest_path`].
pub fn decrypt_manifest_path(umk: &UmkSecrets, blob: &str) -> Result<String> {
    let path = decrypt_text(umk, blob, PATH_CIPHER, PATH_AAD)?;
    validate_relative_path(&path)?;
    Ok(path)
}

/// Encrypts a SHA-256 digest as `v1:base64(nonce12 || ciphertext || tag16)`.
pub fn encrypt_manifest_content_hash(umk: &UmkSecrets, sha256_hex: &str) -> Result<String> {
    validate_sha256_hex(sha256_hex)?;
    encrypt_text(umk, sha256_hex, CONTENT_HASH_CIPHER, CONTENT_HASH_AAD)
}

/// Authenticates and decrypts a digest produced by [`encrypt_manifest_content_hash`].
pub fn decrypt_manifest_content_hash(umk: &UmkSecrets, blob: &str) -> Result<String> {
    let hash = decrypt_text(umk, blob, CONTENT_HASH_CIPHER, CONTENT_HASH_AAD)?;
    validate_sha256_hex(&hash)?;
    Ok(hash)
}

// ---------------------------------------------------------------------------
// Test-only deterministic variants (feature `deterministic-vectors`): same
// wire encoding as the production fns with the nonce supplied by the vector
// generator, so the frozen grid covers the `v1:` metadata blobs too.
// ---------------------------------------------------------------------------
#[cfg(feature = "deterministic-vectors")]
pub fn encrypt_manifest_path_with_nonce(
    umk: &UmkSecrets,
    path: &str,
    nonce: &[u8; crate::keys::NONCE_LEN],
) -> Result<String> {
    validate_relative_path(path)?;
    let key = derive_key(umk, PATH_CIPHER)?;
    let ciphertext_and_tag = GcmBox::seal(&key[..], nonce, path.as_bytes(), PATH_AAD)?;
    let mut blob = Vec::with_capacity(crate::keys::NONCE_LEN + ciphertext_and_tag.len());
    blob.extend_from_slice(nonce);
    blob.extend_from_slice(&ciphertext_and_tag);
    Ok(format!("v1:{}", b64_encode(&blob)))
}

#[cfg(feature = "deterministic-vectors")]
pub fn encrypt_manifest_content_hash_with_nonce(
    umk: &UmkSecrets,
    sha256_hex: &str,
    nonce: &[u8; crate::keys::NONCE_LEN],
) -> Result<String> {
    validate_sha256_hex(sha256_hex)?;
    let key = derive_key(umk, CONTENT_HASH_CIPHER)?;
    let plaintext = sha256_hex.to_ascii_lowercase();
    let ciphertext_and_tag = GcmBox::seal(&key[..], nonce, plaintext.as_bytes(), CONTENT_HASH_AAD)?;
    let mut blob = Vec::with_capacity(crate::keys::NONCE_LEN + ciphertext_and_tag.len());
    blob.extend_from_slice(nonce);
    blob.extend_from_slice(&ciphertext_and_tag);
    Ok(format!("v1:{}", b64_encode(&blob)))
}

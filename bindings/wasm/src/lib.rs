//! WASM binding over `evb-e2ee-core` — browser-side crypto for Everabyte
//! integrations.
//!
//! Conventions shared with the Dart FFI binding:
//! - Envelopes cross the boundary as JSON strings with the canonical
//!   camelCase keys of the `evb-e2ee-v1` format (`ephPublicX25519`,
//!   `kemCiphertext`, `nonce`, `wrappedDek`).
//! - UMK material crosses as `sk(32) || seed(64)` byte strings.
//! - Errors surface as JS exceptions with short, secret-free messages.
//! - Buffer zeroization stays in the Rust core; copies handed to JS are
//!   caller-owned byte strings that the application must treat as sensitive.

use wasm_bindgen::prelude::*;

use evb_e2ee_core as core;
use evb_e2ee_core::content::{Evb1Decryptor, Evb1Encryptor};
use evb_e2ee_core::keys::{UmkPublic, UmkSecrets, NONCE_LEN};
use evb_e2ee_core::names;
use evb_e2ee_core::wrap;

fn err(e: core::E2eeError) -> JsError {
    JsError::new(&e.to_string())
}

fn dek_of(dek: &[u8]) -> Result<[u8; 32], JsError> {
    dek.try_into().map_err(|_| JsError::new("dek must be 32 bytes"))
}

fn nonce_of(n: &[u8]) -> Result<[u8; NONCE_LEN], JsError> {
    n.try_into().map_err(|_| JsError::new("nonce must be 12 bytes"))
}

fn umk_of(sk: &[u8], seed: &[u8]) -> Result<UmkSecrets, JsError> {
    Ok(UmkSecrets {
        private_key_x25519: sk
            .try_into()
            .map_err(|_| JsError::new("umk x25519 private key must be 32 bytes"))?,
        seed_mlkem: seed
            .try_into()
            .map_err(|_| JsError::new("umk ml-kem seed must be 64 bytes"))?,
    })
}

fn umk_to_bytes(umk: &UmkSecrets) -> Vec<u8> {
    let mut out = Vec::with_capacity(96);
    out.extend_from_slice(&umk.private_key_x25519);
    out.extend_from_slice(&umk.seed_mlkem);
    out
}

// ---------------------------------------------------------------------------
// EVB1 content (file payload)
// ---------------------------------------------------------------------------

/// Seals a whole EVB1 payload (header + all 64 KiB chunks) under a DEK and a
/// fresh-or-given fileNonce. Streaming across the network is orchestrated by
/// the application; use the streaming API in `core` when needed.
#[wasm_bindgen]
pub fn evb1_seal_all(dek: &[u8], file_nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, JsError> {
    Evb1Encryptor::seal_all(&dek_of(dek)?, nonce_of(file_nonce)?, plaintext).map_err(err)
}

/// Opens a whole EVB1 payload and returns the plaintext.
#[wasm_bindgen]
pub fn evb1_open_all(dek: &[u8], payload: &[u8]) -> Result<Vec<u8>, JsError> {
    Evb1Decryptor::open_all(&dek_of(dek)?, payload).map_err(err)
}

// ---------------------------------------------------------------------------
// UMK lifecycle
// ---------------------------------------------------------------------------

/// Generates a fresh UMK. Returns `sk(32) || seed(64)`.
#[wasm_bindgen]
pub fn generate_umk() -> Result<Vec<u8>, JsError> {
    wrap::generate_umk().map(|umk| umk_to_bytes(&umk)).map_err(err)
}

/// Derives the public keys of a UMK as canonical JSON:
/// `{ publicKeyX25519: b64(32), publicKeyMlkem: b64(1184) }`.
#[wasm_bindgen]
pub fn umk_public_keys(umk_sk: &[u8], umk_seed: &[u8]) -> Result<String, JsError> {
    let umk = umk_of(umk_sk, umk_seed)?;
    let UmkPublic {
        public_key_x25519,
        public_key_mlkem,
    } = umk.public().map_err(err)?;
    let json = serde_json::json!({
        "publicKeyX25519": wrap::b64_encode(&public_key_x25519),
        "publicKeyMlkem": wrap::b64_encode(&public_key_mlkem),
    });
    serde_json::to_string(&json).map_err(|e| JsError::new(&format!("json: {e}")))
}

/// Wraps the UMK under a fresh recovery mnemonic (PBKDF2-SHA512 100k, v2).
/// Returns the blob as base64.
#[wasm_bindgen]
pub fn wrap_umk_with_mnemonic(umk_sk: &[u8], umk_seed: &[u8], mnemonic: &str) -> Result<String, JsError> {
    let umk = umk_of(umk_sk, umk_seed)?;
    let salt = core::keys::generate_salt16().map_err(err)?;
    let nonce = core::keys::generate_nonce().map_err(err)?;
    wrap::wrap_umk_with_mnemonic(&umk, mnemonic, &salt, &nonce).map_err(err)
}

/// Unwraps the UMK with the recovery mnemonic. Returns `sk(32) || seed(64)`.
#[wasm_bindgen]
pub fn unwrap_umk_with_mnemonic(blob_b64: &str, mnemonic: &str) -> Result<Vec<u8>, JsError> {
    wrap::unwrap_umk_with_mnemonic(blob_b64, mnemonic)
        .map(|umk| umk_to_bytes(&umk))
        .map_err(err)
}

/// Wraps the UMK under a device secret (32 bytes held by the OS secure store).
/// Returns the blob as base64.
#[wasm_bindgen]
pub fn wrap_umk_with_device_key(umk_sk: &[u8], umk_seed: &[u8], device_secret: &[u8]) -> Result<String, JsError> {
    let umk = umk_of(umk_sk, umk_seed)?;
    let secret: [u8; 32] = device_secret
        .try_into()
        .map_err(|_| JsError::new("device secret must be 32 bytes"))?;
    let nonce = core::keys::generate_nonce().map_err(err)?;
    wrap::wrap_umk_with_device_key(&umk, &secret, &nonce).map_err(err)
}

/// Unwraps the UMK with a device secret. Returns `sk(32) || seed(64)`.
#[wasm_bindgen]
pub fn unwrap_umk_with_device_key(blob_b64: &str, device_secret: &[u8]) -> Result<Vec<u8>, JsError> {
    let secret: [u8; 32] = device_secret
        .try_into()
        .map_err(|_| JsError::new("device secret must be 32 bytes"))?;
    wrap::unwrap_umk_with_device_key(blob_b64, &secret)
        .map(|umk| umk_to_bytes(&umk))
        .map_err(err)
}

/// Wraps the UMK under the login password (Argon2id m=64 MiB, t=2, p=1,
/// scheme `evb-e2ee-umk-password-argon2id-m64-t2-p1-aesgcm`). Returns the
/// blob as base64; the server stores it as an opaque blind-proxy blob.
#[wasm_bindgen]
pub fn wrap_umk_with_password(umk_sk: &[u8], umk_seed: &[u8], password: &str) -> Result<String, JsError> {
    let umk = umk_of(umk_sk, umk_seed)?;
    let salt = core::keys::generate_salt16().map_err(err)?;
    let nonce = core::keys::generate_nonce().map_err(err)?;
    wrap::wrap_umk_with_password(&umk, password, &salt, &nonce).map_err(err)
}

/// Unwraps the UMK with the login password. Returns `sk(32) || seed(64)`.
#[wasm_bindgen]
pub fn unwrap_umk_with_password(blob_b64: &str, password: &str) -> Result<Vec<u8>, JsError> {
    wrap::unwrap_umk_with_password(blob_b64, password)
        .map(|umk| umk_to_bytes(&umk))
        .map_err(err)
}

// ---------------------------------------------------------------------------
// File DEK wrap (envelope)
// ---------------------------------------------------------------------------

/// Wraps a file DEK to the recipient UMK (hybrid X25519 + ML-KEM-768).
/// Returns the envelope JSON with canonical camelCase keys.
#[wasm_bindgen]
pub fn wrap_dek_to_umk(
    dek: &[u8],
    public_key_x25519: &[u8],
    public_key_mlkem: &[u8],
) -> Result<String, JsError> {
    let dek = dek_of(dek)?;
    let pk_x: [u8; 32] = public_key_x25519
        .try_into()
        .map_err(|_| JsError::new("public_key_x25519 must be 32 bytes"))?;
    let pubk = UmkPublic::from_parts(pk_x, public_key_mlkem.to_vec()).map_err(err)?;
    let envelope = wrap::wrap_dek_to_umk(&dek, &pubk).map_err(err)?;
    serde_json::to_string(&envelope).map_err(|e| JsError::new(&format!("json: {e}")))
}

/// Unwraps a file DEK from an envelope JSON (canonical camelCase keys).
#[wasm_bindgen]
pub fn unwrap_dek_from_umk(
    envelope_json: &str,
    umk_sk: &[u8],
    umk_seed: &[u8],
) -> Result<Vec<u8>, JsError> {
    let umk = umk_of(umk_sk, umk_seed)?;
    // Version dispatch inside: v: 2 = HPKE (RFC 9180), none = legacy v1.
    Ok(wrap::unwrap_dek_from_umk_json(envelope_json, &umk).map_err(err)?.to_vec())
}

// ---------------------------------------------------------------------------
// Symmetric wraps (sharing: link / invite)
// ---------------------------------------------------------------------------

/// Wraps a DEK under a 32-byte link key. Returns `{ wrappedDek, nonce }` JSON.
#[wasm_bindgen]
pub fn wrap_dek_with_link_key(dek: &[u8], link_key: &[u8]) -> Result<String, JsError> {
    let dek = dek_of(dek)?;
    let key: [u8; 32] = link_key
        .try_into()
        .map_err(|_| JsError::new("link key must be 32 bytes"))?;
    let nonce = core::keys::generate_nonce().map_err(err)?;
    let wrap_obj = wrap::wrap_dek_with_link_key(&dek, &key, &nonce).map_err(err)?;
    serde_json::to_string(&wrap_obj).map_err(|e| JsError::new(&format!("json: {e}")))
}

/// Unwraps a DEK under a 32-byte link key. Takes the `{ wrappedDek, nonce }`
/// JSON produced by [`wrap_dek_with_link_key`].
#[wasm_bindgen]
pub fn unwrap_dek_with_link_key(wrap_json: &str, link_key: &[u8]) -> Result<Vec<u8>, JsError> {
    let w: wrap::SymmetricWrap =
        serde_json::from_str(wrap_json).map_err(|e| JsError::new(&format!("wrap json: {e}")))?;
    let key: [u8; 32] = link_key
        .try_into()
        .map_err(|_| JsError::new("link key must be 32 bytes"))?;
    wrap::unwrap_dek_with_link_key(&w, &key).map(|d| d.to_vec()).map_err(err)
}

/// Wraps a DEK under a 32-byte invite keyShare. Returns `{ wrappedDek, nonce }` JSON.
#[wasm_bindgen]
pub fn wrap_dek_with_invite_key(dek: &[u8], key_share: &[u8]) -> Result<String, JsError> {
    let dek = dek_of(dek)?;
    let key: [u8; 32] = key_share
        .try_into()
        .map_err(|_| JsError::new("invite keyShare must be 32 bytes"))?;
    let nonce = core::keys::generate_nonce().map_err(err)?;
    let wrap_obj = wrap::wrap_dek_with_invite_key(&dek, &key, &nonce).map_err(err)?;
    serde_json::to_string(&wrap_obj).map_err(|e| JsError::new(&format!("json: {e}")))
}

/// Unwraps a DEK under a 32-byte invite keyShare.
#[wasm_bindgen]
pub fn unwrap_dek_with_invite_key(wrap_json: &str, key_share: &[u8]) -> Result<Vec<u8>, JsError> {
    let w: wrap::SymmetricWrap =
        serde_json::from_str(wrap_json).map_err(|e| JsError::new(&format!("wrap json: {e}")))?;
    let key: [u8; 32] = key_share
        .try_into()
        .map_err(|_| JsError::new("invite keyShare must be 32 bytes"))?;
    wrap::unwrap_dek_with_invite_key(&w, &key).map(|d| d.to_vec()).map_err(err)
}

// ---------------------------------------------------------------------------
// Encrypted names (P8)
// ---------------------------------------------------------------------------

/// Opaque wire alias: `evb-` + hex(HMAC-SHA256(nameKey, realName)).
#[wasm_bindgen]
pub fn derive_wire_alias(umk_sk: &[u8], umk_seed: &[u8], real_name: &str) -> Result<String, JsError> {
    let umk = umk_of(umk_sk, umk_seed)?;
    names::derive_opaque_wire_name(&umk, real_name).map_err(err)
}

/// Encrypts a real name under the DEK (files) or folder key (folders):
/// returns base64(nonce12 || ct || tag).
#[wasm_bindgen]
pub fn encrypt_file_name(dek: &[u8], real_name: &str, nonce: &[u8]) -> Result<String, JsError> {
    names::encrypt_file_name(&dek_of(dek)?, real_name, &nonce_of(nonce)?).map_err(err)
}

/// Decrypts an encrypted name blob (base64(nonce12 || ct || tag)).
#[wasm_bindgen]
pub fn decrypt_file_name(dek: &[u8], blob_b64: &str) -> Result<String, JsError> {
    names::decrypt_file_name(&dek_of(dek)?, blob_b64).map_err(err)
}

// ---------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------

/// HKDF-SHA256 with empty salt (RFC 5869), 32-byte output.
#[wasm_bindgen]
pub fn hkdf_sha256(ikm: &[u8], info: &[u8]) -> Result<Vec<u8>, JsError> {
    Ok(wrap::hkdf_sha256_32(ikm, info).map_err(err)?.to_vec())
}

/// Random 32-byte key (DEK / link key / keyShare / device secret).
#[wasm_bindgen]
pub fn generate_random_32() -> Result<Vec<u8>, JsError> {
    Ok(core::keys::generate_dek().map_err(err)?.to_vec())
}

/// Random 12-byte GCM nonce.
#[wasm_bindgen]
pub fn generate_random_12() -> Result<Vec<u8>, JsError> {
    Ok(core::keys::generate_nonce().map_err(err)?.to_vec())
}

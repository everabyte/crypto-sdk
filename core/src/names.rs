use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::error::{E2eeError, Result};
use crate::keys::{UmkSecrets, DEK_LEN, NONCE_LEN};
use crate::wrap::{b64_decode, b64_encode, GcmBox};

/// Wire name alias: `evb-` + lowercase hex of
/// HMAC-SHA256(macKey, UTF-8(realName)) where macKey = SHA-256(privX25519 || seedMlkem).
/// Deterministic by design (same real name => same wire name => versioning /
/// convergence semantics preserved on re-upload).
pub fn derive_opaque_wire_name(umk: &UmkSecrets, real_name: &str) -> Result<String> {
    if real_name.is_empty() {
        return Err(E2eeError::InvalidInput("empty name"));
    }
    let mac_key = crate::wrap::derive_name_mac_key(umk);
    let mut mac = Hmac::<Sha256>::new_from_slice(&mac_key)
        .map_err(|_| E2eeError::InvalidInput("bad mac key"))?;
    mac.update(real_name.as_bytes());
    let tag = mac.finalize().into_bytes();
    Ok(format!("evb-{}", hex::encode(tag)))
}

/// Encrypted real name under the DEK (files) or folder key (folders):
/// base64(nonce12 || ciphertext || tag16).
pub fn encrypt_file_name(dek: &[u8; DEK_LEN], real_name: &str, nonce: &[u8; NONCE_LEN]) -> Result<String> {
    if real_name.is_empty() {
        return Err(E2eeError::InvalidInput("empty name"));
    }
    let ct_tag = GcmBox::seal(dek, nonce, real_name.as_bytes(), &[])?;
    let mut blob = Vec::with_capacity(NONCE_LEN + ct_tag.len());
    blob.extend_from_slice(nonce);
    blob.extend_from_slice(&ct_tag);
    Ok(b64_encode(&blob))
}

pub fn decrypt_file_name(dek: &[u8; DEK_LEN], blob_b64: &str) -> Result<String> {
    let blob = b64_decode(blob_b64)?;
    if blob.len() < NONCE_LEN + 16 {
        return Err(E2eeError::InvalidPayload("encrypted name blob too short"));
    }
    let nonce: [u8; NONCE_LEN] = blob[..NONCE_LEN].try_into().unwrap();
    let ct_tag = &blob[NONCE_LEN..];
    let plain = GcmBox::open(dek, &nonce, ct_tag, &[])?;
    String::from_utf8(plain).map_err(|_| E2eeError::InvalidPayload("name utf8"))
}

/// Re-exported for bindings: name MAC key derivation given raw private parts.
pub fn derive_name_mac_key_from_parts(private_key_x25519: &[u8; 32], seed_mlkem: &[u8; 64]) -> [u8; 32] {
    Sha256::digest([private_key_x25519[..].as_ref(), seed_mlkem[..].as_ref()].concat()).into()
}

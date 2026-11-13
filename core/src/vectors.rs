//! Deterministic helpers for generating the shared test vectors.
//! Gated behind the `deterministic-vectors` feature: these APIs accept full
//! randomness material and MUST NOT be used in production code paths.

use crate::error::Result;
use crate::keys::{UmkPublic, UmkSecrets, DEK_LEN, MLKEM768_PK_LEN, NONCE_LEN, X25519_SK_LEN};
use crate::wrap::FileEnvelope;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

/// Builds a UMK from fixed private material (test-only).
pub fn umk_from_seed_material(private_key_x25519: [u8; 32], seed_mlkem: [u8; 64]) -> UmkSecrets {
    UmkSecrets {
        private_key_x25519,
        seed_mlkem,
    }
}

/// Deterministic ML-KEM-768 encapsulation (FIPS 203 encaps with a 32-byte
/// randomness seed) + X25519 + HKDF + AES-GCM, for vector generation only.
pub fn wrap_dek_to_umk_deterministic(
    dek: &[u8; DEK_LEN],
    recipient: &UmkPublic,
    eph_sk_seed: &[u8; X25519_SK_LEN],
    kem_seed: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
) -> Result<FileEnvelope> {
    use fips203::traits::{Encaps, SerDes};
    use zeroize::Zeroize;

    if recipient.public_key_mlkem.len() != MLKEM768_PK_LEN {
        return Err(crate::error::E2eeError::InvalidInput("ml-kem public key must be 1184 bytes"));
    }

    let eph_pk = x25519_dalek::x25519(*eph_sk_seed, x25519_dalek::X25519_BASEPOINT_BYTES);
    let shared_x = x25519_dalek::x25519(*eph_sk_seed, recipient.public_key_x25519);

    let ek = fips203::ml_kem_768::EncapsKey::try_from_bytes(
        recipient
            .public_key_mlkem
            .clone()
            .try_into()
            .map_err(|_| crate::error::E2eeError::InvalidInput("ml-kem pk size"))?,
    )
    .map_err(|_| crate::error::E2eeError::InvalidInput("ml-kem pk parse"))?;
    let (shared_kem, kem_ct) = Encaps::encaps_from_seed(&ek, kem_seed);

    let mut ikm = Vec::with_capacity(64);
    ikm.extend_from_slice(&shared_x);
    ikm.extend_from_slice(&SerDes::into_bytes(shared_kem));
    let wrap_key = crate::wrap::hkdf_sha256_32_for_vectors(&ikm, crate::wrap::HKDF_INFO_FILE_WRAP);
    ikm.zeroize();

    let ct_tag = crate::wrap::seal_for_vectors(&wrap_key, nonce, dek)?;
    Ok(FileEnvelope {
        eph_public_x25519: crate::wrap::b64_encode(&eph_pk),
        kem_ciphertext: crate::wrap::b64_encode(&SerDes::into_bytes(kem_ct)),
        nonce: crate::wrap::b64_encode(nonce),
        wrapped_dek: crate::wrap::b64_encode(&ct_tag),
    })
}

/// AES-256-GCM seal with explicit nonce (vector helper).
pub fn aes_gcm_seal_with_nonce(key32: &[u8], nonce12: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key32)
        .map_err(|_| crate::error::E2eeError::InvalidInput("bad key length"))?;
    cipher
        .encrypt(
            Nonce::from_slice(nonce12),
            Payload { msg: plaintext, aad },
        )
        .map_err(|_| crate::error::E2eeError::DecryptFailure)
}

/// Legacy v2 PBKDF2 mnemonic wrap (vector-only): seals the UMK with the
/// historical PBKDF2-SHA512-100k scheme so the frozen vectors keep covering
/// the read-only legacy path. NOT a production wrap — production always
/// seals Argon2id (v3).
pub fn pbkdf2_wrap_umk_for_vectors(
    umk: &UmkSecrets,
    mnemonic: &str,
    salt16: &[u8; 16],
    nonce: &[u8; NONCE_LEN],
) -> Result<String> {
    use pbkdf2::pbkdf2_hmac;
    use serde::Serialize;
    use sha2::Sha512;

    #[derive(Serialize)]
    struct LegacyPayload {
        v: u64,
        scheme: String,
        #[serde(rename = "publicKeyX25519")]
        public_key_x25519: String,
        #[serde(rename = "privateKeyX25519")]
        private_key_x25519: String,
        #[serde(rename = "publicKeyMlkem")]
        public_key_mlkem: String,
        #[serde(rename = "seedMlkem")]
        seed_mlkem: String,
    }

    let pubk = umk.public()?;
    let payload = LegacyPayload {
        v: 2,
        scheme: crate::wrap::UMK_WRAP_SCHEME_V2.to_string(),
        public_key_x25519: crate::wrap::b64_encode(&pubk.public_key_x25519),
        private_key_x25519: crate::wrap::b64_encode(&umk.private_key_x25519),
        public_key_mlkem: crate::wrap::b64_encode(&pubk.public_key_mlkem),
        seed_mlkem: crate::wrap::b64_encode(&umk.seed_mlkem),
    };
    let plaintext = serde_json::to_vec(&payload).map_err(|_| crate::error::E2eeError::InvalidInput("json"))?;
    let normalized = crate::mnemonic::normalize_mnemonic(mnemonic);
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha512>(normalized.as_bytes(), salt16, crate::wrap::PBKDF2_ROUNDS, &mut key);
    let ct_tag = crate::wrap::seal_for_vectors(&key, nonce, &plaintext)?;
    let mut blob = Vec::with_capacity(16 + NONCE_LEN + ct_tag.len());
    blob.extend_from_slice(salt16);
    blob.extend_from_slice(nonce);
    blob.extend_from_slice(&ct_tag);
    Ok(crate::wrap::b64_encode(&blob))
}

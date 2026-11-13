//! DEK wrap v2 — HPKE (RFC 9180) key schedule, ciphersuite DHKEM(X25519,
//! HKDF-SHA256) (kem_id 0x0020), HKDF-SHA256 (kdf_id 0x0001), AES-256-GCM
//! (aead_id 0x0003), **mode PSK** injecting the ML-KEM-768 shared secret as
//! the pre-shared key (psk_id = "evb-mlkem768-v1"). The PSK mode is the RFC's
//! standard mechanism for combining an additional secret with a DHKEM — this
//! keeps the whole wrap inside RFC 9180 while retaining the post-quantum
//! layer.
//!
//! Implementation note: the key schedule below implements RFC 9180 §4/§5
//! directly, validated against the official RFC vectors (§A.1.1: shared
//! secret, key schedule context, secret, key, base_nonce). Cross-language
//! byte-exactness (Rust / TypeScript / FFI / WASM) is proven by the frozen
//! vectors (`vectors/evb-e2ee-v1.json`, kind `file-dek-wrap-hpke`).
//!
//! Envelope v2 (JSON, camelCase — no plaintext nonce field: HPKE derives the
//! base_nonce from its key schedule, single-use seq = 0):
//! `{ v: 2, scheme, kemId, kdfId, aeadId, ephPublicX25519, kemCiphertext, wrappedDek }`
//!
//! The scheme id is used as the HPKE `info` AND as the AEAD `aad`, binding
//! the ciphertext to the exact scheme. Legacy v1 envelopes (hybrid
//! X25519+ML-KEM → single HKDF → AES-GCM with a transported nonce) remain
//! readable through [`crate::wrap::unwrap_dek_from_umk_json`] dispatching on
//! the presence of the `v` field.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::error::{E2eeError, Result};
use crate::keys::{
    UmkPublic, UmkSecrets, DEK_LEN, MLKEM768_CT_LEN, MLKEM768_PK_LEN, MLKEM768_SS_LEN, X25519_PK_LEN,
    X25519_SK_LEN,
};

pub const FILE_WRAP_SCHEME_HPKE_V2: &str = "evb-e2ee-file-wrap-hpke-psk-v1";
pub const HPKE_KEM_ID: u32 = 0x0020; // DHKEM(X25519, HKDF-SHA256)
pub const HPKE_KDF_ID: u32 = 0x0001; // HKDF-SHA256
pub const HPKE_AEAD_ID: u32 = 0x0003; // AES-256-GCM
pub const MLKEM_PSK_ID: &[u8] = b"evb-mlkem768-v1";

const HPKE_VERSION_LABEL: &[u8] = b"HPKE-v1";
/// suite_id for DHKEM: "KEM" || I2OSP(kem_id, 2).
const KEM_SUITE_ID: [u8; 5] = [0x4b, 0x45, 0x4d, 0x00, 0x20];
/// suite_id for the key schedule: "HPKE" || I2OSP(kem_id,2) || I2OSP(kdf_id,2) || I2OSP(aead_id,2).
const HPKE_SUITE_ID: [u8; 10] = [0x48, 0x50, 0x4b, 0x45, 0x00, 0x20, 0x00, 0x01, 0x00, 0x03];

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct HpkeFileEnvelope {
    pub v: u64,
    pub scheme: String,
    pub kem_id: u32,
    pub kdf_id: u32,
    pub aead_id: u32,
    pub eph_public_x25519: String,
    pub kem_ciphertext: String,
    pub wrapped_dek: String,
}

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

fn b64_encode(data: &[u8]) -> String {
    use base64::Engine;
    B64.encode(data)
}

fn b64_decode(s: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    B64.decode(s).map_err(|_| E2eeError::InvalidPayload("invalid base64"))
}

/// RFC 9180 §4: HMAC-SHA256 over `"HPKE-v1" || suite_id || label || ikm`
/// keyed by the salt (an empty salt is the RFC 5869 zero-filled key). Note:
/// the RFC final has NO 0x00 separator here (earlier drafts did).
fn hpke_labeled_extract(suite_id: &[u8], salt: &[u8], label: &[u8], ikm: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(salt).expect("hmac accepts any key length");
    mac.update(HPKE_VERSION_LABEL);
    mac.update(suite_id);
    mac.update(label);
    mac.update(ikm);
    mac.finalize().into_bytes().into()
}

/// RFC 9180 §4: HKDF-Expand over `I2OSP(L,2) || "HPKE-v1" || suite_id || label || context`.
fn hpke_labeled_expand(prk: &[u8; 32], suite_id: &[u8], label: &[u8], context: &[u8], len: usize) -> Vec<u8> {
    let mut info = Vec::with_capacity(2 + HPKE_VERSION_LABEL.len() + suite_id.len() + label.len() + context.len());
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.extend_from_slice(HPKE_VERSION_LABEL);
    info.extend_from_slice(suite_id);
    info.extend_from_slice(label);
    info.extend_from_slice(context);
    let hk = Hkdf::<Sha256>::from_prk(prk).expect("32-byte prk is valid");
    let mut out = vec![0u8; len];
    hk.expand(&info, &mut out).expect("expand output within HKDF bounds");
    out
}

/// RFC 9180 §4.1 DHKEM(X25519, HKDF-SHA256) ExtractAndExpand:
/// `eae_prk = LabeledExtract("", "eae_prk", dh)` then
/// `shared_secret = LabeledExpand(eae_prk, "shared_secret", kem_context, Nsecret)`.
/// `dh = DH(sk_self, dh_peer)`; `kem_context = enc || pkRm` — NOTE pkRm is the
/// recipient public key (NOT enc): sender (skE, pkR, enc, pkR),
/// receiver (skR, enc, enc, pkR).
fn dhkem_x25519_shared_secret(sk_self: &[u8; 32], dh_peer: &[u8; 32], enc: &[u8; 32], kem_pk_r: &[u8; 32]) -> [u8; 32] {
    let dh = x25519_dalek::x25519(*sk_self, *dh_peer);
    let mut kem_context = Vec::with_capacity(2 * X25519_PK_LEN);
    kem_context.extend_from_slice(enc);
    kem_context.extend_from_slice(kem_pk_r);
    let prk = hpke_labeled_extract(&KEM_SUITE_ID, &[], b"eae_prk", &dh);
    let out = hpke_labeled_expand(&prk, &KEM_SUITE_ID, b"shared_secret", &kem_context, 32);
    out.try_into().expect("32-byte expand output")
}

/// RFC 9180 §5.1 key schedule, mode PSK (0x01): returns the AEAD key and the
/// base nonce (single-use seq = 0 for these one-shot wraps).
fn key_schedule_mode_psk(shared_secret: &[u8; 32], psk: &[u8], psk_id: &[u8], info: &[u8]) -> ([u8; 32], [u8; 12]) {
    let psk_id_hash = hpke_labeled_extract(&HPKE_SUITE_ID, &[], b"psk_id_hash", psk_id);
    let info_hash = hpke_labeled_extract(&HPKE_SUITE_ID, &[], b"info_hash", info);
    let mut ks_context = Vec::with_capacity(1 + 32 + 32);
    ks_context.push(0x01); // mode_psk
    ks_context.extend_from_slice(&psk_id_hash);
    ks_context.extend_from_slice(&info_hash);
    let secret = hpke_labeled_extract(&HPKE_SUITE_ID, shared_secret, b"secret", psk);
    let key_vec = hpke_labeled_expand(&secret, &HPKE_SUITE_ID, b"key", &ks_context, 32);
    let nonce_vec = hpke_labeled_expand(&secret, &HPKE_SUITE_ID, b"base_nonce", &ks_context, 12);
    let key: [u8; 32] = key_vec.try_into().expect("32-byte key");
    let nonce: [u8; 12] = nonce_vec.try_into().expect("12-byte nonce");
    (key, nonce)
}

/// Encapsulates ML-KEM-768 against the recipient's encapsulation key.
/// `seed` drives the encapsulation randomness (32 bytes, deterministically
/// consumed — the same construction as `vectors.rs::wrap_dek_to_umk_deterministic`).
fn mlkem_encapsulate(pk_mlkem: &[u8], seed: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>)> {
    use fips203::traits::{Encaps, SerDes};
    let ek = fips203::ml_kem_768::EncapsKey::try_from_bytes(
        pk_mlkem
            .to_vec()
            .try_into()
            .map_err(|_| E2eeError::InvalidInput("ml-kem pk size"))?,
    )
    .map_err(|_| E2eeError::InvalidInput("ml-kem pk parse"))?;
    let (ss, ct) = Encaps::encaps_from_seed(&ek, seed);
    Ok((SerDes::into_bytes(ss).to_vec(), SerDes::into_bytes(ct).to_vec()))
}

/// Re-derives the ML-KEM decapsulation key from the UMK seed and decapsulates.
fn mlkem_decapsulate(seed_mlkem: &[u8; 64], kem_ct: &[u8]) -> Result<Vec<u8>> {
    use fips203::traits::{Decaps, SerDes};
    let (_ek, dk) = <fips203::ml_kem_768::KG as fips203::traits::KeyGen>::keygen_from_seed(
        seed_mlkem[0..32].try_into().unwrap(),
        seed_mlkem[32..64].try_into().unwrap(),
    );
    let ct = fips203::ml_kem_768::CipherText::try_from_bytes(
        kem_ct
            .to_vec()
            .try_into()
            .map_err(|_| E2eeError::InvalidPayload("ml-kem ct size"))?,
    )
    .map_err(|_| E2eeError::InvalidPayload("ml-kem ct parse"))?;
    let ss = Decaps::try_decaps(&dk, &ct).map_err(|_| E2eeError::DecryptFailure)?;
    Ok(SerDes::into_bytes(ss).to_vec())
}

/// Wraps a file DEK to the recipient UMK with HPKE v2 (RFC 9180 strict).
/// Randomness comes from the OS CSPRNG (HPKE ephemeral + ML-KEM encaps).
pub fn wrap_dek_to_umk_hpke(dek: &[u8; DEK_LEN], recipient: &UmkPublic) -> Result<HpkeFileEnvelope> {
    let mut ephem_seed = [0u8; X25519_SK_LEN];
    use rand::RngCore;
    rand::rngs::OsRng
        .try_fill_bytes(&mut ephem_seed)
        .map_err(|_| E2eeError::RandomFailure)?;
    let mut mlkem_seed = [0u8; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut mlkem_seed)
        .map_err(|_| E2eeError::RandomFailure)?;
    let env = wrap_dek_to_umk_hpke_with(dek, recipient, &ephem_seed, &mlkem_seed);
    ephem_seed.zeroize();
    mlkem_seed.zeroize();
    env
}

/// Deterministic variant (vector generation only): the full randomness
/// material is supplied by the caller. `ephem_seed` IS the HPKE X25519
/// ephemeral secret key; `mlkem_seed` drives the ML-KEM encapsulation.
pub fn wrap_dek_to_umk_hpke_with(
    dek: &[u8; DEK_LEN],
    recipient: &UmkPublic,
    ephem_seed: &[u8; X25519_SK_LEN],
    mlkem_seed: &[u8; 32],
) -> Result<HpkeFileEnvelope> {
    if recipient.public_key_mlkem.len() != MLKEM768_PK_LEN {
        return Err(E2eeError::InvalidInput("ml-kem public key must be 1184 bytes"));
    }

    // ML-KEM shared secret = the RFC's PSK (RFC 9180 §5.1.4 requires >= 32 B).
    let (mlkem_ss, kem_ct) = mlkem_encapsulate(&recipient.public_key_mlkem, mlkem_seed)?;
    debug_assert_eq!(mlkem_ss.len(), MLKEM768_SS_LEN);

    // HPKE encapsulation: enc = X25519(ephemeral, base point).
    let enc = x25519_dalek::x25519(*ephem_seed, x25519_dalek::X25519_BASEPOINT_BYTES);
    let shared_secret = dhkem_x25519_shared_secret(ephem_seed, &recipient.public_key_x25519, &enc, &recipient.public_key_x25519);

    // Key schedule mode PSK + one-shot seal (seq = 0 -> nonce = base_nonce).
    let scheme_bytes = FILE_WRAP_SCHEME_HPKE_V2.as_bytes();
    let (key, base_nonce) = key_schedule_mode_psk(&shared_secret, &mlkem_ss, MLKEM_PSK_ID, scheme_bytes);
    let wrapped = crate::wrap::GcmBox::seal(&key, &base_nonce, dek, scheme_bytes)?;

    let mut key_zero = key;
    key_zero.zeroize();

    Ok(HpkeFileEnvelope {
        v: 2,
        scheme: FILE_WRAP_SCHEME_HPKE_V2.to_string(),
        kem_id: HPKE_KEM_ID,
        kdf_id: HPKE_KDF_ID,
        aead_id: HPKE_AEAD_ID,
        eph_public_x25519: b64_encode(&enc),
        kem_ciphertext: b64_encode(&kem_ct),
        wrapped_dek: b64_encode(&wrapped),
    })
}

/// Unwraps a file DEK from an HPKE v2 envelope.
pub fn unwrap_dek_from_umk_hpke(envelope: &HpkeFileEnvelope, umk: &UmkSecrets) -> Result<[u8; DEK_LEN]> {
    if envelope.scheme != FILE_WRAP_SCHEME_HPKE_V2 || envelope.v != 2 {
        return Err(E2eeError::UnsupportedWrapScheme(envelope.scheme.clone()));
    }
    if envelope.kem_id != HPKE_KEM_ID || envelope.kdf_id != HPKE_KDF_ID || envelope.aead_id != HPKE_AEAD_ID {
        return Err(E2eeError::InvalidPayload("hpke ciphersuite mismatch"));
    }
    let enc: [u8; X25519_PK_LEN] = b64_decode(&envelope.eph_public_x25519)?
        .try_into()
        .map_err(|_| E2eeError::InvalidPayload("hpke enc size"))?;
    let kem_ct = b64_decode(&envelope.kem_ciphertext)?;
    if kem_ct.len() != MLKEM768_CT_LEN {
        return Err(E2eeError::InvalidPayload("kem ciphertext size"));
    }
    let ct_tag = b64_decode(&envelope.wrapped_dek)?;
    if ct_tag.len() != DEK_LEN + 16 {
        return Err(E2eeError::InvalidPayload("wrapped dek size"));
    }

    let mlkem_ss = mlkem_decapsulate(&umk.seed_mlkem, &kem_ct)?;
    // Receiver side of the DHKEM: dh = X25519(skR, pkE==enc); kem_context carries pkRm.
    let pk_r = x25519_dalek::x25519(umk.private_key_x25519, x25519_dalek::X25519_BASEPOINT_BYTES);
    let shared_secret = dhkem_x25519_shared_secret(&umk.private_key_x25519, &enc, &enc, &pk_r);

    let scheme_bytes = FILE_WRAP_SCHEME_HPKE_V2.as_bytes();
    let (key, base_nonce) = key_schedule_mode_psk(&shared_secret, &mlkem_ss, MLKEM_PSK_ID, scheme_bytes);
    let dek = crate::wrap::GcmBox::open(&key, &base_nonce, &ct_tag, scheme_bytes).map_err(|_| E2eeError::AuthFailure)?;
    let mut out = [0u8; DEK_LEN];
    out.copy_from_slice(&dek);
    Ok(out)
}

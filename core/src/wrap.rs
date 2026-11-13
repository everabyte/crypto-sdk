use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use fips203::traits::SerDes;
use hkdf::Hkdf;
use pbkdf2::pbkdf2_hmac;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroize;

use crate::error::{E2eeError, Result};
use crate::keys::{
    UmkPublic, UmkSecrets, DEK_LEN, MLKEM768_CT_LEN, MLKEM768_PK_LEN, NONCE_LEN, TAG_LEN,
    X25519_PK_LEN, X25519_SK_LEN,
};

pub const HKDF_INFO_FILE_WRAP: &[u8] = b"evb-e2ee-file-wrap-v1";
pub const HKDF_INFO_DEVICE_WRAP: &[u8] = b"evb-e2ee-device-wrap-v1";
pub const HKDF_INFO_LINK_WRAP: &[u8] = b"evb-e2ee-link-wrap-v1";
pub const HKDF_INFO_INVITE_WRAP: &[u8] = b"evb-e2ee-invite-wrap-v1";

/// Legacy v2 scheme: PBKDF2-SHA512 100k. READ-ONLY (historical blobs +
/// blobs mislabelled `kdf: argon2id` by the pre-fix web client). No wrap
/// function exports PBKDF2: new envelopes are always Argon2id.
pub const UMK_WRAP_SCHEME_V2: &str = "evb-e2ee-umk-pbkdf2-sha512-100k-aesgcm";
pub const PBKDF2_ROUNDS: u32 = 100_000;
pub const PBKDF2_SALT_LEN: usize = 16;
pub const PBKDF2_OUT_LEN: usize = 32;

/// Argon2id v1.3 (RFC 9106) — the KDF for every new mnemonic wrap.
/// Parameters are versioned by embedding them in the scheme id (the scheme
/// id is inside the encrypted JSON; the unwrap tries the known candidates
/// in order and lets the GCM tag decide).
pub const UMK_WRAP_SCHEME_ARGON2ID_V3: &str = "evb-e2ee-umk-argon2id-m64-t2-p1-aesgcm";
/// RFC 9106 low-memory recommendation (m=64 MiB, t=3, p=4). Readable
/// everywhere; a wrap alternative for memory-constrained devices after
/// on-device latency validation (see PROTOCOL.md §6).
pub const UMK_WRAP_SCHEME_ARGON2ID_RFC9106: &str = "evb-e2ee-umk-argon2id-m64-t3-p4-aesgcm";

/// Default wrap parameters: 64 MiB / t=2 / p=1 (OWASP profile, aligned with
/// the web client constants; measured ~0.5 s desktop, see PROTOCOL.md §6).
pub const ARGON2ID_M_KIB: u32 = 65_536;
pub const ARGON2ID_T: u32 = 2;
pub const ARGON2ID_P: u32 = 1;

// ---------------------------------------------------------------------------
// AES-256-GCM helper (nonce 12 B, tag 16 B, output = ct || tag)
// ---------------------------------------------------------------------------

pub(crate) struct GcmBox;

impl GcmBox {
    pub(crate) fn seal(key32: &[u8], nonce12: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new_from_slice(key32).map_err(|_| E2eeError::InvalidInput("bad key length"))?;
        let ct = cipher
            .encrypt(
                Nonce::from_slice(nonce12),
                Payload { msg: plaintext, aad },
            )
            .map_err(|_| E2eeError::AuthFailure)?;
        Ok(ct)
    }

    pub(crate) fn open(key32: &[u8], nonce12: &[u8], ct_tag: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new_from_slice(key32).map_err(|_| E2eeError::InvalidInput("bad key length"))?;
        cipher
            .decrypt(Nonce::from_slice(nonce12), Payload { msg: ct_tag, aad })
            .map_err(|_| E2eeError::AuthFailure)
    }
}

// ---------------------------------------------------------------------------
// HKDF-SHA256 (salt-less extract = RFC 5869 zero salt, matches WebCrypto)
// ---------------------------------------------------------------------------

pub fn hkdf_sha256_32(ikm: &[u8], info: &[u8]) -> Result<[u8; 32]> {    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm).map_err(|_| E2eeError::InvalidInput("hkdf length"))?;
    Ok(okm)
}

fn pbkdf2_sha512_32(password: &[u8], salt: &[u8]) -> [u8; PBKDF2_OUT_LEN] {
    let mut out = [0u8; PBKDF2_OUT_LEN];
    pbkdf2_hmac::<Sha512>(password, salt, PBKDF2_ROUNDS, &mut out);
    out
}

// ---------------------------------------------------------------------------
// DEK <-> UMK hybrid wrap (X25519 + ML-KEM-768 -> HKDF -> AES-256-GCM)
// Wire: { ephPublicX25519: b64(32), kemCiphertext: b64(1088), nonce: b64(12),
//         wrappedDek: b64(ct||tag, 48) }
// ---------------------------------------------------------------------------

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct FileEnvelope {
    pub eph_public_x25519: String,
    pub kem_ciphertext: String,
    pub nonce: String,
    pub wrapped_dek: String,
}

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

pub fn b64_encode(data: &[u8]) -> String {
    use base64::Engine;
    B64.encode(data)
}

pub fn b64_decode(s: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    B64.decode(s).map_err(|_| E2eeError::InvalidPayload("invalid base64"))
}

/// Wraps a file DEK to the recipient UMK — **HPKE v2 (RFC 9180 strict)** is
/// the default for every new envelope (see [`crate::hpke`]). The legacy v1
/// hybrid envelope stays available as [`wrap_dek_to_umk_legacy`] and remains
/// readable through [`unwrap_dek_from_umk_json`] dispatch.
pub fn wrap_dek_to_umk(
    dek: &[u8; DEK_LEN],
    recipient: &UmkPublic,
) -> Result<crate::hpke::HpkeFileEnvelope> {
    crate::hpke::wrap_dek_to_umk_hpke(dek, recipient)
}

pub fn wrap_dek_to_umk_legacy(
    dek: &[u8; DEK_LEN],
    recipient: &UmkPublic,
) -> Result<FileEnvelope> {
    let mut eph_sk = [0u8; X25519_SK_LEN];
    use rand::RngCore;
    rand::rngs::OsRng
        .try_fill_bytes(&mut eph_sk)
        .map_err(|_| E2eeError::RandomFailure)?;
    let nonce = crate::keys::generate_nonce()?;

    let env = wrap_dek_to_umk_with(dek, recipient, &eph_sk, &nonce);
    eph_sk.zeroize();
    env
}

/// Dispatches on the envelope version field: `v: 2` = HPKE (RFC 9180 strict,
/// [`crate::hpke`]); no version field = legacy v1 hybrid envelope. New wraps
/// are always HPKE v2; v1 stays readable so existing envelopes never break.
pub fn unwrap_dek_from_umk_json(envelope_json: &str, umk: &UmkSecrets) -> Result<[u8; DEK_LEN]> {
    let parsed: serde_json::Value = serde_json::from_str(envelope_json)
        .map_err(|_| E2eeError::InvalidPayload("envelope json"))?;
    match parsed.get("v").and_then(|v| v.as_u64()) {
        Some(2) => {
            let env: crate::hpke::HpkeFileEnvelope = serde_json::from_value(parsed)
                .map_err(|_| E2eeError::InvalidPayload("hpke envelope json"))?;
            crate::hpke::unwrap_dek_from_umk_hpke(&env, umk)
        }
        _ => {
            let env: FileEnvelope = serde_json::from_value(parsed)
                .map_err(|_| E2eeError::InvalidPayload("envelope json"))?;
            unwrap_dek_from_umk(&env, umk)
        }
    }
}

pub fn wrap_dek_to_umk_with(
    dek: &[u8; DEK_LEN],
    recipient: &UmkPublic,
    eph_sk_seed: &[u8; X25519_SK_LEN],
    nonce: &[u8; NONCE_LEN],
) -> Result<FileEnvelope> {
    if recipient.public_key_mlkem.len() != MLKEM768_PK_LEN {
        return Err(E2eeError::InvalidInput("ml-kem public key must be 1184 bytes"));
    }

    let eph_pk = x25519_dalek::x25519(*eph_sk_seed, x25519_dalek::X25519_BASEPOINT_BYTES);
    let shared_x = x25519_dalek::x25519(*eph_sk_seed, recipient.public_key_x25519);

    let ek = fips203::ml_kem_768::EncapsKey::try_from_bytes(
        recipient.public_key_mlkem.clone().try_into().map_err(|_| E2eeError::InvalidInput("ml-kem pk size"))?,
    )
    .map_err(|_| E2eeError::InvalidInput("ml-kem pk parse"))?;
    let (shared_kem, kem_ct) = fips203::traits::Encaps::try_encaps(&ek)
        .map_err(|_| E2eeError::RandomFailure)?;

    let mut ikm = Vec::with_capacity(64);
    ikm.extend_from_slice(&shared_x);
    ikm.extend_from_slice(&fips203::traits::SerDes::into_bytes(shared_kem));
    let wrap_key = hkdf_sha256_32(&ikm, HKDF_INFO_FILE_WRAP)?;
    ikm.zeroize();

    let ct_tag = GcmBox::seal(&wrap_key, nonce, dek, &[])?;
    Ok(FileEnvelope {
        eph_public_x25519: b64_encode(&eph_pk),
        kem_ciphertext: b64_encode(&fips203::traits::SerDes::into_bytes(kem_ct)),
        nonce: b64_encode(nonce),
        wrapped_dek: b64_encode(&ct_tag),
    })
}

pub fn unwrap_dek_from_umk(
    envelope: &FileEnvelope,
    umk: &UmkSecrets,
) -> Result<[u8; DEK_LEN]> {
    let eph_pk: [u8; X25519_PK_LEN] = b64_decode(&envelope.eph_public_x25519)?
        .try_into()
        .map_err(|_| E2eeError::InvalidPayload("eph public key size"))?;
    let kem_ct: [u8; MLKEM768_CT_LEN] = b64_decode(&envelope.kem_ciphertext)?
        .try_into()
        .map_err(|_| E2eeError::InvalidPayload("kem ciphertext size"))?;
    let nonce: [u8; NONCE_LEN] = b64_decode(&envelope.nonce)?
        .try_into()
        .map_err(|_| E2eeError::InvalidPayload("nonce size"))?;
    let ct_tag = b64_decode(&envelope.wrapped_dek)?;
    if ct_tag.len() != DEK_LEN + TAG_LEN {
        return Err(E2eeError::InvalidPayload("wrapped dek size"));
    }

    let shared_x = x25519_dalek::x25519(umk.private_key_x25519, eph_pk);
    let (_ek, dk) =
        <fips203::ml_kem_768::KG as fips203::traits::KeyGen>::keygen_from_seed(
            umk.seed_mlkem[0..32].try_into().unwrap(),
            umk.seed_mlkem[32..64].try_into().unwrap(),
        );
    let ct = fips203::ml_kem_768::CipherText::try_from_bytes(kem_ct)
        .map_err(|_| E2eeError::InvalidPayload("kem ct parse"))?;
    let shared_kem = fips203::traits::Decaps::try_decaps(&dk, &ct)
        .map_err(|_| E2eeError::DecryptFailure)?;

    let mut ikm = Vec::with_capacity(64);
    ikm.extend_from_slice(&shared_x);
    ikm.extend_from_slice(&fips203::traits::SerDes::into_bytes(shared_kem));
    let wrap_key = hkdf_sha256_32(&ikm, HKDF_INFO_FILE_WRAP)?;
    ikm.zeroize();

    let dek = GcmBox::open(&wrap_key, &nonce, &ct_tag, &[])?;
    let mut out = [0u8; DEK_LEN];
    out.copy_from_slice(&dek);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Symmetric key wraps (link key, invite keyShare) -> { wrappedDek, nonce }
// ---------------------------------------------------------------------------

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SymmetricWrap {
    pub wrapped_dek: String,
    pub nonce: String,
}

fn wrap_dek_with_symmetric_key(
    dek: &[u8; DEK_LEN],
    key32: &[u8],
    info: &[u8],
    nonce: &[u8; NONCE_LEN],
) -> Result<SymmetricWrap> {
    let wrap_key = hkdf_sha256_32(key32, info)?;
    let ct_tag = GcmBox::seal(&wrap_key, nonce, dek, &[])?;
    Ok(SymmetricWrap {
        wrapped_dek: b64_encode(&ct_tag),
        nonce: b64_encode(nonce),
    })
}

fn unwrap_dek_with_symmetric_key(wrap: &SymmetricWrap, key32: &[u8], info: &[u8]) -> Result<[u8; DEK_LEN]> {
    let nonce: [u8; NONCE_LEN] = b64_decode(&wrap.nonce)?
        .try_into()
        .map_err(|_| E2eeError::InvalidPayload("nonce size"))?;
    let ct_tag = b64_decode(&wrap.wrapped_dek)?;
    if ct_tag.len() != DEK_LEN + TAG_LEN {
        return Err(E2eeError::InvalidPayload("wrapped dek size"));
    }
    let wrap_key = hkdf_sha256_32(key32, info)?;
    let dek = GcmBox::open(&wrap_key, &nonce, &ct_tag, &[])?;
    let mut out = [0u8; DEK_LEN];
    out.copy_from_slice(&dek);
    Ok(out)
}

pub fn wrap_dek_with_link_key(
    dek: &[u8; DEK_LEN],
    link_key32: &[u8],
    nonce: &[u8; NONCE_LEN],
) -> Result<SymmetricWrap> {
    wrap_dek_with_symmetric_key(dek, link_key32, HKDF_INFO_LINK_WRAP, nonce)
}

pub fn unwrap_dek_with_link_key(wrap: &SymmetricWrap, link_key32: &[u8]) -> Result<[u8; DEK_LEN]> {
    unwrap_dek_with_symmetric_key(wrap, link_key32, HKDF_INFO_LINK_WRAP)
}

pub fn wrap_dek_with_invite_key(
    dek: &[u8; DEK_LEN],
    key_share32: &[u8],
    nonce: &[u8; NONCE_LEN],
) -> Result<SymmetricWrap> {
    wrap_dek_with_symmetric_key(dek, key_share32, HKDF_INFO_INVITE_WRAP, nonce)
}

pub fn unwrap_dek_with_invite_key(wrap: &SymmetricWrap, key_share32: &[u8]) -> Result<[u8; DEK_LEN]> {
    unwrap_dek_with_symmetric_key(wrap, key_share32, HKDF_INFO_INVITE_WRAP)
}

// ---------------------------------------------------------------------------
// UMK device wrap: HKDF(deviceSecret32, "evb-e2ee-device-wrap-v1") -> AES-GCM
// blob = b64(nonce12 || ct || tag), payload = JSON of the 4 UMK fields
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct DeviceWrapPayload {
    #[serde(rename = "publicKeyX25519")]
    public_key_x25519: String,
    #[serde(rename = "publicKeyMlkem")]
    public_key_mlkem: String,
    #[serde(rename = "privateKeyX25519")]
    private_key_x25519: String,
    #[serde(rename = "seedMlkem")]
    seed_mlkem: String,
}

pub fn wrap_umk_with_device_key(
    umk: &UmkSecrets,
    device_secret32: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
) -> Result<String> {
    let pubk = umk.public()?;
    let payload = DeviceWrapPayload {
        public_key_x25519: b64_encode(&pubk.public_key_x25519),
        public_key_mlkem: b64_encode(&pubk.public_key_mlkem),
        private_key_x25519: b64_encode(&umk.private_key_x25519),
        seed_mlkem: b64_encode(&umk.seed_mlkem),
    };
    let plaintext = serde_json::to_vec(&payload).map_err(|_| E2eeError::InvalidInput("json"))?;
    let wrap_key = hkdf_sha256_32(device_secret32, HKDF_INFO_DEVICE_WRAP)?;
    let ct_tag = GcmBox::seal(&wrap_key, nonce, &plaintext, &[])?;
    let mut blob = Vec::with_capacity(NONCE_LEN + ct_tag.len());
    blob.extend_from_slice(nonce);
    blob.extend_from_slice(&ct_tag);
    Ok(b64_encode(&blob))
}

pub fn unwrap_umk_with_device_key(blob_b64: &str, device_secret32: &[u8; 32]) -> Result<UmkSecrets> {
    let blob = b64_decode(blob_b64)?;
    if blob.len() < NONCE_LEN + TAG_LEN {
        return Err(E2eeError::InvalidPayload("device wrap too short"));
    }
    let nonce = blob[..NONCE_LEN].try_into().unwrap();
    let ct_tag = &blob[NONCE_LEN..];
    let wrap_key = hkdf_sha256_32(device_secret32, HKDF_INFO_DEVICE_WRAP)?;
    let plaintext = GcmBox::open(&wrap_key, nonce, ct_tag, &[])?;
    let payload: DeviceWrapPayload =
        serde_json::from_slice(&plaintext).map_err(|_| E2eeError::InvalidPayload("device wrap json"))?;
    umk_from_json_fields(
        &payload.private_key_x25519,
        &payload.seed_mlkem,
        &payload.public_key_x25519,
        &payload.public_key_mlkem,
    )
}

// ---------------------------------------------------------------------------
// UMK mnemonic wrap (KEK derivation).
// v2 (legacy, read-only): PBKDF2-SHA512 100k -> AES-256-GCM.
// v3 (current): Argon2id v1.3 (RFC 9106) -> AES-256-GCM; parameters are
//   versioned by the scheme id embedded in the encrypted JSON.
// blob framing is shared: b64( salt(16) || iv(12) || ct||tag ).
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct MnemonicWrapPayload {
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

/// Argon2id v1.3 KEK derivation (32-byte AES-256-GCM key).
/// `m_kib` in KiB (65_536 = 64 MiB), `t` passes, `p` lanes.
fn argon2id_kek(password: &[u8], salt: &[u8], m_kib: u32, t: u32, p: u32) -> Result<[u8; 32]> {
    let params = argon2::Params::new(m_kib, t, p, Some(32))
        .map_err(|_| E2eeError::InvalidInput("argon2 params"))?;
    let a2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = [0u8; 32];
    a2.hash_password_into(password, salt, &mut out)
        .map_err(|_| E2eeError::InvalidInput("argon2 derivation"))?;
    Ok(out)
}

/// KDF candidate for the mnemonic unwrap: ordered, versioned by scheme id.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct KdfCandidate {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

fn seal_mnemonic_blob(
    umk: &UmkSecrets,
    salt16: &[u8; PBKDF2_SALT_LEN],
    nonce: &[u8; NONCE_LEN],
    v: u64,
    scheme: &str,
    kek: &[u8; 32],
) -> Result<String> {
    let pubk = umk.public()?;
    let payload = MnemonicWrapPayload {
        v,
        scheme: scheme.to_string(),
        public_key_x25519: b64_encode(&pubk.public_key_x25519),
        private_key_x25519: b64_encode(&umk.private_key_x25519),
        public_key_mlkem: b64_encode(&pubk.public_key_mlkem),
        seed_mlkem: b64_encode(&umk.seed_mlkem),
    };
    let plaintext = serde_json::to_vec(&payload).map_err(|_| E2eeError::InvalidInput("json"))?;
    let ct_tag = GcmBox::seal(kek, nonce, &plaintext, &[])?;
    let mut blob = Vec::with_capacity(PBKDF2_SALT_LEN + NONCE_LEN + ct_tag.len());
    blob.extend_from_slice(salt16);
    blob.extend_from_slice(nonce);
    blob.extend_from_slice(&ct_tag);
    Ok(b64_encode(&blob))
}

/// Wraps the UMK under a fresh recovery mnemonic with the default Argon2id
/// profile (m=64 MiB, t=2, p=1, v3). This is the ONLY exported mnemonic wrap
/// apart from the explicit-parameter variant: PBKDF2 is never used for new
/// envelopes.
pub fn wrap_umk_with_mnemonic(
    umk: &UmkSecrets,
    mnemonic: &str,
    salt16: &[u8; PBKDF2_SALT_LEN],
    nonce: &[u8; NONCE_LEN],
) -> Result<String> {
    wrap_umk_with_mnemonic_params(umk, mnemonic, salt16, nonce, ARGON2ID_M_KIB, ARGON2ID_T, ARGON2ID_P)
}

/// Wraps the UMK under the mnemonic with explicit Argon2id parameters
/// (e.g. the RFC 9106 low-memory profile: m=65536, t=3, p=4). Parameters
/// must be covered by a scheme id the unwrappers know, otherwise the blob
/// is unreadable — check with [`unwrap_umk_with_mnemonic`] after wrapping.
pub fn wrap_umk_with_mnemonic_params(
    umk: &UmkSecrets,
    mnemonic: &str,
    salt16: &[u8; PBKDF2_SALT_LEN],
    nonce: &[u8; NONCE_LEN],
    m_kib: u32,
    t: u32,
    p: u32,
) -> Result<String> {
    let scheme = scheme_for_params(m_kib, t, p)
        .ok_or(E2eeError::InvalidInput("argon2 params have no versioned scheme id"))?;
    let normalized = crate::mnemonic::normalize_mnemonic(mnemonic);
    let kek = argon2id_kek(normalized.as_bytes(), salt16, m_kib, t, p)?;
    seal_mnemonic_blob(umk, salt16, nonce, 3, scheme, &kek)
}

/// Scheme id for known parameter sets (the unwrap tries exactly these).
fn scheme_for_params(m_kib: u32, t: u32, p: u32) -> Option<&'static str> {
    match (m_kib, t, p) {
        (65_536, 2, 1) => Some(UMK_WRAP_SCHEME_ARGON2ID_V3),
        (65_536, 3, 4) => Some(UMK_WRAP_SCHEME_ARGON2ID_RFC9106),
        _ => None,
    }
}

fn params_for_scheme(scheme: &str) -> Option<KdfCandidate> {
    match scheme {
        UMK_WRAP_SCHEME_ARGON2ID_V3 => Some(KdfCandidate { m_kib: 65_536, t: 2, p: 1 }),
        UMK_WRAP_SCHEME_ARGON2ID_RFC9106 => Some(KdfCandidate { m_kib: 65_536, t: 3, p: 4 }),
        _ => None,
    }
}

/// Legacy read-only unwrap of a v2 PBKDF2 blob (historical envelopes,
/// including those mislabelled `kdf: argon2id` by the pre-fix web client).
pub fn unwrap_umk_with_mnemonic_pbkdf2(blob_b64: &str, mnemonic: &str) -> Result<UmkSecrets> {
    let (salt, nonce, ct_tag) = parse_mnemonic_blob(blob_b64)?;
    let normalized = crate::mnemonic::normalize_mnemonic(mnemonic);
    let key = pbkdf2_sha512_32(normalized.as_bytes(), &salt);
    let plaintext =
        GcmBox::open(&key, &nonce, &ct_tag, &[]).map_err(|_| E2eeError::AuthFailure)?;
    open_mnemonic_payload(&plaintext)
}

/// Unwraps the UMK with the recovery mnemonic. Tries the versioned KDF
/// candidates in order (v3 Argon2id default, RFC 9106 profile, then the
/// legacy v2 PBKDF2 scheme) and lets the AES-GCM tag decide which one the
/// blob uses — the KDF parameters that open a blob are by construction the
/// ones it was sealed with (no silent reinterpretation of an old ciphertext
/// as a newer format). A wrong phrase fails on every candidate.
pub fn unwrap_umk_with_mnemonic(blob_b64: &str, mnemonic: &str) -> Result<UmkSecrets> {
    let (salt, nonce, ct_tag) = parse_mnemonic_blob(blob_b64)?;
    let normalized = crate::mnemonic::normalize_mnemonic(mnemonic);

    // v3 Argon2id candidates (default profile first, RFC 9106 second).
    for (m, t, p) in [
        (ARGON2ID_M_KIB, ARGON2ID_T, ARGON2ID_P),
        (65_536, 3, 4),
    ] {
        let kek = argon2id_kek(normalized.as_bytes(), &salt, m, t, p)?;
        if let Ok(plaintext) = GcmBox::open(&kek, &nonce, &ct_tag, &[]) {
            return open_mnemonic_payload(&plaintext);
        }
    }
    // Legacy v2 PBKDF2 (read-only path; also covers blobs the pre-fix web
    // client mislabelled as argon2id).
    let key = pbkdf2_sha512_32(normalized.as_bytes(), &salt);
    if let Ok(plaintext) = GcmBox::open(&key, &nonce, &ct_tag, &[]) {
        return open_mnemonic_payload(&plaintext);
    }
    Err(E2eeError::AuthFailure)
}

fn parse_mnemonic_blob(blob_b64: &str) -> Result<([u8; PBKDF2_SALT_LEN], [u8; NONCE_LEN], Vec<u8>)> {
    let blob = b64_decode(blob_b64)?;
    if blob.len() < PBKDF2_SALT_LEN + NONCE_LEN + TAG_LEN {
        return Err(E2eeError::InvalidPayload("mnemonic wrap too short"));
    }
    let mut salt = [0u8; PBKDF2_SALT_LEN];
    salt.copy_from_slice(&blob[..PBKDF2_SALT_LEN]);
    let nonce = blob[PBKDF2_SALT_LEN..PBKDF2_SALT_LEN + NONCE_LEN].try_into().unwrap();
    let ct_tag = blob[PBKDF2_SALT_LEN + NONCE_LEN..].to_vec();
    Ok((salt, nonce, ct_tag))
}

fn open_mnemonic_payload(plaintext: &[u8]) -> Result<UmkSecrets> {
    let payload: MnemonicWrapPayload =
        serde_json::from_slice(plaintext).map_err(|_| E2eeError::InvalidPayload("mnemonic wrap json"))?;
    // v2 legacy: scheme is the PBKDF2 id, v == 2. v3: v == 3 + Argon2id id.
    match (payload.v, payload.scheme.as_str()) {
        (2, UMK_WRAP_SCHEME_V2) => {}
        (3, s) if params_for_scheme(s).is_some() => {}
        (v, _) => {
            return Err(if v < 2 {
                E2eeError::UnsupportedWrapVersion(v)
            } else {
                E2eeError::UnsupportedWrapScheme(payload.scheme.clone())
            })
        }
    }
    umk_from_json_fields(
        &payload.private_key_x25519,
        &payload.seed_mlkem,
        &payload.public_key_x25519,
        &payload.public_key_mlkem,
    )
}

fn umk_from_json_fields(
    private_key_x25519: &str,
    seed_mlkem: &str,
    public_key_x25519: &str,
    public_key_mlkem: &str,
) -> Result<UmkSecrets> {
    let sk: [u8; X25519_SK_LEN] = b64_decode(private_key_x25519)?
        .try_into()
        .map_err(|_| E2eeError::InvalidPayload("x25519 private key size"))?;
    let seed: [u8; 64] = b64_decode(seed_mlkem)?
        .try_into()
        .map_err(|_| E2eeError::InvalidPayload("ml-kem seed size"))?;
    let pk_x: [u8; X25519_PK_LEN] = b64_decode(public_key_x25519)?
        .try_into()
        .map_err(|_| E2eeError::InvalidPayload("x25519 public key size"))?;
    let pk_kem = b64_decode(public_key_mlkem)?;
    if pk_kem.len() != MLKEM768_PK_LEN {
        return Err(E2eeError::InvalidPayload("ml-kem public key size"));
    }
    // Cross-check the private material against the declared publics.
    let derived_pk_x = x25519_dalek::x25519(sk, x25519_dalek::X25519_BASEPOINT_BYTES);
    if derived_pk_x != pk_x {
        return Err(E2eeError::InvalidPayload("x25519 key pair mismatch"));
    }
    let (ek, _dk) =
        <fips203::ml_kem_768::KG as fips203::traits::KeyGen>::keygen_from_seed(
            seed[0..32].try_into().unwrap(),
            seed[32..64].try_into().unwrap(),
        );
    if fips203::traits::SerDes::into_bytes(ek) != pk_kem[..] {
        return Err(E2eeError::InvalidPayload("ml-kem key pair mismatch"));
    }
    Ok(UmkSecrets {
        private_key_x25519: sk,
        seed_mlkem: seed,
    })
}

// ---------------------------------------------------------------------------
// Vector-support internals (public to the `deterministic-vectors` module only)
// ---------------------------------------------------------------------------

#[cfg(feature = "deterministic-vectors")]
pub(crate) fn hkdf_sha256_32_for_vectors(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    hkdf_sha256_32(ikm, info).unwrap_or([0u8; 32])
}

#[cfg(feature = "deterministic-vectors")]
pub(crate) fn seal_for_vectors(key32: &[u8], nonce12: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    GcmBox::seal(key32, nonce12, plaintext, &[])
}

// ---------------------------------------------------------------------------
// UMK generation (client-side only)
// ---------------------------------------------------------------------------

pub fn generate_umk() -> Result<UmkSecrets> {
    let mut sk = [0u8; X25519_SK_LEN];
    let mut seed = [0u8; 64];
    use rand::RngCore;
    let mut rng = rand::rngs::OsRng;
    rng.try_fill_bytes(&mut sk).map_err(|_| E2eeError::RandomFailure)?;
    rng.try_fill_bytes(&mut seed).map_err(|_| E2eeError::RandomFailure)?;
    Ok(UmkSecrets {
        private_key_x25519: sk,
        seed_mlkem: seed,
    })
}

// ---------------------------------------------------------------------------
// File name MAC key (P8): SHA-256(privX25519 || seedMlkem)
// ---------------------------------------------------------------------------

pub fn derive_name_mac_key(umk: &UmkSecrets) -> [u8; 32] {
    Sha256::digest(
        [&umk.private_key_x25519[..], &umk.seed_mlkem[..]].concat(),
    )
    .into()
}

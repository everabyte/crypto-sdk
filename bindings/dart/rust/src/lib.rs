//! C ABI surface over `evb-e2ee-core` for the Dart/Flutter binding.
//!
//! Conventions:
//! - Every function returns a status code: 0 = OK, negative = error.
//! - Output buffers are caller-allocated; the callee writes `out_len`.
//! - Errors carry a short, secret-free message in a global slot readable via
//!   `evb_last_error` (copied, never logged by the SDK itself).
//! - Lengths are u64 / capacities are u64 to keep the ABI simple on 64-bit.

use std::ffi::{c_char, CStr};
use std::sync::Mutex;

use evb_e2ee_core as core;
use evb_e2ee_core::content::{Evb1Decryptor, Evb1Encryptor};
use evb_e2ee_core::keys::{UmkSecrets, NONCE_LEN};
use zeroize::Zeroize;

const OK: i32 = 0;
const ERR_ARG: i32 = -1;
const ERR_CRYPTO: i32 = -2;
const ERR_PAYLOAD: i32 = -3;
const ERR_BUF: i32 = -4;
const ERR_JSON: i32 = -5;
const ERR_UTF8: i32 = -6;
const ERR_LOCK: i32 = -7;

static LAST_ERROR: Mutex<Option<String>> = Mutex::new(None);

fn set_err(msg: &str) {
    if let Ok(mut slot) = LAST_ERROR.lock() {
        let slot = slot.get_or_insert_with(String::new);
        slot.clear();
        slot.push_str(msg);
    }
}

fn take_err(buf: *mut c_char, cap: u64) -> i32 {
    let msg = match LAST_ERROR.lock() {
        Ok(guard) => guard.clone().unwrap_or_default(),
        Err(_) => return ERR_LOCK,
    };
    let bytes = msg.as_bytes();
    if cap == 0 {
        return bytes.len() as i32 + 1; // required capacity (incl. NUL)
    }
    let cap = cap.min(i32::MAX as u64 - 1) as usize;
    if bytes.len() + 1 > cap {
        set_err("error buffer too small");
        return ERR_BUF;
    }
    // Safety: caller guarantees `cap` writable bytes at `buf`.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr() as *const c_char, buf, bytes.len());
        *buf.add(bytes.len()) = 0;
    }
    OK
}

fn err_of(e: &core::E2eeError) -> i32 {
    match e {
        core::E2eeError::InvalidInput(m) => {
            set_err(m);
            ERR_ARG
        }
        core::E2eeError::InvalidPayload(m) => {
            set_err(m);
            ERR_PAYLOAD
        }
        core::E2eeError::DecryptFailure | core::E2eeError::AuthFailure => {
            set_err("authentication failed");
            ERR_CRYPTO
        }
        core::E2eeError::UnsupportedWrapVersion(_) => {
            set_err("unsupported wrap version");
            ERR_PAYLOAD
        }
        core::E2eeError::UnsupportedWrapScheme(_) => {
            set_err("unsupported wrap scheme");
            ERR_PAYLOAD
        }
        core::E2eeError::UnsupportedFormatVersion(_) => {
            set_err("unsupported content format version");
            ERR_PAYLOAD
        }
        core::E2eeError::RandomFailure => {
            set_err("random source failure");
            ERR_CRYPTO
        }
    }
}

/// Copies `src[..len]` into `out` (capacity `cap`), sets `*out_len`.
/// Safety: caller guarantees out/cap valid, out_len valid.
unsafe fn write_out(out: *mut u8, cap: u64, out_len: *mut u64, src: &[u8]) -> i32 {
    if (cap as usize) < src.len() {
        set_err("output buffer too small");
        return ERR_BUF;
    }
    if !src.is_empty() {
        std::ptr::copy_nonoverlapping(src.as_ptr(), out, src.len());
    }
    *out_len = src.len() as u64;
    OK
}

fn read_str(p: *const c_char) -> Result<String, i32> {
    if p.is_null() {
        set_err("null string argument");
        return Err(ERR_ARG);
    }
    // Safety: caller guarantees a valid NUL-terminated string.
    unsafe { CStr::from_ptr(p) }
        .to_str()
        .map(|s| s.to_string())
        .map_err(|_| {
            set_err("invalid utf-8 in string argument");
            ERR_UTF8
        })
}

/// Safety: `p` must be valid for `len` bytes when len > 0.
unsafe fn slice<'a>(p: *const u8, len: u64) -> &'a [u8] {
    if p.is_null() || len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(p, len as usize)
    }
}

// ---------------------------------------------------------------------------
// EVB1 content one-shot
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn evb1_seal_all(
    dek: *const u8,
    file_nonce: *const u8,
    plaintext: *const u8,
    plaintext_len: u64,
    out: *mut u8,
    out_cap: u64,
    out_len: *mut u64,
) -> i32 {
    let Some(dek) = (unsafe { slice(dek, 32) }).try_into().ok() else {
        set_err("dek must be 32 bytes");
        return ERR_ARG;
    };
    if file_nonce.is_null() || out_len.is_null() {
        set_err("null argument");
        return ERR_ARG;
    }
    let nonce: [u8; NONCE_LEN] = (unsafe { slice(file_nonce, 12) }).try_into().unwrap();
    let pt = unsafe { slice(plaintext, plaintext_len) };
    match Evb1Encryptor::seal_all(&dek, nonce, pt) {
        Ok(ct) => unsafe { write_out(out, out_cap, out_len, &ct) },
        Err(e) => err_of(&e),
    }
}

#[no_mangle]
pub extern "C" fn evb1_open_all(
    dek: *const u8,
    payload: *const u8,
    payload_len: u64,
    out: *mut u8,
    out_cap: u64,
    out_len: *mut u64,
) -> i32 {
    let Some(dek) = (unsafe { slice(dek, 32) }).try_into().ok() else {
        set_err("dek must be 32 bytes");
        return ERR_ARG;
    };
    if out_len.is_null() {
        set_err("null argument");
        return ERR_ARG;
    }
    let payload = unsafe { slice(payload, payload_len) };
    match Evb1Decryptor::open_all(&dek, payload) {
        Ok(pt) => unsafe { write_out(out, out_cap, out_len, &pt) },
        Err(e) => err_of(&e),
    }
}

// ---------------------------------------------------------------------------
// File DEK wrap
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn evb_unwrap_dek_from_umk(
    envelope_json: *const c_char,
    umk_sk: *const u8,
    umk_seed: *const u8,
    out: *mut u8,
    out_cap: u64,
    out_len: *mut u64,
) -> i32 {
    let env_json = match read_str(envelope_json) {
        Ok(s) => s,
        Err(code) => return code,
    };
    if umk_sk.is_null() || umk_seed.is_null() || out_len.is_null() {
        set_err("null argument");
        return ERR_ARG;
    }
    // Version dispatch happens inside: v: 2 = HPKE (RFC 9180), none = legacy v1.
    let umk = UmkSecrets {
        private_key_x25519: unsafe { slice(umk_sk, 32) }.try_into().unwrap(),
        seed_mlkem: unsafe { slice(umk_seed, 64) }.try_into().unwrap(),
    };
    let mut sk_buf = umk.private_key_x25519; // UmkSecrets zeroizes on drop; keep scope tight
    match core::wrap::unwrap_dek_from_umk_json(&env_json, &umk) {
        Ok(dek) => {
            let res = unsafe { write_out(out, out_cap, out_len, &dek) };
            let mut d = dek;
            d.zeroize();
            sk_buf.zeroize();
            res
        }
        Err(e) => {
            sk_buf.zeroize();
            err_of(&e)
        }
    }
}

#[no_mangle]
pub extern "C" fn evb_wrap_dek_to_umk(
    dek: *const u8,
    public_key_x25519: *const u8,
    public_key_mlkem: *const u8,
    out_json: *mut c_char,
    out_cap: u64,
) -> i32 {
    let Some(dek) = (unsafe { slice(dek, 32) }).try_into().ok() else {
        set_err("dek must be 32 bytes");
        return ERR_ARG;
    };
    if public_key_x25519.is_null() || public_key_mlkem.is_null() {
        set_err("null argument");
        return ERR_ARG;
    }
    let pubk = match core::keys::UmkPublic::from_parts(
        unsafe { slice(public_key_x25519, 32) }.try_into().unwrap(),
        unsafe { slice(public_key_mlkem, 1184) }.to_vec(),
    ) {
        Ok(p) => p,
        Err(e) => return err_of(&e),
    };
    let mut d = dek;
    let res = match core::wrap::wrap_dek_to_umk(&d, &pubk) {
        Ok(env) => match serde_json::to_string(&env) {
            Ok(json) => {
                let bytes = json.as_bytes();
                if (out_cap as usize) < bytes.len() + 1 {
                    set_err("output buffer too small");
                    ERR_BUF
                } else {
                    // Safety: out_cap >= len+1 guaranteed above.
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            bytes.as_ptr() as *const c_char,
                            out_json,
                            bytes.len(),
                        );
                        *out_json.add(bytes.len()) = 0;
                    }
                    OK
                }
            }
            Err(_) => {
                set_err("json serialization failed");
                ERR_JSON
            }
        },
        Err(e) => err_of(&e),
    };
    d.zeroize();
    res
}

// ---------------------------------------------------------------------------
// Mnemonic wrap
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn evb_unwrap_umk_with_mnemonic(
    blob_b64: *const c_char,
    mnemonic: *const c_char,
    out_sk: *mut u8,
    out_seed: *mut u8,
) -> i32 {
    let blob = match read_str(blob_b64) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let phrase = match read_str(mnemonic) {
        Ok(s) => s,
        Err(code) => return code,
    };
    if out_sk.is_null() || out_seed.is_null() {
        set_err("null argument");
        return ERR_ARG;
    }
    match core::wrap::unwrap_umk_with_mnemonic(&blob, &phrase) {
        Ok(umk) => {
            let mut sk = umk.private_key_x25519;
            let mut seed = umk.seed_mlkem;
            // Safety: caller-provided buffers sized 32 / 64 by contract.
            unsafe {
                std::ptr::copy_nonoverlapping(sk.as_ptr(), out_sk, 32);
                std::ptr::copy_nonoverlapping(seed.as_ptr(), out_seed, 64);
            }
            sk.zeroize();
            seed.zeroize();
            OK
        }
        Err(e) => err_of(&e),
    }
}

// ---------------------------------------------------------------------------
// Names
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn evb_derive_wire_alias(
    umk_sk: *const u8,
    umk_seed: *const u8,
    real_name: *const c_char,
    out: *mut c_char,
    out_cap: u64,
) -> i32 {
    if umk_sk.is_null() || umk_seed.is_null() || out.is_null() {
        set_err("null argument");
        return ERR_ARG;
    }
    let name = match read_str(real_name) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let umk = UmkSecrets {
        private_key_x25519: unsafe { slice(umk_sk, 32) }.try_into().unwrap(),
        seed_mlkem: unsafe { slice(umk_seed, 64) }.try_into().unwrap(),
    };
    match core::names::derive_opaque_wire_name(&umk, &name) {
        Ok(alias) => {
            let bytes = alias.as_bytes();
            if (out_cap as usize) < bytes.len() + 1 {
                set_err("output buffer too small");
                return ERR_BUF;
            }
            // Safety: capacity checked above.
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr() as *const c_char, out, bytes.len());
                *out.add(bytes.len()) = 0;
            }
            OK
        }
        Err(e) => err_of(&e),
    }
}

fn metadata_string(
    umk_sk: *const u8,
    umk_seed: *const u8,
    input: *const c_char,
    out: *mut c_char,
    out_cap: u64,
    op: fn(&UmkSecrets, &str) -> core::Result<String>,
) -> i32 {
    if umk_sk.is_null() || umk_seed.is_null() || input.is_null() || out.is_null() {
        set_err("null argument");
        return ERR_ARG;
    }
    let value = match read_str(input) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let umk = UmkSecrets {
        private_key_x25519: unsafe { slice(umk_sk, 32) }.try_into().unwrap(),
        seed_mlkem: unsafe { slice(umk_seed, 64) }.try_into().unwrap(),
    };
    match op(&umk, &value) {
        Ok(result) => unsafe { write_nul_str(out, out_cap, &result) },
        Err(error) => err_of(&error),
    }
}

#[no_mangle]
pub extern "C" fn evb_derive_opaque_manifest_path(
    umk_sk: *const u8,
    umk_seed: *const u8,
    path: *const c_char,
    out: *mut c_char,
    out_cap: u64,
) -> i32 {
    metadata_string(
        umk_sk,
        umk_seed,
        path,
        out,
        out_cap,
        core::metadata::derive_opaque_manifest_path,
    )
}

#[no_mangle]
pub extern "C" fn evb_derive_opaque_path_ancestors(
    umk_sk: *const u8,
    umk_seed: *const u8,
    path: *const c_char,
    out: *mut c_char,
    out_cap: u64,
) -> i32 {
    metadata_string(umk_sk, umk_seed, path, out, out_cap, |umk, path| {
        let aliases = core::metadata::derive_opaque_path_ancestors(umk, path)?;
        serde_json::to_string(&aliases)
            .map_err(|_| core::E2eeError::InvalidPayload("metadata json"))
    })
}

#[no_mangle]
pub extern "C" fn evb_derive_opaque_content_hash(
    umk_sk: *const u8,
    umk_seed: *const u8,
    hash: *const c_char,
    out: *mut c_char,
    out_cap: u64,
) -> i32 {
    metadata_string(
        umk_sk,
        umk_seed,
        hash,
        out,
        out_cap,
        core::metadata::derive_opaque_content_hash,
    )
}

#[no_mangle]
pub extern "C" fn evb_encrypt_manifest_path(
    umk_sk: *const u8,
    umk_seed: *const u8,
    path: *const c_char,
    out: *mut c_char,
    out_cap: u64,
) -> i32 {
    metadata_string(
        umk_sk,
        umk_seed,
        path,
        out,
        out_cap,
        core::metadata::encrypt_manifest_path,
    )
}

#[no_mangle]
pub extern "C" fn evb_decrypt_manifest_path(
    umk_sk: *const u8,
    umk_seed: *const u8,
    blob: *const c_char,
    out: *mut c_char,
    out_cap: u64,
) -> i32 {
    metadata_string(
        umk_sk,
        umk_seed,
        blob,
        out,
        out_cap,
        core::metadata::decrypt_manifest_path,
    )
}

#[no_mangle]
pub extern "C" fn evb_encrypt_manifest_content_hash(
    umk_sk: *const u8,
    umk_seed: *const u8,
    hash: *const c_char,
    out: *mut c_char,
    out_cap: u64,
) -> i32 {
    metadata_string(
        umk_sk,
        umk_seed,
        hash,
        out,
        out_cap,
        core::metadata::encrypt_manifest_content_hash,
    )
}

#[no_mangle]
pub extern "C" fn evb_decrypt_manifest_content_hash(
    umk_sk: *const u8,
    umk_seed: *const u8,
    blob: *const c_char,
    out: *mut c_char,
    out_cap: u64,
) -> i32 {
    metadata_string(
        umk_sk,
        umk_seed,
        blob,
        out,
        out_cap,
        core::metadata::decrypt_manifest_content_hash,
    )
}

// ---------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn evb_hkdf_sha256(
    ikm: *const u8,
    ikm_len: u64,
    info: *const u8,
    info_len: u64,
    out: *mut u8,
) -> i32 {
    if out.is_null() {
        set_err("null argument");
        return ERR_ARG;
    }
    let ikm = unsafe { slice(ikm, ikm_len) };
    let info = unsafe { slice(info, info_len) };
    match core::wrap::hkdf_sha256_32(ikm, info) {
        Ok(okm) => {
            // Safety: caller contract = 32-byte buffer.
            unsafe { std::ptr::copy_nonoverlapping(okm.as_ptr(), out, 32) };
            OK
        }
        Err(e) => err_of(&e),
    }
}

// ---------------------------------------------------------------------------
// UMK generation, publics, device + mnemonic wraps (full flow from C)
// ---------------------------------------------------------------------------

/// Generates a fresh UMK into `out` (capacity >= 96): 32-byte X25519 secret
/// followed by the 64-byte ML-KEM-768 seed (d||z).
#[no_mangle]
pub extern "C" fn evb_generate_umk(out: *mut u8, out_cap: u64, out_len: *mut u64) -> i32 {
    if out.is_null() || out_len.is_null() {
        set_err("null argument");
        return ERR_ARG;
    }
    match core::wrap::generate_umk() {
        Ok(umk) => {
            let mut bytes = [0u8; 96];
            bytes[..32].copy_from_slice(&umk.private_key_x25519);
            bytes[32..].copy_from_slice(&umk.seed_mlkem);
            let res = unsafe { write_out(out, out_cap, out_len, &bytes) };
            bytes.zeroize();
            res
        }
        Err(e) => err_of(&e),
    }
}

/// Derives the public keys of a UMK as canonical JSON:
/// `{ "publicKeyX25519": b64(32), "publicKeyMlkem": b64(1184) }` (NUL-terminated).
#[no_mangle]
pub extern "C" fn evb_umk_public_keys(
    umk_sk: *const u8,
    umk_seed: *const u8,
    out_json: *mut c_char,
    out_cap: u64,
) -> i32 {
    if umk_sk.is_null() || umk_seed.is_null() || out_json.is_null() {
        set_err("null argument");
        return ERR_ARG;
    }
    let umk = UmkSecrets {
        private_key_x25519: unsafe { slice(umk_sk, 32) }.try_into().unwrap(),
        seed_mlkem: unsafe { slice(umk_seed, 64) }.try_into().unwrap(),
    };
    let public = match umk.public() {
        Ok(p) => p,
        Err(e) => return err_of(&e),
    };
    let json = match serde_json::to_string(&serde_json::json!({
        "publicKeyX25519": core::wrap::b64_encode(&public.public_key_x25519),
        "publicKeyMlkem": core::wrap::b64_encode(&public.public_key_mlkem),
    })) {
        Ok(j) => j,
        Err(_) => {
            set_err("json serialization failed");
            return ERR_JSON;
        }
    };
    let bytes = json.as_bytes();
    if (out_cap as usize) < bytes.len() + 1 {
        set_err("output buffer too small");
        return ERR_BUF;
    }
    // Safety: capacity checked above.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr() as *const c_char, out_json, bytes.len());
        *out_json.add(bytes.len()) = 0;
    }
    OK
}

/// Seals the UMK under a recovery phrase (Argon2id v3, m=64 MiB t=2 p=1).
/// `salt` (16 B) and `nonce` (12 B) come from the caller's CSPRNG — see
/// `evb_random`. Output is the b64 blob (NUL-terminated; recommended
/// capacity 8192).
#[no_mangle]
pub extern "C" fn evb_wrap_umk_with_mnemonic(
    umk_sk: *const u8,
    umk_seed: *const u8,
    mnemonic: *const c_char,
    salt: *const u8,
    nonce: *const u8,
    out_blob: *mut c_char,
    out_cap: u64,
) -> i32 {
    if umk_sk.is_null()
        || umk_seed.is_null()
        || salt.is_null()
        || nonce.is_null()
        || out_blob.is_null()
    {
        set_err("null argument");
        return ERR_ARG;
    }
    let phrase = match read_str(mnemonic) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let umk = UmkSecrets {
        private_key_x25519: unsafe { slice(umk_sk, 32) }.try_into().unwrap(),
        seed_mlkem: unsafe { slice(umk_seed, 64) }.try_into().unwrap(),
    };
    let salt: [u8; 16] = unsafe { slice(salt, 16) }.try_into().unwrap();
    let nonce: [u8; 12] = unsafe { slice(nonce, 12) }.try_into().unwrap();
    match core::wrap::wrap_umk_with_mnemonic(&umk, &phrase, &salt, &nonce) {
        Ok(blob) => unsafe { write_nul_str(out_blob, out_cap, &blob) },
        Err(e) => err_of(&e),
    }
}

/// Seals the UMK under a 32-byte device secret (kept on the device).
/// Output is the b64 blob (NUL-terminated; recommended capacity 8192).
#[no_mangle]
pub extern "C" fn evb_wrap_umk_with_device_key(
    umk_sk: *const u8,
    umk_seed: *const u8,
    device_secret: *const u8,
    nonce: *const u8,
    out_blob: *mut c_char,
    out_cap: u64,
) -> i32 {
    if umk_sk.is_null()
        || umk_seed.is_null()
        || device_secret.is_null()
        || nonce.is_null()
        || out_blob.is_null()
    {
        set_err("null argument");
        return ERR_ARG;
    }
    let umk = UmkSecrets {
        private_key_x25519: unsafe { slice(umk_sk, 32) }.try_into().unwrap(),
        seed_mlkem: unsafe { slice(umk_seed, 64) }.try_into().unwrap(),
    };
    let secret: [u8; 32] = unsafe { slice(device_secret, 32) }.try_into().unwrap();
    let nonce: [u8; 12] = unsafe { slice(nonce, 12) }.try_into().unwrap();
    match core::wrap::wrap_umk_with_device_key(&umk, &secret, &nonce) {
        Ok(blob) => unsafe { write_nul_str(out_blob, out_cap, &blob) },
        Err(e) => err_of(&e),
    }
}

/// Seals the UMK under the login password (Argon2id m=64 MiB t=2 p=1, scheme
/// `evb-e2ee-umk-password-argon2id-m64-t2-p1-aesgcm`). `salt` (16 B) and
/// `nonce` (12 B) come from the caller's CSPRNG — see `evb_random`. Output is
/// the b64 blob (NUL-terminated; recommended capacity 8192).
#[no_mangle]
pub extern "C" fn evb_wrap_umk_with_password(
    umk_sk: *const u8,
    umk_seed: *const u8,
    password: *const c_char,
    salt: *const u8,
    nonce: *const u8,
    out_blob: *mut c_char,
    out_cap: u64,
) -> i32 {
    if umk_sk.is_null()
        || umk_seed.is_null()
        || salt.is_null()
        || nonce.is_null()
        || out_blob.is_null()
    {
        set_err("null argument");
        return ERR_ARG;
    }
    let password = match read_str(password) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let umk = UmkSecrets {
        private_key_x25519: unsafe { slice(umk_sk, 32) }.try_into().unwrap(),
        seed_mlkem: unsafe { slice(umk_seed, 64) }.try_into().unwrap(),
    };
    let salt: [u8; 16] = unsafe { slice(salt, 16) }.try_into().unwrap();
    let nonce: [u8; 12] = unsafe { slice(nonce, 12) }.try_into().unwrap();
    match core::wrap::wrap_umk_with_password(&umk, &password, &salt, &nonce) {
        Ok(blob) => unsafe { write_nul_str(out_blob, out_cap, &blob) },
        Err(e) => err_of(&e),
    }
}

/// Opens a password wrap produced by [`evb_wrap_umk_with_password`]. Output
/// is the 96-byte UMK written to `out_sk` (32) and `out_seed` (64).
#[no_mangle]
pub extern "C" fn evb_unwrap_umk_with_password(
    blob_b64: *const c_char,
    password: *const c_char,
    out_sk: *mut u8,
    out_seed: *mut u8,
) -> i32 {
    let blob = match read_str(blob_b64) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let password = match read_str(password) {
        Ok(s) => s,
        Err(code) => return code,
    };
    if out_sk.is_null() || out_seed.is_null() {
        set_err("null argument");
        return ERR_ARG;
    }
    match core::wrap::unwrap_umk_with_password(&blob, &password) {
        Ok(umk) => {
            let mut sk = umk.private_key_x25519;
            let mut seed = umk.seed_mlkem;
            // Safety: caller-provided buffers sized 32 / 64 by contract.
            unsafe {
                std::ptr::copy_nonoverlapping(sk.as_ptr(), out_sk, 32);
                std::ptr::copy_nonoverlapping(seed.as_ptr(), out_seed, 64);
            }
            sk.zeroize();
            seed.zeroize();
            OK
        }
        Err(e) => err_of(&e),
    }
}

/// Encrypts a display name under the DEK. Output is the b64 blob
/// `b64(nonce12 || ct || tag16)` (NUL-terminated); `nonce` is 12 random
/// bytes from the caller's CSPRNG.
#[no_mangle]
pub extern "C" fn evb_encrypt_file_name(
    dek: *const u8,
    real_name: *const c_char,
    nonce: *const u8,
    out_blob: *mut c_char,
    out_cap: u64,
) -> i32 {
    let Some(dek) = (unsafe { slice(dek, 32) }).try_into().ok() else {
        set_err("dek must be 32 bytes");
        return ERR_ARG;
    };
    let name = match read_str(real_name) {
        Ok(s) => s,
        Err(code) => return code,
    };
    if nonce.is_null() || out_blob.is_null() {
        set_err("null argument");
        return ERR_ARG;
    }
    let nonce: [u8; 12] = unsafe { slice(nonce, 12) }.try_into().unwrap();
    match core::names::encrypt_file_name(&dek, &name, &nonce) {
        Ok(blob) => unsafe { write_nul_str(out_blob, out_cap, &blob) },
        Err(e) => err_of(&e),
    }
}

/// Decrypts a display-name blob produced by [`evb_encrypt_file_name`].
/// Output is the UTF-8 name bytes (caller supplies a buffer; NOT
/// NUL-terminated — length is written to `out_len`).
#[no_mangle]
pub extern "C" fn evb_decrypt_file_name(
    dek: *const u8,
    blob_b64: *const c_char,
    out: *mut u8,
    out_cap: u64,
    out_len: *mut u64,
) -> i32 {
    let Some(dek) = (unsafe { slice(dek, 32) }).try_into().ok() else {
        set_err("dek must be 32 bytes");
        return ERR_ARG;
    };
    let blob = match read_str(blob_b64) {
        Ok(s) => s,
        Err(code) => return code,
    };
    if out.is_null() || out_len.is_null() {
        set_err("null argument");
        return ERR_ARG;
    }
    match core::names::decrypt_file_name(&dek, &blob) {
        Ok(name) => unsafe { write_out(out, out_cap, out_len, name.as_bytes()) },
        Err(e) => err_of(&e),
    }
}

/// CSPRNG fill: writes `len` random bytes into `out` (capacity >= len).
#[no_mangle]
pub extern "C" fn evb_random(len: u64, out: *mut u8, out_cap: u64, out_len: *mut u64) -> i32 {
    if out.is_null() || out_len.is_null() {
        set_err("null argument");
        return ERR_ARG;
    }
    if (out_cap as usize) < len as usize {
        set_err("output buffer too small");
        return ERR_BUF;
    }
    match core::keys::random_bytes(len as usize) {
        Ok(bytes) => unsafe { write_out(out, out_cap, out_len, &bytes) },
        Err(e) => err_of(&e),
    }
}

/// Copies `s` into `out` with a NUL terminator (capacity must fit len+1).
/// Safety: caller guarantees out/out_cap valid.
unsafe fn write_nul_str(out: *mut c_char, out_cap: u64, s: &str) -> i32 {
    let bytes = s.as_bytes();
    if (out_cap as usize) < bytes.len() + 1 {
        set_err("output buffer too small");
        return ERR_BUF;
    }
    // Safety: capacity checked above.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr() as *const c_char, out, bytes.len());
        *out.add(bytes.len()) = 0;
    }
    OK
}

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

/// Copies the last error message (secret-free) into `buf`. Returns 0 on
/// success, or `required_capacity` (>0) when the buffer is too small.
#[no_mangle]
pub extern "C" fn evb_last_error(buf: *mut c_char, cap: u64) -> i32 {
    if buf.is_null() {
        return ERR_ARG;
    }
    take_err(buf, cap)
}

/// Zeroizes the last error slot.
#[no_mangle]
pub extern "C" fn evb_clear_last_error() -> i32 {
    match LAST_ERROR.lock() {
        Ok(mut slot) => {
            *slot = None;
            OK
        }
        Err(_) => ERR_LOCK,
    }
}

#[cfg(test)]
mod c_abi_tests {
    use super::*;

    #[test]
    fn generate_umk_and_public_keys_roundtrip() {
        unsafe {
            let mut umk = [0u8; 96];
            let mut len = 0u64;
            assert_eq!(OK, evb_generate_umk(umk.as_mut_ptr(), 96, &mut len));
            assert_eq!(96, len);

            let mut json = [0u8; 2048];
            assert_eq!(
                OK,
                evb_umk_public_keys(
                    umk.as_ptr(),
                    umk.as_ptr().add(32),
                    json.as_mut_ptr() as *mut c_char,
                    2048,
                )
            );
            let nul = json.iter().position(|b| *b == 0).unwrap();
            let json = std::str::from_utf8(&json[..nul]).unwrap();
            assert!(json.contains("publicKeyX25519"));
            assert!(json.contains("publicKeyMlkem"));
        }
    }

    #[test]
    fn mnemonic_and_device_wrap_roundtrip_through_c() {
        unsafe {
            let mut umk = [0u8; 96];
            let mut len = 0u64;
            assert_eq!(OK, evb_generate_umk(umk.as_mut_ptr(), 96, &mut len));

            let mut salt = [0u8; 16];
            let mut nonce = [0u8; 12];
            assert_eq!(OK, evb_random(16, salt.as_mut_ptr(), 16, &mut len));
            assert_eq!(OK, evb_random(12, nonce.as_mut_ptr(), 12, &mut len));

            let phrase = c"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
            let mut blob = [0u8; 4096];
            assert_eq!(
                OK,
                evb_wrap_umk_with_mnemonic(
                    umk.as_ptr(),
                    umk.as_ptr().add(32),
                    phrase.as_ptr(),
                    salt.as_ptr(),
                    nonce.as_ptr(),
                    blob.as_mut_ptr() as *mut c_char,
                    4096,
                )
            );
            assert!(blob[..16].iter().any(|b| *b != 0));

            let device_secret = [7u8; 32];
            let mut device_nonce = [0u8; 12];
            assert_eq!(OK, evb_random(12, device_nonce.as_mut_ptr(), 12, &mut len));
            let mut device_blob = [0u8; 4096];
            assert_eq!(
                OK,
                evb_wrap_umk_with_device_key(
                    umk.as_ptr(),
                    umk.as_ptr().add(32),
                    device_secret.as_ptr(),
                    device_nonce.as_ptr(),
                    device_blob.as_mut_ptr() as *mut c_char,
                    4096,
                )
            );
            assert!(device_blob[..32].iter().any(|b| *b != 0));
        }
    }

    #[test]
    fn file_name_encrypt_decrypt_roundtrip_through_c() {
        unsafe {
            let dek = [3u8; 32];
            let mut nonce = [0u8; 12];
            let mut len = 0u64;
            assert_eq!(OK, evb_random(12, nonce.as_mut_ptr(), 12, &mut len));

            let mut blob = [0u8; 512];
            let name = c"budget 2026 (final).xlsx";
            assert_eq!(
                OK,
                evb_encrypt_file_name(
                    dek.as_ptr(),
                    name.as_ptr(),
                    nonce.as_ptr(),
                    blob.as_mut_ptr() as *mut c_char,
                    512,
                )
            );
            let nul = blob.iter().position(|b| *b == 0).unwrap();
            let blob = std::str::from_utf8(&blob[..nul]).unwrap();

            let mut out = [0u8; 256];
            assert_eq!(
                OK,
                evb_decrypt_file_name(
                    dek.as_ptr(),
                    blob.as_ptr() as *const c_char,
                    out.as_mut_ptr(),
                    256,
                    &mut len,
                )
            );
            assert_eq!(&out[..len as usize], name.to_bytes());
        }
    }

    #[test]
    fn wrap_dek_and_unwrap_through_c() {
        unsafe {
            let mut umk = [0u8; 96];
            let mut len = 0u64;
            assert_eq!(OK, evb_generate_umk(umk.as_mut_ptr(), 96, &mut len));

            let mut json = [0u8; 2048];
            assert_eq!(
                OK,
                evb_umk_public_keys(
                    umk.as_ptr(),
                    umk.as_ptr().add(32),
                    json.as_mut_ptr() as *mut c_char,
                    2048,
                )
            );
            let nul = json.iter().position(|b| *b == 0).unwrap();
            let json_str = std::str::from_utf8(&json[..nul]).unwrap();
            let v: serde_json::Value = serde_json::from_str(json_str).unwrap();
            let pk_x = base64_decode(v["publicKeyX25519"].as_str().unwrap());
            let pk_k = base64_decode(v["publicKeyMlkem"].as_str().unwrap());

            let dek = [5u8; 32];
            let mut env = [0u8; 4096];
            assert_eq!(
                OK,
                evb_wrap_dek_to_umk(
                    dek.as_ptr(),
                    pk_x.as_ptr(),
                    pk_k.as_ptr(),
                    env.as_mut_ptr() as *mut c_char,
                    4096,
                )
            );
            let nul = env.iter().position(|b| *b == 0).unwrap();
            let env = std::str::from_utf8(&env[..nul]).unwrap();

            let mut dek_back = [0u8; 32];
            assert_eq!(
                OK,
                evb_unwrap_dek_from_umk(
                    env.as_ptr() as *const c_char,
                    umk.as_ptr(),
                    umk.as_ptr().add(32),
                    dek_back.as_mut_ptr(),
                    32,
                    &mut len,
                )
            );
            assert_eq!(dek_back, dek);
        }
    }

    fn base64_decode(input: &str) -> Vec<u8> {
        const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = Vec::new();
        let mut buf = 0u32;
        let mut bits = 0;
        for b in input.bytes().filter(|b| *b != b'=') {
            let v = T.iter().position(|c| *c == b).expect("valid b64") as u32;
            buf = (buf << 6) | v;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((buf >> bits) as u8);
            }
        }
        out
    }
}

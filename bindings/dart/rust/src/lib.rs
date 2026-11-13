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

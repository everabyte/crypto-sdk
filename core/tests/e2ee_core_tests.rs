//! Integration tests for the Everabyte E2EE core.
//!
//! Coverage: EVB1 content roundtrips (streaming + one-shot, chunk boundaries,
//! empty file), header/payload corruption, wrong keys, wraps (file DEK,
//! link, invite, UMK mnemonic, UMK device), encrypted names, mnemonic
//! normalization and validation.

use evb_e2ee_core::content::{self, Evb1Decryptor, Evb1Encryptor, HEADER_LEN};
use evb_e2ee_core::error::E2eeError;
use evb_e2ee_core::keys::{generate_dek, UmkPublic, UmkSecrets, DEK_LEN, NONCE_LEN, TAG_LEN};
use evb_e2ee_core::mnemonic::{normalize_mnemonic, validate_bip39_english};
#[cfg(feature = "deterministic-vectors")]
use evb_e2ee_core::vectors;
use evb_e2ee_core::names;
use evb_e2ee_core::wrap;

// ---------------------------------------------------------------------------
// Fixed test material (do not rely on OS RNG for roundtrip assertions).
// ---------------------------------------------------------------------------

fn fixed(bytes_len: usize, mul: u8, add: u8) -> Vec<u8> {
    (0..bytes_len).map(|i| (i as u8).wrapping_mul(mul).wrapping_add(add)).collect()
}

fn fixed32(mul: u8, add: u8) -> [u8; 32] {
    fixed(32, mul, add).try_into().unwrap()
}

fn fixed_umk() -> UmkSecrets {
    UmkSecrets {
        private_key_x25519: fixed32(11, 2),
        seed_mlkem: fixed(64, 13, 3).try_into().unwrap(),
    }
}

fn fixed_other_umk() -> UmkSecrets {
    UmkSecrets {
        private_key_x25519: fixed32(3, 5),
        seed_mlkem: fixed(64, 7, 1).try_into().unwrap(),
    }
}

fn pattern(len: usize) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut out = Vec::with_capacity(len);
    let mut i: u64 = 0;
    while out.len() < len {
        let mut h = Sha256::new();
        h.update(b"EVB-VECTOR");
        h.update(i.to_be_bytes());
        let block = h.finalize();
        let take = (len - out.len()).min(32);
        out.extend_from_slice(&block[..take]);
        i += 1;
    }
    out
}

// ---------------------------------------------------------------------------
// EVB1 content: roundtrips
// ---------------------------------------------------------------------------

#[test]
fn content_roundtrip_empty_file_single_empty_chunk() {
    let dek = fixed32(7, 1);
    let nonce = fixed(12, 31, 0).try_into().unwrap();
    let ct = Evb1Encryptor::seal_all(&dek, nonce, b"").unwrap();

    // empty file => header + exactly one tag over an empty plaintext chunk
    assert_eq!(ct.len(), content::HEADER_LEN + 16);
    let pt = Evb1Decryptor::open_all(&dek, &ct).unwrap();
    assert!(pt.is_empty());
    assert_eq!(content::ciphertext_len_for(0), ct.len());
}

#[test]
fn content_roundtrip_chunk_boundaries() {
    let dek = fixed32(7, 1);
    let nonce: [u8; NONCE_LEN] = fixed(12, 31, 0).try_into().unwrap();

    for len in [1usize, 63, 64, 65535, 65536, 65537, 131072, 131077] {
        let pt = pattern(len);
        let ct = Evb1Encryptor::seal_all(&dek, nonce, &pt).unwrap();
        assert_eq!(ct.len(), content::ciphertext_len_for(len), "len {len}");
        let rt = Evb1Decryptor::open_all(&dek, &ct).unwrap();
        assert_eq!(rt, pt, "roundtrip len {len}");
    }
}

#[test]
fn content_roundtrip_streaming_push_in_pieces() {
    // Feed plaintext in awkward piece sizes; output must equal one-shot seal.
    let dek = fixed32(9, 4);
    let nonce: [u8; NONCE_LEN] = fixed(12, 17, 9).try_into().unwrap();
    let pt = pattern(200_000);

    let one_shot = Evb1Encryptor::seal_all(&dek, nonce, &pt).unwrap();

    let mut enc = Evb1Encryptor::new(&dek, nonce);
    let mut ct = Vec::new();
    ct.extend_from_slice(&enc.header());
    for piece in pt.chunks(10_000) {
        ct.extend_from_slice(&enc.push(piece).unwrap());
    }
    ct.extend_from_slice(&enc.finish().unwrap());
    assert_eq!(ct, one_shot);

    // Decrypt in awkward piece sizes too.
    let mut dec = Evb1Decryptor::new(&dek, nonce);
    assert!(dec.push(&ct[HEADER_LEN..HEADER_LEN + 7]).unwrap().is_empty());
    let mut out = dec.push(&ct[HEADER_LEN + 7..]).unwrap();
    out.extend_from_slice(&dec.finish().unwrap());
    assert_eq!(out, pt);
}

#[test]
fn content_header_and_wire_sizes() {
    let dek = fixed32(1, 1);
    let nonce: [u8; NONCE_LEN] = fixed(12, 2, 2).try_into().unwrap();
    let enc = Evb1Encryptor::new(&dek, nonce);
    let header = enc.header();
    assert_eq!(&header[..4], b"EVB1");
    assert_eq!(&header[4..16], &nonce[..]);
    assert_eq!(HEADER_LEN, 16);
    assert_eq!(content::CHUNK_SIZE, 64 * 1024);
    assert_eq!(content::CHUNK_BLOCK_LEN, 64 * 1024 + 16);
}

// ---------------------------------------------------------------------------
// EVB1 content: header errors
// ---------------------------------------------------------------------------

#[test]
fn content_rejects_bad_magic_and_short_header() {
    let dek = fixed32(7, 1);
    let mut ct = Evb1Encryptor::seal_all(&dek, [0u8; 12], b"hello").unwrap();
    ct[0] = b'X';
    match Evb1Decryptor::open_all(&dek, &ct) {
        Err(E2eeError::InvalidPayload(_)) => {}
        other => panic!("expected InvalidPayload for bad magic, got {other:?}"),
    }

    let too_short = vec![0u8; HEADER_LEN - 1];
    assert!(matches!(content::parse_header(&too_short), Err(E2eeError::InvalidPayload(_))));
    let too_long = vec![0u8; HEADER_LEN + 1];
    assert!(matches!(content::parse_header(&too_long), Err(E2eeError::InvalidPayload(_))));
    let mut bad_magic = vec![0u8; HEADER_LEN];
    assert!(matches!(content::parse_header(&bad_magic), Err(E2eeError::InvalidPayload(_))));
    bad_magic[..4].copy_from_slice(&content::MAGIC);
    assert!(content::parse_header(&bad_magic).is_ok());
}

#[test]
fn content_rejects_truncated_and_trailing_garbage() {
    let dek = fixed32(7, 1);
    let nonce: [u8; NONCE_LEN] = fixed(12, 31, 0).try_into().unwrap();
    let pt = pattern(150_000);
    let mut ct = Evb1Encryptor::seal_all(&dek, nonce, &pt).unwrap();

    // Truncated ciphertext (missing final chunk bytes).
    match Evb1Decryptor::open_all(&dek, &ct[..ct.len() - 10]) {
        Err(E2eeError::InvalidPayload(_) | E2eeError::DecryptFailure) => {}
        other => panic!("expected error for truncated payload, got {other:?}"),
    }

    // Trailing garbage after the final chunk.
    let mut with_garbage = ct.clone();
    with_garbage.extend_from_slice(&[0u8; 8]);
    // push() sees a partial trailing block; finish() must reject or fail auth.
    let mut dec = Evb1Decryptor::new(&dek, nonce);
    assert!(dec.push(&with_garbage[HEADER_LEN..]).is_ok());
    assert!(dec.finish().is_err());

    // Too short overall.
    assert!(Evb1Decryptor::open_all(&dek, &ct[..HEADER_LEN - 1]).is_err());

    // Corrupt the tag of the last chunk => auth failure.
    let last = ct.len() - TAG_LEN;
    ct[last] ^= 0x01;
    match Evb1Decryptor::open_all(&dek, &ct) {
        Err(E2eeError::DecryptFailure) => {}
        other => panic!("expected DecryptFailure for corrupted tag, got {other:?}"),
    }
}

#[test]
fn content_rejects_wrong_dek_and_tampered_ciphertext() {
    let dek = fixed32(7, 1);
    let nonce: [u8; NONCE_LEN] = fixed(12, 31, 0).try_into().unwrap();
    let pt = pattern(70_000);
    let mut ct = Evb1Encryptor::seal_all(&dek, nonce, &pt).unwrap();

    // Wrong key.
    let wrong_dek = fixed32(7, 2);
    match Evb1Decryptor::open_all(&wrong_dek, &ct) {
        Err(E2eeError::DecryptFailure) => {}
        other => panic!("expected DecryptFailure for wrong dek, got {other:?}"),
    }

    // Bit flip in ciphertext body (not tag): nonce reuse protection aside,
    // this must fail authentication.
    let mid = HEADER_LEN + 100;
    ct[mid] ^= 0x40;
    match Evb1Decryptor::open_all(&dek, &ct) {
        Err(E2eeError::DecryptFailure) => {}
        other => panic!("expected DecryptFailure for bit flip, got {other:?}"),
    }
}

#[test]
fn content_state_errors() {
    let dek = fixed32(7, 1);
    let nonce = [0u8; NONCE_LEN];

    let mut enc = Evb1Encryptor::new(&dek, nonce);
    let _ = enc.push(b"data").unwrap();
    let _ = enc.finish().unwrap();
    assert!(matches!(enc.finish(), Err(E2eeError::InvalidInput(_))));
    assert!(matches!(enc.push(b"more"), Err(E2eeError::InvalidInput(_))));

    let mut dec = Evb1Decryptor::new(&dek, nonce);
    let _ = dec.push(&[0u8; 64]).unwrap();
    let _ = dec.finish().unwrap_err(); // garbage block fails auth
    assert!(matches!(dec.finish(), Err(E2eeError::InvalidInput(_))));
}

// ---------------------------------------------------------------------------
// File DEK wrap (X25519 + ML-KEM-768 -> HKDF -> AES-GCM)
// ---------------------------------------------------------------------------

#[test]
fn file_dek_wrap_roundtrip_and_malformed() {
    let umk = fixed_umk();
    let pubk = umk.public().unwrap();
    let dek: [u8; DEK_LEN] = fixed32(7, 1);
    let nonce: [u8; NONCE_LEN] = fixed(12, 31, 0).try_into().unwrap();
    let eph_sk: [u8; 32] = fixed32(17, 4);

    let env = wrap::wrap_dek_to_umk_with(&dek, &pubk, &eph_sk, &nonce).unwrap();
    // ML-KEM encapsulation uses internal randomness (like the web client via
    // noble): two wraps of the same inputs differ, but both unwrap correctly.
    let env2 = wrap::wrap_dek_to_umk_with(&dek, &pubk, &eph_sk, &nonce).unwrap();
    assert_ne!(env, env2);
    assert_eq!(wrap::unwrap_dek_from_umk(&env2, &umk).unwrap(), dek);

    let rt = wrap::unwrap_dek_from_umk(&env, &umk).unwrap();
    assert_eq!(rt, dek);

    // Wrong recipient UMK => auth failure.
    let other = fixed_other_umk();
    assert!(matches!(
        wrap::unwrap_dek_from_umk(&env, &other),
        Err(E2eeError::AuthFailure)
    ));

    // Tampered wrappedDek => auth failure.
    let mut tampered = env.clone();
    let mut raw = wrap::b64_decode(&tampered.wrapped_dek).unwrap();
    raw[0] ^= 1;
    tampered.wrapped_dek = wrap::b64_encode(&raw);
    assert!(matches!(
        wrap::unwrap_dek_from_umk(&tampered, &umk),
        Err(E2eeError::AuthFailure)
    ));

    // Malformed envelopes: bad base64, bad sizes.
    let bad_b64 = wrap::FileEnvelope {
        eph_public_x25519: "!!!not base64!!!".into(),
        ..env.clone()
    };
    assert!(wrap::unwrap_dek_from_umk(&bad_b64, &umk).is_err());
    let bad_size = wrap::FileEnvelope {
        eph_public_x25519: wrap::b64_encode(&[0u8; 31]),
        ..env.clone()
    };
    assert!(matches!(
        wrap::unwrap_dek_from_umk(&bad_size, &umk),
        Err(E2eeError::InvalidPayload(_))
    ));
    let bad_ct_size = wrap::FileEnvelope {
        kem_ciphertext: wrap::b64_encode(&[0u8; 1087]),
        ..env
    };
    assert!(matches!(
        wrap::unwrap_dek_from_umk(&bad_ct_size, &umk),
        Err(E2eeError::InvalidPayload(_))
    ));
}

#[test]
fn file_dek_wrap_rejects_bad_ml_kem_public_key() {
    let dek: [u8; DEK_LEN] = fixed32(7, 1);
    let nonce = [0u8; NONCE_LEN];
    let eph_sk: [u8; 32] = fixed32(17, 4);
    let bad_pub = UmkPublic::from_parts(fixed32(2, 2), vec![0u8; 1183]);
    assert!(bad_pub.is_err());

    let pubk = fixed_umk().public().unwrap();
    let good = wrap::wrap_dek_to_umk_with(&dek, &pubk, &eph_sk, &nonce).unwrap();
    assert!(wrap::unwrap_dek_from_umk(&good, &fixed_umk()).is_ok());
}

#[test]
fn file_dek_wrap_random_version_differs() {
    // Two random wraps of the same DEK must produce different envelopes.
    let umk = fixed_umk();
    let pubk = umk.public().unwrap();
    let dek: [u8; DEK_LEN] = fixed32(7, 1);
    let a = wrap::wrap_dek_to_umk(&dek, &pubk).unwrap();
    let b = wrap::wrap_dek_to_umk(&dek, &pubk).unwrap();
    assert_ne!(a, b);
    let a_json = serde_json::to_string(&a).unwrap();
    let b_json = serde_json::to_string(&b).unwrap();
    assert_eq!(wrap::unwrap_dek_from_umk_json(&a_json, &umk).unwrap(), dek);
    assert_eq!(wrap::unwrap_dek_from_umk_json(&b_json, &umk).unwrap(), dek);
}

// ---------------------------------------------------------------------------
// Symmetric wraps: link key + invite key share
// ---------------------------------------------------------------------------

#[test]
fn link_and_invite_wrap_roundtrip_and_wrong_key() {
    let dek: [u8; DEK_LEN] = fixed32(7, 1);
    let nonce: [u8; NONCE_LEN] = fixed(12, 31, 0).try_into().unwrap();
    let link_key = fixed32(37, 8);
    let invite_key = fixed32(41, 9);

    let lw = wrap::wrap_dek_with_link_key(&dek, &link_key, &nonce).unwrap();
    assert_eq!(wrap::unwrap_dek_with_link_key(&lw, &link_key).unwrap(), dek);
    let wrong = fixed32(1, 1);
    assert!(matches!(
        wrap::unwrap_dek_with_link_key(&lw, &wrong),
        Err(E2eeError::AuthFailure)
    ));

    let iw = wrap::wrap_dek_with_invite_key(&dek, &invite_key, &nonce).unwrap();
    assert_eq!(wrap::unwrap_dek_with_invite_key(&iw, &invite_key).unwrap(), dek);
    assert!(matches!(
        wrap::unwrap_dek_with_invite_key(&iw, &wrong),
        Err(E2eeError::AuthFailure)
    ));

    // Tampered ciphertext.
    let mut raw = wrap::b64_decode(&lw.wrapped_dek).unwrap();
    raw[5] ^= 0x08;
    let tampered = wrap::SymmetricWrap {
        wrapped_dek: wrap::b64_encode(&raw),
        nonce: lw.nonce.clone(),
    };
    assert!(matches!(
        wrap::unwrap_dek_with_link_key(&tampered, &link_key),
        Err(E2eeError::AuthFailure)
    ));
}

// ---------------------------------------------------------------------------
// UMK mnemonic wrap
// ---------------------------------------------------------------------------

#[test]
fn umk_mnemonic_wrap_roundtrip_and_normalization_variants() {
    let umk = fixed_umk();
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    validate_bip39_english(mnemonic).unwrap();
    let salt16: [u8; 16] = fixed(16, 23, 6).try_into().unwrap();
    let nonce: [u8; NONCE_LEN] = fixed(12, 31, 0).try_into().unwrap();

    let blob = wrap::wrap_umk_with_mnemonic(&umk, mnemonic, &salt16, &nonce).unwrap();

    // The same phrase in different presentation must unwrap identically:
    // uppercase, extra whitespace, mixed spacing.
    let variants = [
        mnemonic.to_uppercase(),
        format!("  {mnemonic}  "),
        mnemonic.replace(' ', "  \t "),
    ];
    for v in variants {
        let rt = wrap::unwrap_umk_with_mnemonic(&blob, &v).unwrap();
        assert_eq!(rt.private_key_x25519, umk.private_key_x25519);
        assert_eq!(rt.seed_mlkem, umk.seed_mlkem);
    }

    // Wrong mnemonic => auth failure.
    let wrong = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
    assert!(matches!(
        wrap::unwrap_umk_with_mnemonic(&blob, wrong),
        Err(E2eeError::AuthFailure)
    ));

    // Tampered blob => auth failure.
    let raw = wrap::b64_decode(&blob).unwrap();
    let mut bad = raw.clone();
    let n = bad.len();
    bad[n - 1] ^= 1;
    assert!(matches!(
        wrap::unwrap_umk_with_mnemonic(&wrap::b64_encode(&bad), mnemonic),
        Err(E2eeError::AuthFailure)
    ));

    // Too-short blob.
    let short = wrap::b64_encode(&[0u8; 32]);
    assert!(matches!(
        wrap::unwrap_umk_with_mnemonic(&short, mnemonic),
        Err(E2eeError::InvalidPayload(_))
    ));
}

#[test]
fn umk_password_wrap_roundtrip_and_kind_isolation() {
    let umk = fixed_umk();
    let salt16: [u8; 16] = fixed(16, 41, 3).try_into().unwrap();
    let nonce: [u8; NONCE_LEN] = fixed(12, 47, 9).try_into().unwrap();

    let password = "correct horse battery staple  ";
    let blob = wrap::wrap_umk_with_password(&umk, password, &salt16, &nonce).unwrap();

    // Trimmed/untrimmed variants unwrap identically (mirror of localUmkCache).
    for v in ["correct horse battery staple", "  correct horse battery staple"] {
        let rt = wrap::unwrap_umk_with_password(&blob, v).unwrap();
        assert_eq!(rt.private_key_x25519, umk.private_key_x25519);
        assert_eq!(rt.seed_mlkem, umk.seed_mlkem);
    }

    // Wrong password => auth failure; tampered blob too.
    assert!(matches!(
        wrap::unwrap_umk_with_password(&blob, "wrong password"),
        Err(E2eeError::AuthFailure)
    ));
    let raw = wrap::b64_decode(&blob).unwrap();
    let mut bad = raw.clone();
    let n = bad.len();
    bad[n - 1] ^= 1;
    assert!(matches!(
        wrap::unwrap_umk_with_password(&wrap::b64_encode(&bad), password),
        Err(E2eeError::AuthFailure)
    ));

    // Kind isolation: a password blob never opens through the mnemonic
    // unwrap (payload scheme id rejected), even with the same string.
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let same_string = wrap::wrap_umk_with_password(&umk, mnemonic, &salt16, &nonce).unwrap();
    assert!(matches!(
        wrap::unwrap_umk_with_mnemonic(&same_string, mnemonic),
        Err(E2eeError::UnsupportedWrapScheme(_))
    ));
    // And a mnemonic blob never opens through the password unwrap.
    let mnemonic_blob = wrap::wrap_umk_with_mnemonic(&umk, mnemonic, &salt16, &nonce).unwrap();
    assert!(matches!(
        wrap::unwrap_umk_with_password(&mnemonic_blob, mnemonic),
        Err(E2eeError::UnsupportedWrapScheme(_))
    ));
}

#[test]
fn umk_wrap_rejects_tampered_public_keys() {
    // Tamper with the stored public keys inside the wrap payload: the
    // private/public cross-check must reject.
    let umk = fixed_umk();
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let salt16 = [0u8; 16];
    let nonce = [0u8; NONCE_LEN];
    let blob = wrap::wrap_umk_with_mnemonic(&umk, mnemonic, &salt16, &nonce).unwrap();

    let raw = wrap::b64_decode(&blob).unwrap();
    // payload = salt16 || iv12 || ct || tag ; decrypt manually to tamper JSON.
    // The default wrap is Argon2id v3 (m64-t2-p1) — re-derive the same KEK.
    let ct_tag = &raw[28..];
    let key = argon2id_kek_repro(mnemonic, &salt16, 65_536, 2, 1);
    let plain = gcm_open_repro(&key, &raw[16..28], ct_tag).unwrap();
    let mut doc: serde_json::Value = serde_json::from_slice(&plain).unwrap();
    doc["publicKeyX25519"] = serde_json::Value::String(wrap::b64_encode(&fixed32(9, 9)));
    let tampered_plain = serde_json::to_vec(&doc).unwrap();
    let new_ct = gcm_seal_repro(&key, &raw[16..28], &tampered_plain);
    let mut new_blob = raw[..28].to_vec();
    new_blob.extend_from_slice(&new_ct);
    assert!(matches!(
        wrap::unwrap_umk_with_mnemonic(&wrap::b64_encode(&new_blob), mnemonic),
        Err(E2eeError::InvalidPayload(_))
    ));
}

// ---------------------------------------------------------------------------
// UMK mnemonic wrap: Argon2id v3 + legacy PBKDF2 read-only
// ---------------------------------------------------------------------------

#[test]
fn umk_mnemonic_argon2id_v3_roundtrip_and_scheme_id() {
    let umk = fixed_umk();
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let salt16: [u8; 16] = fixed(16, 41, 1).try_into().unwrap();
    let nonce: [u8; NONCE_LEN] = fixed(12, 43, 0).try_into().unwrap();

    // Default wrap is Argon2id m64-t2-p1 (v3) and carries its scheme id.
    let blob = wrap::wrap_umk_with_mnemonic(&umk, mnemonic, &salt16, &nonce).unwrap();
    let raw = wrap::b64_decode(&blob).unwrap();
    let key = argon2id_kek_repro(mnemonic, &salt16, 65_536, 2, 1);
    let plain = gcm_open_repro(&key, &raw[16..28], &raw[28..]).unwrap();
    let doc: serde_json::Value = serde_json::from_slice(&plain).unwrap();
    assert_eq!(doc["v"], 3);
    assert_eq!(doc["scheme"], wrap::UMK_WRAP_SCHEME_ARGON2ID_V3);
    let opened = wrap::unwrap_umk_with_mnemonic(&blob, mnemonic).unwrap();
    assert_eq!(opened.private_key_x25519, umk.private_key_x25519);
    assert_eq!(opened.seed_mlkem, umk.seed_mlkem);
}

#[test]
fn umk_mnemonic_rfc9106_profile_roundtrip() {
    let umk = fixed_umk();
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let salt16: [u8; 16] = fixed(16, 47, 2).try_into().unwrap();
    let nonce: [u8; NONCE_LEN] = fixed(12, 53, 0).try_into().unwrap();

    // RFC 9106 low-memory profile (m=64 MiB, t=3, p=4) — explicit params,
    // versioned scheme id, readable by the same versioned unwrap.
    let blob = wrap::wrap_umk_with_mnemonic_params(&umk, mnemonic, &salt16, &nonce, 65_536, 3, 4).unwrap();
    let raw = wrap::b64_decode(&blob).unwrap();
    let key = argon2id_kek_repro(mnemonic, &salt16, 65_536, 3, 4);
    let plain = gcm_open_repro(&key, &raw[16..28], &raw[28..]).unwrap();
    let doc: serde_json::Value = serde_json::from_slice(&plain).unwrap();
    assert_eq!(doc["scheme"], wrap::UMK_WRAP_SCHEME_ARGON2ID_RFC9106);
    let opened = wrap::unwrap_umk_with_mnemonic(&blob, mnemonic).unwrap();
    assert_eq!(opened.private_key_x25519, umk.private_key_x25519);

    // Parameters without a versioned scheme id are refused at wrap time.
    assert!(matches!(
        wrap::wrap_umk_with_mnemonic_params(&umk, mnemonic, &salt16, &nonce, 65_536, 9, 1),
        Err(E2eeError::InvalidInput(_))
    ));
}

#[cfg(feature = "deterministic-vectors")]
#[test]
fn umk_mnemonic_pbkdf2_is_read_only() {
    let umk = fixed_umk();
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let salt16: [u8; 16] = fixed(16, 23, 6).try_into().unwrap();
    let nonce: [u8; NONCE_LEN] = fixed(12, 31, 0).try_into().unwrap();

    // A legacy v2 PBKDF2 blob still opens through the versioned unwrap.
    let legacy = vectors::pbkdf2_wrap_umk_for_vectors(&umk, mnemonic, &salt16, &nonce).unwrap();
    let opened = wrap::unwrap_umk_with_mnemonic(&legacy, mnemonic).unwrap();
    assert_eq!(opened.private_key_x25519, umk.private_key_x25519);

    // And through the explicit legacy-only function.
    let opened = wrap::unwrap_umk_with_mnemonic_pbkdf2(&legacy, mnemonic).unwrap();
    assert_eq!(opened.seed_mlkem, umk.seed_mlkem);
}

// Latency measurement (run explicitly: cargo test --release -- --ignored --nocapture).
// Documents the on-device cost of the v3 unwrap: the happy path hits the
// first candidate (default profile); a wrong phrase pays all three.
#[test]
#[ignore]
fn latency_argon2id_unwrap_profiles() {
    use std::time::Instant;

    let umk = fixed_umk();
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let salt16: [u8; 16] = fixed(16, 41, 1).try_into().unwrap();
    let nonce: [u8; NONCE_LEN] = fixed(12, 43, 0).try_into().unwrap();

    let blob_v3 = wrap::wrap_umk_with_mnemonic(&umk, mnemonic, &salt16, &nonce).unwrap();
    let blob_rfc = wrap::wrap_umk_with_mnemonic_params(&umk, mnemonic, &salt16, &nonce, 65_536, 3, 4).unwrap();

    let measure = |label: &str, blob: &str, phrase: &str| {
        let times: Vec<u128> = (0..5)
            .map(|_| {
                let t0 = Instant::now();
                let _ = wrap::unwrap_umk_with_mnemonic(blob, phrase);
                t0.elapsed().as_millis()
            })
            .collect();
        let mut sorted = times.clone();
        sorted.sort();
        println!("{label}: median {} ms (runs {:?})", sorted[2], times);
    };

    measure("v3 m64-t2-p1 happy path (1st candidate)", &blob_v3, mnemonic);
    measure("v3 m64-t2-p1 wrong phrase (3 candidates)", &blob_v3, "wrong phrase");
    measure("RFC9106 m64-t3-p4 happy path (2nd candidate)", &blob_rfc, mnemonic);
}

// ---------------------------------------------------------------------------
// DEK wrap v2: HPKE (RFC 9180 strict) + legacy v1 read-only dispatch
// ---------------------------------------------------------------------------

#[test]
fn hpke_v2_wrap_roundtrip_and_version_dispatch() {
    let umk = fixed_umk();
    let pubk = umk.public().unwrap();
    let dek = fixed32(5, 50);
    let ephem_seed: [u8; 32] = fixed32(6, 60);
    let mlkem_seed: [u8; 32] = fixed32(7, 70);

    // Deterministic HPKE wrap.
    let env = evb_e2ee_core::hpke::wrap_dek_to_umk_hpke_with(&dek, &pubk, &ephem_seed, &mlkem_seed).unwrap();
    let json = serde_json::to_string(&env).unwrap();
    assert_eq!(env.v, 2);
    assert_eq!(env.scheme, "evb-e2ee-file-wrap-hpke-psk-v1");
    assert_eq!(env.kem_id, 0x0020);
    assert_eq!(env.kdf_id, 0x0001);
    assert_eq!(env.aead_id, 0x0003);

    // The JSON dispatcher opens v2 (HPKE).
    let opened = wrap::unwrap_dek_from_umk_json(&json, &umk).unwrap();
    assert_eq!(opened, dek);

    // Determinism: same seeds -> byte-identical envelope.
    let env2 = evb_e2ee_core::hpke::wrap_dek_to_umk_hpke_with(&dek, &pubk, &ephem_seed, &mlkem_seed).unwrap();
    assert_eq!(env, env2);

    // Legacy v1 envelope still opens through the same dispatcher.
    let legacy = wrap::wrap_dek_to_umk_legacy(&dek, &pubk).unwrap();
    let legacy_json = serde_json::to_string(&legacy).unwrap();
    let opened_v1 = wrap::unwrap_dek_from_umk_json(&legacy_json, &umk).unwrap();
    assert_eq!(opened_v1, dek);

    // A foreign UMK fails authentication on both versions.
    let foreign = fixed_other_umk();
    assert!(matches!(
        wrap::unwrap_dek_from_umk_json(&json, &foreign),
        Err(E2eeError::AuthFailure)
    ));

    // Ciphersuite mismatch is rejected (not silently reinterpreted).
    let mut tampered = env.clone();
    tampered.aead_id = 0x0002; // ChaCha20Poly1305 — not our suite
    assert!(matches!(
        evb_e2ee_core::hpke::unwrap_dek_from_umk_hpke(&tampered, &umk),
        Err(E2eeError::InvalidPayload(_))
    ));
}

// Reproduction helpers (test-only, same primitives as wrap.rs).
fn pbkdf2_repro(mnemonic: &str, salt: &[u8]) -> [u8; 32] {
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha512;
    let mut out = [0u8; 32];
    pbkdf2_hmac::<Sha512>(normalize_mnemonic(mnemonic).as_bytes(), salt, 100_000, &mut out);
    out
}

fn argon2id_kek_repro(mnemonic: &str, salt: &[u8], m_kib: u32, t: u32, p: u32) -> [u8; 32] {
    let params = argon2::Params::new(m_kib, t, p, Some(32)).unwrap();
    let a2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = [0u8; 32];
    a2.hash_password_into(normalize_mnemonic(mnemonic).as_bytes(), salt, &mut out)
        .unwrap();
    out
}

fn gcm_open_repro(key: &[u8; 32], nonce: &[u8], ct_tag: &[u8]) -> Result<Vec<u8>, ()> {
    use aes_gcm::aead::{Aead, Payload};
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| ())?;
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct_tag, aad: &[] })
        .map_err(|_| ())
}

fn gcm_seal_repro(key: &[u8; 32], nonce: &[u8], plaintext: &[u8]) -> Vec<u8> {
    use aes_gcm::aead::{Aead, Payload};
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    let cipher = Aes256Gcm::new_from_slice(key).unwrap();
    cipher
        .encrypt(Nonce::from_slice(nonce), Payload { msg: plaintext, aad: &[] })
        .unwrap()
}

// ---------------------------------------------------------------------------
// UMK device wrap
// ---------------------------------------------------------------------------

#[test]
fn umk_device_wrap_roundtrip_and_wrong_secret() {
    let umk = fixed_umk();
    let device_secret = fixed32(29, 7);
    let nonce: [u8; NONCE_LEN] = fixed(12, 31, 0).try_into().unwrap();

    let blob = wrap::wrap_umk_with_device_key(&umk, &device_secret, &nonce).unwrap();
    let rt = wrap::unwrap_umk_with_device_key(&blob, &device_secret).unwrap();
    assert_eq!(rt.private_key_x25519, umk.private_key_x25519);
    assert_eq!(rt.seed_mlkem, umk.seed_mlkem);

    let wrong = fixed32(1, 1);
    assert!(matches!(
        wrap::unwrap_umk_with_device_key(&blob, &wrong),
        Err(E2eeError::AuthFailure)
    ));

    let short = wrap::b64_encode(&[0u8; 20]);
    assert!(matches!(
        wrap::unwrap_umk_with_device_key(&short, &device_secret),
        Err(E2eeError::InvalidPayload(_))
    ));
}

// ---------------------------------------------------------------------------
// Names
// ---------------------------------------------------------------------------

#[test]
fn name_alias_deterministic_and_format() {
    let umk = fixed_umk();
    let real = "budget 2026 (final).xlsx";
    let a = names::derive_opaque_wire_name(&umk, real).unwrap();
    let b = names::derive_opaque_wire_name(&umk, real).unwrap();
    assert_eq!(a, b);
    assert!(a.starts_with("evb-"));
    let hex_part = &a[4..];
    assert_eq!(hex_part.len(), 64);
    assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));

    // Different UMK => different alias.
    let other = fixed_other_umk();
    assert_ne!(a, names::derive_opaque_wire_name(&other, real).unwrap());

    // Same UMK, different real name => different alias.
    assert_ne!(a, names::derive_opaque_wire_name(&umk, "other.txt").unwrap());

    // Empty name rejected.
    assert!(matches!(
        names::derive_opaque_wire_name(&umk, ""),
        Err(E2eeError::InvalidInput(_))
    ));
}

#[test]
fn encrypted_name_roundtrip_and_errors() {
    let dek = fixed32(7, 1);
    let nonce: [u8; NONCE_LEN] = fixed(12, 31, 0).try_into().unwrap();
    let real = "budget 2026 (final).xlsx";

    let blob = names::encrypt_file_name(&dek, real, &nonce).unwrap();
    assert_eq!(names::decrypt_file_name(&dek, &blob).unwrap(), real);

    // Wrong DEK => auth failure.
    let wrong = fixed32(7, 2);
    assert!(matches!(
        names::decrypt_file_name(&wrong, &blob),
        Err(E2eeError::AuthFailure)
    ));

    // Tampered blob => auth failure.
    let mut raw = wrap::b64_decode(&blob).unwrap();
    let n = raw.len();
    raw[n - 1] ^= 1;
    assert!(matches!(
        names::decrypt_file_name(&dek, &wrap::b64_encode(&raw)),
        Err(E2eeError::AuthFailure)
    ));

    // Short blob.
    assert!(matches!(
        names::decrypt_file_name(&dek, &wrap::b64_encode(&[0u8; 24])),
        Err(E2eeError::InvalidPayload(_))
    ));

    // Empty name.
    assert!(matches!(
        names::encrypt_file_name(&dek, "", &nonce),
        Err(E2eeError::InvalidInput(_))
    ));
}

// ---------------------------------------------------------------------------
// Mnemonic normalization + validation
// ---------------------------------------------------------------------------

#[test]
fn mnemonic_normalization_nfkd_and_collapse() {
    // NFKD: é (U+00E9) -> e + combining accent; both forms must match.
    assert_eq!(normalize_mnemonic("café"), normalize_mnemonic("cafe\u{301}"));
    // Case folding + whitespace collapse.
    assert_eq!(normalize_mnemonic("  ABANDON   abandon \t about "), "abandon abandon about");
}

#[test]
fn mnemonic_validation() {
    let valid12 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    assert!(validate_bip39_english(valid12).is_ok());
    // Wrong checksum.
    assert!(validate_bip39_english(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
    )
    .is_err());
    // Unknown word.
    assert!(validate_bip39_english(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon zz"
    )
    .is_err());
    // Empty.
    assert!(validate_bip39_english("").is_err());

    // Generated phrase must validate.
    let gen = evb_e2ee_core::mnemonic::generate_bip39_english_12().unwrap();
    assert!(validate_bip39_english(&gen).is_ok());
}

// ---------------------------------------------------------------------------
// Key material sanity
// ---------------------------------------------------------------------------

#[test]
fn umk_public_consistency_and_random_generation() {
    let umk = wrap::generate_umk().unwrap();
    let pubk = umk.public().unwrap();
    // x25519 public key must match the private key.
    let derived = x25519_dalek::x25519(umk.private_key_x25519, x25519_dalek::X25519_BASEPOINT_BYTES);
    assert_eq!(derived, pubk.public_key_x25519);
    assert_eq!(pubk.public_key_mlkem.len(), 1184);

    let dek = generate_dek().unwrap();
    let nonce = evb_e2ee_core::keys::generate_nonce().unwrap();
    let env = wrap::wrap_dek_to_umk_with(&dek, &pubk, &fixed32(1, 1), &nonce).unwrap();
    assert_eq!(wrap::unwrap_dek_from_umk(&env, &umk).unwrap(), dek);

    // Name MAC key from parts == from UmkSecrets.
    let from_parts = names::derive_name_mac_key_from_parts(&umk.private_key_x25519, &umk.seed_mlkem);
    assert_eq!(from_parts, wrap::derive_name_mac_key(&umk));
}

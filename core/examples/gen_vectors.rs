//! Generates the shared test-vector file (JSON) used by the Rust core, the
//! Dart/Flutter binding and the WASM binding. Run with:
//!   cargo run --features deterministic-vectors --example gen_vectors
//! The output is deterministic: identical inputs always produce identical
//! artifacts, so the file can be diffed across releases.

use evb_e2ee_core::content::Evb1Encryptor;
use evb_e2ee_core::keys::{UmkPublic, DEK_LEN, NONCE_LEN};
use evb_e2ee_core::vectors::{aes_gcm_seal_with_nonce, pbkdf2_wrap_umk_for_vectors, umk_from_seed_material, wrap_dek_to_umk_deterministic};
use evb_e2ee_core::wrap;

use serde_json::json;
use sha2::{Digest, Sha256};

fn hex(s: &str) -> Vec<u8> {
    let mut out = vec![0u8; s.len() / 2];
    hex::decode_to_slice(s, &mut out).unwrap();
    out
}

fn hx(b: &[u8]) -> String {
    hex::encode(b)
}

/// Deterministic "pattern" plaintext (documented in PROTOCOL.md):
/// pattern(i) = SHA-256("EVB-VECTOR" || BE u64 i), repeated to fill `len`.
fn pattern(len: usize) -> Vec<u8> {
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

fn main() {
    let mut vectors = Vec::new();

    // Fixed master material (16 x 00..ff style deterministic bytes).
    let dek: [u8; DEK_LEN] = {
        let mut d = [0u8; DEK_LEN];
        for (i, b) in d.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(1);
        }
        d
    };
    let file_nonce: [u8; NONCE_LEN] = {
        let mut n = [0u8; NONCE_LEN];
        for (i, b) in n.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(31);
        }
        n
    };
    let umk_sk: [u8; 32] = {
        let mut d = [0u8; 32];
        for (i, b) in d.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(11).wrapping_add(2);
        }
        d
    };
    let umk_seed: [u8; 64] = {
        let mut d = [0u8; 64];
        for (i, b) in d.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(13).wrapping_add(3);
        }
        d
    };
    let eph_sk: [u8; 32] = {
        let mut d = [0u8; 32];
        for (i, b) in d.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(17).wrapping_add(4);
        }
        d
    };
    let kem_seed: [u8; 32] = {
        let mut d = [0u8; 32];
        for (i, b) in d.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(19).wrapping_add(5);
        }
        d
    };

    let umk = umk_from_seed_material(umk_sk, umk_seed);
    let pubk = umk.public().unwrap();
    let UmkPublic {
        public_key_x25519,
        public_key_mlkem,
    } = pubk;

    // ---- content vectors ---------------------------------------------------
    for (id, len) in [
        ("content-empty", 0usize),
        ("content-1b", 1),
        ("content-63b", 63),
        ("content-64b", 64),
        ("content-chunk-minus-1", 65535),
        ("content-chunk-exact", 65536),
        ("content-chunk-plus-1", 65537),
        ("content-two-chunks-exact", 131072),
        ("content-2-chunks-plus-5", 131077),
    ] {
        let plaintext = pattern(len);
        let ciphertext = Evb1Encryptor::seal_all(&dek, file_nonce, &plaintext).unwrap();
        vectors.push(json!({
            "kind": "content",
            "id": id,
            "dek": hx(&dek),
            "fileNonce": hx(&file_nonce),
            "plaintext": hx(&plaintext),
            "ciphertext": hx(&ciphertext),
        }));
    }

    // ---- file DEK wrap vector ----------------------------------------------
    let env = wrap_dek_to_umk_deterministic(&dek, &UmkPublic::from_parts(public_key_x25519, public_key_mlkem.clone()).unwrap(), &eph_sk, &kem_seed, &file_nonce)
        .unwrap();
    vectors.push(json!({
        "kind": "file-dek-wrap",
        "id": "wrap-file-dek",
        "dek": hx(&dek),
        "recipientPrivateKeyX25519": hx(&umk_sk),
        "recipientSeedMlkem": hx(&umk_seed),
        "recipientPublicKeyX25519": hx(&public_key_x25519),
        "recipientPublicKeyMlkem": hx(&public_key_mlkem),
        "ephSk": hx(&eph_sk),
        "kemSeed": hx(&kem_seed),
        "nonce": hx(&file_nonce),
        "envelope": env,
    }));

    // ---- DEK wrap v2 (HPKE RFC 9180 strict) vector --------------------------
    // Deterministic: eph_seed drives the HPKE X25519 ephemeral; kem_seed the
    // ML-KEM encapsulation. The dispatcher (unwrap_dek_from_umk_json) opens
    // it by the v: 2 field.
    let eph_seed: [u8; 32] = {
        let mut d = [0u8; 32];
        for (i, b) in d.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(31).wrapping_add(11);
        }
        d
    };
    let kem_seed: [u8; 32] = {
        let mut d = [0u8; 32];
        for (i, b) in d.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37).wrapping_add(12);
        }
        d
    };
    let hpke_recipient = UmkPublic::from_parts(public_key_x25519, public_key_mlkem.clone()).expect("vector recipient");
    let hpke_env = evb_e2ee_core::hpke::wrap_dek_to_umk_hpke_with(&dek, &hpke_recipient, &eph_seed, &kem_seed)
        .expect("hpke wrap for vector");
    vectors.push(json!({
        "kind": "file-dek-wrap-hpke",
        "id": "wrap-file-dek-hpke-v2",
        "dek": hx(&dek),
        "recipientPrivateKeyX25519": hx(&umk_sk),
        "recipientSeedMlkem": hx(&umk_seed),
        "recipientPublicKeyX25519": hx(&public_key_x25519),
        "recipientPublicKeyMlkem": hx(&public_key_mlkem),
        "ephemSeed": hx(&eph_seed),
        "kemSeed": hx(&kem_seed),
        "envelope": hpke_env,
    }));

    // ---- UMK mnemonic wrap vector ------------------------------------------
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    evb_e2ee_core::mnemonic::validate_bip39_english(mnemonic).expect("vector mnemonic must be valid");
    let salt: [u8; 16] = {
        let mut d = [0u8; 16];
        for (i, b) in d.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(23).wrapping_add(6);
        }
        d
    };
    // Legacy v2 PBKDF2 blob (read-only historical scheme, kept so every
    // client keeps proving it can still open pre-Argon2id envelopes).
    let legacy_blob = pbkdf2_wrap_umk_for_vectors(&umk, mnemonic, &salt, &file_nonce).unwrap();
    vectors.push(json!({
        "kind": "umk-mnemonic-wrap",
        "id": "umk-mnemonic-wrap-pbkdf2-v2",
        "mnemonic": mnemonic,
        "privateKeyX25519": hx(&umk_sk),
        "seedMlkem": hx(&umk_seed),
        "publicKeyX25519": hx(&public_key_x25519),
        "publicKeyMlkem": hx(&public_key_mlkem),
        "salt": hx(&salt),
        "iv": hx(&file_nonce),
        "blob": legacy_blob,
        "scheme": "evb-e2ee-umk-pbkdf2-sha512-100k-aesgcm",
    }));

    // Current v3 Argon2id blob (default profile m64-t2-p1; the RFC 9106
    // alternate profile m64-t3-p4 is exercised in unit tests, not in
    // vectors — vectors must stay deterministic and quick to verify).
    let wrap_blob = wrap::wrap_umk_with_mnemonic(&umk, mnemonic, &salt, &file_nonce).unwrap();
    vectors.push(json!({
        "kind": "umk-mnemonic-wrap",
        "id": "umk-mnemonic-wrap-argon2id-v3",
        "mnemonic": mnemonic,
        "privateKeyX25519": hx(&umk_sk),
        "seedMlkem": hx(&umk_seed),
        "publicKeyX25519": hx(&public_key_x25519),
        "publicKeyMlkem": hx(&public_key_mlkem),
        "salt": hx(&salt),
        "iv": hx(&file_nonce),
        "blob": wrap_blob,
        "scheme": "evb-e2ee-umk-argon2id-m64-t2-p1-aesgcm",
    }));

    // ---- UMK device wrap vector --------------------------------------------
    let device_secret: [u8; 32] = {
        let mut d = [0u8; 32];
        for (i, b) in d.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(29).wrapping_add(7);
        }
        d
    };
    let device_blob = wrap::wrap_umk_with_device_key(&umk, &device_secret, &file_nonce).unwrap();
    vectors.push(json!({
        "kind": "umk-device-wrap",
        "id": "umk-device-wrap-v1",
        "deviceSecret": hx(&device_secret),
        "privateKeyX25519": hx(&umk_sk),
        "seedMlkem": hx(&umk_seed),
        "publicKeyX25519": hx(&public_key_x25519),
        "publicKeyMlkem": hx(&public_key_mlkem),
        "iv": hx(&file_nonce),
        "blob": device_blob,
    }));

    // ---- UMK password wrap vector (owner decision 2026-11-14) ---------------
    // Same framing as the mnemonic wrap; scheme id inside the payload.
    let password = "vector-password-2026";
    let password_blob = wrap::wrap_umk_with_password(&umk, password, &salt, &file_nonce).unwrap();
    vectors.push(json!({
        "kind": "umk-password-wrap",
        "id": "umk-password-wrap-argon2id-v3",
        "password": password,
        "privateKeyX25519": hx(&umk_sk),
        "seedMlkem": hx(&umk_seed),
        "publicKeyX25519": hx(&public_key_x25519),
        "publicKeyMlkem": hx(&public_key_mlkem),
        "salt": hx(&salt),
        "iv": hx(&file_nonce),
        "blob": password_blob,
        "scheme": "evb-e2ee-umk-password-argon2id-m64-t2-p1-aesgcm",
    }));

    // ---- names --------------------------------------------------------------
    let real_name = "budget 2026 (final).xlsx";
    let wire_name = evb_e2ee_core::names::derive_opaque_wire_name(&umk, real_name).unwrap();
    vectors.push(json!({
        "kind": "name-alias",
        "id": "name-alias",
        "privateKeyX25519": hx(&umk_sk),
        "seedMlkem": hx(&umk_seed),
        "realName": real_name,
        "wireName": wire_name,
    }));

    let name_blob = evb_e2ee_core::names::encrypt_file_name(&dek, real_name, &file_nonce).unwrap();
    vectors.push(json!({
        "kind": "name-encrypted",
        "id": "name-encrypted",
        "dek": hx(&dek),
        "realName": real_name,
        "nonce": hx(&file_nonce),
        "blob": name_blob,
    }));

    // ---- opaque backup metadata (contract v2.2, 2026-11-20) -----------------
    // Deterministic alias/token kinds need no nonce injection; the sealed
    // blobs use the nonce-picked variants (feature deterministic-vectors).
    let manifest_path = "jobs/docs/quarterly-report.pdf";
    let manifest_hash = "3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca7c2de8";
    vectors.push(json!({
        "kind": "metadata-path-alias",
        "id": "metadata-path-alias",
        "privateKeyX25519": hx(&umk_sk),
        "seedMlkem": hx(&umk_seed),
        "path": manifest_path,
        "alias": evb_e2ee_core::metadata::derive_opaque_manifest_path(&umk, manifest_path).unwrap(),
    }));
    vectors.push(json!({
        "kind": "metadata-path-ancestors",
        "id": "metadata-path-ancestors",
        "privateKeyX25519": hx(&umk_sk),
        "seedMlkem": hx(&umk_seed),
        "path": manifest_path,
        "ancestors": evb_e2ee_core::metadata::derive_opaque_path_ancestors(&umk, manifest_path).unwrap(),
    }));
    vectors.push(json!({
        "kind": "metadata-content-token",
        "id": "metadata-content-token",
        "privateKeyX25519": hx(&umk_sk),
        "seedMlkem": hx(&umk_seed),
        "sha256": manifest_hash,
        "token": evb_e2ee_core::metadata::derive_opaque_content_hash(&umk, manifest_hash).unwrap(),
    }));
    vectors.push(json!({
        "kind": "metadata-encrypted-path",
        "id": "metadata-encrypted-path",
        "privateKeyX25519": hx(&umk_sk),
        "seedMlkem": hx(&umk_seed),
        "path": manifest_path,
        "nonce": hx(&file_nonce),
        "blob": evb_e2ee_core::metadata::encrypt_manifest_path_with_nonce(&umk, manifest_path, &file_nonce).unwrap(),
    }));
    vectors.push(json!({
        "kind": "metadata-encrypted-hash",
        "id": "metadata-encrypted-hash",
        "privateKeyX25519": hx(&umk_sk),
        "seedMlkem": hx(&umk_seed),
        "sha256": manifest_hash,
        "nonce": hx(&file_nonce),
        "blob": evb_e2ee_core::metadata::encrypt_manifest_content_hash_with_nonce(&umk, manifest_hash, &file_nonce).unwrap(),
    }));

    // ---- link + invite wraps -------------------------------------------------
    let link_key: [u8; 32] = {
        let mut d = [0u8; 32];
        for (i, b) in d.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37).wrapping_add(8);
        }
        d
    };
    let link_wrap = wrap::wrap_dek_with_link_key(&dek, &link_key, &file_nonce).unwrap();
    vectors.push(json!({
        "kind": "link-wrap",
        "id": "link-wrap",
        "dek": hx(&dek),
        "linkKey": hx(&link_key),
        "nonce": hx(&file_nonce),
        "wrap": link_wrap,
    }));

    let invite_key: [u8; 32] = {
        let mut d = [0u8; 32];
        for (i, b) in d.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(41).wrapping_add(9);
        }
        d
    };
    let invite_wrap = wrap::wrap_dek_with_invite_key(&dek, &invite_key, &file_nonce).unwrap();
    vectors.push(json!({
        "kind": "invite-wrap",
        "id": "invite-wrap",
        "dek": hx(&dek),
        "keyShare": hx(&invite_key),
        "nonce": hx(&file_nonce),
        "wrap": invite_wrap,
    }));

    // ---- raw primitive cross-check vector (AES-GCM + HKDF) -------------------
    let ikm = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    let hkdf_out = wrap::hkdf_sha256_32(&ikm, b"evb-e2ee-file-wrap-v1").unwrap();
    vectors.push(json!({
        "kind": "primitive",
        "id": "hkdf-file-wrap",
        "ikm": hx(&ikm),
        "info": "evb-e2ee-file-wrap-v1",
        "okm": hx(&hkdf_out),
    }));

    let gcm_out = aes_gcm_seal_with_nonce(&dek, &file_nonce, &pattern(35), &[]).unwrap();
    vectors.push(json!({
        "kind": "primitive",
        "id": "aes-gcm-no-aad",
        "key": hx(&dek),
        "nonce": hx(&file_nonce),
        "plaintext": hx(&pattern(35)),
        "aad": "",
        "ciphertext": hx(&gcm_out),
    }));

    let doc = json!({
        "protocol": "evb-e2ee-v1",
        "canonical": "Everabyte zero-knowledge wire format evb-e2ee-v1",
        "generatedBy": "evb-e2ee-core 0.4.0 (example gen_vectors)",
        "note": "plaintextPattern for content vectors: pattern(i) = SHA-256(\"EVB-VECTOR\" || BE u64 i); concatenation of 32-byte blocks truncated to len",
        "vectors": vectors,
    });

    println!("{}", serde_json::to_string_pretty(&doc).unwrap());
}

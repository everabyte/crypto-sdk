//! Verifies the frozen shared vector artifacts (crypto-sdk/vectors/evb-e2ee-v1.json)
//! against the Rust implementation. The same file is consumed by the Dart and
//! WASM bindings for cross-language verification.

use serde_json::Value;

use evb_e2ee_core::content::Evb1Decryptor;
use evb_e2ee_core::keys::{UmkPublic, UmkSecrets, DEK_LEN, NONCE_LEN};
use evb_e2ee_core::names;
use evb_e2ee_core::wrap;

fn vectors() -> Vec<Value> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../vectors/evb-e2ee-v1.json");
    let raw = std::fs::read_to_string(path).expect("vectors file present");
    let doc: Value = serde_json::from_str(&raw).expect("vectors json valid");
    assert_eq!(doc["protocol"], "evb-e2ee-v1");
    doc["vectors"].as_array().cloned().expect("vectors array")
}

fn hx(v: &Value, key: &str) -> Vec<u8> {
    hex::decode(v[key].as_str().expect(key)).expect("hex")
}

fn find<'a>(v: &'a [Value], kind: &str, id: &str) -> &'a Value {
    v.iter()
        .find(|x| x["kind"] == kind && x["id"] == id)
        .unwrap_or_else(|| panic!("vector {kind}/{id} missing"))
}

#[test]
fn frozen_content_vectors_roundtrip() {
    let vectors = vectors();
    let mut checked = 0;
    for v in &vectors {
        if v["kind"] != "content" {
            continue;
        }
        let dek = hx(v, "dek");
        let file_nonce = hx(v, "fileNonce");
        let pt = hx(v, "plaintext");
        let ct = hx(v, "ciphertext");

        // Decrypt the frozen ciphertext.
        let rt = Evb1Decryptor::open_all(
            &dek.clone().try_into().unwrap(),
            &ct,
        )
        .unwrap();
        assert_eq!(rt, pt, "{}", v["id"]);

        // Re-encrypt must be byte-identical (fixed fileNonce, deterministic format).
        let re = evb_e2ee_core::content::Evb1Encryptor::seal_all(
            &dek.try_into().unwrap(),
            file_nonce.try_into().unwrap(),
            &pt,
        )
        .unwrap();
        assert_eq!(re, ct, "re-encrypt {}", v["id"]);
        checked += 1;
    }
    assert_eq!(checked, 9, "expected 9 content vectors");
}

#[test]
fn frozen_file_dek_wrap_unwraps() {
    let vectors = vectors();
    let v = find(&vectors, "file-dek-wrap", "wrap-file-dek");
    let dek = hx(v, "dek");
    let umk = UmkSecrets {
        private_key_x25519: hx(v, "recipientPrivateKeyX25519").try_into().unwrap(),
        seed_mlkem: hx(v, "recipientSeedMlkem").try_into().unwrap(),
    };
    let env: wrap::FileEnvelope = serde_json::from_value(v["envelope"].clone()).unwrap();

    let rt = wrap::unwrap_dek_from_umk(&env, &umk).unwrap();
    assert_eq!(&rt[..], &dek[..]);

    // Publics declared in the vector must match the private material.
    let pubk = umk.public().unwrap();
    assert_eq!(pubk.public_key_x25519, hx(v, "recipientPublicKeyX25519")[..]);
    assert_eq!(pubk.public_key_mlkem, hx(v, "recipientPublicKeyMlkem"));
}

#[test]
fn frozen_mnemonic_wrap_unwraps() {
    let vectors = vectors();
    // Legacy v2 PBKDF2 blob: the versioned unwrap must still open it.
    let v = find(&vectors, "umk-mnemonic-wrap", "umk-mnemonic-wrap-pbkdf2-v2");
    assert_eq!(v["scheme"], wrap::UMK_WRAP_SCHEME_V2);
    let umk = wrap::unwrap_umk_with_mnemonic(v["blob"].as_str().unwrap(), v["mnemonic"].as_str().unwrap()).unwrap();
    assert_eq!(umk.private_key_x25519, hx(v, "privateKeyX25519")[..]);
    assert_eq!(umk.seed_mlkem, hx(v, "seedMlkem")[..]);

    // Current v3 Argon2id blob (default profile m64-t2-p1).
    let v = find(&vectors, "umk-mnemonic-wrap", "umk-mnemonic-wrap-argon2id-v3");
    assert_eq!(v["scheme"], wrap::UMK_WRAP_SCHEME_ARGON2ID_V3);
    let umk = wrap::unwrap_umk_with_mnemonic(v["blob"].as_str().unwrap(), v["mnemonic"].as_str().unwrap()).unwrap();
    assert_eq!(umk.private_key_x25519, hx(v, "privateKeyX25519")[..]);
    assert_eq!(umk.seed_mlkem, hx(v, "seedMlkem")[..]);

    // Same blobs open through the explicit legacy path too.
    let v = find(&vectors, "umk-mnemonic-wrap", "umk-mnemonic-wrap-pbkdf2-v2");
    let umk =
        wrap::unwrap_umk_with_mnemonic_pbkdf2(v["blob"].as_str().unwrap(), v["mnemonic"].as_str().unwrap()).unwrap();
    assert_eq!(umk.private_key_x25519, hx(v, "privateKeyX25519")[..]);
}

#[test]
fn frozen_device_wrap_unwraps() {
    let vectors = vectors();
    let v = find(&vectors, "umk-device-wrap", "umk-device-wrap-v1");
    let secret = hx(v, "deviceSecret");
    let umk =
        wrap::unwrap_umk_with_device_key(v["blob"].as_str().unwrap(), &secret.clone().try_into().unwrap()).unwrap();
    assert_eq!(umk.private_key_x25519, hx(v, "privateKeyX25519")[..]);
    assert_eq!(umk.seed_mlkem, hx(v, "seedMlkem")[..]);
}

#[test]
fn frozen_name_vectors() {
    let vectors = vectors();

    let v = find(&vectors, "name-alias", "name-alias");
    let umk = UmkSecrets {
        private_key_x25519: hx(v, "privateKeyX25519").try_into().unwrap(),
        seed_mlkem: hx(v, "seedMlkem").try_into().unwrap(),
    };
    let wire = names::derive_opaque_wire_name(&umk, v["realName"].as_str().unwrap()).unwrap();
    assert_eq!(wire, v["wireName"]);

    let v = find(&vectors, "name-encrypted", "name-encrypted");
    let dek = hx(v, "dek");
    let name = names::decrypt_file_name(&dek.try_into().unwrap(), v["blob"].as_str().unwrap()).unwrap();
    assert_eq!(name, v["realName"]);
}

#[test]
fn frozen_link_and_invite_wraps() {
    let vectors = vectors();

    let v = find(&vectors, "link-wrap", "link-wrap");
    let dek = hx(v, "dek");
    let w: wrap::SymmetricWrap = serde_json::from_value(v["wrap"].clone()).unwrap();
    let rt = wrap::unwrap_dek_with_link_key(&w, &hx(v, "linkKey")).unwrap();
    assert_eq!(&rt[..], &dek[..]);

    let v = find(&vectors, "invite-wrap", "invite-wrap");
    let dek = hx(v, "dek");
    let w: wrap::SymmetricWrap = serde_json::from_value(v["wrap"].clone()).unwrap();
    let rt = wrap::unwrap_dek_with_invite_key(&w, &hx(v, "keyShare")).unwrap();
    assert_eq!(&rt[..], &dek[..]);
}

#[test]
fn frozen_primitives() {
    let vectors = vectors();

    let v = find(&vectors, "primitive", "hkdf-file-wrap");
    let okm = wrap::hkdf_sha256_32(&hx(v, "ikm"), v["info"].as_str().unwrap().as_bytes()).unwrap();
    assert_eq!(okm.to_vec(), hx(v, "okm"));

    let v = find(&vectors, "primitive", "aes-gcm-no-aad");
    let pt = hx(v, "plaintext");
    use aes_gcm::aead::{Aead, Payload};
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    let cipher = Aes256Gcm::new_from_slice(&hx(v, "key")).unwrap();
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&hx(v, "nonce")),
            Payload {
                msg: &pt,
                aad: &[],
            },
        )
        .unwrap();
    assert_eq!(ct, hx(v, "ciphertext"));
}

#[test]
fn frozen_umk_publics_consistent() {
    let vectors = vectors();
    let v = find(&vectors, "file-dek-wrap", "wrap-file-dek");
    // Rebuild the public key from the private material and check the vector.
    let umk = UmkSecrets {
        private_key_x25519: hx(v, "recipientPrivateKeyX25519").try_into().unwrap(),
        seed_mlkem: hx(v, "recipientSeedMlkem").try_into().unwrap(),
    };
    let pubk: UmkPublic = serde_json::from_value(serde_json::json!({
        "public_key_x25519": hx(v, "recipientPublicKeyX25519"),
        "public_key_mlkem": hx(v, "recipientPublicKeyMlkem"),
    }))
    .unwrap();
    let derived = umk.public().unwrap();
    assert_eq!(derived.public_key_x25519, pubk.public_key_x25519);
    assert_eq!(derived.public_key_mlkem, pubk.public_key_mlkem);
    assert_eq!(pubk.public_key_mlkem.len(), 1184);
    assert_eq!(NONCE_LEN, 12);
    assert_eq!(DEK_LEN, 32);
}

#[test]
fn frozen_hpke_v2_wrap_unwraps() {
    let vectors = vectors();
    let v = find(&vectors, "file-dek-wrap-hpke", "wrap-file-dek-hpke-v2");
    assert_eq!(v["envelope"]["scheme"], "evb-e2ee-file-wrap-hpke-psk-v1");
    assert_eq!(v["envelope"]["v"], 2);
    let umk = evb_e2ee_core::keys::UmkSecrets {
        private_key_x25519: hx(v, "recipientPrivateKeyX25519").try_into().unwrap(),
        seed_mlkem: hx(v, "recipientSeedMlkem").try_into().unwrap(),
    };
    let dek = wrap::unwrap_dek_from_umk_json(&v["envelope"].to_string(), &umk).unwrap();
    assert_eq!(dek[..], hx(v, "dek")[..]);
}

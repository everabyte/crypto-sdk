use evb_e2ee_core::keys::UmkSecrets;
use evb_e2ee_core::metadata::{
    decrypt_manifest_content_hash, decrypt_manifest_path, derive_opaque_content_hash,
    derive_opaque_manifest_path, derive_opaque_path_ancestors,
    encrypt_manifest_content_hash, encrypt_manifest_path,
};

fn umk(byte: u8) -> UmkSecrets {
    UmkSecrets {
        private_key_x25519: [byte; 32],
        seed_mlkem: [byte.wrapping_add(1); 64],
    }
}

fn sha256_hex(byte: char) -> String {
    std::iter::repeat_n(byte, 64).collect()
}

#[test]
fn manifest_path_aliases_are_deterministic_and_scoped() {
    let account = umk(0x21);
    let path = "documents/2026/report.pdf";
    let alias = derive_opaque_manifest_path(&account, path).unwrap();

    assert!(alias.starts_with("evb-"));
    assert_eq!(alias.len(), 68);
    assert_eq!(alias, derive_opaque_manifest_path(&account, path).unwrap());
    assert_ne!(alias, derive_opaque_manifest_path(&account, "documents/2026/other.pdf").unwrap());
    assert_ne!(alias, derive_opaque_manifest_path(&umk(0x22), path).unwrap());
}

#[test]
fn path_ancestor_aliases_cover_each_prefix_in_order() {
    let account = umk(0x31);
    let ancestors = derive_opaque_path_ancestors(&account, "a/b/report.pdf").unwrap();

    assert_eq!(ancestors.len(), 3);
    assert_eq!(ancestors[0], derive_opaque_manifest_path(&account, "a").unwrap());
    assert_eq!(ancestors[1], derive_opaque_manifest_path(&account, "a/b").unwrap());
    assert_eq!(ancestors[2], derive_opaque_manifest_path(&account, "a/b/report.pdf").unwrap());
}

#[test]
fn content_equality_token_normalizes_hex_case_and_is_keyed() {
    let account = umk(0x41);
    let digest = sha256_hex('a');
    let token = derive_opaque_content_hash(&account, &digest).unwrap();

    assert_eq!(token.len(), 64);
    assert_eq!(token, derive_opaque_content_hash(&account, &digest.to_uppercase()).unwrap());
    assert_ne!(token, derive_opaque_content_hash(&account, &sha256_hex('b')).unwrap());
    assert_ne!(token, derive_opaque_content_hash(&umk(0x42), &digest).unwrap());
}

#[test]
fn encrypted_manifest_fields_roundtrip_and_authenticate() {
    let account = umk(0x51);
    let path = "documents/private/report.pdf";
    let digest = sha256_hex('c');
    let encrypted_path = encrypt_manifest_path(&account, path).unwrap();
    let encrypted_hash = encrypt_manifest_content_hash(&account, &digest).unwrap();

    assert!(encrypted_path.starts_with("v1:"));
    assert!(encrypted_hash.starts_with("v1:"));
    assert_eq!(path, decrypt_manifest_path(&account, &encrypted_path).unwrap());
    assert_eq!(digest, decrypt_manifest_content_hash(&account, &encrypted_hash).unwrap());
    assert!(decrypt_manifest_path(&umk(0x52), &encrypted_path).is_err());
    assert!(decrypt_manifest_content_hash(&umk(0x52), &encrypted_hash).is_err());

    let mut tampered = encrypted_path.into_bytes();
    let index = tampered.len() - 3;
    tampered[index] = if tampered[index] == b'A' { b'B' } else { b'A' };
    assert!(decrypt_manifest_path(&account, std::str::from_utf8(&tampered).unwrap()).is_err());
}

#[test]
fn invalid_paths_and_digests_are_rejected() {
    let account = umk(0x61);
    for path in ["", "/rooted", "a//b", "a/./b", "a/../b", "a\\b"] {
        assert!(derive_opaque_manifest_path(&account, path).is_err(), "path: {path:?}");
        assert!(encrypt_manifest_path(&account, path).is_err(), "path: {path:?}");
    }
    assert!(derive_opaque_manifest_path(&account, &format!("{}", "a/".repeat(513) + "b")).is_err());
    assert!(derive_opaque_content_hash(&account, "not-a-digest").is_err());
    assert!(encrypt_manifest_content_hash(&account, &"g".repeat(64)).is_err());
}

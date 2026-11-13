use unicode_normalization::UnicodeNormalization;

use crate::error::{E2eeError, Result};

/// Normalizes a recovery phrase the same way the web client does
/// (`utils/crypto/recoveryKeyCrypto.ts`): NFKD, trim, lowercase, collapse
/// inner whitespace runs to a single space.
pub fn normalize_mnemonic(input: &str) -> String {
    let nfkd: String = input.nfkd().collect();
    nfkd
        .to_lowercase()
        .split_whitespace()
        .collect::<Vec<&str>>()
        .join(" ")
}

/// Validates a 12- or 24-word English BIP-39 phrase (checksum included).
pub fn validate_bip39_english(phrase: &str) -> Result<()> {
    let normalized = normalize_mnemonic(phrase);
    bip39::Mnemonic::parse_in_normalized(bip39::Language::English, &normalized)
        .map(|_| ())
        .map_err(|_| E2eeError::InvalidInput("invalid BIP-39 mnemonic"))
}

/// Generates a fresh 12-word English BIP-39 recovery phrase (128-bit entropy).
pub fn generate_bip39_english_12() -> Result<String> {
    let mut entropy = [0u8; 16];
    use rand::RngCore;
    rand::rngs::OsRng
        .try_fill_bytes(&mut entropy)
        .map_err(|_| E2eeError::RandomFailure)?;
    let m = bip39::Mnemonic::from_entropy_in(bip39::Language::English, &entropy)
        .map_err(|_| E2eeError::RandomFailure)?;
    Ok(m.to_string())
}

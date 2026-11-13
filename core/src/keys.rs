use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{E2eeError, Result};

pub const X25519_SK_LEN: usize = 32;
pub const X25519_PK_LEN: usize = 32;
pub const MLKEM768_SEED_LEN: usize = 64;
pub const MLKEM768_PK_LEN: usize = 1184;
pub const MLKEM768_CT_LEN: usize = 1088;
pub const MLKEM768_SS_LEN: usize = 32;
pub const DEK_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

#[derive(Zeroize, ZeroizeOnDrop, Clone)]
pub struct UmkSecrets {
    pub private_key_x25519: [u8; X25519_SK_LEN],
    pub seed_mlkem: [u8; MLKEM768_SEED_LEN],
}

impl UmkSecrets {
    pub fn public(&self) -> Result<UmkPublic> {
        let pk_x = x25519_dalek::x25519(self.private_key_x25519, x25519_dalek::X25519_BASEPOINT_BYTES);
        let (ek, _dk) =
            <fips203::ml_kem_768::KG as fips203::traits::KeyGen>::keygen_from_seed(
                self.seed_mlkem[0..32].try_into().unwrap(),
                self.seed_mlkem[32..64].try_into().unwrap(),
            );
        let pk_kem = fips203::traits::SerDes::into_bytes(ek);
        Ok(UmkPublic {
            public_key_x25519: pk_x,
            public_key_mlkem: pk_kem.to_vec(),
        })
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct UmkPublic {
    pub public_key_x25519: [u8; X25519_PK_LEN],
    #[serde(with = "serde_bytes_buf")]
    pub public_key_mlkem: Vec<u8>,
}

impl UmkPublic {
    pub fn from_parts(public_key_x25519: [u8; 32], public_key_mlkem: Vec<u8>) -> Result<Self> {
        if public_key_mlkem.len() != MLKEM768_PK_LEN {
            return Err(E2eeError::InvalidInput("ml-kem public key must be 1184 bytes"));
        }
        Ok(Self {
            public_key_x25519,
            public_key_mlkem,
        })
    }
}

pub fn generate_dek() -> Result<[u8; DEK_LEN]> {
    let mut dek = [0u8; DEK_LEN];
    use rand::RngCore;
    rand::rngs::OsRng
        .try_fill_bytes(&mut dek)
        .map_err(|_| E2eeError::RandomFailure)?;
    Ok(dek)
}

/// Random 12-byte GCM nonce.
pub fn generate_nonce() -> Result<[u8; NONCE_LEN]> {
    let mut n = [0u8; NONCE_LEN];
    use rand::RngCore;
    rand::rngs::OsRng
        .try_fill_bytes(&mut n)
        .map_err(|_| E2eeError::RandomFailure)?;
    Ok(n)
}

/// CSPRNG fill of a caller-sized buffer (FFI convenience; production code
/// should prefer the fixed-size generators above).
pub fn random_bytes(len: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    use rand::RngCore;
    rand::rngs::OsRng
        .try_fill_bytes(&mut buf)
        .map_err(|_| E2eeError::RandomFailure)?;
    Ok(buf)
}

/// Random 16-byte PBKDF2 salt (mnemonic wrap).
pub fn generate_salt16() -> Result<[u8; 16]> {
    let mut s = [0u8; 16];
    use rand::RngCore;
    rand::rngs::OsRng
        .try_fill_bytes(&mut s)
        .map_err(|_| E2eeError::RandomFailure)?;
    Ok(s)
}

pub(crate) mod serde_bytes_buf {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        v.serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        Vec::<u8>::deserialize(d)
    }
}

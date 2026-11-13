use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use zeroize::Zeroize;

use crate::error::{E2eeError, Result};

/// Canonical EVB1 content format (matches the deployed web client
/// `frontend-next/utils/crypto/e2eeFileCrypto.ts`):
///
/// payload = magic "EVB1"(4) || fileNonce(12) || chunk*   (header = 16 B)
/// every chunk = `ciphertext || tag(16)`; chunk plaintext size is 64 KiB
/// except the final chunk (may be shorter; an empty file still has exactly
/// one empty final chunk).
/// chunkNonce = fileNonce[0..4] || BE u64 counter (fileNonce[4..12] is
/// transported but unused by the nonce derivation — v1 quirk, see PROTOCOL).
/// AAD = 8 bytes: BE u32 counter in bytes 0..4, zero bytes 4..8.
pub const CHUNK_SIZE: usize = 64 * 1024;
pub const CHUNK_BLOCK_LEN: usize = CHUNK_SIZE + 16;
pub const MAGIC: [u8; 4] = [0x45, 0x56, 0x42, 0x31]; // "EVB1"
pub const HEADER_LEN: usize = 16;

fn chunk_nonce(file_nonce: &[u8; 12], counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(&file_nonce[..4]);
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

fn chunk_aad(counter: u64) -> [u8; 8] {
    let mut aad = [0u8; 8];
    aad[..4].copy_from_slice(&(counter as u32).to_be_bytes());
    aad
}

pub fn ciphertext_len_for(plaintext_len: usize) -> usize {
    let chunks = if plaintext_len == 0 {
        1
    } else {
        (plaintext_len + CHUNK_SIZE - 1) / CHUNK_SIZE
    };
    HEADER_LEN + plaintext_len + chunks * 16
}

/// Validates and strips the payload header, returning the 12-byte fileNonce
/// (bytes 4..12 of the nonce are unused for nonce derivation in v1).
pub fn parse_header(header: &[u8]) -> Result<[u8; 12]> {
    if header.len() != HEADER_LEN {
        return Err(E2eeError::InvalidPayload("evb1 header size"));
    }
    if header[..4] != MAGIC {
        return Err(E2eeError::InvalidPayload("not an EVB1 payload"));
    }
    let mut file_nonce = [0u8; 12];
    file_nonce.copy_from_slice(&header[4..16]);
    Ok(file_nonce)
}

/// Streaming EVB1 encryptor. Feed plaintext with `push`, collect ciphertext;
/// call `finish` to emit the final chunk (always emitted, even for empty
/// input). Only one chunk (max 64 KiB) is buffered in memory.
pub struct Evb1Encryptor {
    dek: [u8; 32],
    file_nonce: [u8; 12],
    counter: u64,
    buf: Vec<u8>,
    started: bool,
    finished: bool,
}

impl Evb1Encryptor {
    pub fn new(dek: &[u8; 32], file_nonce: [u8; 12]) -> Self {
        Self {
            dek: *dek,
            file_nonce,
            counter: 0,
            buf: Vec::with_capacity(CHUNK_SIZE),
            started: false,
            finished: false,
        }
    }

    pub fn header(&self) -> [u8; HEADER_LEN] {
        let mut header = [0u8; HEADER_LEN];
        header[..4].copy_from_slice(&MAGIC);
        header[4..16].copy_from_slice(&self.file_nonce);
        header
    }

    fn seal_chunk(&self, plaintext: &[u8], counter: u64) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new_from_slice(&self.dek)
            .map_err(|_| E2eeError::InvalidInput("bad dek"))?;
        let nonce_bytes = chunk_nonce(&self.file_nonce, counter);
        let nonce = Nonce::from_slice(&nonce_bytes);
        cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad: &chunk_aad(counter),
                },
            )
            .map_err(|_| E2eeError::DecryptFailure)
    }

    /// Push plaintext; returns ciphertext bytes for all full 64 KiB chunks.
    pub fn push(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if self.finished {
            return Err(E2eeError::InvalidInput("encryptor already finished"));
        }
        self.started = true;
        let mut out = Vec::new();
        let mut rest = plaintext;
        if !self.buf.is_empty() {
            let need = CHUNK_SIZE - self.buf.len();
            let take = need.min(rest.len());
            self.buf.extend_from_slice(&rest[..take]);
            rest = &rest[take..];
            if self.buf.len() == CHUNK_SIZE {
                let sealed = self.seal_chunk(&self.buf, self.counter)?;
                self.counter += 1;
                out.extend_from_slice(&sealed);
                self.buf.clear();
            }
        }
        while rest.len() >= CHUNK_SIZE {
            let sealed = self.seal_chunk(&rest[..CHUNK_SIZE], self.counter)?;
            self.counter += 1;
            out.extend_from_slice(&sealed);
            rest = &rest[CHUNK_SIZE..];
        }
        if !rest.is_empty() {
            self.buf.extend_from_slice(rest);
        }
        Ok(out)
    }

    /// Seal the buffered remainder as the final chunk (possibly empty).
    /// Emits nothing if chunks were already sealed and no remainder is
    /// buffered (plaintext was an exact multiple of CHUNK_SIZE) — matches
    /// the reference web encryptor (chunks = ceil(len / CHUNK_SIZE), min 1).
    pub fn finish(&mut self) -> Result<Vec<u8>> {
        if self.finished {
            return Err(E2eeError::InvalidInput("encryptor already finished"));
        }
        self.finished = true;
        if self.counter > 0 && self.buf.is_empty() {
            return Ok(Vec::new());
        }
        let sealed = self.seal_chunk(&self.buf, self.counter)?;
        self.counter += 1;
        self.buf.clear();
        Ok(sealed)
    }

    /// One-shot helper: full EVB1 payload (with header) for a plaintext buffer.
    pub fn seal_all(dek: &[u8; 32], file_nonce: [u8; 12], plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut enc = Evb1Encryptor::new(dek, file_nonce);
        let mut out = Vec::with_capacity(ciphertext_len_for(plaintext.len()));
        out.extend_from_slice(&enc.header());
        out.extend_from_slice(&enc.push(plaintext)?);
        out.extend_from_slice(&enc.finish()?);
        Ok(out)
    }
}

impl Drop for Evb1Encryptor {
    fn drop(&mut self) {
        self.dek.zeroize();
        self.buf.zeroize();
    }
}

/// Streaming EVB1 decryptor. Parse the header with `parse_header`, then feed
/// the remaining ciphertext bytes with `push`; call `finish`.
pub struct Evb1Decryptor {
    dek: [u8; 32],
    file_nonce: [u8; 12],
    counter: u64,
    buf: Vec<u8>,
    finished: bool,
}

impl Evb1Decryptor {
    pub fn new(dek: &[u8; 32], file_nonce: [u8; 12]) -> Self {
        Self {
            dek: *dek,
            file_nonce,
            counter: 0,
            buf: Vec::new(),
            finished: false,
        }
    }

    fn open_chunk(&self, block: &[u8], counter: u64) -> Result<Vec<u8>> {
        if block.len() < 16 {
            return Err(E2eeError::InvalidPayload("chunk block too short"));
        }
        let cipher = Aes256Gcm::new_from_slice(&self.dek)
            .map_err(|_| E2eeError::InvalidInput("bad dek"))?;
        let nonce_bytes = chunk_nonce(&self.file_nonce, counter);
        let nonce = Nonce::from_slice(&nonce_bytes);
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: block,
                    aad: &chunk_aad(counter),
                },
            )
            .map_err(|_| E2eeError::DecryptFailure)
    }

    /// Push ciphertext bytes (after the header); returns decrypted plaintext
    /// for all complete blocks (chunk + tag).
    pub fn push(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if self.finished {
            return Err(E2eeError::InvalidInput("decryptor already finished"));
        }
        let mut out = Vec::new();
        let mut rest = ciphertext;
        if !self.buf.is_empty() {
            let need = CHUNK_BLOCK_LEN - self.buf.len();
            let take = need.min(rest.len());
            self.buf.extend_from_slice(&rest[..take]);
            rest = &rest[take..];
            if self.buf.len() == CHUNK_BLOCK_LEN {
                let plain = self.open_chunk(&self.buf, self.counter)?;
                self.counter += 1;
                out.extend_from_slice(&plain);
                self.buf.clear();
            }
        }
        while rest.len() >= CHUNK_BLOCK_LEN {
            let plain = self.open_chunk(&rest[..CHUNK_BLOCK_LEN], self.counter)?;
            self.counter += 1;
            out.extend_from_slice(&plain);
            rest = &rest[CHUNK_BLOCK_LEN..];
        }
        if !rest.is_empty() {
            self.buf.extend_from_slice(rest);
        }
        Ok(out)
    }

    /// Decrypt the final (possibly shorter) block. Errors on truncated or
    /// trailing-garbage payloads. A payload ending exactly on a full-block
    /// boundary is accepted (matches the reference web decryptor).
    pub fn finish(&mut self) -> Result<Vec<u8>> {
        if self.finished {
            return Err(E2eeError::InvalidInput("decryptor already finished"));
        }
        self.finished = true;
        if self.buf.is_empty() {
            // Payload ended exactly on a block boundary: valid iff at least
            // one full block was already processed.
            if self.counter == 0 {
                return Err(E2eeError::InvalidPayload("missing final chunk"));
            }
            return Ok(Vec::new());
        }
        if self.buf.len() < 16 {
            return Err(E2eeError::InvalidPayload("truncated final chunk"));
        }
        let plain = self.open_chunk(&self.buf, self.counter)?;
        self.counter += 1;
        self.buf.clear();
        Ok(plain)
    }

    /// One-shot helper: decrypt a full EVB1 payload (with header).
    pub fn open_all(dek: &[u8; 32], payload: &[u8]) -> Result<Vec<u8>> {
        if payload.len() < HEADER_LEN {
            return Err(E2eeError::InvalidPayload("evb1 payload too short"));
        }
        let file_nonce = parse_header(&payload[..HEADER_LEN])?;
        let mut dec = Evb1Decryptor::new(dek, file_nonce);
        let mut out = Vec::with_capacity(payload.len());
        out.extend_from_slice(&dec.push(&payload[HEADER_LEN..])?);
        out.extend_from_slice(&dec.finish()?);
        Ok(out)
    }
}

impl Drop for Evb1Decryptor {
    fn drop(&mut self) {
        self.dek.zeroize();
        self.buf.zeroize();
    }
}

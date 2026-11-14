/* tslint:disable */
/* eslint-disable */

/**
 * Decrypts an encrypted name blob (base64(nonce12 || ct || tag)).
 */
export function decrypt_file_name(dek: Uint8Array | number[], blob_b64: string): string;

/**
 * Opaque wire alias: `evb-` + hex(HMAC-SHA256(nameKey, realName)).
 */
export function derive_wire_alias(umk_sk: Uint8Array | number[], umk_seed: Uint8Array | number[], real_name: string): string;

/**
 * Encrypts a real name under the DEK (files) or folder key (folders):
 * returns base64(nonce12 || ct || tag).
 */
export function encrypt_file_name(dek: Uint8Array | number[], real_name: string, nonce: Uint8Array | number[]): string;

/**
 * Opens a whole EVB1 payload and returns the plaintext.
 */
export function evb1_open_all(dek: Uint8Array | number[], payload: Uint8Array | number[]): Uint8Array;

/**
 * Seals a whole EVB1 payload (header + all 64 KiB chunks) under a DEK and a
 * fresh-or-given fileNonce. Streaming across the network is orchestrated by
 * the application; use the streaming API in `core` when needed.
 */
export function evb1_seal_all(dek: Uint8Array | number[], file_nonce: Uint8Array | number[], plaintext: Uint8Array | number[]): Uint8Array;

/**
 * Random 12-byte GCM nonce.
 */
export function generate_random_12(): Uint8Array;

/**
 * Random 32-byte key (DEK / link key / keyShare / device secret).
 */
export function generate_random_32(): Uint8Array;

/**
 * Generates a fresh UMK. Returns `sk(32) || seed(64)`.
 */
export function generate_umk(): Uint8Array;

/**
 * HKDF-SHA256 with empty salt (RFC 5869), 32-byte output.
 */
export function hkdf_sha256(ikm: Uint8Array | number[], info: Uint8Array | number[]): Uint8Array;

/**
 * Derives the public keys of a UMK as canonical JSON:
 * `{ publicKeyX25519: b64(32), publicKeyMlkem: b64(1184) }`.
 */
export function umk_public_keys(umk_sk: Uint8Array | number[], umk_seed: Uint8Array | number[]): string;

/**
 * Unwraps a file DEK from an envelope JSON (canonical camelCase keys).
 */
export function unwrap_dek_from_umk(envelope_json: string, umk_sk: Uint8Array | number[], umk_seed: Uint8Array | number[]): Uint8Array;

/**
 * Unwraps a DEK under a 32-byte invite keyShare.
 */
export function unwrap_dek_with_invite_key(wrap_json: string, key_share: Uint8Array | number[]): Uint8Array;

/**
 * Unwraps a DEK under a 32-byte link key. Takes the `{ wrappedDek, nonce }`
 * JSON produced by [`wrap_dek_with_link_key`].
 */
export function unwrap_dek_with_link_key(wrap_json: string, link_key: Uint8Array | number[]): Uint8Array;

/**
 * Unwraps the UMK with a device secret. Returns `sk(32) || seed(64)`.
 */
export function unwrap_umk_with_device_key(blob_b64: string, device_secret: Uint8Array | number[]): Uint8Array;

/**
 * Unwraps the UMK with the recovery mnemonic. Returns `sk(32) || seed(64)`.
 */
export function unwrap_umk_with_mnemonic(blob_b64: string, mnemonic: string): Uint8Array;

/**
 * Unwraps the UMK with the login password. Returns `sk(32) || seed(64)`.
 */
export function unwrap_umk_with_password(blob_b64: string, password: string): Uint8Array;

/**
 * Wraps a file DEK to the recipient UMK (hybrid X25519 + ML-KEM-768).
 * Returns the envelope JSON with canonical camelCase keys.
 */
export function wrap_dek_to_umk(dek: Uint8Array | number[], public_key_x25519: Uint8Array | number[], public_key_mlkem: Uint8Array | number[]): string;

/**
 * Wraps a DEK under a 32-byte invite keyShare. Returns `{ wrappedDek, nonce }` JSON.
 */
export function wrap_dek_with_invite_key(dek: Uint8Array | number[], key_share: Uint8Array | number[]): string;

/**
 * Wraps a DEK under a 32-byte link key. Returns `{ wrappedDek, nonce }` JSON.
 */
export function wrap_dek_with_link_key(dek: Uint8Array | number[], link_key: Uint8Array | number[]): string;

/**
 * Wraps the UMK under a device secret (32 bytes held by the OS secure store).
 * Returns the blob as base64.
 */
export function wrap_umk_with_device_key(umk_sk: Uint8Array | number[], umk_seed: Uint8Array | number[], device_secret: Uint8Array | number[]): string;

/**
 * Wraps the UMK under a fresh recovery mnemonic (PBKDF2-SHA512 100k, v2).
 * Returns the blob as base64.
 */
export function wrap_umk_with_mnemonic(umk_sk: Uint8Array | number[], umk_seed: Uint8Array | number[], mnemonic: string): string;

/**
 * Wraps the UMK under the login password (Argon2id m=64 MiB, t=2, p=1,
 * scheme `evb-e2ee-umk-password-argon2id-m64-t2-p1-aesgcm`). Returns the
 * blob as base64; the server stores it as an opaque blind-proxy blob.
 */
export function wrap_umk_with_password(umk_sk: Uint8Array | number[], umk_seed: Uint8Array | number[], password: string): string;

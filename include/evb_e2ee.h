/*
 * Everabyte E2EE SDK — C ABI header (`evb-e2ee-v1` wire protocol).
 *
 * Consumable from any language with a C FFI (PHP FFI, Java FFM/JNI,
 * C# P/Invoke, Go cgo, Dart FFI, Python ctypes...). Link against the
 * `evb_e2ee_ffi` shared library built from `bindings/dart/rust`.
 *
 * Conventions (all functions):
 *  - Return 0 = OK; negative = error (see codes below).
 *  - Output buffers are caller-allocated; the callee writes the length to
 *    `out_len` when present, and NUL-terminates string outputs.
 *  - A short, secret-free error message is readable via evb_last_error().
 *  - Strings are UTF-8, NUL-terminated; base64 is standard alphabet.
 *  - All counters/lengths are u64 (little structure, 64-bit targets).
 *
 * Recommended capacities: UMK out 96; public-keys JSON 2048; mnemonic /
 * device wrap blobs 8192; encrypted-name blob 512; envelope JSON 4096;
 * decrypted-name buffer = name length + 1.
 */

#ifndef EVB_E2EE_H
#define EVB_E2EE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Status codes */
#define EVB_OK           0
#define EVB_ERR_ARG     -1  /* null / wrong-size argument               */
#define EVB_ERR_CRYPTO  -2  /* cryptographic failure (wrong key, RNG)   */
#define EVB_ERR_PAYLOAD -3  /* malformed payload / unsupported version  */
#define EVB_ERR_BUF     -4  /* output buffer too small                  */
#define EVB_ERR_JSON     -5 /* JSON serialization failure               */
#define EVB_ERR_UTF8     -6 /* input string was not valid UTF-8         */
#define EVB_ERR_LOCK     -7 /* internal error-slot lock failure         */

/* ── Randomness (OS CSPRNG) ──────────────────────────────────────────── */

/* Writes `len` random bytes into `out` (capacity >= len). */
int32_t evb_random(uint64_t len, uint8_t *out, uint64_t out_cap,
                   uint64_t *out_len);

/* ── Account key (UMK): 96 bytes = X25519 secret(32) ‖ ML-KEM seed(64) ── */

int32_t evb_generate_umk(uint8_t *out, uint64_t out_cap, uint64_t *out_len);

/* JSON: {"publicKeyX25519": b64(32), "publicKeyMlkem": b64(1184)} */
int32_t evb_umk_public_keys(const uint8_t *umk_sk, const uint8_t *umk_seed,
                            char *out_json, uint64_t out_cap);

/* ── UMK wraps (recovery + device) ───────────────────────────────────── */

/* Argon2id v3 (m=64 MiB, t=2, p=1). salt=16 B, nonce=12 B (CSPRNG). */
int32_t evb_wrap_umk_with_mnemonic(const uint8_t *umk_sk,
                                   const uint8_t *umk_seed,
                                   const char *mnemonic,
                                   const uint8_t *salt,
                                   const uint8_t *nonce,
                                   char *out_blob, uint64_t out_cap);

/* Opens a mnemonic wrap (tries v3 profiles then legacy PBKDF2; the GCM tag
 * decides). Output: 96 bytes = sk ‖ seed. */
int32_t evb_unwrap_umk_with_mnemonic(const char *blob_b64,
                                     const char *mnemonic,
                                     uint8_t *out, uint64_t out_cap,
                                     uint64_t *out_len);

/* Device wrap: `device_secret` (32 B) stays on the device, nonce = 12 B. */
int32_t evb_wrap_umk_with_device_key(const uint8_t *umk_sk,
                                     const uint8_t *umk_seed,
                                     const uint8_t *device_secret,
                                     const uint8_t *nonce,
                                     char *out_blob, uint64_t out_cap);

/* Password wrap (owner decision 2026-11-14): KEK = Argon2id(login password),
 * scheme `evb-e2ee-umk-password-argon2id-m64-t2-p1-aesgcm`. The server stores
 * the blob as an opaque blind-proxy value. salt=16 B, nonce=12 B (CSPRNG). */
int32_t evb_wrap_umk_with_password(const uint8_t *umk_sk,
                                   const uint8_t *umk_seed,
                                   const char *password,
                                   const uint8_t *salt,
                                   const uint8_t *nonce,
                                   char *out_blob, uint64_t out_cap);

/* Opens a password wrap (single Argon2id candidate; the GCM tag decides).
 * Output: 96 bytes = sk ‖ seed. */
int32_t evb_unwrap_umk_with_password(const char *blob_b64,
                                     const char *password,
                                     uint8_t *out_sk,
                                     uint8_t *out_seed);

/* ── File data key (DEK, 32 B) envelope ──────────────────────────────── */

/* HPKE v2 envelope as JSON (scheme evb-e2ee-file-wrap-hpke-psk-v1):
 * { v:2, scheme, kemId:32, kdfId:1, aeadId:3, ephPublicX25519,
 *   kemCiphertext, wrappedDek }. */
int32_t evb_wrap_dek_to_umk(const uint8_t *dek,
                            const uint8_t *public_key_x25519,
                            const uint8_t *public_key_mlkem,
                            char *out_json, uint64_t out_cap);

/* Opens any envelope version (v:2 HPKE / legacy v1). Output: 32-byte DEK. */
int32_t evb_unwrap_dek_from_umk(const char *envelope_json,
                                const uint8_t *umk_sk,
                                const uint8_t *umk_seed,
                                uint8_t *out, uint64_t out_cap,
                                uint64_t *out_len);

/* ── File content (EVB1: header 16 B + 64 KiB authenticated chunks) ──── */

int32_t evb1_seal_all(const uint8_t *dek, const uint8_t *file_nonce,
                      const uint8_t *plaintext, uint64_t plaintext_len,
                      uint8_t *out, uint64_t out_cap, uint64_t *out_len);

int32_t evb1_open_all(const uint8_t *dek, const uint8_t *payload,
                      uint64_t payload_len,
                      uint8_t *out, uint64_t out_cap, uint64_t *out_len);

/* ── File names (metadata encryption) ────────────────────────────────── */

/* Deterministic opaque alias: "evb-" + hex64(HMAC-SHA256(...)). */
int32_t evb_derive_wire_alias(const uint8_t *umk_sk, const uint8_t *umk_seed,
                              const char *real_name,
                              char *out, uint64_t out_cap);

/* b64(nonce12 || ct || tag16) of the UTF-8 name under the DEK. */
int32_t evb_encrypt_file_name(const uint8_t *dek, const char *real_name,
                              const uint8_t *nonce,
                              char *out_blob, uint64_t out_cap);

/* Inverse of evb_encrypt_file_name (out = UTF-8 name bytes). */
int32_t evb_decrypt_file_name(const uint8_t *dek, const char *blob_b64,
                              uint8_t *out, uint64_t out_cap,
                              uint64_t *out_len);

/* ── Opaque backup metadata ──────────────────────────────────────────── */

/* Alias for a normalized relative path: "evb-" + HMAC-SHA256 hex. */
int32_t evb_derive_opaque_manifest_path(const uint8_t *umk_sk,
                                        const uint8_t *umk_seed,
                                        const char *path,
                                        char *out, uint64_t out_cap);

/* JSON array of path-prefix aliases, root to leaf. */
int32_t evb_derive_opaque_path_ancestors(const uint8_t *umk_sk,
                                         const uint8_t *umk_seed,
                                         const char *path,
                                         char *out, uint64_t out_cap);

/* HMAC token of a 64-character SHA-256 hex digest. */
int32_t evb_derive_opaque_content_hash(const uint8_t *umk_sk,
                                      const uint8_t *umk_seed,
                                      const char *sha256_hex,
                                      char *out, uint64_t out_cap);

/* Versioned v1:base64(nonce12 || ciphertext || tag16) metadata blobs. */
int32_t evb_encrypt_manifest_path(const uint8_t *umk_sk,
                                  const uint8_t *umk_seed,
                                  const char *path,
                                  char *out, uint64_t out_cap);
int32_t evb_decrypt_manifest_path(const uint8_t *umk_sk,
                                  const uint8_t *umk_seed,
                                  const char *blob,
                                  char *out, uint64_t out_cap);
int32_t evb_encrypt_manifest_content_hash(const uint8_t *umk_sk,
                                          const uint8_t *umk_seed,
                                          const char *sha256_hex,
                                          char *out, uint64_t out_cap);
int32_t evb_decrypt_manifest_content_hash(const uint8_t *umk_sk,
                                          const uint8_t *umk_seed,
                                          const char *blob,
                                          char *out, uint64_t out_cap);

/* ── Primitives & diagnostics ────────────────────────────────────────── */

int32_t evb_hkdf_sha256(const uint8_t *ikm, uint64_t ikm_len,
                        const uint8_t *info, uint64_t info_len,
                        uint8_t out[32]);

int32_t evb_last_error(char *buf, uint64_t cap); /* 0 ok; >0 = cap needed */
int32_t evb_clear_last_error(void);

#ifdef __cplusplus
}
#endif

#endif /* EVB_E2EE_H */

# Everabyte E2EE Protocol — `evb-e2ee-v1`

> This SDK is the canonical implementation of the protocol. The frozen test
> vectors (`vectors/evb-e2ee-v1.json`) are its compatibility contract: every
> binding must open them before it ships, and the constructions are checked
> against the official test vectors of the underlying standards (RFC 9180,
> NIST SP 800-38D, RFC 5869).

## 0. Scope and trust model

- File-content encryption and key operations happen **client-side only**.
  Everabyte's servers act as blind proxies for ciphertext and envelopes and
  never receive private keys or file-content plaintext. Applications can
  choose to expose selected metadata; the current Drive policy leaves real
  file names and extensions visible to the server for locked-state display.
- The SDK covers crypto and wire format only: streaming chunking, key
  derivation, wraps, encrypted names, sensitive-buffer hygiene. Networking,
  auth, UI, OS integration and secure storage live in the consuming
  application.
- Recovery phrase (mnemonic) loss = unrecoverable data. This is a property of
  the model, not a defect to "fix" server-side.

## 1. Content format EVB1 (file payloads)

```
payload   = magic(4) || fileNonce(12) || block*      # header = 16 bytes total
magic     = "EVB1" = 45 56 42 31
block     = ciphertext || tag(16)        # AES-256-GCM output, ct||tag
```

- **Chunk plaintext size**: 64 KiB (`65536`), every chunk except the last.
  The last chunk may be shorter; **an empty file still has exactly one empty
  chunk** (a lone 16-byte tag). Chunk count = `ceil(len / 65536)`, minimum 1.
- **fileNonce**: 12 random bytes, per file. Bytes `[4..12]` are **transported
  but unused** by the nonce derivation (v1 quirk, kept for wire
  compatibility — see §10).
- **chunkNonce(i)** = `fileNonce[0..4] || BE u64(i)` (12 bytes total).
- **AAD(i)** = 8 bytes: `BE u32(i)` in bytes 0..4, zeros in bytes 4..8.
  This binds chunk position/order: reordering or splicing chunks fails the
  GCM tag check.
- Decryption: every block is opened with its sequential index as counter. A
  payload may end exactly on a full-block boundary. Truncated tags, trailing
  garbage and unknown magic are errors.
- Streaming: the encryptor/decryptor buffer at most one chunk (≤ 64 KiB + tag)
  in memory. DEK and buffers are zeroized on drop.

## 2. Key hierarchy

```
UMK   (User Master Key, per user, held by the client)
  ├─ private_key_x25519 : 32 B (X25519)
  ├─ seed_mlkem         : 64 B = d || z (FIPS 203 seed form, 32+32)
  ├─ public_key_x25519  : 32 B = X25519(sk, basepoint)
  └─ public_key_mlkem   : 1184 B (ML-KEM-768 encaps key from seed)

DEK   (file content key, 32 B, random per file)  — encrypts EVB1 payload
nameKey = SHA-256(privX25519 || seedMlkem)        — file-name alias MAC
linkKey / keyShare : 32 B symmetric keys for sharing wraps
deviceKey : 32 B secret held by the (native) device store
```

- ML-KEM-768 seed form: `keygen(d, z)` with `seed = d || z` (64 B) —
  compatible with `@noble/post-quantum` `ml_kem768.keygen(seed)` and the Dart
  `pqcrypto` bindings. Derived sizes: pk 1184, ct 1088, ss 32, dk 2400.

## 3. File DEK wrap (envelope sent with every E2EE file)

### 3.1 v2 (current): HPKE RFC 9180 strict — `evb-e2ee-file-wrap-hpke-psk-v1`

Ciphersuite DHKEM(X25519, HKDF-SHA256) (kemId 0x0020), HKDF-SHA256
(kdfId 0x0001), AES-256-GCM (aeadId 0x0003), **mode PSK** injecting the
ML-KEM-768 shared secret (pskId "evb-mlkem768-v1") — the RFC's standard
mechanism for combining a second secret, so the post-quantum hybrid is no
longer a bespoke construction. The scheme id is used as HPKE `info` AND as
AEAD `aad`; the base_nonce is derived by the key schedule (single-use
seq = 0 — there is NO transported nonce field).

```
envelope = {
  v: 2, scheme, kemId, kdfId, aeadId,
  ephPublicX25519: b64(32),      // HPKE enc = pkE
  kemCiphertext:    b64(1088),   // ML-KEM-768 ct
  wrappedDek:       b64(48)      // HPKE-sealed ct(32) || tag(16)
}

kem_context = enc || pkRm                      (RFC 9180 §4.1 Encap)
eae_prk     = LabeledExtract("", "eae_prk", DH(skE, pkRm))
shared      = LabeledExpand(eae_prk, "shared_secret", kem_context, 32)
psk_id_hash = LabeledExtract("", "psk_id_hash", pskId)
info_hash   = LabeledExtract("", "info_hash", info)
ks_context  = 0x01 || psk_id_hash || info_hash           // mode_psk
secret      = LabeledExtract(shared, "secret", psk)
key         = LabeledExpand(secret, "key", ks_context, 32)
base_nonce  = LabeledExpand(secret, "base_nonce", ks_context, 12)
wrappedDek  = AES-256-GCM(key, base_nonce, DEK, aad = schemeId)
```

- The key schedule implements RFC 9180 §4/§5 directly and is validated
  against the official RFC vectors (§A.1.1 and §A.1.2: shared_secret,
  key_schedule_context, secret, key, base_nonce — all byte-exact). This SDK
  implements the schedule in-tree to keep one auditable path shared by every
  binding.
- ML-KEM encapsulation randomness is internal to the KEM; two wraps of the
  same DEK differ and both are valid.

### 3.2 v1 (legacy, read-only): hybrid single-HKDF

```
envelope = { ephPublicX25519: b64(32), kemCiphertext: b64(1088),
             nonce: b64(12), wrappedDek: b64(48) }
wrapKey = HKDF-SHA256(ikm = X25519(ephSk, recipientPkX25519) ||
                              MLKEM768.encaps(pkMlkem).sharedSecret,
                      salt = empty, info = "evb-e2ee-file-wrap-v1")
wrappedDek = AES-256-GCM(wrapKey, nonce, DEK, aad = empty)
```

- New wraps NEVER produce this scheme; every client unwraps it via the
  version dispatch (`v` field present = v2 HPKE, absent = v1). Empty HKDF
  salt (RFC 5869 zero-salt extract). Unwrap: rebuild `dk` from the UMK seed,
  `decaps(ct)`, recompute the same derivation, GCM-open. Any mismatch →
  auth failure.

## 4. Symmetric wraps (sharing: links + invites)

```
wrapKey = HKDF-SHA256(key32, salt = empty, info = <per-use>)
SymmetricWrap = { wrappedDek: b64(48), nonce: b64(12) }
```

- Link: info = `evb-e2ee-link-wrap-v1`, key = 32-byte link key (URL fragment).
- Invite: info = `evb-e2ee-invite-wrap-v1`, key = 32-byte invite keyShare.

## 5. UMK device wrap

```
blob = b64( nonce(12) || ct || tag(16) )
wrapKey = HKDF-SHA256(deviceSecret32, salt = empty,
                      info = "evb-e2ee-device-wrap-v1")
plaintext = JSON { publicKeyX25519, publicKeyMlkem,
                   privateKeyX25519, seedMlkem }   // all b64
```

`deviceSecret32` is 32 random bytes held only on the device (OS secure
store); the server receives the wrapped blob and a public device label.

## 6. UMK mnemonic (recovery) wrap — KEK derivation

The mnemonic wrap derives a KEK from the recovery phrase and seals the UMK
under it. The KEK never encrypts file content (files keep their own random
DEKs) and never leaves the client. Blob framing is shared across schemes:
`b64( salt(16) || iv(12) || ct || tag(16) )` with the scheme id + version
inside the encrypted JSON.

### 6.1 v3 (current): Argon2id v1.3 (RFC 9106)

```
key = Argon2id(password = normalizedPhrase, salt, m = 65536 KiB (64 MiB),
               t = 2, p = 1, dkLen = 32, version = 0x13)
plaintext = JSON { v: 3, scheme: "evb-e2ee-umk-argon2id-m64-t2-p1-aesgcm",
                   publicKeyX25519, privateKeyX25519,
                   publicKeyMlkem, seedMlkem }    // all b64
```

- **Every new envelope uses this scheme.** PBKDF2 is never used for new
  wraps (no wrap function exports it).
- Alternate profile for memory-constrained devices — RFC 9106 §4
  low-memory recommendation: `m = 65536 KiB, t = 3, p = 4`, scheme id
  `evb-e2ee-umk-argon2id-m64-t3-p4-aesgcm`. Available as an explicit-params
  wrap (`wrap_umk_with_mnemonic_params`) and readable by every unwrap;
  parameters are versioned by the scheme id.
- Reference latencies for the default profile (unwrap through the versioned
  candidates; desktop native release and Node/WASM):

  | Profile | Happy path (1st candidate) | Wrong phrase (3 candidates) |
  |---|---|---|
  | m64-t2-p1, native release | ~61 ms | ~193 ms |
  | m64-t2-p1, WASM/Node | ~84 ms | ~268 ms |
  | m64-t3-p4 (RFC), native (2nd candidate) | ~153 ms | — |

### 6.2 v2 (legacy, READ-ONLY): PBKDF2-SHA512 100k

```
key = PBKDF2-SHA512(password = normalizedPhrase, salt, rounds = 100000, dkLen = 32)
plaintext = JSON { v: 2, scheme: "evb-e2ee-umk-pbkdf2-sha512-100k-aesgcm", ... }
```

- Read-only: historical envelopes keep opening. Wrap **metadata** is
  untrusted; the versioned unwrap relies on the AES-GCM tag, not on
  metadata.
- New wraps MUST NOT use this scheme (no exported wrap path; the vector-only
  helper in `core/src/vectors.rs` exists solely to keep the frozen legacy
  vector reproducible).

### 6.3 Unwrap contract (all clients)

Try the versioned candidates in order — v3 m64-t2-p1, v3 RFC m64-t3-p4,
legacy v2 PBKDF2 — and let the AES-GCM tag decide. A wrong phrase fails on
all candidates; a valid blob opens on exactly one. Each candidate validates
the embedded `scheme`/`v` against the parameters it derived with, so an old
ciphertext is never silently reinterpreted as a newer format.

**Migration**: after a successful unwrap, re-wrap to the current scheme
(unwrap + `wrap_umk_with_mnemonic` on the SDK) and submit only the new
opaque blob to the server — the phrase, the KEK and the private material
never leave the client.

- **Normalization** (applied by every client): NFKD → trim → lowercase →
  collapse internal whitespace runs to one space.
- Unwrap rejects unknown `v` / `scheme` values explicitly, and
  cross-checks the JSON publics against the private material
  (X25519 pk recomputation + ML-KEM seed re-derivation). A tampered public
  key in a validly-sealed blob is rejected.
- The KEK is never a file key: file DEKs are random per-file keys wrapped to
  the UMK (§3) — the mnemonic KEK only seals the UMK envelope.

### 6.4 Password wrap (owner decision 2026-11-14, v0.2.0)

The login password can also seal the UMK (`wrap_umk_with_password`) so that
signing in on any device unlocks the vault silently — the recovery phrase is
then strictly for account recovery. Same framing as §6: the KDF input is the
**trimmed** password bytes (no mnemonic normalization) and the payload scheme
id differs:

```
key = Argon2id(password = trimmedPassword, salt, m = 65536 KiB (64 MiB),
               t = 2, p = 1, dkLen = 32, version = 0x13)
plaintext = JSON { v: 3, scheme: "evb-e2ee-umk-password-argon2id-m64-t2-p1-aesgcm", ... }
```

- The embedded scheme id prevents kind-crossing: a password blob never opens
  through the mnemonic unwrap and vice versa, even when the strings match.
- Trust-model note: the mnemonic wrap resists a malicious server; the
  password wrap is a convenience path whose KEK is derivable from the login
  password the server legitimately sees during authentication. It is stored
  as an opaque blind-proxy blob (one active `password` wrap per chain, see
  `e2ee_key_wraps.wrapKind`).

## 7. Encrypted names (metadata)

- **Opaque name alias** for names the application chooses to hide (currently
  folder names; stable and visible to servers):
  `alias = "evb-" || lowercase-hex( HMAC-SHA256(nameKey, UTF-8(realName)) )`
  with `nameKey = SHA-256(privX25519 || seedMlkem)`. Deterministic by design:
  the same real name always maps to the same alias (versioning / convergence
  semantics).
- **Encrypted real name** (stored as client-side metadata):
  `blob = b64( nonce(12) || ct || tag(16) )` under the DEK (files) or the
  folder key (folders), AES-256-GCM, aad empty.
- Drive also stores the real file name in `files.name` and its extension in
  `ext_file` for display when the vault is locked. This is an explicit
  metadata-privacy exception: encrypting `encryptedName` does not hide those
  database columns.

## 8. Opaque backup metadata

These constructions are the canonical shared implementation for clients that
need backup deduplication and local restore without disclosing paths or raw
SHA-256 digests to the API. They use the account UMK only on the client.

### 8.1 Key derivation

For each purpose, derive an independent 32-byte key with HKDF-SHA256, empty
salt, and:

```
IKM  = privateKeyX25519(32) || seedMlkem(64)
info = UTF-8("evb-agent-metadata-v1:" || purpose)
```

Purpose labels are fixed: `manifest-path-index`, `content-equality`,
`manifest-path-cipher`, and `manifest-content-hash-cipher`.

### 8.2 Opaque indexes

```
pathAlias = "evb-" || lowercase-hex(HMAC-SHA256(pathKey, UTF-8(path)))
hashToken = lowercase-hex(HMAC-SHA256(contentKey, UTF-8(lowercase(sha256Hex))))
```

Paths must be normalized relative paths using `/`, no more than 4096 UTF-8
bytes and 512 components, with no empty, `.` or `..` components and no leading
`/` or `\\`. A SHA-256 digest must be exactly 64 hexadecimal characters.
Ancestor aliases are the path aliases for every prefix from the first
component through the complete path, in order.

### 8.3 Recoverable metadata

Path and digest ciphertexts use separate derived keys and AAD values
`evb-agent-manifest-path-v1` and
`evb-agent-manifest-content-hash-v1` respectively. The encoding is
`v1:base64(nonce12 || ciphertext || tag16)` using a fresh random nonce and
AES-256-GCM. Decryption must authenticate, validate UTF-8, and revalidate the
plaintext type (normalized path or SHA-256 hex) before returning it.

Servers may compare the deterministic HMAC tokens and filter by ancestor
aliases, but clients must encrypt the original path and digest and decrypt
them locally before restore. This metadata protocol does not encrypt file
names in `files.name` or `ext_file`; that storage policy is controlled by the
application.

## 9. Cryptographic notes

- **DEK wrap v2 = HPKE RFC 9180 strict** (mode PSK carrying ML-KEM-768) —
  standard construction, see §3.1. The legacy v1 hybrid (single HKDF over the
  concatenation of both shared secrets) is retained for reading only.
  Wrapping: new envelopes are always v2.
- HKDF saltless extract ≡ zero salt: the HMAC-SHA256 key is padded to 64 zero
  bytes, identical across WebCrypto / Rust / Dart implementations.
- All b64 is standard alphabet with padding (`BASE64`, not url-safe).
- Byte order: counters/AAD are **big-endian**.

## 10. Known v1 quirks (do not "fix", preserve)

1. The header is exactly 16 bytes (`EVB1` + the 12-byte fileNonce). Of that
   nonce, only `fileNonce[0..4]` participates in the chunk-nonce derivation
   (`fileNonce[0..4]` + counter) — the remaining 8 bytes ride along in the
   header. Preserved for wire compatibility with existing data.
2. AAD is 8 bytes with the counter in the first 4 and zeros after — not a
   length-prefixed or typed AAD.
3. Empty files carry a full GCM tag over an empty chunk (16 bytes), so the
   minimum payload is 32 bytes.
4. Header-only payloads (0 blocks) are rejected by the SDK decryptor — the
   SDK is stricter than strictly required.

## 11. Errors

| Condition | Error |
|---|---|
| Bad magic / header size / not b64 / size mismatch | `InvalidPayload` |
| GCM tag failure (wrong key, tamper, reorder) | `DecryptFailure` / `AuthFailure` |
| Unknown UMK wrap `v` / `scheme` | `UnsupportedWrapVersion` / `UnsupportedWrapScheme` |
| Bad caller input (size, empty name) | `InvalidInput` |
| OS RNG failure | `RandomFailure` |

Unknown **content** format versions: the EVB1 header has no version field
beyond the magic; any future format change ships as a new magic/extension and
must be explicit (no silent downgrade).

## 12. Test vectors

- File: `vectors/evb-e2ee-v1.json` (frozen artifact, deterministic:
  regenerating yields an identical file). Generated once by the Rust core:
  `cargo run --features deterministic-vectors -p evb-e2ee-core --example gen_vectors`
  (the `deterministic-vectors` feature exposes test-only APIs that accept full
  randomness material — never enabled in production builds).
- Content plaintexts: `pattern(i) = SHA-256("EVB-VECTOR" || BE u64 i)`,
  32-byte blocks truncated to the requested length.
- The vector mnemonic is the canonical BIP-39 test phrase
  `abandon … about` (12 words).
- Consumers: the Rust core and the WASM and Dart bindings — all must pass
  against the same frozen file before any release.
- Consumers: the Rust core and the WASM and Dart bindings — all must pass
  against the same frozen file before any release.
- Metadata kinds (0.4.0, contract v2.2 opaque backup metadata §8): the grid
  also freezes `metadata-path-alias`, `metadata-path-ancestors`,
  `metadata-content-token`, `metadata-encrypted-path` and
  `metadata-encrypted-hash` — the deterministic kinds need no nonce
  injection, the sealed blobs use the feature-gated `*_with_nonce` variants.

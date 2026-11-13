# Everabyte E2EE Protocol — `evb-e2ee-v1`

> **Canonical reference**: the deployed web client
> `frontend-next/utils/crypto/e2eeFileCrypto.ts` (+ `e2eeKeyCrypto.ts`,
> `recoveryKeyCrypto.ts`). This SDK is a byte-exact reimplementation of that
> wire format, verified against frozen test vectors
> (`crypto-sdk/vectors/evb-e2ee-v1.json`).

## 0. Scope and trust model

- Everything in this document happens **client-side only**. The nodejs-api and
  golang-api backends act as blind proxies: they store/relay ciphertext,
  envelopes and metadata and **never** receive private keys or plaintext.
- The SDK covers crypto and wire format only: streaming chunking, key
  derivation, wraps, encrypted names, sensitive-buffer hygiene. Networking,
  auth, UI, OS integration and secure storage live in each client app.
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
  compatibility — see §9).
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
UMK   (User Master Key, per user, non-extractable from the device)
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
  pqcrypto bindings. Derived sizes: pk 1184, ct 1088, ss 32, dk 2400.

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
psk_id_hash = LabeledExtract("", "psk_id_hash", pskId)   // label: psk_id_hash
info_hash   = LabeledExtract("", "info_hash", info)
ks_context  = 0x01 || psk_id_hash || info_hash           // mode_psk
secret      = LabeledExtract(shared, "secret", psk)
key         = LabeledExpand(secret, "key", ks_context, 32)
base_nonce  = LabeledExpand(secret, "base_nonce", ks_context, 12)
wrappedDek  = AES-256-GCM(key, base_nonce, DEK, aad = schemeId)
```

- The key schedule implements RFC 9180 §4/§5 directly and is validated
  against the official RFC vectors (§A.1.1: shared_secret, key_schedule_context,
  secret, key, base_nonce — all byte-exact). The `hpke` crate 0.11 on
  crates.io is RFC-final-conform; this SDK implements the schedule in-tree to
  keep one auditable path shared by every binding.
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
  salt (RFC 5869 zero-salt extract) — identical to WebCrypto `deriveBits`
  with empty salt and to `Hkdf::new(None, …)`. Unwrap: rebuild `dk` from the
  UMK seed, `decaps(ct)`, recompute the same derivation, GCM-open. Any
  mismatch → auth failure.

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
- Measured latencies (unwrap through the versioned candidates; Windows
  desktop native release and Node/WASM as a browser proxy — real-device
  mobile numbers still pending, see §6.3):

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

- Read-only: historical envelopes keep opening. NOTE: the pre-fix web client
  wrote `kdf: "argon2id"` in its wrap **metadata** while actually sealing
  with PBKDF2 (wrap and unwrap both called the PBKDF2 path) — metadata is
  untrusted; the versioned unwrap relies on the GCM tag, not on metadata.
- New wraps MUST NOT use this scheme (no exported wrap path; the vector-only
  helper in `crypto-sdk/core/src/vectors.rs` exists solely to keep the frozen
  legacy vector reproducible).

### 6.3 Unwrap contract (all clients)

Try the versioned candidates in order — v3 m64-t2-p1, v3 RFC m64-t3-p4,
legacy v2 PBKDF2 — and let the AES-GCM tag decide. A wrong phrase fails on
all candidates; a valid blob opens on exactly one. Each candidate validates
the embedded `scheme`/`v` against the parameters it derived with, so an old
ciphertext is never silently reinterpreted as a newer format.

**Migration**: after a successful unwrap, re-wrap to the current scheme
(`migrateUmkWrapToCurrentScheme` on the web; unwrap + wrap on the SDK) and
submit only the new opaque blob to the server — the phrase, the KEK and the
private material never leave the client.

- **Normalization** (matches web `recoveryKeyCrypto.ts`): NFKD → trim →
  lowercase → collapse internal whitespace runs to one space.
- Unwrap rejects unknown `v` / `scheme` values explicitly, and
  cross-checks the JSON publics against the private material
  (X25519 pk recomputation + ML-KEM seed re-derivation). A tampered public
  key in a validly-sealed blob is rejected.
- The KEK is never a file key: file DEKs are random per-file keys wrapped to
  the UMK (§3) — the mnemonic KEK only seals the UMK envelope.

## 7. Encrypted names (P8)

- **Wire alias** (stable, visible to servers):
  `alias = "evb-" || lowercase-hex( HMAC-SHA256(nameKey, UTF-8(realName)) )`
  with `nameKey = SHA-256(privX25519 || seedMlkem)`. Deterministic by design:
  the same real name always maps to the same alias (versioning / convergence
  semantics).
- **Encrypted real name** (stored next to the alias):
  `blob = b64( nonce(12) || ct || tag(16) )` under the DEK (files) or the
  folder key (folders), AES-256-GCM, aad empty.

## 8. Cryptographic notes and deviations

- **DEK wrap v2 = HPKE RFC 9180 strict** (mode PSK carrying ML-KEM-768) —
  standard construction, see §3.1. The legacy v1 hybrid (single HKDF over the
  concatenation of both shared secrets) is retained for reading only.
  Wrapping: new envelopes are always v2.
- HKDF saltless extract ≡ zero salt: the HMAC-SHA256 key is padded to 64 zero
  bytes, identical across WebCrypto / Rust / Dart implementations.
- All b64 is standard alphabet with padding (`BASE64`, not url-safe).
- Byte order: counters/AAD are **big-endian**.

## 9. Known v1 quirks (do not "fix", preserve)

1. The header is exactly 16 bytes (`EVB1` + the 12-byte fileNonce). Of that
   nonce, only `fileNonce[0..4]` participates in the chunk-nonce derivation
   (`fileNonce[0..4]` + counter) — the remaining 8 bytes ride along in the
   header. Kept byte-compatible with the deployed web format.
2. AAD is 8 bytes with the counter in the first 4 and zeros after — not a
   length-prefixed or typed AAD.
3. Empty files carry a full GCM tag over an empty chunk (16 bytes), so the
   minimum payload is 32 bytes.
4. Header-only payloads (0 blocks) are rejected by the SDK decryptor; the
   reference web decryptor would silently return empty. SDK is stricter.

## 10. Errors

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

## 11. Deviations found in the Dart clients (status 2026-11-13 — all closed)

The Dart implementations (agent-backup `backup_core`, mobile) shipped a
non-canonical content format and have been **corrected to the 16-byte
canonical header** (both now pass the frozen vectors):

| Item | Web (canonical) | Dart before fix | Status |
|---|---|---|---|
| Header | `EVB1` + fileNonce(12) = **16 B** | magic+prefix = 8 B | ✅ fixed 2026-11-12, vector-gated |
| AAD | BE u32 counter + 4 zero bytes | BE u64 | ✅ fixed 2026-11-12, vector-gated |
| wrappedDek | ct‖tag (48 B) | missing GCM tag | ✅ fixed 2026-11-13 (agent + mobile), vector-gated |
| Mnemonic unwrap | Argon2id v3 / PBKDF2 v2 + proper GCM ct‖tag | broken `SecretBox` (empty Mac), PBKDF2 only | ✅ fixed 2026-11-13 (agent + mobile): candidate chain Argon2id m64-t2-p1 → RFC 9106 m64-t3-p4 → PBKDF2, blob parsed as salt16‖iv12‖ct‖tag |
| Mnemonic normalization | NFKD + trim + lowercase + collapse | `trim().toLowerCase()` only | ✅ fixed 2026-11-13 (agent + mobile, `unorm_dart` NFKD) |
| DEK wrap default | HPKE v2 (RFC 9180 PSK) | legacy v1 hybrid only | ✅ fixed 2026-11-13 (agent + mobile): `wrapDekToUmk` = HPKE v2, unwrap dispatches v2/v1 — vector-gated byte-exact re-seal |

Every row is now gated by the frozen vectors in each client
(`test/e2ee_frozen_vectors_test.dart` agent + mobile: content ×9, DEK wrap
v1 re-seal byte-exact + unwrap, DEK wrap HPKE v2 re-seal byte-exact + unwrap,
device wrap v1, mnemonic Argon2id v3 / PBKDF2 v2 unwrap, name-alias,
name-encrypted, NFKD normalization). **No pure-Dart path remains unverified
against the grid.**

Server-side (nodejs-api): the envelope DTO accepts both wire formats
(dispatch on `v`; v2 requires kemId/kdfId/aeadId and forbids a transported
nonce), migration 0074 makes `nonce` nullable and adds `kem_id/kdf_id/aead_id`
on the three UMK-wrapped envelope tables — clients produce HPKE v2 by default.

Web client (`frontend-next/utils/crypto/e2eeFileCrypto.ts`): `wrapFileDekToUmk`
now defaults to HPKE v2 and `unwrapFileDek` dispatches v2/v1, matching the
Rust SDK and both Dart clients. Legacy v1 data stays readable everywhere.

## 12. Test vectors

- File: `crypto-sdk/vectors/evb-e2ee-v1.json` (frozen artifact, deterministic:
  regenerating yields an identical file). Generated once by the Rust core:
  `cargo run --features deterministic-vectors --example gen_vectors`
  (the `deterministic-vectors` feature exposes test-only APIs that accept full
  randomness material — never enabled in production builds).
- Content plaintexts: `pattern(i) = SHA-256("EVB-VECTOR" || BE u64 i)`,
  32-byte blocks truncated to the requested length.
- The vector mnemonic is the canonical BIP-39 test phrase
  `abandon … about` (12 words).
- Consumers: Rust (`tests/frozen_vectors.rs`), Dart binding, WASM binding —
  all must pass against the same frozen file before any client integration.

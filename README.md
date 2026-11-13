# Everabyte Crypto SDK (`evb-e2ee-core`)

Rust core for real end-to-end encryption (E2EE) in Everabyte clients — mobile
(Flutter), agent-backup (Flutter/Dart) and the web bundle (WASM). The servers
(nodejs-api, golang-api) stay blind proxies: they never see private keys or
plaintext.

**Canonical wire format**: byte-exact reimplementation of the deployed web
client format (`frontend-next/utils/crypto/e2eeFileCrypto.ts`), version
`evb-e2ee-v1`. See [`PROTOCOL.md`](PROTOCOL.md) for the full specification.

## Repository

Public: `https://github.com/everabyte/crypto-sdk` (Cargo workspace: `core`, `bindings/wasm`, `bindings/dart/rust`; frozen vectors under `vectors/`).

## Published documentation

Public-facing documentation lives in `evb-doc` (docs.everabyte.com):

- `/sdk/overview` — what the SDK is, standards, language matrix, honest limits
- `/sdk/quickstart-typescript` / `quickstart-rust` / `quickstart-dart` — full ZK round trips per binding
- `/sdk/api-reference` — every exported function of the three bindings
- `/sdk/protocol-reference` — the `evb-e2ee-v1` wire format (public summary of PROTOCOL.md)
- `/sdk/migration` — moving legacy server-encrypted files to zero-knowledge
- `/security/client-encryption` — the user-facing model description

## Installation (public repository)

```bash
git clone https://github.com/everabyte/crypto-sdk.git
cd crypto-sdk

# Rust core — build + tests (frozen vectors run in CI)
cargo test -p evb-e2ee-core

# WASM binding — rebuild the committed pkg/ after core changes
wasm-pack build bindings/wasm --target web --out-dir pkg
wasm-pack build bindings/wasm --target nodejs --out-dir pkg-node

# Dart FFI native library
cargo build --release -p evb_e2ee_ffi
```

Consumers (no Rust toolchain needed):

- **Node/npm**: `npm install everabyte/crypto-sdk#path:bindings/wasm/pkg-node` (npm >= 9.4) — use `bindings/wasm/pkg` for bundlers.
- **Cargo**: `evb-e2ee-core = { git = "https://github.com/everabyte/crypto-sdk.git", tag = "..." }` (root workspace resolves the crate).
- **Dart**: git dependency on `bindings/dart` + native lib built per platform (`cargo build --release -p evb_e2ee_ffi`) or fetched from GitHub Releases.

## Packaging status

| Artifact | State |
|---|---|
| GitHub repo | public, git deps usable today (this repo) |
| crates.io (`evb-e2ee-core`) | pending — `cargo publish` (fill `repository`/`homepage` first) |
| npm (`evb-e2ee-wasm`) | pending — `npm publish` from `bindings/wasm/pkg` |
| pub.dev (`evb_e2ee_dart`) | pending — needs a prebuilt native binaries story (Releases/cargokit) |
| LICENSE | **owner decision before going public** — manifests currently say `license = "Proprietary"`; a public repo without a LICENSE file is "all rights reserved" by default. Pick and add one (proprietary EULA or an open-source license) |

**Pre-publish checklist**: LICENSE decided and added - external audit still pending (publication != audit) - tags matching the vector grid - GitHub Releases carrying per-platform `libevb_e2ee_ffi` binaries.

## Layout

```
crypto-sdk/
├── PROTOCOL.md            wire format specification (canonical = web)
├── vectors/
│   └── evb-e2ee-v1.json   frozen cross-language test vectors (18)
└── core/
    ├── src/
    │   ├── content.rs     EVB1 streaming encryptor/decryptor (64 KiB chunks)
    │   ├── wrap.rs        DEK wraps: UMK hybrid KEM, link, invite, device, mnemonic
    │   ├── keys.rs        UMK/DEK material + random generation
    │   ├── names.rs       opaque name aliases + encrypted real names
    │   ├── mnemonic.rs    NFKD normalization + BIP-39 validate/generate
    │   ├── vectors.rs     deterministic helpers (feature-gated, test-only)
    │   └── error.rs
    ├── examples/gen_vectors.rs
    └── tests/             unit/integration tests + frozen-vector consumer
```

## What it does / does not do

| In the SDK | NOT in the SDK (app-side) |
|---|---|
| EVB1 streaming AEAD chunking | HTTP/network, auth tokens |
| X25519 + ML-KEM-768 hybrid DEK wraps | Key storage (device secure store) |
| Mnemonic / device / link / invite wraps | UI, prompts, sync scheduling |
| Encrypted names + HMAC aliases | Upload/download orchestration |
| Buffer zeroization, no secret logging | SSE (`sse-v1`) legacy paths |

## Build and test

```bash
cd core
cargo build
cargo test                                   # 28 tests
cargo test --features deterministic-vectors  # also compiles vectors module
```

Regenerate the frozen vectors (deterministic — output diffs must be empty):

```bash
cargo run --features deterministic-vectors --example gen_vectors \
  > ../vectors/evb-e2ee-v1.json
```

## Cryptography

AES-256-GCM (64 KiB chunks, per-chunk counter in nonce + AAD),
X25519, ML-KEM-768 (FIPS 203 seed form, d‖z), HKDF-SHA256 (empty salt),
PBKDF2-SHA512 (100k, mnemonic wrap). Crates: `aes-gcm`, `x25519-dalek`,
`fips203`, `hkdf`, `pbkdf2`, `bip39`, `zeroize`, `rand`.

## Status / next steps

- [x] Rust core: format, wraps, names, mnemonics — tests green (28)
- [x] Frozen vectors generated and self-verified by Rust (16-byte canonical
      header, camelCase envelope keys, HPKE v2 envelope vector — 20 vectors)
- [x] Dart FFI binding (`bindings/dart`) — 10/10 frozen-vector tests green
- [x] WASM binding (`bindings/wasm`) — 16/16 frozen-vector tests green
      (web + nodejs targets, wasm-pack)
- [x] **DEK wrap v2 = HPKE RFC 9180 strict** (DHKEM(X25519) + ML-KEM-768 via
      mode PSK) — key schedule validated against the official RFC vectors
      (§A.1.1); legacy v1 hybrid stays readable via version dispatch
- [x] **Mnemonic wrap v3 = Argon2id v1.3** (RFC 9106) — PBKDF2 read-only
      legacy; key schedule validated, latencies measured (see PROTOCOL §6)
- [x] agent-backup content codec aligned to the canonical format (header 16 B,
      AAD BE u32 + zeros) — 309/309 backup_core + 553 root, vectors gated
- [x] mobile content codec aligned to the canonical format — 223/223,
      vectors gated
- [x] frontend-next frozen-vector gate (`e2eeFrozenVectors.test.ts`) —
      proves the production TS codec is byte-exact with the SDK (700/700 jest)
- [ ] Envelope/mnemonic pure-Dart paths (agent + mobile) re-verified against
      the frozen vectors or ported to the SDK (see PROTOCOL.md §11)
- [ ] Client integrations (upload/download paths, envelope submission,
      migration SSE → E2EE with explicit, loss-free controls)

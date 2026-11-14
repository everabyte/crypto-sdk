# Everabyte Crypto SDK

Client-side encryption library for Everabyte integrations: encrypt file
contents and file names **on your machine**, before any network call. The
Everabyte servers store opaque ciphertext and never receive the keys that
open it.

One protocol (`evb-e2ee-v1`), three bindings generated from the same Rust
core — a file encrypted with one decrypts with all the others. Every binding
opens the same frozen test vectors in CI, and the constructions are validated
against the official test vectors of the underlying standards.

Full guides and API walkthroughs: **https://docs.everabyte.com** (Zero-Knowledge SDK section).

## Version

Current release: **0.1.0** (see the `VERSION` file).

Versioning rule (strict):

- Format `MAJOR.MINOR.BUILD`, each segment starts at **0** and increments.
- `BUILD` and `MINOR` are capped at **100** — never more (e.g. `x.y.100` is
  valid, `x.y.101` is not; the next increment moves `y` +1 and resets the
  build to 0).
- `MINOR` overflow moves `MAJOR` +1 and resets minor and build to 0.
- A change to the wire format is always a new scheme id or a bumped `v`
  field (see [`PROTOCOL.md`](PROTOCOL.md)) — never a silent reinterpretation.

## Installation

```bash
git clone https://github.com/everabyte/crypto-sdk.git
cd crypto-sdk
```

Or install directly from this repository, per language:

| Language | Command |
|---|---|
| Node.js | `npm install everabyte/crypto-sdk#path:bindings/wasm/pkg-node` (npm ≥ 9.4) |
| Browsers/bundlers | `npm install everabyte/crypto-sdk#path:bindings/wasm/pkg` |
| Rust | `evb-e2ee-core = { git = "https://github.com/everabyte/crypto-sdk.git", tag = "v0.1.0" }` |
| Dart/Flutter | pub git dependency on `bindings/dart` (+ native lib `cargo build --release -p evb_e2ee_ffi`) |
| PHP 8 / Java 22+ / C# / Go | any C FFI against `evb_e2ee_ffi` — header in `include/evb_e2ee.h`, see https://docs.everabyte.com/sdk/quickstart-php (and java/csharp/golang) |

Registry publications (npm, crates.io, pub.dev) are planned; git installs above work today.

Consumers can also install straight from this repository:

- **Node.js / npm** — prebuilt WASM, no toolchain:
  `npm install everabyte/crypto-sdk#path:bindings/wasm/pkg-node` (npm ≥ 9.4).
  For browsers and bundlers use `#path:bindings/wasm/pkg`.
- **Rust (Cargo)**:
  `evb-e2ee-core = { git = "https://github.com/everabyte/crypto-sdk.git", tag = "v0.1.0" }`
- **Dart / Flutter**:
  ```yaml
  dependencies:
    evb_e2ee_dart:
      git:
        url: https://github.com/everabyte/crypto-sdk.git
        path: bindings/dart
  ```
  The Dart package wraps a native library built from `bindings/dart/rust`
  (`cargo build --release -p evb_e2ee_ffi`), located via the `EVB_E2EE_LIB`
  environment variable, or shipped with your app.

## Usage

### 1. Account key (UMK) — generated on the client, once

The UMK is 96 bytes: 32-byte X25519 secret ‖ 64-byte ML-KEM-768 seed. Only
public keys and wrapped copies ever leave the machine.

```js
// TypeScript / WASM
import init, { generate_umk, umk_public_keys, wrap_umk_with_mnemonic } from "evb-e2ee-wasm";
await init();

const umk = generate_umk();                       // 96 bytes — keep client-side
const publics = JSON.parse(umk_public_keys(umk.subarray(0, 32), umk.subarray(32)));
const blob  = wrap_umk_with_mnemonic(umk.subarray(0, 32), umk.subarray(32), mnemonic); // recovery phrase, 12 BIP-39 words
```

```rust
// Rust
use evb_e2ee_core::wrap;

let umk = wrap::generate_umk();
let public = umk.public()?;
let blob = wrap::wrap_umk_with_mnemonic(&umk, phrase, &salt16, &nonce12)?;
```

```dart
// Dart
final umk = EvbE2ee.generateUmk();                // 96 bytes
final publics = EvbE2ee.umkPublicKeys(umk.sublist(0, 32), umk.sublist(32));
final blob = EvbE2ee.wrapUmkWithMnemonic(umk.sublist(0, 32), umk.sublist(32), mnemonic);
```

Besides the recovery phrase, the UMK can be sealed under the **login
password** (`wrap_umk_with_password`) so sign-in on any device unlocks the
vault silently — the phrase stays strictly for account recovery (see
PROTOCOL.md §6.4).

Register `publics` and `blob` with the Everabyte key-chain endpoint
(`POST /e2ee/keys/register`); keep the phrase and the private material on
your side.

### 2. Encrypt a file

Every file gets a fresh 32-byte data key (DEK). The DEK encrypts the content
(`EVB1` chunked AES-256-GCM), the file name becomes an opaque alias, and the
DEK is wrapped to the account key:

```js
const dek = generate_random_32();                       // never persisted
const fileNonce = generate_random_12();
const payload = evb1_seal_all(dek, fileNonce, plaintext);

const wireName = derive_wire_alias(umk.subarray(0, 32), umk.subarray(32), "report.pdf");
const encryptedName = encrypt_file_name(dek, "report.pdf", generate_random_12());
const envelope = wrap_dek_to_umk(dek, Buffer.from(publics.publicKeyX25519, "base64"),
                                      Buffer.from(publics.publicKeyMlkem, "base64"));
```

```rust
let dek = keys::generate_dek()?;
let file_nonce = keys::generate_nonce()?;
let payload = content::seal_all(&dek, &file_nonce, &plaintext)?;

let wire_name = names::derive_opaque_wire_name(&umk, "report.pdf")?;
let encrypted_name = names::encrypt_file_name(&dek, "report.pdf", &file_nonce)?;
let envelope = wrap::wrap_dek_to_umk(&dek, &public)?;
```

```dart
final dek = EvbE2ee.generateRandom32();
final fileNonce = EvbE2ee.generateRandom12();
final payload = EvbE2ee.evb1SealAll(dek, fileNonce, plaintext);

final wireName = EvbE2ee.deriveWireAlias(umk.sublist(0, 32), umk.sublist(32), "report.pdf");
final encryptedName = EvbE2ee.encryptFileName(dek, "report.pdf", EvbE2ee.generateRandom12());
final envelopeJson = EvbE2ee.wrapDekToUmk(dek, x25519PubBytes, mlkemPubBytes);
```

### 3. Upload ciphertext, attach the envelope

Upload the ciphertext under `wireName` through the Everabyte REST API
(`POST /files/upload/...`), then attach the envelope by path
(`POST /e2ee/files/by-path/envelope` with `bucketId`, `fileName: wireName`,
`encryptedName` and the envelope fields). Complete walkthroughs:
[docs.everabyte.com → Zero-Knowledge SDK](https://docs.everabyte.com/sdk/overview).

### 4. Download and decrypt

Fetch the envelope (`GET /e2ee/files/{fileId}/envelope`) and the stored
ciphertext (`GET /files/{fileId}/stream`), then unwrap and decrypt locally:

```js
const dek = unwrap_dek_from_umk(JSON.stringify(envelope), umk.subarray(0, 32), umk.subarray(32));
const original = evb1_open_all(dek, storedCiphertext);   // === plaintext
const realName = decrypt_file_name(dek, envelope.encryptedName);
```

```rust
let dek = wrap::unwrap_dek_from_umk_json(&envelope_json, &umk)?;
let original = content::open_all(&dek, &stored_ciphertext)?;
```

```dart
final dek = EvbE2ee.unwrapDekFromUmk(envelopeJson, umk.sublist(0, 32), umk.sublist(32));
final original = EvbE2ee.evb1OpenAll(dek, storedCiphertext);
```

Recovery uses the same primitives: `unwrap_umk_with_mnemonic` opens a
mnemonic wrap with the phrase (see [`PROTOCOL.md`](PROTOCOL.md) §6 for the
scheme handling).

## Scope

| In the SDK | In your application |
|---|---|
| EVB1 chunked encryption (AES-256-GCM) | HTTP calls, authentication |
| DEK envelopes (HPKE, X25519 + ML-KEM-768) | Key storage (keychain/KMS) |
| Mnemonic / device / link / invite wraps | Enrollment and upload orchestration |
| Opaque aliases + encrypted names | UI |
| Buffer zeroization | — |

## Build and test

```bash
cargo test -p evb-e2ee-core                   # unit + frozen-vector tests
cargo test --features deterministic-vectors   # also compiles the vectors module

# WASM binding (after any core change, rebuild the committed pkg/)
wasm-pack build bindings/wasm --target web --out-dir pkg
wasm-pack build bindings/wasm --target nodejs --out-dir pkg-node

# Dart FFI native library
cargo build --release -p evb_e2ee_ffi
```

Regenerate the frozen vectors (output must be byte-identical):

```bash
cargo run --features deterministic-vectors -p evb-e2ee-core --example gen_vectors \
  > vectors/evb-e2ee-v1.json
```

## Cryptography

| Purpose | Algorithm | Standard |
|---|---|---|
| File content | AES-256-GCM, 64 KiB chunks, per-chunk AAD | NIST SP 800-38D |
| File-key envelopes | HPKE mode PSK, DHKEM(X25519) + ML-KEM-768 | RFC 9180, FIPS 203 |
| Key derivation | HKDF-SHA256 | RFC 5869 |
| Recovery-phrase KDF | Argon2id (m=64 MiB, t=2, p=1) | RFC 9106 |
| Recovery phrase | BIP-39 English, NFKD-normalized | BIP-39 |

## Repository layout

```
crypto-sdk/
├── Cargo.toml              workspace (core, bindings/wasm, bindings/dart/rust)
├── VERSION                 release version
├── PROTOCOL.md             wire format specification (evb-e2ee-v1)
├── vectors/
│   └── evb-e2ee-v1.json    frozen cross-language test vectors
├── core/                   Rust core (canonical implementation)
└── bindings/
    ├── wasm/               WASM/TypeScript binding (+ prebuilt pkg/, pkg-node/)
    └── dart/               Dart FFI binding (+ native crate rust/)
```

## License

Source-available and proprietary. Use of this repository and its packages is
governed by [`LICENSE.md`](LICENSE.md). The license permits installation and
use as a dependency in Authorized Everabyte Integrations; it does not permit
standalone redistribution or use to build a competing service. Third-party
components remain subject to their own license terms.

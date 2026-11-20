import { test } from 'node:test';
import assert from 'node:assert/strict';

import * as wasm from '../pkg-node/evb_e2ee_wasm.js';

const account = (value) => ({
  sk: new Uint8Array(32).fill(value),
  seed: new Uint8Array(64).fill(value + 1),
});

test('opaque manifest path aliases and ancestors', () => {
  const { sk, seed } = account(0x21);
  const path = 'documents/2026/report.pdf';
  const alias = wasm.derive_opaque_manifest_path(sk, seed, path);
  const ancestors = JSON.parse(wasm.derive_opaque_path_ancestors(sk, seed, path));

  assert.match(alias, /^evb-[0-9a-f]{64}$/);
  assert.deepEqual(ancestors, [
    wasm.derive_opaque_manifest_path(sk, seed, 'documents'),
    wasm.derive_opaque_manifest_path(sk, seed, 'documents/2026'),
    alias,
  ]);
  assert.throws(() => wasm.derive_opaque_manifest_path(sk, seed, '../secret'));
});

test('opaque content equality token normalizes hex case', () => {
  const { sk, seed } = account(0x31);
  const digest = 'ab'.repeat(32);
  const token = wasm.derive_opaque_content_hash(sk, seed, digest);

  assert.match(token, /^[0-9a-f]{64}$/);
  assert.equal(wasm.derive_opaque_content_hash(sk, seed, digest.toUpperCase()), token);
  assert.notEqual(wasm.derive_opaque_content_hash(sk, seed, 'cd'.repeat(32)), token);
});

test('encrypted backup path and digest authenticate and roundtrip', () => {
  const { sk, seed } = account(0x41);
  const digest = 'ef'.repeat(32);
  const path = 'documents/private/report.pdf';
  const encryptedPath = wasm.encrypt_manifest_path(sk, seed, path);
  const encryptedHash = wasm.encrypt_manifest_content_hash(sk, seed, digest);

  assert.match(encryptedPath, /^v1:/);
  assert.match(encryptedHash, /^v1:/);
  assert.equal(wasm.decrypt_manifest_path(sk, seed, encryptedPath), path);
  assert.equal(wasm.decrypt_manifest_content_hash(sk, seed, encryptedHash), digest);
  assert.throws(() => wasm.decrypt_manifest_path(account(0x42).sk, seed, encryptedPath));
  assert.throws(() => wasm.decrypt_manifest_content_hash(sk, seed, `${encryptedHash.slice(0, -1)}x`));
});

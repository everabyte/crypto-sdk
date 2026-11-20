import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';

import 'package:evb_e2ee_dart/evb_e2ee_dart.dart';

Uint8List hx(String s) {
  final out = Uint8List(s.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(s.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

String toHex(Uint8List b) =>
    b.map((e) => e.toRadixString(16).padLeft(2, '0')).join();

Map<String, dynamic> find(List<dynamic> vectors, String kind, String id) =>
    vectors.firstWhere((v) => v['kind'] == kind && v['id'] == id);

void main() {
  final sdk = EvbE2ee.instance;

  final vectorsPath = _vectorsFile();
  final doc = jsonDecode(File(vectorsPath).readAsStringSync());
  final vectors = doc['vectors'] as List<dynamic>;

  group('frozen vectors vs native library', () {
    test('protocol id', () {
      expect(doc['protocol'], 'evb-e2ee-v1');
    });

    test('EVB1 content roundtrip (9 vectors)', () {
      final contents = vectors.where((v) => v['kind'] == 'content').toList();
      expect(contents.length, 9);
      for (final v in contents) {
        final dek = hx(v['dek']);
        final fileNonce = hx(v['fileNonce']);
        final plaintext = hx(v['plaintext']);
        final ciphertext = hx(v['ciphertext']);

        // Decrypt the frozen ciphertext.
        expect(sdk.openAll(dek, ciphertext), plaintext, reason: v['id']);

        // Re-encrypt must be byte-identical (fixed fileNonce).
        expect(sdk.sealAll(dek, fileNonce, plaintext), ciphertext,
            reason: v['id']);
      }
    });

    test('file DEK wrap unwrap', () {
      final v = find(vectors, 'file-dek-wrap', 'wrap-file-dek');
      final dek = sdk.unwrapDekFromUmk(
        (v['envelope'] as Map).cast<String, dynamic>(),
        hx(v['recipientPrivateKeyX25519']),
        hx(v['recipientSeedMlkem']),
      );
      expect(toHex(dek), v['dek']);
    });

    test('file DEK wrap v2 HPKE (RFC 9180) unwrap via JSON dispatch', () {
      final v = vectors.firstWhere(
        (x) => x['kind'] == 'file-dek-wrap-hpke' && x['id'] == 'wrap-file-dek-hpke-v2',
      );
      final envelope = (v['envelope'] as Map).cast<String, dynamic>();
      expect(envelope['scheme'], 'evb-e2ee-file-wrap-hpke-psk-v1');
      expect(envelope['v'], 2);
      final dek = sdk.unwrapDekFromUmk(
        envelope,
        hx(v['recipientPrivateKeyX25519']),
        hx(v['recipientSeedMlkem']),
      );
      expect(toHex(dek), v['dek']);
    });

    test('file DEK wrap roundtrip through native wrap (HPKE v2)', () {
      final v = find(vectors, 'file-dek-wrap', 'wrap-file-dek');
      final env = sdk.wrapDekToUmk(
        hx(v['dek']),
        hx(v['recipientPublicKeyX25519']),
        hx(v['recipientPublicKeyMlkem']),
      );
      // v2 = HPKE (RFC 9180 strict): no plaintext nonce field — the base
      // nonce is derived from the HPKE key schedule.
      expect(env.keys, containsAll(
          ['v', 'scheme', 'ephPublicX25519', 'kemCiphertext', 'wrappedDek']));
      expect(env['scheme'], 'evb-e2ee-file-wrap-hpke-psk-v1');
      // A freshly wrapped DEK must unwrap with the same UMK.
      final dek = sdk.unwrapDekFromUmk(
        env,
        hx(v['recipientPrivateKeyX25519']),
        hx(v['recipientSeedMlkem']),
      );
      expect(toHex(dek), v['dek']);
    });

    test('mnemonic wrap unwrap (legacy PBKDF2 v2 + current Argon2id v3)', () {
      // Legacy v2 blob: the versioned unwrap must still open it.
      final vLegacy =
          find(vectors, 'umk-mnemonic-wrap', 'umk-mnemonic-wrap-pbkdf2-v2');
      expect(vLegacy['scheme'], 'evb-e2ee-umk-pbkdf2-sha512-100k-aesgcm');
      final legacy = sdk.unwrapUmkWithMnemonic(
        vLegacy['blob'],
        vLegacy['mnemonic'],
      );
      expect(toHex(legacy.sublist(0, 32)), vLegacy['privateKeyX25519']);
      expect(toHex(legacy.sublist(32, 96)), vLegacy['seedMlkem']);

      // Current v3 Argon2id blob (default profile m64-t2-p1).
      final v =
          find(vectors, 'umk-mnemonic-wrap', 'umk-mnemonic-wrap-argon2id-v3');
      expect(v['scheme'], 'evb-e2ee-umk-argon2id-m64-t2-p1-aesgcm');
      final combined = sdk.unwrapUmkWithMnemonic(
        v['blob'],
        v['mnemonic'],
      );
      expect(toHex(combined.sublist(0, 32)), v['privateKeyX25519']);
      expect(toHex(combined.sublist(32, 96)), v['seedMlkem']);
    });

    test('password wrap unwrap (Argon2id v3, login password)', () {
      final v =
          find(vectors, 'umk-password-wrap', 'umk-password-wrap-argon2id-v3');
      expect(v['scheme'], 'evb-e2ee-umk-password-argon2id-m64-t2-p1-aesgcm');
      final combined = sdk.unwrapUmkWithPassword(v['blob'], v['password']);
      expect(toHex(combined.sublist(0, 32)), v['privateKeyX25519']);
      expect(toHex(combined.sublist(32, 96)), v['seedMlkem']);
    });

    test('wire alias', () {
      final v = find(vectors, 'name-alias', 'name-alias');
      final alias = sdk.deriveWireAlias(
        hx(v['privateKeyX25519']),
        hx(v['seedMlkem']),
        v['realName'],
      );
      expect(alias, v['wireName']);
      expect(alias.startsWith('evb-'), isTrue);
    });

    test('HKDF primitive', () {
      final v = find(vectors, 'primitive', 'hkdf-file-wrap');
      final okm = sdk.hkdfSha256(hx(v['ikm']), utf8.encode(v['info']));
      expect(toHex(okm), v['okm']);
    });

    test('wrong UMK rejected with auth failure', () {
      final v = find(vectors, 'file-dek-wrap', 'wrap-file-dek');
      final wrongSk = Uint8List(32)..fillRange(0, 32, 0x42);
      final wrongSeed = Uint8List(64)..fillRange(0, 64, 0x42);
      expect(
        () => sdk.unwrapDekFromUmk(
          (v['envelope'] as Map).cast<String, dynamic>(),
          wrongSk,
          wrongSeed,
        ),
        throwsA(isA<EvbFfiException>()),
      );
    });

    test('corrupted ciphertext rejected', () {
      final v = find(vectors, 'content', 'content-1b');
      final ct = hx(v['ciphertext']);
      ct[ct.length - 1] ^= 0x01;
      expect(
        () => sdk.openAll(hx(v['dek']), ct),
        throwsA(isA<EvbFfiException>()),
      );
    });

    test('opaque backup paths and ancestor aliases', () {
      final sk = Uint8List(32)..fillRange(0, 32, 0x21);
      final seed = Uint8List(64)..fillRange(0, 64, 0x22);
      const path = 'documents/2026/report.pdf';
      final alias = sdk.deriveOpaqueManifestPath(sk, seed, path);
      final ancestors = sdk.deriveOpaquePathAncestors(sk, seed, path);

      expect(alias, startsWith('evb-'));
      expect(alias, hasLength(68));
      expect(ancestors, hasLength(3));
      expect(ancestors.last, alias);
      expect(ancestors[0], sdk.deriveOpaqueManifestPath(sk, seed, 'documents'));
      expect(ancestors[1], sdk.deriveOpaqueManifestPath(sk, seed, 'documents/2026'));
      expect(() => sdk.deriveOpaqueManifestPath(sk, seed, '../secret'),
          throwsA(isA<EvbFfiException>()));
    });

    test('opaque content hash and encrypted metadata roundtrip', () {
      final sk = Uint8List(32)..fillRange(0, 32, 0x31);
      final seed = Uint8List(64)..fillRange(0, 64, 0x32);
      final digest = 'ab' * 32;
      final token = sdk.deriveOpaqueContentHash(sk, seed, digest);
      final encryptedPath = sdk.encryptManifestPath(sk, seed, 'a/b/report.pdf');
      final encryptedHash = sdk.encryptManifestContentHash(sk, seed, digest);

      expect(token, hasLength(64));
      expect(sdk.deriveOpaqueContentHash(sk, seed, digest.toUpperCase()), token);
      expect(sdk.decryptManifestPath(sk, seed, encryptedPath), 'a/b/report.pdf');
      expect(sdk.decryptManifestContentHash(sk, seed, encryptedHash), digest);
      expect(() => sdk.decryptManifestPath(Uint8List(32), seed, encryptedPath),
          throwsA(isA<EvbFfiException>()));
    });
  });
}

String _vectorsFile() {
  // vectors/ sits two levels above this package (crypto-sdk/vectors).
  var dir = Directory.current;
  while (true) {
    final candidate = File(_join(dir.path,
        'vectors${Platform.pathSeparator}evb-e2ee-v1.json'));
    if (candidate.existsSync()) return candidate.path;
    final parent = dir.parent;
    if (parent.path == dir.path) {
      throw StateError('vectors/evb-e2ee-v1.json not found');
    }
    dir = parent;
  }
}

String _join(String a, String b) => a.endsWith(Platform.pathSeparator)
    ? '$a$b'
    : '$a${Platform.pathSeparator}$b';

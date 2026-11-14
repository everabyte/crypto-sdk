import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

/// dart:ffi bindings for the evb-e2ee-ffi native library.
///
/// Status codes: 0 = OK, negative = error (message via [lastError]).
const int ok = 0;

class EvbFfiException implements Exception {
  final int code;
  final String message;
  EvbFfiException(this.code, this.message);
  @override
  String toString() => 'EvbFfiException($code): $message';
}

/// Loads the native library: env override `EVB_E2EE_LIB`, else the debug
/// build from `rust/target/` relative to this package directory.
DynamicLibrary _openLibrary() {
  final env = Platform.environment['EVB_E2EE_LIB'];
  if (env != null && env.isNotEmpty) return DynamicLibrary.open(env);
  final pkgRoot = _packageRoot();
  for (final candidate in [
    'rust/target/debug/evb_e2ee_ffi.dll',
    'rust/target/release/evb_e2ee_ffi.dll',
    'rust/target/debug/libevb_e2ee_ffi.so',
    'rust/target/release/libevb_e2ee_ffi.so',
    'rust/target/debug/libevb_e2ee_ffi.dylib',
    'rust/target/release/libevb_e2ee_ffi.dylib',
  ]) {
    final p = File(_join(pkgRoot, candidate));
    if (p.existsSync()) return DynamicLibrary.open(p.path);
  }
  throw StateError('evb_e2ee_ffi native library not found. '
      'Build it with: cd bindings/dart/rust && cargo build');
}

String? _pkgRootCache;
String _packageRoot() {
  if (_pkgRootCache != null) return _pkgRootCache!;
  // Package root = nearest ancestor holding pubspec.yaml.
  var dir = Directory.current;
  while (true) {
    if (File(_join(dir.path, 'pubspec.yaml')).existsSync()) {
      return _pkgRootCache = dir.path;
    }
    final parent = dir.parent;
    if (parent.path == dir.path) {
      return _pkgRootCache = Directory.current.path;
    }
    dir = parent;
  }
}

String _join(String a, String b) =>
    a.endsWith(Platform.pathSeparator) ? '$a$b' : '$a${Platform.pathSeparator}$b';

void _checkLen(List<int> list, int len, String name) {
  if (list.length != len) {
    throw ArgumentError('$name must be exactly $len bytes, got ${list.length}');
  }
}

Pointer<Uint8> _copyIn(Uint8List data) {
  final p = calloc<Uint8>(data.isEmpty ? 1 : data.length);
  if (data.isNotEmpty) p.asTypedList(data.length).setAll(0, data);
  return p;
}

class EvbE2ee {
  final DynamicLibrary lib;

  late final int Function(Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>, int,
      Pointer<Uint8>, int, Pointer<Uint64>) _sealAll;
  late final int Function(Pointer<Uint8>, Pointer<Uint8>, int, Pointer<Uint8>,
      int, Pointer<Uint64>) _openAll;
  late final int Function(Pointer<Int8>, Pointer<Uint8>, Pointer<Uint8>,
      Pointer<Uint8>, int, Pointer<Uint64>) _unwrapDekFromUmk;
  late final int Function(Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>,
      Pointer<Int8>, int) _wrapDekToUmk;
  late final int Function(
      Pointer<Int8>, Pointer<Int8>, Pointer<Uint8>, Pointer<Uint8>) _unwrapUmk;
  late final int Function(
      Pointer<Int8>, Pointer<Int8>, Pointer<Uint8>, Pointer<Uint8>)
      _unwrapUmkPassword;
  late final int Function(Pointer<Uint8>, Pointer<Uint8>, Pointer<Int8>,
      Pointer<Int8>, int) _deriveWireAlias;
  late final int Function(
      Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>) _hkdf;
  late final int Function(Pointer<Int8>, int) _lastError;
  late final int Function() _clearLastError;

  EvbE2ee._(this.lib) {
    _sealAll = lib
        .lookup<
            NativeFunction<
                Int32 Function(Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>,
                    Uint64, Pointer<Uint8>, Uint64,
                    Pointer<Uint64>)>>('evb1_seal_all')
        .asFunction();
    _openAll = lib
        .lookup<
            NativeFunction<
                Int32 Function(Pointer<Uint8>, Pointer<Uint8>, Uint64,
                    Pointer<Uint8>, Uint64, Pointer<Uint64>)>>('evb1_open_all')
        .asFunction();
    _unwrapDekFromUmk = lib
        .lookup<
            NativeFunction<
                Int32 Function(Pointer<Int8>, Pointer<Uint8>, Pointer<Uint8>,
                    Pointer<Uint8>, Uint64,
                    Pointer<Uint64>)>>('evb_unwrap_dek_from_umk')
        .asFunction();
    _wrapDekToUmk = lib
        .lookup<
            NativeFunction<
                Int32 Function(Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>,
                    Pointer<Int8>, Uint64)>>('evb_wrap_dek_to_umk')
        .asFunction();
    _unwrapUmk = lib
        .lookup<
            NativeFunction<
                Int32 Function(Pointer<Int8>, Pointer<Int8>, Pointer<Uint8>,
                    Pointer<Uint8>)>>('evb_unwrap_umk_with_mnemonic')
        .asFunction();
    _unwrapUmkPassword = lib
        .lookup<
            NativeFunction<
                Int32 Function(Pointer<Int8>, Pointer<Int8>, Pointer<Uint8>,
                    Pointer<Uint8>)>>('evb_unwrap_umk_with_password')
        .asFunction();
    _deriveWireAlias = lib
        .lookup<
            NativeFunction<
                Int32 Function(Pointer<Uint8>, Pointer<Uint8>, Pointer<Int8>,
                    Pointer<Int8>, Uint64)>>('evb_derive_wire_alias')
        .asFunction();
    _hkdf = lib
        .lookup<
            NativeFunction<
                Int32 Function(Pointer<Uint8>, Uint64, Pointer<Uint8>, Uint64,
                    Pointer<Uint8>)>>('evb_hkdf_sha256')
        .asFunction();
    _lastError = lib
        .lookup<NativeFunction<Int32 Function(Pointer<Int8>, Uint64)>>(
            'evb_last_error')
        .asFunction();
    _clearLastError = lib
        .lookup<NativeFunction<Int32 Function()>>('evb_clear_last_error')
        .asFunction();
  }

  static final EvbE2ee instance = EvbE2ee._(_openLibrary());

  void clearLastError() => _clearLastError();

  String lastError() {
    final buf = calloc<Int8>(1024);
    try {
      final code = _lastError(buf, 1024);
      return code == ok ? buf.cast<Utf8>().toDartString() : 'error $code';
    } finally {
      calloc.free(buf);
    }
  }

  Never _fail(int code) => throw EvbFfiException(code, lastError());

  Uint8List _readOut(Pointer<Uint8> out, Pointer<Uint64> outLen) {
    final result = Uint8List.fromList(out.asTypedList(outLen.value).sublist(0));
    return result;
  }

  // ---- EVB1 content -------------------------------------------------------

  static int ciphertextLenFor(int plaintextLen) {
    final chunks =
        plaintextLen == 0 ? 1 : (plaintextLen + 65536 - 1) ~/ 65536;
    return 20 + plaintextLen + chunks * 16;
  }

  Uint8List sealAll(Uint8List dek, Uint8List fileNonce, Uint8List plaintext) {
    _checkLen(dek, 32, 'dek');
    _checkLen(fileNonce, 12, 'fileNonce');
    final outCap = ciphertextLenFor(plaintext.length);
    final out = calloc<Uint8>(outCap);
    final outLen = calloc<Uint64>();
    final dekP = _copyIn(dek);
    final nonceP = _copyIn(fileNonce);
    final ptP = _copyIn(plaintext);
    try {
      final code = _sealAll(
          dekP, nonceP, ptP, plaintext.length, out, outCap, outLen);
      if (code != ok) _fail(code);
      return _readOut(out, outLen);
    } finally {
      calloc.free(out);
      calloc.free(outLen);
      calloc.free(dekP);
      calloc.free(nonceP);
      calloc.free(ptP);
    }
  }

  Uint8List openAll(Uint8List dek, Uint8List payload) {
    _checkLen(dek, 32, 'dek');
    final out = calloc<Uint8>(payload.length);
    final outLen = calloc<Uint64>();
    final dekP = _copyIn(dek);
    final payloadP = _copyIn(payload);
    try {
      final code = _openAll(
          dekP, payloadP, payload.length, out, payload.length, outLen);
      if (code != ok) _fail(code);
      return _readOut(out, outLen);
    } finally {
      calloc.free(out);
      calloc.free(outLen);
      calloc.free(dekP);
      calloc.free(payloadP);
    }
  }

  // ---- File DEK wrap ------------------------------------------------------

  Uint8List unwrapDekFromUmk(
      Map<String, dynamic> envelope, Uint8List umkSk, Uint8List umkSeed) {
    _checkLen(umkSk, 32, 'umkSk');
    _checkLen(umkSeed, 64, 'umkSeed');
    final envP = jsonEncode(envelope).toNativeUtf8().cast<Int8>();
    final skP = _copyIn(umkSk);
    final seedP = _copyIn(umkSeed);
    final out = calloc<Uint8>(32);
    final outLen = calloc<Uint64>();
    try {
      final code = _unwrapDekFromUmk(envP, skP, seedP, out, 32, outLen);
      if (code != ok) _fail(code);
      return _readOut(out, outLen);
    } finally {
      calloc.free(envP);
      calloc.free(skP);
      calloc.free(seedP);
      calloc.free(out);
      calloc.free(outLen);
    }
  }

  Map<String, dynamic> wrapDekToUmk(Uint8List dek, Uint8List publicKeyX25519,
      Uint8List publicKeyMlkem) {
    _checkLen(dek, 32, 'dek');
    _checkLen(publicKeyX25519, 32, 'publicKeyX25519');
    _checkLen(publicKeyMlkem, 1184, 'publicKeyMlkem');
    const outCap = 4096;
    final out = calloc<Int8>(outCap);
    final dekP = _copyIn(dek);
    final pkXP = _copyIn(publicKeyX25519);
    final pkKP = _copyIn(publicKeyMlkem);
    try {
      final code = _wrapDekToUmk(dekP, pkXP, pkKP, out, outCap);
      if (code != ok) _fail(code);
      final json = out.cast<Utf8>().toDartString();
      return (jsonDecode(json) as Map).cast<String, dynamic>();
    } finally {
      calloc.free(out);
      calloc.free(dekP);
      calloc.free(pkXP);
      calloc.free(pkKP);
    }
  }

  // ---- Mnemonic wrap ------------------------------------------------------

  Uint8List unwrapUmkWithMnemonic(String blobB64, String mnemonic) {
    final blobP = blobB64.toNativeUtf8().cast<Int8>();
    final phraseP = mnemonic.toNativeUtf8().cast<Int8>();
    final outSk = calloc<Uint8>(32);
    final outSeed = calloc<Uint8>(64);
    try {
      final code = _unwrapUmk(blobP, phraseP, outSk, outSeed);
      if (code != ok) _fail(code);
      final sk = Uint8List.fromList(outSk.asTypedList(32).sublist(0));
      final seed = Uint8List.fromList(outSeed.asTypedList(64).sublist(0));
      return Uint8List.fromList([...sk, ...seed]);
    } finally {
      calloc.free(blobP);
      calloc.free(phraseP);
      calloc.free(outSk);
      calloc.free(outSeed);
    }
  }

  // ---- Password wrap ------------------------------------------------------

  /// Unwraps a password wrap (login-password KEK, see PROTOCOL.md §6.4).
  /// Returns the 96-byte UMK: sk(32) ‖ seed(64).
  Uint8List unwrapUmkWithPassword(String blobB64, String password) {
    final blobP = blobB64.toNativeUtf8().cast<Int8>();
    final passwordP = password.toNativeUtf8().cast<Int8>();
    final outSk = calloc<Uint8>(32);
    final outSeed = calloc<Uint8>(64);
    try {
      final code = _unwrapUmkPassword(blobP, passwordP, outSk, outSeed);
      if (code != ok) _fail(code);
      final sk = Uint8List.fromList(outSk.asTypedList(32).sublist(0));
      final seed = Uint8List.fromList(outSeed.asTypedList(64).sublist(0));
      return Uint8List.fromList([...sk, ...seed]);
    } finally {
      calloc.free(blobP);
      calloc.free(passwordP);
      calloc.free(outSk);
      calloc.free(outSeed);
    }
  }

  // ---- Names --------------------------------------------------------------

  String deriveWireAlias(
      Uint8List umkSk, Uint8List umkSeed, String realName) {
    _checkLen(umkSk, 32, 'umkSk');
    _checkLen(umkSeed, 64, 'umkSeed');
    final nameP = realName.toNativeUtf8().cast<Int8>();
    final skP = _copyIn(umkSk);
    final seedP = _copyIn(umkSeed);
    const outCap = 80; // "evb-" + 64 hex + NUL
    final out = calloc<Int8>(outCap);
    try {
      final code = _deriveWireAlias(skP, seedP, nameP, out, outCap);
      if (code != ok) _fail(code);
      return out.cast<Utf8>().toDartString();
    } finally {
      calloc.free(nameP);
      calloc.free(skP);
      calloc.free(seedP);
      calloc.free(out);
    }
  }

  // ---- Primitives ---------------------------------------------------------

  Uint8List hkdfSha256(Uint8List ikm, Uint8List info) {
    final ikmP = _copyIn(ikm);
    final infoP = _copyIn(info);
    final out = calloc<Uint8>(32);
    try {
      final code = _hkdf(ikmP, ikm.length, infoP, info.length, out);
      if (code != ok) _fail(code);
      return Uint8List.fromList(out.asTypedList(32).sublist(0));
    } finally {
      calloc.free(ikmP);
      calloc.free(infoP);
      calloc.free(out);
    }
  }
}

// AOT-compiled by test/release_mode_test.dart. `dart compile exe` defines
// dart.vm.product=true, so kDebugMode is false here, exactly as in a Flutter
// release build.
import 'dart:io';

import 'package:dio/dio.dart';
import 'package:vibeshield_flutter/vibeshield_flutter.dart';

void main() {
  final out = <String>[];
  VibeShield.customPrinter = out.add;

  // App registers its .env secret once, then scrubs an LLM prompt in production.
  VibeShield.run(() {}, exactSecrets: ['MyExactSecretValue99']);
  stdout.writeln('KDEBUG:$kDebugMode');
  stdout.writeln('AISAFE:${'prompt MyExactSecretValue99 end'.aiSafe}');

  // Interceptor explicitly enabled for release must still log.
  VibeShield.dioInterceptor(enableInRelease: true).onRequest(
      RequestOptions(path: 'https://api.example.com/x'),
      RequestInterceptorHandler());
  stdout.writeln('DIOLINES:${out.length}');
}

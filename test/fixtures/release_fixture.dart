// AOT-compiled by test/release_mode_test.dart. `dart compile exe` defines
// dart.vm.product=true, so kDebugMode is false here, exactly as in a Flutter
// release build.
import 'dart:io';

import 'package:dio/dio.dart';
import 'package:tracecloak/tracecloak.dart';

void main() {
  final out = <String>[];
  TraceCloak.customPrinter = out.add;

  // App registers its .env secret once, then scrubs an LLM prompt in production.
  TraceCloak.run(() {}, exactSecrets: ['MyExactSecretValue99']);
  stdout.writeln('KDEBUG:$kDebugMode');
  stdout.writeln('AISAFE:${'prompt MyExactSecretValue99 end'.aiSafe}');

  // Interceptor explicitly enabled for release must still log.
  TraceCloak.dioInterceptor(enableInRelease: true).onRequest(
      RequestOptions(path: 'https://api.example.com/x'),
      RequestInterceptorHandler());
  stdout.writeln('DIOLINES:${out.length}');
}

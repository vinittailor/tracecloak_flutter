// Every Dart snippet in README.md that can run without Flutter is reproduced
// here verbatim (Flutter-only calls replaced by plain-Dart stand-ins), so the
// README cannot drift from the real API again. See AUDIT.md M5.
import 'dart:convert';

import 'package:test/test.dart';
import 'package:tracecloak/tracecloak.dart';

void main() {
  late List<String> printed;

  setUp(() {
    TraceCloak.reset();
    printed = [];
    TraceCloak.customPrinter = printed.add;
  });
  tearDown(TraceCloak.reset);

  test('Masking modes: set, change at runtime, cycle', () {
    TraceCloak.run(() {}, mode: MaskMode.full);
    expect(TraceCloak.mode, MaskMode.full);

    // Or change dynamically at runtime
    TraceCloak.setMode(MaskMode.full);
    expect(TraceCloak.mode, MaskMode.full);

    // Cycle through: off -> partial -> full -> off
    final newMode = TraceCloak.cycleMode();
    expect(newMode, MaskMode.off);
  });

  test('Quick start: plain print inside run() is masked', () {
    TraceCloak.run(() {
      print(
          'Calling Stripe API with: sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890'); // tracecloak-ignore
    });
    expect(printed.single, 'Calling Stripe API with: sk_live_****7890');
  });

  test('Manual error sanitization', () {
    try {
      throw StateError('login failed for token=hunter2');
    } catch (e, stack) {
      final (safeErr, safeStack) = TraceCloak.sanitizeError(e, stack);
      TraceCloak.error('Authentication failed: $safeErr',
          stackTrace: safeStack);
    }
    expect(printed.single, isNot(contains('hunter2')));
  });

  test('debugPrint hook', () {
    final out = <String>[];
    void Function(String? message, {int? wrapWidth}) debugPrint =
        (m, {wrapWidth}) => out.add(m!);
    debugPrint = TraceCloak.wrapDebugPrint(debugPrint);
    debugPrint('framework token: AKIAIOSFODNN7EXAMPLE'); // tracecloak-ignore
    expect(out.single, contains('AKIA****MPLE'));
  });

  test('SecureKey: interpolation, jsonEncode and structured logs stay masked',
      () {
    final stripeKey = SecureKey(
        'sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890'); // tracecloak-ignore
    expect('Config: $stripeKey', 'Config: sk_live_****7890');
    expect(jsonEncode({'key': stripeKey}), '{"key":"sk_live_****7890"}');

    TraceCloak.log('Initializing payment intent', LogLevel.info)
        .data({'customer': 'cus_123', 'key': stripeKey}).send();
    expect(printed.single, contains('sk_live_****7890'));
    expect(printed.single, isNot(contains('51Hc29KJ8f3ks9fQ2')));
  });

  test('aiSafe for strings and maps', () {
    final rawContext =
        'Error with token: ghp_16C7e42F292c6912E7710c838347Ae178B4a'; // tracecloak-ignore
    final safePrompt = rawContext.aiSafe;
    expect(safePrompt, isNot(contains('16C7e42F292c6912')));

    final safeData = TraceCloak.aiSafe({'password': 'hunter2', 'step': 3});
    expect(safeData.toString(), isNot(contains('hunter2')));
  });

  test('Structured logging section output', () {
    TraceCloak.info('User signed in',
        metadata: {'userId': 42, 'password': 'hunter2'});
    expect(printed.single,
        '[INFO] User signed in | metadata: {userId: 42, password: ****}');
  });

  test('Scenario 2 output line', () {
    final secretKey = SecureKey(
        'sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890'); // tracecloak-ignore
    TraceCloak.log('Initializing payment intent', LogLevel.info)
        .data({'customer': 'cus_123', 'key': secretKey}).send();
    expect(printed.single,
        '[INFO] Initializing payment intent | metadata: {customer: cus_123, key: sk_live_****7890}');
  });

  test('fromEnvironment snippet', () {
    TraceCloak.setMode(MaskMode.fromEnvironment('TRACECLOAK_MODE'));
    expect(TraceCloak.mode, MaskMode.partial);
  });

  test('Testing-your-app snippet', () {
    final lines = <String>[];
    TraceCloak.customPrinter = lines.add;
    TraceCloak.info(
        'key sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890'); // tracecloak-ignore
    expect(lines.single, contains('sk_live_****7890'));
  });

  test('Login response scenario: JSON string with tokens is masked', () {
    const body =
        '{"userId": 1024, "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMDI0In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", '
        '"refreshToken": "aB39xK7mQ2vL5pT8wR1yU4zE6nJ0sAbCd"}';
    TraceCloak.run(() => print('User logged in successfully: $body'));
    expect(printed.single,
        'User logged in successfully: {"userId": 1024, "token": "eyJ****sw5c", "refreshToken": "aB39****AbCd"}');
  });
}

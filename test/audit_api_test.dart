// Audit findings that needed a new or corrected public API (see AUDIT.md).
// This file did not compile on the pre-release baseline.
import 'package:test/test.dart';
import 'package:vibeshield_flutter/vibeshield_flutter.dart';

void main() {
  test('L5 VibeShield.reset() restores every piece of global state', () {
    VibeShield.mode = MaskMode.off;
    VibeShield.addExactMatches(['L5-exact-secret']);
    VibeShield.addRules([
      DartSecretRule(
          id: 'x',
          name: 'x',
          category: 'x',
          cwe: 'x',
          regex: RegExp('L5-custom')),
    ]);
    VibeShield.customPrinter = (_) {};
    VibeShield.onRedacted = (_) {};

    VibeShield.reset();

    expect(VibeShield.mode, MaskMode.partial);
    expect(VibeShield.customPrinter, isNull);
    expect(VibeShield.onRedacted, isNull);
    expect(VibeShield.isInstalled, isFalse);
    expect(VibeShield.redact('x L5-exact-secret L5-custom y'),
        'x L5-exact-secret L5-custom y');
  });

  test(
      'M1 RedactedError keeps the original error and only exposes redacted text',
      () {
    RedactedError? received;
    VibeShield.run(
      () => throw ArgumentError(
          'bad key sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890'),
      onError: (e, _) => received = e as RedactedError,
    );
    expect(received!.original, isA<ArgumentError>());
    expect(received!.originalType, ArgumentError);
    expect(received.toString(), contains('sk_live_****7890'));
    expect(received!.message, isNot(contains('51Hc29KJ8f3ks9fQ2')));
  });
}

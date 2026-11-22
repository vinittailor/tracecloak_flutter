// Audit findings that needed a new or corrected public API (see AUDIT.md).
// This file did not compile on the pre-release baseline.
import 'package:test/test.dart';
import 'package:tracecloak/tracecloak.dart';

void main() {
  test('L5 TraceCloak.reset() restores every piece of global state', () {
    TraceCloak.mode = MaskMode.off;
    TraceCloak.addExactMatches(['L5-exact-secret']);
    TraceCloak.addRules([
      DartSecretRule(
          id: 'x',
          name: 'x',
          category: 'x',
          cwe: 'x',
          regex: RegExp('L5-custom')),
    ]);
    TraceCloak.customPrinter = (_) {};
    TraceCloak.onRedacted = (_) {};

    TraceCloak.reset();

    expect(TraceCloak.mode, MaskMode.partial);
    expect(TraceCloak.customPrinter, isNull);
    expect(TraceCloak.onRedacted, isNull);
    expect(TraceCloak.isInstalled, isFalse);
    expect(TraceCloak.redact('x L5-exact-secret L5-custom y'),
        'x L5-exact-secret L5-custom y');
  });

  test(
      'M1 RedactedError keeps the original error and only exposes redacted text',
      () {
    RedactedError? received;
    TraceCloak.run(
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

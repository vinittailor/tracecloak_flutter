import 'package:test/test.dart';
import 'package:dio/dio.dart';
import 'package:tracecloak/tracecloak.dart';

void main() {
  group('Unified TraceCloak Combined Approach Tests', () {
    setUp(TraceCloak.reset);

    test(
        '1. Extension Methods on String (apiKey.masked, .fullMasked, .redacted)',
        () {
      const stripeKey = 'sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890';
      expect(stripeKey.masked.startsWith('sk_live_****'), isTrue);
      expect(stripeKey.masked.endsWith('7890'), isTrue);

      const secret = 'sk_live_51Hc29KJ8f3ks9fQ2';
      final fullMask = secret.fullMasked;
      expect(fullMask, equals('aa_aaaa_00aa00aa0a0aa0aa0'));
      expect(verifyZeroCharacterOverlap(secret, fullMask), isTrue);

      const logMessage =
          'Connecting to Stripe sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890 securely';
      expect(logMessage.redacted.contains('sk_live_****7890'), isTrue);
      expect(
          logMessage.redacted.contains('51Hc29KJ8f3ks9fQ2ABCDEF12'), isFalse);
    });

    test('2. Global Zone Interception (TraceCloak.run)', () {
      final captured = <String>[];
      TraceCloak.customPrinter = (msg) => captured.add(msg);

      TraceCloak.run(() {
        // Standard print with zero TraceCloak references inside the block:
        print('Raw log with key: sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890');
      });

      expect(captured.length, equals(1));
      expect(captured[0].contains('sk_live_****7890'), isTrue);
      expect(captured[0].contains('51Hc29KJ8f3ks9fQ2ABCDEF12'), isFalse);
      TraceCloak.customPrinter = null;
    });

    test('3. Fluent Structured Logging with Metadata (.data().tag().send())',
        () {
      final captured = <String>[];
      TraceCloak.customPrinter = (msg) => captured.add(msg);

      TraceCloak.log('User completed checkout', LogLevel.info)
          .tag('BILLING')
          .data({
        'userId': 99,
        'stripeKey': 'sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890',
        'nested': {
          'apiKey': 'AKIAIOSFODNN7EXAMPLE',
        },
      }).send();

      expect(captured.length, equals(1));
      final out = captured[0];
      expect(out.contains('[BILLING] User completed checkout'), isTrue);
      expect(out.contains('sk_live_****7890'), isTrue);
      expect(out.contains('AKIA****MPLE'), isTrue);
      expect(out.contains('51Hc29KJ8f3ks9fQ2'), isFalse);
      expect(out.contains('IOSFODNN7EXA'), isFalse);
      TraceCloak.customPrinter = null;
    });

    test('4. HTTP & Network Header Scrubbing (TraceCloak.sanitizeHeaders)', () {
      final headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890',
        'X-Api-Key': 'AKIAIOSFODNN7EXAMPLE',
        'User-Agent': 'FlutterApp/1.0',
      };

      final sanitized = TraceCloak.sanitizeHeaders(headers);

      expect(sanitized['Content-Type'], equals('application/json'));
      expect(sanitized['User-Agent'], equals('FlutterApp/1.0'));
      expect(sanitized['Authorization'].toString().contains('sk_live_****7890'),
          isTrue);
      expect(
          sanitized['Authorization'].toString().contains('51Hc29KJ8f3ks9fQ2'),
          isFalse);
      expect(
          sanitized['X-Api-Key'].toString().contains('AKIA****MPLE'), isTrue);
      expect(
          sanitized['X-Api-Key'].toString().contains('IOSFODNN7EXA'), isFalse);
    });

    test(
        '5. Backward Compatibility: SecureLog alias works identical to TraceCloak',
        () {
      expect(SecureLog.mask('sk_live_51Hc29KJ8f3ks9fQ2'),
          equals('sk_live_****9fQ2'));
    });

    test('6. Three Masking Modes: Off, Half (Partial), and Full + cycleMode',
        () {
      const secret = 'sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890';

      // Mode: OFF
      TraceCloak.setMode(MaskMode.off);
      expect(TraceCloak.isOff, isTrue);
      expect(TraceCloak.redact('Key: $secret'), equals('Key: $secret'));

      // Mode: HALF / PARTIAL
      TraceCloak.setMode(MaskMode.partial);
      expect(TraceCloak.isPartial, isTrue);
      expect(TraceCloak.redact('Key: $secret'), contains('sk_live_****7890'));
      expect(secret.halfMasked, contains('sk_live_****7890'));

      // Mode: FULL (Shape-preserving, 0% overlap)
      TraceCloak.setMode(MaskMode.full);
      expect(TraceCloak.isFull, isTrue);
      final full = TraceCloak.redact('Key: $secret');
      expect(full.contains('sk_live'), isFalse);
      expect(full.contains('aa_aaaa'), isTrue);

      // cycleMode: full -> off -> partial -> full
      expect(TraceCloak.cycleMode(), equals(MaskMode.off));
      expect(TraceCloak.cycleMode(), equals(MaskMode.partial));
      expect(TraceCloak.cycleMode(), equals(MaskMode.full));

      // Reset
      TraceCloak.setMode(MaskMode.partial);
    });

    test(
        '7. Direct TraceCloakDioInterceptor cleans headers, query, and body in logs',
        () {
      final captured = <String>[];
      TraceCloak.customPrinter = (msg) => captured.add(msg);

      final dio = Dio();
      final interceptor = TraceCloak.dioInterceptor();
      dio.interceptors.add(interceptor);
      expect(dio.interceptors.contains(interceptor), isTrue);

      final options = RequestOptions(
        path: '/v1/charges',
        headers: {
          'Authorization': 'Bearer sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890',
        },
        queryParameters: {
          'apiKey': 'AKIAIOSFODNN7EXAMPLE',
        },
        data: {
          'clientSecret': 'sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890',
          'amount': 2000,
        },
      );

      final handler = _TestRequestHandler();
      interceptor.onRequest(options, handler);

      expect(handler.passedOptions, isNotNull);
      // The real HTTP request over the wire preserves the valid authorization key
      expect(options.headers['Authorization'],
          equals('Bearer sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890'));

      // BUT the logged console output has the secret safely redacted!
      expect(captured.isNotEmpty, isTrue);
      final log = captured[0];
      expect(log.contains('sk_live_****7890'), isTrue);
      expect(log.contains('51Hc29KJ8f3ks9fQ2ABCDEF12'), isFalse);
      expect(log.contains('AKIA****MPLE'), isTrue);

      TraceCloak.customPrinter = null;
    });

    test(
        '8. Provable Zero Release Footprint: enableInRelease = false directly runs body',
        () {
      bool executed = false;
      final value = TraceCloak.run(
        () {
          executed = true;
          return 'hello_production';
        },
        enableInRelease: false,
      );

      expect(executed, isTrue);
      expect(value, equals('hello_production'));
    });

    test(
        '9. SecureKey AI-Proof Wrapper: prevents toString/JSON/context leakage',
        () {
      const rawSecret = 'sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890';
      const secureKey = SecureKey(rawSecret);

      // String interpolation & toString ONLY returns masked preview
      expect(secureKey.toString(), contains('sk_live_****7890'));
      expect(
          secureKey.toString().contains('51Hc29KJ8f3ks9fQ2ABCDEF12'), isFalse);
      expect('Bearer $secureKey', contains('sk_live_****7890'));

      // JSON serialization is safe
      expect(secureKey.toJson().toString(), contains('sk_live_****7890'));

      // Raw value is ONLY accessible via explicit exposeRaw()
      expect(secureKey.exposeRaw(), equals(rawSecret));
    });

    test(
        '10. TraceCloak.aiSafe & String.aiSafe scrubs prompts before sending to LLMs',
        () {
      const promptWithSecret =
          'User asked for refund on Stripe key sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890 and token ghp_16C7e42F292c6912E7710c838347Ae178B4a';

      final safePrompt = promptWithSecret.aiSafe;
      expect(safePrompt.contains('sk_live'), isFalse);
      expect(safePrompt.contains('ghp_'), isFalse);
      expect(safePrompt.contains('51Hc29KJ8f3ks9fQ2'), isFalse);

      final safeMap = TraceCloak.aiSafe({
        'context': 'Debug context',
        'auth': 'sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890',
      }) as Map;

      expect(safeMap['auth'].toString().contains('sk_live'), isFalse);
    });

    test(
        '11. Stack trace and error sanitization (no leaked variables in crashes)',
        () {
      final captured = <String>[];
      TraceCloak.customPrinter = (msg) => captured.add(msg);

      final fakeStackTrace = StackTrace.fromString(
        '#0 Database.connect (package:app/db.dart:42)\n'
        '#1 ApiClient.get (https://api.stripe.com/v1/charges?key=sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890)\n'
        '#2 main (package:app/main.dart:10)',
      );

      final sanitizedTrace = TraceCloak.sanitizeStackTrace(fakeStackTrace);
      expect(sanitizedTrace.toString().contains('sk_live_****7890'), isTrue);
      expect(sanitizedTrace.toString().contains('51Hc29KJ8f3ks9fQ2ABCDEF12'),
          isFalse);

      TraceCloak.error(
        'Fatal failure in auth service',
        error: 'Failed with token: ghp_16C7e42F292c6912E7710c838347Ae178B4a',
        stackTrace: fakeStackTrace,
      );

      expect(captured.length, equals(1));
      expect(captured[0].contains('ghp_****8B4a'), isTrue);
      expect(captured[0].contains('sk_live_****7890'), isTrue);
      expect(captured[0].contains('16C7e42F292c6912E7710c838347Ae'), isFalse);

      TraceCloak.customPrinter = null;
    });

    test('12. wrapDebugPrint sanitizes framework-level logs', () {
      final captured = <String>[];
      final wrapped =
          TraceCloak.wrapDebugPrint((msg, {wrapWidth}) => captured.add(msg!));

      wrapped(
          'Flutter framework internal log: AWS secret AKIAIOSFODNN7EXAMPLE');
      expect(captured.length, equals(1));
      expect(captured[0].contains('AKIA****MPLE'), isTrue);
      expect(captured[0].contains('IOSFODNN7EXA'), isFalse);
    });

    test('13. Dio Interceptor sanitizes URI query parameters and error dumps',
        () {
      final captured = <String>[];
      TraceCloak.customPrinter = (msg) => captured.add(msg);

      final interceptor = TraceCloak.dioInterceptor();
      final options = RequestOptions(
        path:
            'https://api.example.com/checkout?apiKey=sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890',
        method: 'GET',
      );

      final handler = _TestRequestHandler();
      interceptor.onRequest(options, handler);

      expect(captured.any((c) => c.contains('sk_live_****7890')), isTrue);
      expect(captured.any((c) => c.contains('51Hc29KJ8f3ks9fQ2ABCDEF12')),
          isFalse);

      TraceCloak.customPrinter = null;
    });

    test(
        '14. TraceCloak.run with onError sanitizes uncaught exception & stack trace',
        () {
      Object? receivedError;
      StackTrace? receivedStack;

      TraceCloak.run(
        () {
          throw Exception(
              'Network auth failed with token: ghp_16C7e42F292c6912E7710c838347Ae178B4a');
        },
        onError: (err, stack) {
          receivedError = err;
          receivedStack = stack;
        },
      );

      expect(receivedError.toString().contains('ghp_****8B4a'), isTrue);
      expect(
          receivedError.toString().contains('16C7e42F292c6912E7710c838347Ae'),
          isFalse);
      expect(receivedStack, isNotNull);
    });
  });
}

class _TestRequestHandler extends RequestInterceptorHandler {
  RequestOptions? passedOptions;

  @override
  void next(RequestOptions requestOptions) {
    passedOptions = requestOptions;
  }
}

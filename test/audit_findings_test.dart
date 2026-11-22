// Regression tests for the findings in AUDIT.md. Each test name starts with the
// finding ID. Every test here failed on the pre-release baseline
// unless its name says "characterisation".
import 'dart:async';
import 'dart:io';

import 'package:dio/dio.dart';
import 'package:test/test.dart';
import 'package:tracecloak/tracecloak.dart';

class _User {
  final String password;
  _User(this.password);
  @override
  String toString() => 'User(password: $password)';
}

class _Handler extends RequestInterceptorHandler {
  @override
  void next(RequestOptions requestOptions) {}
}

/// Asserts that every character of [raw] that is not a structural separator
/// differs from the character at the same position in [masked].
void _expectNoContentOverlap(String raw, String masked) {
  expect(masked.length, raw.length);
  const separators = ' \t\r\n_-:/.@=\'",;';
  for (var i = 0; i < raw.length; i++) {
    if (separators.contains(raw[i])) continue;
    expect(masked[i].toLowerCase() == raw[i].toLowerCase(), isFalse,
        reason: 'char "${raw[i]}" at $i survived full mask: $masked');
  }
}

void main() {
  late List<String> printed;

  setUp(() {
    TraceCloak.reset();
    printed = [];
    TraceCloak.customPrinter = printed.add;
  });

  tearDown(TraceCloak.reset);

  group('critical', () {
    test(
        'C1 sanitizeHeaders always masks credential headers, even short values',
        () {
      final h = TraceCloak.sanitizeHeaders({
        'Authorization': 'Bearer hunter2',
        'Cookie': 'session=abc123',
        'X-Api-Key': 'k3yk3y9',
        'Content-Type': 'application/json',
      });
      final out = h.toString();
      expect(out, isNot(contains('hunter2')));
      expect(out, isNot(contains('abc123')));
      expect(out, isNot(contains('k3yk3y9')));
      expect(h['Authorization'], startsWith('Bearer '));
      expect(h['Content-Type'], 'application/json');
    });

    test('C2 sanitize() does not let custom objects leak through toString()',
        () {
      const secret = 'sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890';
      expect(TraceCloak.sanitize({'o': _User(secret)}).toString(),
          isNot(contains('51Hc29KJ8f3ks9fQ2')));

      TraceCloak.info('user', metadata: {'o': _User(secret)});
      expect(printed.single, isNot(contains('51Hc29KJ8f3ks9fQ2')));
    });

    test('C3 sanitize() masks values stored under sensitive keys', () {
      final out = TraceCloak.sanitize({
        'password': 'hunter2',
        'token': 'zq7',
        'nested': {'apiKey': 'k3y9'},
        'name': 'bob',
      }).toString();
      expect(out, isNot(contains('hunter2')));
      expect(out, isNot(contains('zq7')));
      expect(out, isNot(contains('k3y9')));
      expect(out, contains('bob'));
    });

    test('C3 Dio query parameters and bodies with short secrets are masked',
        () {
      TraceCloak.dioInterceptor().onRequest(
        RequestOptions(
          path: 'https://api.example.com/login',
          queryParameters: {'token': 'shortTok1'},
          data: {'password': 'hunter2', 'user': 'bob'},
        ),
        _Handler(),
      );
      expect(printed.join(), isNot(contains('shortTok1')));
      expect(printed.join(), isNot(contains('hunter2')));
      expect(printed.join(), contains('bob'));
    });
  });

  group('high', () {
    test('H1 short secrets next to keywords are masked', () {
      for (final line in [
        'password=hunter2',
        'login password=hunter2 token=abc9',
        '{"password":"hunter2","email":"a@b.c"}',
        "pwd: 'hunter2'",
        'Cookie: session=abc123',
        'secret_key: "k9F#hunter2"',
        'User(authToken: hunter2)',
      ]) {
        final out = TraceCloak.redact(line);
        expect(out, isNot(contains('hunter2')), reason: out);
        expect(out, isNot(contains('abc9')), reason: out);
        expect(out, isNot(contains('abc123')), reason: out);
        expect(out, isNot(contains('k9F#')), reason: out);
      }
      // No false positives on ordinary words, types and literals.
      for (final line in [
        'maxTokens: 500',
        'tokenCount=5',
        'author: bob',
        'tokenizer: bpe',
        'token: string',
        'isSecret: true',
        'password: null',
      ]) {
        expect(TraceCloak.redact(line), line);
      }
    });

    test(
        'H2 custom rule without a capture group masks the whole match instead of throwing',
        () {
      TraceCloak.addRules([
        DartSecretRule(
            id: 'acme',
            name: 'ACME',
            category: 'custom',
            cwe: 'CWE-798',
            regex: RegExp(r'ACME-[0-9]{8}')),
      ]);
      late String out;
      expect(() => out = TraceCloak.redact('my key ACME-12345678 here'),
          returnsNormally);
      expect(out, isNot(contains('12345678')));
    });

    test(
        'H3 an exact secret that contains another exact secret is fully masked',
        () {
      TraceCloak.addExactMatches(['h3abcd1234', 'h3abcd1234XYZsecretvalue']);
      final out = TraceCloak.redact('a h3abcd1234XYZsecretvalue b');
      expect(out, isNot(contains('XYZsecret')));
      expect(out, isNot(contains('secretvalue')));
    });

    test(
        'H4 partial mask never reveals more than a third of a secret without a known prefix',
        () {
      for (final s in [
        'hunter2',
        'hunter22',
        'abcdefghij',
        'Zx9!Qw7#Er',
        'abcdefghijklmnop',
        'aB39xK7mQ2vL5pT8wR1y'
      ]) {
        final masked = partialMask(s);
        final visible = masked.replaceAll('*', '').length;
        expect(visible <= s.length / 3, isTrue, reason: '$s -> $masked');
      }
    });

    test('H5 full mask does not keep symbols or non-ASCII letters', () {
      for (final s in [
        'пароль123',
        'p@\$\$w0rd!#%',
        'clé-secrète',
        'aB3+/xY9=='
      ]) {
        _expectNoContentOverlap(s, fullMask(s));
      }
    });

    test('H6 PEM, URL credentials, query params and AWS secret keys are masked',
        () {
      final cases = {
        '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA04m/+Q\nabcdEFGH/+12\n-----END RSA PRIVATE KEY-----':
            ['MIIEowIBAAKCAQEA04m', 'abcdEFGH'],
        'GET https://admin:hunter2@example.com/x': ['hunter2'],
        'GET https://api.x.com/v1?access_token=abc123xyz&api_key=k3y9&page=2': [
          'abc123xyz',
          'k3y9'
        ],
        'aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY': [
          'K7MDENG',
          'bPxRfiCY'
        ],
      };
      cases.forEach((input, leaks) {
        final out = TraceCloak.redact(input);
        for (final leak in leaks) {
          expect(out, isNot(contains(leak)), reason: out);
        }
      });
      expect(
          TraceCloak.redact(
              'GET https://api.x.com/v1?access_token=abc123xyz&page=2'),
          contains('page=2'));
    });

    test(
        'H6 provider keys are matched by a named rule, not just the entropy fallback',
        () {
      final samples = {
        'sk_test_4eC39HqLyjWDarjtT1zdp7dc': 'sk_test_',
        'AIzaSyD-1234567890abcdefghijklmnopqrstu': 'AIza',
        'sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCD': 'sk-proj-',
        'sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCD-xyzAA':
            'sk-ant-',
        'github_pat_11AAAAAAA0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_abcdefg':
            'github_pat_',
        'gho_16C7e42F292c6912E7710c838347Ae178B4a': 'gho_',
        'xoxp-123456789012-123456789012-abcdefghijklmnopqrstuvwx': 'xoxp-',
      };
      samples.forEach((key, prefix) {
        final events = <RedactionEvent>[];
        TraceCloak.onRedacted = events.add;
        final out = TraceCloak.redact('value $key end');
        expect(out,
            isNot(contains(key.substring(prefix.length, prefix.length + 10))),
            reason: out);
        expect(events.map((e) => e.ruleName),
            isNot(contains('High-Entropy Token')),
            reason: '$key -> $events');
        expect(out, contains('$prefix****'), reason: out);
      });
    });
  });

  group('medium', () {
    test(
        'M1 run(onError:) receives an object that keeps the original exception type',
        () {
      Object? received;
      TraceCloak.run(
        () => throw StateError(
            'auth failed ghp_16C7e42F292c6912E7710c838347Ae178B4a'),
        onError: (e, _) => received = e,
      );
      expect(received, isNot(isA<String>()));
      expect((received as dynamic).original, isA<StateError>());
      expect(received.toString(), isNot(contains('16C7e42F292c6912')));
    });

    test('M3 a customPrinter that calls print() inside run() does not recurse',
        () {
      final out = <String>[];
      runZoned(
        () {
          TraceCloak.customPrinter = (m) => print('[app] $m');
          TraceCloak.run(
              () => print('hello sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890'));
        },
        zoneSpecification:
            ZoneSpecification(print: (_, __, ___, line) => out.add(line)),
      );
      expect(out, ['[app] hello sk_live_****7890']);
    });

    test(
        'M4 protectProject() refreshes a stale managed block and keeps user lines',
        () {
      final dir = Directory.systemTemp.createTempSync('vs_m4_');
      addTearDown(() => dir.deleteSync(recursive: true));
      File('${dir.path}/.cursorignore').writeAsStringSync(
        'my-own-rule\n'
        '# --- TraceCloak Managed AI-Ignore Rules ---\n'
        '.env\n'
        '# --- End TraceCloak Managed Rules ---\n'
        'another-user-rule\n',
      );
      AiShield.protectProject(dir.path);
      final content = File('${dir.path}/.cursorignore').readAsStringSync();
      expect(content, contains('*.jks'));
      expect(content, contains('my-own-rule'));
      expect(content, contains('another-user-rule'));
      expect(
          '# --- TraceCloak Managed AI-Ignore Rules ---'
              .allMatches(content)
              .length,
          1);
    });

    test('M6 class names and identifiers are not treated as secrets', () {
      for (final s in [
        'class AbstractSingletonProxyFactoryBeanImpl',
        'TraceCloakDioInterceptorFactoryBuilder2024',
        'id 550e8400-e29b-41d4-a716-446655440000',
        'sha 3f786850e387550fdab836ed7e6dc881de23001b',
        'path lib/src/features/authentication/presentation/login_screen.dart',
        'pkg flutter_secure_storage_platform_interface',
      ]) {
        expect(TraceCloak.redact(s), s);
      }
    });
  });

  group('low', () {
    test('L1 log level appears in output', () {
      TraceCloak.warn('disk almost full');
      TraceCloak.error('boom');
      expect(printed[0], contains('WARN'));
      expect(printed[1], contains('ERROR'));
    });

    test(
        'L2 MaskMode.fromEnvironment rejects unsupported keys instead of silently ignoring them',
        () {
      expect(() => MaskMode.fromEnvironment('OTHER_KEY'),
          throwsA(isA<AssertionError>()));
      expect(
          MaskMode.fromEnvironment('TRACECLOAK_MODE', fallback: MaskMode.full),
          MaskMode.full);
    });

    test('L3 the dead secure_log.dart duplicate is gone', () {
      expect(File('lib/src/secure_log.dart').existsSync(), isFalse);
    });

    test('L4 characterisation: install() does not intercept print()', () {
      final out = <String>[];
      TraceCloak.install();
      runZoned(
        () => print('raw sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890'),
        zoneSpecification:
            ZoneSpecification(print: (_, __, ___, line) => out.add(line)),
      );
      expect(out.single, contains('51Hc29KJ8f3ks9fQ2'));
    });

    test(
        'L6 characterisation: async, timer and microtask prints inside run() are intercepted',
        () async {
      final done = Completer<void>();
      TraceCloak.run(() async {
        await Future<void>.delayed(Duration.zero);
        print('a sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890');
        scheduleMicrotask(
            () => print('b sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890'));
        Timer(Duration.zero, () {
          print('c sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890');
          done.complete();
        });
      });
      await done.future;
      expect(printed, hasLength(3));
      expect(printed.join(), isNot(contains('51Hc29KJ8f3ks9fQ2')));
    });

    test('L7 a throwing onRedacted callback does not break redaction', () {
      TraceCloak.onRedacted = (_) => throw StateError('telemetry down');
      late String out;
      expect(
          () => out =
              TraceCloak.redact('k sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890'),
          returnsNormally);
      expect(out, contains('sk_live_****7890'));
    });

    test('L8 sanitize() survives cyclic structures', () {
      final cyclic = <String, dynamic>{
        'token': 'sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890'
      };
      cyclic['self'] = cyclic;
      expect(() => TraceCloak.sanitize(cyclic), returnsNormally);
    });

    test('L9 rules match at _ and - boundaries', () {
      final events = <RedactionEvent>[];
      TraceCloak.onRedacted = events.add;
      TraceCloak.redact('k: sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890_x');
      expect(events.map((e) => e.ruleName), contains('Stripe Live Secret Key'));

      const jwt =
          'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw-';
      expect(TraceCloak.redact('jwt $jwt end', overrideMode: MaskMode.full),
          isNot(contains('w-')));
    });

    test('L10 redact() handles a 1 MB log in well under a second', () {
      final big = List.generate(
              20000, (i) => 'line $i user=bob action=click value=${i * 31}')
          .join('\n');
      final sw = Stopwatch()..start();
      TraceCloak.redact(big);
      expect(sw.elapsedMilliseconds, lessThan(1000));
    });

    test('L10 no rule backtracks catastrophically on adversarial input', () {
      const n = 50000;
      final inputs = [
        'postgres://a:${'b' * n}',
        'x=${'a-' * n}!',
        'eyJ${'a' * 20}.${'b' * 20}.${'-' * n}',
        'ab+' * n,
        'https://u:${'p' * n}',
        'token: ' * (n ~/ 4),
        '-----BEGIN PRIVATE KEY-----${'A' * n}',
        'aB3+/' * n,
      ];
      TraceCloak.redact(inputs.first); // JIT warm-up
      for (final input in inputs) {
        final sw = Stopwatch()..start();
        TraceCloak.redact(input);
        expect(sw.elapsedMilliseconds, lessThan(1000),
            reason: input.substring(0, 20));
      }
    });

    test('L11 protectProject() writes the JetBrains .aiignore file', () {
      final dir = Directory.systemTemp.createTempSync('vs_l11_');
      addTearDown(() => dir.deleteSync(recursive: true));
      AiShield.protectProject(dir.path);
      expect(File('${dir.path}/.aiignore').existsSync(), isTrue);
    });
  });
}

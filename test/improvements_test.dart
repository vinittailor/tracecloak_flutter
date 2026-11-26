import 'dart:convert';
import 'dart:io';
import 'package:dio/dio.dart';
import 'package:test/test.dart';
import 'package:tracecloak/tracecloak.dart';

class _NoopRequestHandler extends RequestInterceptorHandler {
  @override
  void next(RequestOptions requestOptions) {}
}

class _NoopResponseHandler extends ResponseInterceptorHandler {
  @override
  void next(Response response) {}
}

void main() {
  setUp(TraceCloak.reset);

  test(
      'AiShield.protectProject writes and merges .claude/settings.json deny rules',
      () {
    final dir = Directory.systemTemp.createTempSync('tc_claude_');
    addTearDown(() => dir.deleteSync(recursive: true));

    // Pre-existing settings with a custom allow rule and one deny rule
    final claudeDir = Directory('${dir.path}${Platform.pathSeparator}.claude')
      ..createSync();
    final settingsFile =
        File('${claudeDir.path}${Platform.pathSeparator}settings.json')
          ..writeAsStringSync(jsonEncode({
            'permissions': {
              'allow': ['Read(lib/**)'],
              'deny': ['Read(.env)'],
            },
          }));

    final updated = AiShield.protectProject(dir.path);
    expect(updated, contains('.claude/settings.json'));

    final decoded =
        jsonDecode(settingsFile.readAsStringSync()) as Map<String, dynamic>;
    final perms = decoded['permissions'] as Map<String, dynamic>;
    expect(perms['allow'], equals(['Read(lib/**)']));
    final deny = perms['deny'] as List;
    expect(deny.where((e) => e == 'Read(.env)').length, equals(1));
    expect(deny, contains('Read(**/key.properties)'));
    expect(deny, contains('Read(**/*.keystore)'));

    // Running again is idempotent
    final secondRun = AiShield.protectProject(dir.path);
    expect(secondRun, isEmpty);
  });

  test('TraceCloak.wrapPrint redacts third-party logger callbacks', () {
    final printed = <Object?>[];
    final wrapped = TraceCloak.wrapPrint(printed.add);

    wrapped('Token: sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890');
    expect(printed.single.toString(), contains('sk_live_****7890'));
    expect(printed.single.toString(),
        isNot(contains('51Hc29KJ8f3ks9fQ2ABCDEF12')));
  });

  test(
      'TraceCloak.redact and run() mask custom sensitiveKeys in plain JSON print',
      () {
    TraceCloak.addSensitiveKeys(['xyz_key']);
    final captured = <String>[];
    TraceCloak.customPrinter = captured.add;

    TraceCloak.run(() {
      print('API payload: {"xyz_key": "keyss here", "ok": true}');
    });

    expect(captured.single, isNot(contains('keyss here')));
    expect(captured.single, contains('"ok": true'));
  });

  test(
      'Dio interceptor summarizes bytes, truncates maxBodyLength, and respects body/header flags',
      () {
    final captured = <String>[];
    TraceCloak.customPrinter = captured.add;

    final interceptor = TraceCloak.dioInterceptor(
      logRequestHeaders: false,
      logRequestBody: false,
      maxBodyLength: 20,
    );

    final req = RequestOptions(
      path: 'https://api.example.com/upload',
      method: 'POST',
      headers: {'Authorization': 'Bearer secret-token'},
      data: {'secret': 'should-not-appear'},
    );
    interceptor.onRequest(req, _NoopRequestHandler());
    expect(captured.last, isNot(contains('headers:')));
    expect(captured.last, isNot(contains('body:')));

    // Binary bytes response
    interceptor.onResponse(
      Response(
        requestOptions: req,
        statusCode: 200,
        data: <int>[1, 2, 3, 4, 5],
      ),
      _NoopResponseHandler(),
    );
    expect(captured.last, contains('<5 bytes>'));

    // Long string response truncated after sanitization
    interceptor.onResponse(
      Response(
        requestOptions: req,
        statusCode: 200,
        data: 'x' * 100,
      ),
      _NoopResponseHandler(),
    );
    expect(captured.last, contains('...[truncated]'));
  });

  test(
      'CLI scanner ignores only comment directives and supports tracecloak-ignore-next-line',
      () async {
    final dir = Directory.systemTemp.createTempSync('tc_cli_ignore_');
    addTearDown(() => dir.deleteSync(recursive: true));

    File('${dir.path}${Platform.pathSeparator}lib.dart').writeAsStringSync('''
// tracecloak-ignore-next-line
const nextLineOk = 'sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890';
const inlineOk = 'sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890'; // tracecloak-ignore
const sneaky = 'https://tracecloak-ignore.example.com?k=sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890';
''');

    final res = await Process.run(
      Platform.resolvedExecutable,
      ['run', 'bin/tracecloak.dart', '--path=${dir.path}', '--json'],
      workingDirectory: Directory.current.path,
    );
    expect(res.exitCode, equals(1));
    final report = jsonDecode(res.stdout as String) as Map<String, dynamic>;
    expect(report['confirmedLeaks'], equals(1));
    final first = (report['findings'] as List).first as Map<String, dynamic>;
    expect(first['line'], equals(4));
    expect(first['rule'], equals('Stripe Live Secret Key'));
  });
}

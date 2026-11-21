// Release-build behaviour can only be observed in an AOT binary, because
// kDebugMode is a compile-time constant. See AUDIT.md H7 and M2.
@Timeout(Duration(minutes: 5))
library;

import 'dart:io';

import 'package:test/test.dart';

void main() {
  late Map<String, String> result;

  setUpAll(() async {
    final dir = Directory.systemTemp.createTempSync('vs_release_');
    addTearDown(() => dir.deleteSync(recursive: true));
    final exe = '${dir.path}/fixture${Platform.isWindows ? '.exe' : ''}';
    final compile = await Process.run(
      Platform.resolvedExecutable,
      ['compile', 'exe', 'test/fixtures/release_fixture.dart', '-o', exe],
    );
    expect(compile.exitCode, 0, reason: '${compile.stdout}${compile.stderr}');
    final run = await Process.run(exe, const []);
    result = {
      for (final line in (run.stdout as String)
          .split(RegExp(r'\r?\n'))
          .where((l) => l.contains(':')))
        line.substring(0, line.indexOf(':')):
            line.substring(line.indexOf(':') + 1),
    };
  });

  test('fixture really runs as a release build', () {
    expect(result['KDEBUG'], 'false');
  });

  test(
      'H7 exactSecrets passed to run() are honoured by aiSafe in release builds',
      () {
    expect(result['AISAFE'], isNot(contains('MyExactSecretValue99')));
  });

  test('M2 Dio interceptor with enableInRelease: true logs in release builds',
      () {
    expect(int.parse(result['DIOLINES']!), greaterThan(0));
  });
}

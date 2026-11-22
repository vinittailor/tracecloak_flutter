// Integration tests for bin/tracecloak.dart (see AUDIT.md H8).
@Timeout(Duration(minutes: 3))
library;

import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';

Future<ProcessResult> _scan(Directory dir, [List<String> extra = const []]) =>
    Process.run(Platform.resolvedExecutable,
        ['run', 'bin/tracecloak.dart', '--path=${dir.path}', ...extra]);

void main() {
  late Directory dir;

  setUp(() {
    dir = Directory.systemTemp.createTempSync('vs_cli_');
    Directory('${dir.path}/lib').createSync();
  });
  tearDown(() => dir.deleteSync(recursive: true));

  test('H8 --json exits 1 when a confirmed leak is found', () async {
    File('${dir.path}/lib/a.dart').writeAsStringSync(
        "const k = 'sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890';\n");
    final r = await _scan(dir, ['--json']);
    final report = jsonDecode(r.stdout as String) as Map<String, dynamic>;
    expect(report['confirmedLeaks'], 1);
    expect(r.exitCode, 1);
  });

  test(
      'clean project passes in both modes, and log-only heuristics do not fail CI',
      () async {
    File('${dir.path}/lib/a.dart').writeAsStringSync(
      'final password = TextEditingController();\n'
      "final url = 'https://api.example.com/v1?api_key=\$apiKey';\n",
    );
    final text = await _scan(dir);
    expect(text.exitCode, 0, reason: '${text.stdout}');
    final json = await _scan(dir, ['--json']);
    expect(json.exitCode, 0, reason: '${json.stdout}');
    expect((jsonDecode(json.stdout as String) as Map)['confirmedLeaks'], 0);
  });
}

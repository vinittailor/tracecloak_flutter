// File access for AiShield on platforms with dart:io (VM, mobile, desktop).
// Selected by a conditional import in ai_shield.dart; not exported.
import 'dart:io';

/// Writes [fileNames] in [rootPath] (default: current directory).
/// [render] receives the existing content (null if the file is missing) and
/// returns the new content. Returns the names of files that changed.
List<String> writeManagedFiles(
  String? rootPath,
  List<String> fileNames,
  String Function(String? existing) render,
) {
  final root = Directory(rootPath ?? Directory.current.path);
  if (!root.existsSync()) {
    throw ArgumentError.value(rootPath, 'rootPath', 'Directory does not exist');
  }
  final updated = <String>[];
  for (final name in fileNames) {
    final file = File('${root.path}${Platform.pathSeparator}$name');
    final existing = file.existsSync() ? file.readAsStringSync() : null;
    final next = render(existing);
    if (next != existing) {
      file.writeAsStringSync(next);
      updated.add(name);
    }
  }
  return updated;
}

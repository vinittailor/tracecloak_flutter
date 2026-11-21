// AiShield file access on platforms without dart:io (web).
// Selected by a conditional import in ai_shield.dart; not exported.

/// Always throws: there is no project directory to write to on the web.
List<String> writeManagedFiles(
  String? rootPath,
  List<String> fileNames,
  String Function(String? existing) render,
) {
  throw UnsupportedError(
    'AiShield.protectProject() needs dart:io and is not available on the web. '
    'Run `dart run vibeshield --shield-ai` from your project instead.',
  );
}

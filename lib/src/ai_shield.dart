import 'dart:convert';
import 'ai_shield_stub.dart' if (dart.library.io) 'ai_shield_io.dart' as files;
import 'tracecloak.dart';

/// An AI-proof wrapper for sensitive credentials.
///
/// Whenever this secret is printed, converted to string, serialized to JSON,
/// or inspected by an AI assistant in your editor, [toString] and [toJson]
/// ONLY return the masked representation (e.g. `sk_live_****7890`).
///
/// To pass the real credential to your HTTPS network client, explicitly call [exposeRaw].
///
/// Example:
/// ```dart
/// final stripeKey = SecureKey('sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890'); // tracecloak-ignore
///
/// print('Key: $stripeKey'); // Prints: Key: sk_live_****7890 (Safe from AI context!)
///
/// // Only exposed at the moment of HTTP network handshake:
/// final response = await dio.post(
///   '/charge',
///   options: Options(headers: {'Authorization': 'Bearer ${stripeKey.exposeRaw()}'}),
/// );
/// ```
class SecureKey {
  final String _raw;
  final MaskMode _maskMode;

  const SecureKey(this._raw, {MaskMode maskMode = MaskMode.partial})
      : _maskMode = maskMode;

  /// Safe masked representation (AI tools and loggers only see the mask!).
  @override
  String toString() => TraceCloak.mask(_raw, overrideMode: _maskMode);

  /// Safe JSON serialization.
  dynamic toJson() => toString();

  /// Explicitly retrieves the raw credential for the final HTTPS network call.
  String exposeRaw() => _raw;

  int get length => _raw.length;
}

/// AI Shield file generator for Flutter & Dart projects.
///
/// Creates and maintains a TraceCloak-managed block in AI-ignore files so AI
/// coding tools that honour them do not index `.env` files, key stores and
/// signing configs:
/// - `.aiignore` — JetBrains AI Assistant (documented, gitignore syntax)
/// - `.aiexclude` — Gemini in Android Studio
/// - `.cursorignore` — Cursor
/// - `.copilotignore`, `.claudeignore` — conventions without official vendor
///   documentation at the time of writing; kept for tools that read them.
///   GitHub Copilot content exclusion and Claude Code permission rules are
///   configured in their own settings, not by these files.
///
/// Uses `dart:io` file APIs, so it is meant for the CLI and desktop/VM tooling;
/// it does not work on Flutter Web.
class AiShield {
  static const List<String> managedAiIgnoreFiles = [
    '.aiignore',
    '.aiexclude',
    '.cursorignore',
    '.copilotignore',
    '.claudeignore',
  ];

  static const String _beginMarker =
      '# --- TraceCloak Managed AI-Ignore Rules ---';
  static const String _endMarker = '# --- End TraceCloak Managed Rules ---';

  static const List<String> defaultShieldRules = [
    _beginMarker,
    '# Protects sensitive Flutter & Dart files from AI indexing and prompt context',
    '.env',
    '.env.*',
    '*.env',
    '*.properties',
    'key.properties',
    'local.properties',
    'google-services.json',
    'GoogleService-Info.plist',
    '*.keystore',
    '*.jks',
    '*.p12',
    '*.pem',
    '*.key',
    '*secret*',
    '*credential*',
    _endMarker,
  ];

  static const String claudeSettingsFile = '.claude/settings.json';

  static const List<String> claudeDenyRules = [
    'Read(.env)',
    'Read(.env.*)',
    'Read(**/*.env)',
    'Read(**/key.properties)',
    'Read(**/local.properties)',
    'Read(**/google-services.json)',
    'Read(**/GoogleService-Info.plist)',
    'Read(**/*.keystore)',
    'Read(**/*.jks)',
    'Read(**/*.p12)',
    'Read(**/*.pem)',
    'Read(**/*.key)',
  ];

  /// Creates the AI-ignore files and `.claude/settings.json` deny rules in
  /// [rootPath] (defaults to the current directory), or refreshes the
  /// TraceCloak-managed entries inside existing ones.
  /// Lines outside the managed block (and existing Claude settings) are kept.
  /// Returns the names of files that were created or modified.
  /// Throws [UnsupportedError] on the web (no `dart:io`).
  static List<String> protectProject([String? rootPath]) {
    final updated = <String>[
      ...files.writeManagedFiles(
          rootPath, managedAiIgnoreFiles, _withManagedBlock),
      ...files.writeManagedFiles(
          rootPath, [claudeSettingsFile], _mergeClaudeSettings),
    ];
    return updated;
  }

  static String _mergeClaudeSettings(String? existing) {
    Map<String, dynamic> doc;
    if (existing == null || existing.trim().isEmpty) {
      doc = <String, dynamic>{};
    } else {
      try {
        final parsed = jsonDecode(existing);
        if (parsed is! Map<String, dynamic>) return existing;
        doc = Map<String, dynamic>.from(parsed);
      } on FormatException {
        // Never overwrite malformed user settings.
        return existing;
      }
    }

    final rawPerms = doc['permissions'];
    final perms = rawPerms is Map<String, dynamic>
        ? Map<String, dynamic>.from(rawPerms)
        : <String, dynamic>{};
    final rawDeny = perms['deny'];
    final deny = rawDeny is List ? List<dynamic>.from(rawDeny) : <dynamic>[];

    var changed = existing == null || existing.trim().isEmpty;
    for (final rule in claudeDenyRules) {
      if (!deny.contains(rule)) {
        deny.add(rule);
        changed = true;
      }
    }
    if (!changed && existing != null) return existing;

    perms['deny'] = deny;
    doc['permissions'] = perms;
    return '${const JsonEncoder.withIndent('  ').convert(doc)}\n';
  }

  /// Inserts or replaces the managed block in [existing] (null = new file).
  static String _withManagedBlock(String? existing) {
    final block = defaultShieldRules.join('\n');
    if (existing == null) return '$block\n';
    final begin = existing.indexOf(_beginMarker);
    if (begin < 0) {
      final sep = existing.isEmpty || existing.endsWith('\n') ? '\n' : '\n\n';
      return '$existing$sep$block\n';
    }
    final endIdx = existing.indexOf(_endMarker, begin);
    final after =
        endIdx < 0 ? '\n' : existing.substring(endIdx + _endMarker.length);
    return '${existing.substring(0, begin)}$block$after';
  }
}

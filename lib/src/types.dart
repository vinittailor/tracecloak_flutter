/// Core types, enums, and events for TraceCloak.
library;

/// Equivalent to Flutter's kDebugMode in pure Dart / Flutter environments.
/// In release mode (`dart.vm.product == true`), this evaluates to a compile-time false,
/// enabling Dart's AOT compiler to tree-shake out all code inside `if (kDebugMode)`.
const bool kDebugMode = !bool.fromEnvironment('dart.vm.product');

/// Secret masking mode enum used across TraceCloak:
/// - [off]: No redaction (raw secret string displayed).
/// - [partial]: Half mask / preview mode (e.g. `sk_live_****7890`).
/// - [full]: Full shape-preserving mask guaranteeing 0% character overlap (`aa_aaaa_00aa...`).
enum MaskMode {
  off,
  partial,
  full;

  /// Helper to check if this mode is off.
  bool get isOff => this == MaskMode.off;

  /// Helper to check if this mode is partial / half.
  bool get isPartial => this == MaskMode.partial;

  /// Helper to check if this mode is full.
  bool get isFull => this == MaskMode.full;

  /// Parses a string into MaskMode (case-insensitive).
  /// Accepts: 'off', 'none', 'half', 'partial', 'preview', 'full', 'strict'.
  static MaskMode fromString(String? value,
      {MaskMode fallback = MaskMode.partial}) {
    if (value == null) return fallback;
    switch (value.trim().toLowerCase()) {
      case 'off':
      case 'none':
        return MaskMode.off;
      case 'half':
      case 'partial':
      case 'preview':
        return MaskMode.partial;
      case 'full':
      case 'strict':
        return MaskMode.full;
      default:
        return fallback;
    }
  }

  /// Resolves MaskMode from the compile-time `--dart-define=TRACECLOAK_MODE=value` flag.
  /// Example: `flutter run --dart-define=TRACECLOAK_MODE=full`
  ///
  /// Only the key `'TRACECLOAK_MODE'` is supported: Dart can only read
  /// `--dart-define` values with a constant key on AOT and web builds.
  /// Other keys trigger an assertion in debug builds and return [fallback].
  /// For a custom key, read it yourself:
  /// `MaskMode.fromString(const String.fromEnvironment('MY_KEY'))`.
  static MaskMode fromEnvironment(String key,
      {MaskMode fallback = MaskMode.partial}) {
    assert(
      key == 'TRACECLOAK_MODE',
      "MaskMode.fromEnvironment only supports 'TRACECLOAK_MODE' (got '$key'). "
      "Use MaskMode.fromString(const String.fromEnvironment('$key')) instead.",
    );
    const definedValue = String.fromEnvironment('TRACECLOAK_MODE');
    if (definedValue.isNotEmpty && key == 'TRACECLOAK_MODE') {
      return fromString(definedValue, fallback: fallback);
    }
    return fallback;
  }
}

/// Log severity levels for structured logging.
enum LogLevel { debug, info, warn, error }

/// Non-custodial redaction event (Never contains raw secret strings).
class RedactionEvent {
  final String ruleName;
  final String category;
  final String maskedPreview;
  final DateTime timestamp;
  final String source;

  const RedactionEvent({
    required this.ruleName,
    required this.category,
    required this.maskedPreview,
    required this.timestamp,
    required this.source,
  });

  @override
  String toString() =>
      'RedactionEvent($ruleName, category: $category, preview: $maskedPreview, time: $timestamp)';
}

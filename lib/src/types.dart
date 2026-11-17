/// Core types, enums, and events for VibeShield.
library vibeshield.types;

/// Equivalent to Flutter's kDebugMode in pure Dart / Flutter environments.
/// In release mode (`dart.vm.product == true`), this evaluates to a compile-time false,
/// enabling Dart's AOT compiler to tree-shake out all code inside `if (kDebugMode)`.
const bool kDebugMode = !bool.fromEnvironment('dart.vm.product');

/// Secret masking mode enum used across VibeShield:
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
  static MaskMode fromString(String? value, {MaskMode fallback = MaskMode.partial}) {
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

  /// Resolves MaskMode from a compile-time `--dart-define=KEY=value` flag.
  /// Example: `flutter run --dart-define=VIBESHIELD_MODE=full`
  static MaskMode fromEnvironment(String key, {MaskMode fallback = MaskMode.partial}) {
    const definedValue = String.fromEnvironment('VIBESHIELD_MODE');
    if (definedValue.isNotEmpty && key == 'VIBESHIELD_MODE') {
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

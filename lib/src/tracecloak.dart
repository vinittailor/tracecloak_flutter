/// Unified TraceCloak Flutter/Dart SDK combining:
/// 1. Zone-based `print()` interception (`TraceCloak.run()`)
/// 2. Native Dart extension methods (`secret.masked`, `text.redacted`, `secret.fullMasked`)
/// 3. Structured fluent logging with auto-sanitized metadata (`TraceCloak.info(...)`, `TraceCloak.log(...).send()`)
/// 4. Network header scrubbing (`TraceCloak.sanitizeHeaders(...)`)
/// 5. Non-custodial audit callbacks (`TraceCloak.onRedacted`)
/// 6. No zone and no log output in release builds unless `enableInRelease: true`
library;

import 'dart:async';
import 'masker.dart';
import 'rules.dart';
import 'entropy.dart';
import 'types.dart';
import 'dio_interceptor.dart';
import 'ai_shield.dart';
import 'log_output.dart';

export 'masker.dart';
export 'rules.dart';
export 'entropy.dart';
export 'types.dart';
export 'dio_interceptor.dart';
export 'ai_shield.dart';

/// Backward-compatibility alias
typedef SecureLog = TraceCloak;

/// An error whose text has been redacted, passed to `TraceCloak.run(onError:)`
/// and to the parent zone's uncaught-error handler.
///
/// [toString] and [message] contain only redacted text, so it is safe to hand
/// to Crashlytics, Sentry or a logger. [original] is the untouched error, kept
/// so you can branch on its type (`if (e.original is DioException)`); do not log
/// [original] itself, because its `toString()` may contain secrets.
class RedactedError implements Exception {
  /// The original, unredacted error object.
  final Object original;

  /// `original.toString()` with all secrets redacted.
  final String message;

  RedactedError(this.original, this.message);

  /// Runtime type of [original].
  Type get originalType => original.runtimeType;

  @override
  String toString() => message;
}

class _Span {
  final int start;
  final int end;
  final String ruleName;
  final String category;
  final String? prefix;

  /// Tie-breaker for spans with the same bounds: 0 exact / confirmed rule,
  /// 1 heuristic rule, 2 entropy.
  final int rank;
  const _Span(this.start, this.end, this.ruleName, this.category, this.rank,
      [this.prefix]);
}

class TraceCloak {
  static MaskMode mode = MaskMode.partial;
  static final Set<String> _exactMatches = {};
  static final List<DartSecretRule> _customRules = [];
  static void Function(String message)? customPrinter;
  static bool _installed = false;
  static bool _releaseOutputEnabled = false;

  /// Maximum nesting depth walked by [sanitize]; deeper values are replaced.
  static const int _maxDepth = 32;

  /// Map keys / header names whose values are always masked in full.
  static final RegExp _sensitiveKey = RegExp(
    r'pass(?:word|wd|phrase)|^pass$|pwd|secret|token|api[-_ ]?key|access[-_ ]?key|private[-_ ]?key|'
    r'credential|cookie|session|authorization|auth$|signature|^pin$|^otp$|^cvv$|^key$',
    caseSensitive: false,
  );

  static final RegExp _authScheme = RegExp(
      r'^(Bearer|Basic|Digest|Token|Bot)\s+(.+)$',
      caseSensitive: false,
      dotAll: true);

  /// Mode inspection getters
  static bool get isOff => mode == MaskMode.off;
  static bool get isPartial => mode == MaskMode.partial;
  static bool get isFull => mode == MaskMode.full;

  /// Sets the active masking mode:
  /// - `MaskMode.off`: No redaction (raw secret).
  /// - `MaskMode.partial`: Half mask / preview (`sk_live_****9fQ2`).
  /// - `MaskMode.full`: Shape-preserving full mask (`aa_aaaa_00aa...`, 0% character overlap).
  static void setMode(MaskMode newMode) {
    mode = newMode;
  }

  /// Cycles through masking modes: off -> partial -> full -> off.
  static MaskMode cycleMode() {
    switch (mode) {
      case MaskMode.off:
        mode = MaskMode.partial;
        break;
      case MaskMode.partial:
        mode = MaskMode.full;
        break;
      case MaskMode.full:
        mode = MaskMode.off;
        break;
    }
    return mode;
  }

  /// Restores all global state to its defaults: mode, exact matches, custom
  /// rules, [customPrinter], [onRedacted] and the installed/release flags.
  /// Intended for tests (`setUp(TraceCloak.reset)`).
  static void reset() {
    mode = MaskMode.partial;
    _exactMatches.clear();
    _customRules.clear();
    customPrinter = null;
    onRedacted = null;
    _installed = false;
    _releaseOutputEnabled = false;
  }

  /// Direct plug-and-play Dio Interceptor instance.
  /// Usage: `dio.interceptors.add(TraceCloak.dioInterceptor());`
  /// Optionally override the masking mode specifically for Dio:
  /// `dio.interceptors.add(TraceCloak.dioInterceptor(mode: MaskMode.full));`
  static TraceCloakDioInterceptor dioInterceptor({
    MaskMode? mode,
    bool enableInRelease = false,
    bool logRequests = true,
    bool logResponses = true,
    bool logErrors = true,
  }) =>
      TraceCloakDioInterceptor(
        overrideMode: mode,
        enableInRelease: enableInRelease,
        logRequests: logRequests,
        logResponses: logResponses,
        logErrors: logErrors,
      );

  /// Non-custodial audit callback hook (Safe for Sentry, Crashlytics, Telemetry).
  /// Exceptions thrown by the callback are swallowed so they cannot break logging.
  static void Function(RedactionEvent event)? onRedacted;

  // --------------------------------------------------------------------------
  // 1. ZONE-BASED PRINT INTERCEPTION
  // --------------------------------------------------------------------------

  /// Stores global configuration (mode, exact secrets, audit listener) WITHOUT
  /// intercepting anything.
  ///
  /// `install()` does **not** mask plain `print()`. Dart's `print()` can only be
  /// intercepted by running code inside a [Zone]; use [TraceCloak.run] for that:
  /// ```dart
  /// void main() => TraceCloak.run(() => runApp(const MyApp()));
  /// ```
  /// Configuration is applied in every build mode, so [redact], [aiSafe] and
  /// [sanitize] keep honouring [exactSecrets] in release builds. Structured log
  /// output ([TraceCloak.print], [info], ...) is only emitted in release builds
  /// when [enableInRelease] is true.
  static void install({
    MaskMode? initialMode,
    bool enableInRelease = false,
    List<String>? exactSecrets,
    void Function(RedactionEvent event)? onRedactionEvent,
  }) {
    _applyConfig(initialMode, exactSecrets, onRedactionEvent);
    if (enableInRelease) _releaseOutputEnabled = true;
    if (kDebugMode || enableInRelease) _installed = true;
  }

  /// True if [install] or [run] has configured TraceCloak for this build mode.
  /// This does not mean `print()` is intercepted — only code inside [run] is.
  static bool get isInstalled => _installed;

  static void _applyConfig(
    MaskMode? newMode,
    List<String>? exactSecrets,
    void Function(RedactionEvent event)? onRedactionEvent,
  ) {
    if (newMode != null) mode = newMode;
    if (exactSecrets != null) addExactMatches(exactSecrets);
    if (onRedactionEvent != null) onRedacted = onRedactionEvent;
  }

  /// Runs an entire Flutter app or code block inside an auto-redacting Dart Zone.
  ///
  /// Every `print()` executed inside [body] — including async code, timers and
  /// microtasks started from it — is redacted. Not covered: `stdout.write`,
  /// `dart:developer` `log()`, other isolates, Flutter's `debugPrint` (wrap it
  /// with [wrapDebugPrint]), and errors thrown before [run] is called.
  ///
  /// Uncaught errors are wrapped in a [RedactedError] (redacted text, original
  /// object kept in [RedactedError.original]) and passed to [onError], or to the
  /// parent zone if [onError] is null.
  ///
  /// In release builds with [enableInRelease] false (the default), [body] runs
  /// directly with no Zone. [mode], [exactSecrets] and [onRedactionEvent] are
  /// still applied so explicit [redact] / [aiSafe] calls keep working.
  ///
  /// ```dart
  /// void main() => TraceCloak.run(() => runApp(const MyApp()));
  /// ```
  static R? run<R>(
    R Function() body, {
    MaskMode? mode,
    bool enableInRelease = false,
    List<String>? exactSecrets,
    void Function(RedactionEvent event)? onRedactionEvent,
    void Function(Object error, StackTrace stackTrace)? onError,
  }) {
    _applyConfig(mode, exactSecrets, onRedactionEvent);

    // In release builds, bypass the Zone entirely by default.
    if (!kDebugMode && !enableInRelease) {
      return body();
    }

    _installed = true;
    if (enableInRelease) _releaseOutputEnabled = true;

    final zoneSpec = ZoneSpecification(
      print: (self, parent, zone, line) {
        final sanitized = redact(line);
        final printer = customPrinter;
        if (printer != null) {
          // Run outside this zone so a printer that itself calls print()
          // does not re-enter this handler.
          self.parent!.run(() => printer(sanitized));
        } else {
          parent.print(zone, sanitized);
        }
      },
      handleUncaughtError: onError != null
          ? null
          : (self, parent, zone, error, stackTrace) {
              parent.handleUncaughtError(
                  zone, _redactError(error), sanitizeStackTrace(stackTrace));
            },
    );

    if (onError != null) {
      return runZonedGuarded<R>(
        body,
        (error, stackTrace) =>
            onError(_redactError(error), sanitizeStackTrace(stackTrace)),
        zoneSpecification: zoneSpec,
      );
    }

    return runZoned(body, zoneSpecification: zoneSpec);
  }

  static RedactedError _redactError(Object error) => error is RedactedError
      ? error
      : RedactedError(error, redact(error.toString()));

  /// Intercepts Flutter's `debugPrint` callback to ensure framework logs are masked.
  ///
  /// Usage in Flutter `main()`:
  /// ```dart
  /// debugPrint = TraceCloak.wrapDebugPrint(debugPrint);
  /// ```
  static void Function(String? message, {int? wrapWidth}) wrapDebugPrint([
    void Function(String? message, {int? wrapWidth})? original,
  ]) {
    return (String? message, {int? wrapWidth}) {
      if (message == null) return;
      final sanitized = redact(message);
      if (original != null) {
        original(sanitized, wrapWidth: wrapWidth);
      } else if (customPrinter != null) {
        customPrinter!(sanitized);
      } else {
        Zone.root.print(sanitized);
      }
    };
  }

  /// Sanitizes a [StackTrace], ensuring credentials, tokens in query parameters,
  /// or dumped variable strings in stack traces do not leak to the console.
  static StackTrace sanitizeStackTrace(StackTrace stackTrace,
      {MaskMode? overrideMode}) {
    final sanitized = redact(stackTrace.toString(), overrideMode: overrideMode);
    return StackTrace.fromString(sanitized);
  }

  /// Sanitizes an error/exception and its optional stack trace.
  static (String error, StackTrace? stackTrace) sanitizeError(
    Object error, [
    StackTrace? stackTrace,
    MaskMode? overrideMode,
  ]) {
    final sanitizedError = redact(error.toString(), overrideMode: overrideMode);
    final sanitizedStack = stackTrace != null
        ? sanitizeStackTrace(stackTrace, overrideMode: overrideMode)
        : null;
    return (sanitizedError, sanitizedStack);
  }

  // --------------------------------------------------------------------------
  // 2. SECRET REDACTION & MASKING CORE
  // --------------------------------------------------------------------------

  /// Register exact match strings to redact (e.g. from local environment / .env).
  /// Values shorter than 4 characters (after trimming) are ignored.
  static void addExactMatches(List<String> secrets) {
    for (final s in secrets) {
      if (s.trim().length >= 4) {
        _exactMatches.add(s.trim());
      }
    }
  }

  /// Register custom secret rules. If a rule's regex has a capture group, only
  /// group 1 is masked (it should be at the end of the match); otherwise the
  /// whole match is masked.
  static void addRules(List<DartSecretRule> rules) {
    _customRules.addAll(rules);
  }

  /// Clears registered custom rules.
  static void clearRules() {
    _customRules.clear();
  }

  // True if a map key or header name (e.g. `password`, `Authorization`,
  // `X-Api-Key`, `Cookie`) marks its value as a secret.
  static bool _isSensitiveKey(String key) => _sensitiveKey.hasMatch(key);

  /// Convenience single-value masking helper.
  static String mask(String secret, {MaskMode? overrideMode}) {
    final activeMode = overrideMode ?? mode;
    if (activeMode == MaskMode.off || secret.isEmpty) return secret;
    if (activeMode == MaskMode.full) {
      return fullMask(secret);
    }
    return partialMask(secret);
  }

  /// Recursively sanitizes any value for logging.
  ///
  /// - Strings are passed through [redact].
  /// - Map values under sensitive keys (see `_sensitiveKey`) are masked in full.
  /// - Maps and iterables are walked (iterables become lists, cycles and nesting
  ///   deeper than 32 levels are replaced by a placeholder).
  /// - `null`, numbers, booleans and enums are returned unchanged.
  /// - Any other object is converted with `toString()` and redacted, so custom
  ///   classes cannot leak secrets through their `toString()`.
  static dynamic sanitize(dynamic value, {MaskMode? overrideMode}) {
    final activeMode = overrideMode ?? mode;
    if (activeMode == MaskMode.off) return value;
    return _sanitize(value, activeMode, Set<Object>.identity(), 0, false);
  }

  static dynamic _sanitize(
      dynamic value, MaskMode m, Set<Object> seen, int depth, bool forceMask) {
    if (value == null) return null;
    if (value is Map || value is Iterable) {
      if (depth >= _maxDepth) return '[max depth]';
      if (!seen.add(value as Object)) return '[circular]';
      try {
        if (value is Map) {
          final out = <dynamic, dynamic>{};
          for (final entry in value.entries) {
            final key = entry.key;
            final sensitive =
                forceMask || (key is String && _isSensitiveKey(key));
            out[_sanitizeKey(key, m)] =
                _sanitize(entry.value, m, seen, depth + 1, sensitive);
          }
          return out;
        }
        return [
          for (final item in value as Iterable)
            _sanitize(item, m, seen, depth + 1, forceMask)
        ];
      } finally {
        seen.remove(value);
      }
    }
    // SecureKey is already masked by its own toString().
    if (value is SecureKey) return value.toString();
    if (forceMask) return _maskWhole(value.toString(), m);
    if (value is String) return redact(value, overrideMode: m);
    if (value is num || value is bool || value is Enum) return value;
    return redact(value.toString(), overrideMode: m);
  }

  static dynamic _sanitizeKey(dynamic key, MaskMode m) {
    if (key == null || key is num || key is bool || key is Enum) return key;
    return redact(key.toString(), overrideMode: m);
  }

  /// Masks an entire value known to be secret, keeping an auth scheme
  /// (`Bearer ****`) visible.
  static String _maskWhole(String value, MaskMode m) {
    if (value.isEmpty) return value;
    final scheme = _authScheme.firstMatch(value);
    final masked = scheme != null
        ? '${scheme.group(1)} ${mask(scheme.group(2)!, overrideMode: m)}'
        : mask(value, overrideMode: m);
    _fireRedactedEvent('Sensitive Key', 'key', masked);
    return masked;
  }

  /// Redacts sensitive credentials across any string message.
  ///
  /// Exact matches, rule matches and high-entropy tokens are all located on the
  /// original text, overlapping hits are merged, and each merged span is masked
  /// exactly once.
  static String redact(String message, {MaskMode? overrideMode}) {
    final activeMode = overrideMode ?? mode;
    if (activeMode == MaskMode.off || message.isEmpty) return message;

    final spans = <_Span>[];

    // 1. Exact matches (.env, vault)
    for (final exact in _exactMatches) {
      var i = message.indexOf(exact);
      while (i >= 0) {
        spans.add(_Span(i, i + exact.length, 'Exact Match', 'exact', 0));
        i = message.indexOf(exact, i + exact.length);
      }
    }

    // 2. Pattern rules (canonical + custom)
    _collectRuleSpans(defaultDartRules, message, spans);
    if (_customRules.isNotEmpty) {
      _collectRuleSpans(_customRules, message, spans);
    }

    // 3. Fallback: Shannon entropy detection for unknown tokens, on a copy where
    // spans already found are blanked out (same offsets), so a rule hit is not
    // swallowed by a longer token such as `apiKey=sk_live_...`.
    var entropyInput = message;
    if (spans.isNotEmpty) {
      final units = List<int>.of(message.codeUnits);
      for (final s in spans) {
        units.fillRange(s.start, s.end, 0x20);
      }
      entropyInput = String.fromCharCodes(units);
    }
    for (final em in scanHighEntropyTokens(entropyInput)) {
      spans.add(_Span(em.start, em.end, 'High-Entropy Token', 'entropy', 2));
    }

    if (spans.isEmpty) return message;

    // Earliest first; for equal starts the longest first, then the most
    // specific rule, so it names the merged span.
    spans.sort((a, b) {
      if (a.start != b.start) return a.start.compareTo(b.start);
      if (a.end != b.end) return b.end.compareTo(a.end);
      return a.rank.compareTo(b.rank);
    });

    final out = StringBuffer();
    var cursor = 0;
    var i = 0;
    while (i < spans.length) {
      final head = spans[i];
      var end = head.end;
      var j = i + 1;
      while (j < spans.length && spans[j].start < end) {
        if (spans[j].end > end) end = spans[j].end;
        j++;
      }
      final raw = message.substring(head.start, end);
      final replacement = activeMode == MaskMode.full
          ? fullMask(raw)
          : partialMask(raw, prefix: head.prefix);
      out
        ..write(message.substring(cursor, head.start))
        ..write(replacement);
      _fireRedactedEvent(head.ruleName, head.category, replacement);
      cursor = end;
      i = j;
    }
    out.write(message.substring(cursor));
    return out.toString();
  }

  static void _collectRuleSpans(
      List<DartSecretRule> rules, String message, List<_Span> spans) {
    for (final rule in rules) {
      for (final match in rule.regex.allMatches(message)) {
        final whole = match.group(0)!;
        var start = match.start;
        var end = match.end;
        final group = match.groupCount >= 1 ? match.group(1) : null;
        if (group != null && group.isNotEmpty) {
          final offset = whole.endsWith(group)
              ? whole.length - group.length
              : whole.lastIndexOf(group);
          start = match.start + offset;
          end = start + group.length;
        }
        if (end > start) {
          spans.add(_Span(start, end, rule.name, rule.category,
              rule.confidence == kConfidenceHeuristic ? 1 : 0, rule.prefix));
        }
      }
    }
  }

  static void _fireRedactedEvent(
      String ruleName, String category, String maskedPreview) {
    final listener = onRedacted;
    if (listener == null) return;
    try {
      listener(RedactionEvent(
        ruleName: ruleName,
        category: category,
        maskedPreview: maskedPreview,
        timestamp: DateTime.now(),
        source: 'flutter-sdk',
      ));
    } catch (_) {
      // A failing audit hook must never break logging.
    }
  }

  /// Sanitizes text, prompts, logs, or JSON payloads specifically for passing to AI / LLM models.
  /// Replaces all API keys, bearer tokens, passwords, and high-entropy strings with shape-preserving
  /// masks (0% character overlap), ensuring no real secret ever reaches OpenAI, Anthropic, Gemini, or any LLM server.
  static dynamic aiSafe(dynamic payload) {
    return sanitize(payload, overrideMode: MaskMode.full);
  }

  /// Creates or refreshes AI-ignore files (`.aiignore`, `.aiexclude`, `.cursorignore`,
  /// `.copilotignore`, `.claudeignore`) in your project to keep `.env`,
  /// `key.properties` and keystores out of AI tools that honour them.
  /// Requires `dart:io` (not available on Flutter Web).
  static List<String> protectFromAi([String? rootPath]) {
    return AiShield.protectProject(rootPath);
  }

  // --------------------------------------------------------------------------
  // 3. NETWORK & HTTP SCRUBBING (Headers & Payloads)
  // --------------------------------------------------------------------------

  /// Sanitizes an HTTP headers map. Headers whose names mark them as credentials
  /// (`Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`, `*-Token`, ...) are
  /// always masked in full (`Bearer ****`); other headers are scanned with [redact].
  static Map<String, dynamic> sanitizeHeaders(
    Map<String, dynamic> headers, {
    MaskMode? overrideMode,
  }) {
    final activeMode = overrideMode ?? mode;
    if (activeMode == MaskMode.off) return Map.of(headers);
    final seen = Set<Object>.identity();
    return {
      for (final entry in headers.entries)
        entry.key: _sanitize(
            entry.value, activeMode, seen, 0, _isSensitiveKey(entry.key)),
    };
  }

  // --------------------------------------------------------------------------
  // 4. FLUENT STRUCTURED LOGGING
  // --------------------------------------------------------------------------

  /// Fluent log builder: `TraceCloak.log('Checkout').tag('BILLING').data({...}).send()`
  static TraceCloakLogBuilder log(String message,
          [LogLevel level = LogLevel.info]) =>
      TraceCloakLogBuilder(message, level);

  /// Direct structured methods for each log level
  static void debug(
    Object? message, {
    Map<String, dynamic>? metadata,
    Object? error,
    StackTrace? stackTrace,
    String? tag,
  }) =>
      print(message,
          metadata: metadata,
          error: error,
          stackTrace: stackTrace,
          tag: tag,
          level: LogLevel.debug);

  static void info(
    Object? message, {
    Map<String, dynamic>? metadata,
    Object? error,
    StackTrace? stackTrace,
    String? tag,
  }) =>
      print(message,
          metadata: metadata,
          error: error,
          stackTrace: stackTrace,
          tag: tag,
          level: LogLevel.info);

  static void warn(
    Object? message, {
    Map<String, dynamic>? metadata,
    Object? error,
    StackTrace? stackTrace,
    String? tag,
  }) =>
      print(message,
          metadata: metadata,
          error: error,
          stackTrace: stackTrace,
          tag: tag,
          level: LogLevel.warn);

  static void error(
    Object? message, {
    Map<String, dynamic>? metadata,
    Object? error,
    StackTrace? stackTrace,
    String? tag,
  }) =>
      print(message,
          metadata: metadata,
          error: error,
          stackTrace: stackTrace,
          tag: tag,
          level: LogLevel.error);

  /// Direct structured print method. Output format:
  /// `[LEVEL] [tag] message | metadata: {...} | error: ...` followed by the stack trace.
  ///
  /// Emits in debug builds, and in release builds only after [run] or [install]
  /// was called with `enableInRelease: true`.
  static void print(
    Object? object, {
    Map<String, dynamic>? metadata,
    Object? error,
    StackTrace? stackTrace,
    String? tag,
    LogLevel level = LogLevel.info,
  }) {
    if (kDebugMode || _releaseOutputEnabled) {
      emitStructuredLog(
        object,
        metadata: metadata,
        error: error,
        stackTrace: stackTrace,
        tag: tag,
        level: level,
      );
    }
  }
}

/// Fluent builder for structured logs with metadata, error, and tags.
class TraceCloakLogBuilder {
  final String _message;
  final LogLevel _level;
  String? _tag;
  Map<String, dynamic>? _metadata;
  Object? _error;
  StackTrace? _stackTrace;

  TraceCloakLogBuilder(this._message, [this._level = LogLevel.info]);

  TraceCloakLogBuilder tag(String tag) {
    _tag = tag;
    return this;
  }

  TraceCloakLogBuilder data(Map<String, dynamic> metadata) {
    _metadata = metadata;
    return this;
  }

  TraceCloakLogBuilder error(Object error, [StackTrace? stackTrace]) {
    _error = error;
    _stackTrace = stackTrace;
    return this;
  }

  void send() {
    TraceCloak.print(
      _message,
      metadata: _metadata,
      error: _error,
      stackTrace: _stackTrace,
      tag: _tag,
      level: _level,
    );
  }
}

// --------------------------------------------------------------------------
// 5. NATIVE DART STRING EXTENSIONS
// --------------------------------------------------------------------------

/// Idiomatic Dart string extension for effortless secret masking.
extension TraceCloakStringExtension on String {
  /// Redacts all sensitive credentials contained in this string.
  String get redacted => TraceCloak.redact(this);

  /// Masks this string as a single secret in partial (half) mode (e.g. `sk_live_****9fQ2`).
  String get masked => TraceCloak.mask(this, overrideMode: MaskMode.partial);

  /// Half mask alias for partial mode.
  String get halfMasked =>
      TraceCloak.mask(this, overrideMode: MaskMode.partial);

  /// Masks this string in full shape-preserving mode (guaranteeing 0% character overlap).
  String get fullMasked => TraceCloak.mask(this, overrideMode: MaskMode.full);

  /// Masks this string using an explicit mode.
  String maskWith(MaskMode mode) => TraceCloak.mask(this, overrideMode: mode);

  /// Converts this string or prompt into an AI-safe prompt where all credentials are fully masked.
  String get aiSafe => TraceCloak.redact(this, overrideMode: MaskMode.full);
}

// Internal: shared structured-log formatter. Not exported from the package.
library;

import 'dart:async';

import 'vibeshield.dart';

/// Formats, sanitises and emits one structured log line. Callers decide
/// whether output is allowed (debug build or explicit `enableInRelease`).
void emitStructuredLog(
  Object? object, {
  Map<String, dynamic>? metadata,
  Object? error,
  StackTrace? stackTrace,
  String? tag,
  LogLevel level = LogLevel.info,
  MaskMode? overrideMode,
}) {
  final buffer = StringBuffer('[${level.name.toUpperCase()}] ');
  if (tag != null) buffer.write('[$tag] ');
  buffer.write(VibeShield.redact(object?.toString() ?? 'null',
      overrideMode: overrideMode));

  if (metadata != null && metadata.isNotEmpty) {
    buffer.write(
        ' | metadata: ${VibeShield.sanitize(metadata, overrideMode: overrideMode)}');
  }
  if (error != null) {
    buffer.write(
        ' | error: ${VibeShield.redact(error.toString(), overrideMode: overrideMode)}');
  }
  if (stackTrace != null) {
    buffer.write(
        '\n${VibeShield.sanitizeStackTrace(stackTrace, overrideMode: overrideMode)}');
  }

  final output = buffer.toString();
  final printer = VibeShield.customPrinter;
  if (printer != null) {
    printer(output);
  } else {
    Zone.root.print(output);
  }
}

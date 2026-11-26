// Internal: shared structured-log formatter. Not exported from the package.
library;

import 'dart:async';

import 'tracecloak.dart';

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
  Iterable<String>? sensitiveKeys,
}) {
  final buffer = StringBuffer('[${level.name.toUpperCase()}] ');
  if (tag != null) buffer.write('[$tag] ');
  buffer.write(TraceCloak.redact(object?.toString() ?? 'null',
      overrideMode: overrideMode));

  if (metadata != null && metadata.isNotEmpty) {
    buffer.write(
        ' | metadata: ${TraceCloak.sanitize(metadata, overrideMode: overrideMode, sensitiveKeys: sensitiveKeys)}');
  }
  if (error != null) {
    buffer.write(
        ' | error: ${TraceCloak.redact(error.toString(), overrideMode: overrideMode)}');
  }
  if (stackTrace != null) {
    buffer.write(
        '\n${TraceCloak.sanitizeStackTrace(stackTrace, overrideMode: overrideMode)}');
  }

  final output = buffer.toString();
  final printer = TraceCloak.customPrinter;
  if (printer != null) {
    printer(output);
  } else {
    Zone.root.print(output);
  }
}

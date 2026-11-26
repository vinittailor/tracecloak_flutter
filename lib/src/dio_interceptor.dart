import 'package:dio/dio.dart';
import 'log_output.dart';
import 'tracecloak.dart';

/// Plug-and-play Dio interceptor that automatically scrubs sensitive credentials
/// from HTTP request headers, query parameters, request bodies, and responses in logs.
///
/// In release builds (`--release`), if [enableInRelease] is false (the default),
/// this interceptor immediately bypasses with zero overhead to protect production performance.
///
/// Usage:
/// ```dart
/// final dio = Dio();
/// dio.interceptors.add(TraceCloakDioInterceptor());
/// ```
class TraceCloakDioInterceptor extends Interceptor {
  /// Explicit masking mode for this interceptor.
  /// When null, defaults to the globally active [TraceCloak.mode].
  final MaskMode? overrideMode;

  /// Whether to run this interceptor in release builds (`--release`).
  /// Defaults to `false` so the interceptor immediately calls `handler.next()` with zero overhead in production.
  final bool enableInRelease;

  /// Whether to log outgoing HTTP requests (method, URI, sanitized headers, query params, and body).
  final bool logRequests;

  /// Whether to log incoming HTTP responses (status code, URI, and sanitized response body).
  final bool logResponses;

  /// Whether to log Dio HTTP errors and stack traces with sanitized output.
  final bool logErrors;

  /// Whether to include request headers in [DIO-REQ] logs. Default is `true`.
  final bool logRequestHeaders;

  /// Whether to include request body in [DIO-REQ] logs. Default is `true`.
  final bool logRequestBody;

  /// Whether to include response body in [DIO-RES] logs. Default is `true`.
  final bool logResponseBody;

  /// Optional maximum character length for logged request/response bodies.
  /// Bodies exceeding this limit are sanitized first and then truncated.
  final int? maxBodyLength;

  /// Additional map/JSON/query/header key names whose values should always be masked
  /// (case-insensitive), e.g. `['xyz_key', 'mpin', 'secret_answer']`.
  final List<String> sensitiveKeys;

  /// Creates a new [TraceCloakDioInterceptor] with configurable logging options.
  ///
  /// * [overrideMode]: Optional mode override ([MaskMode.partial], [MaskMode.full], or [MaskMode.off]).
  /// * [enableInRelease]: Set to true only if you explicitly want network logs in production. Default is `false`.
  /// * [logRequests]: Enable/disable logging outgoing requests. Default is `true`.
  /// * [logResponses]: Enable/disable logging incoming responses. Default is `true`.
  /// * [logErrors]: Enable/disable logging Dio exceptions. Default is `true`.
  /// * [logRequestHeaders]: Include request headers in logs. Default is `true`.
  /// * [logRequestBody]: Include request body in logs. Default is `true`.
  /// * [logResponseBody]: Include response body in logs. Default is `true`.
  /// * [maxBodyLength]: Optional max character length for sanitized bodies in logs.
  /// * [sensitiveKeys]: Additional key names whose values should always be masked in logs.
  TraceCloakDioInterceptor({
    this.overrideMode,
    this.enableInRelease = false,
    this.logRequests = true,
    this.logResponses = true,
    this.logErrors = true,
    this.logRequestHeaders = true,
    this.logRequestBody = true,
    this.logResponseBody = true,
    this.maxBodyLength,
    this.sensitiveKeys = const [],
  });

  bool get _active => kDebugMode || enableInRelease;

  dynamic _prepareBody(dynamic data) {
    if (data is List<int>) {
      return '<${data.length} bytes>';
    }
    if (data is FormData) {
      return {
        'fields': {for (final f in data.fields) f.key: f.value},
        if (data.files.isNotEmpty)
          'files': [
            for (final f in data.files)
              '${f.key}: ${f.value.filename ?? 'file'}'
          ],
      };
    }
    final limit = maxBodyLength;
    if (limit == null) return data;
    final sanitized = TraceCloak.sanitize(
      data,
      overrideMode: overrideMode,
      sensitiveKeys: sensitiveKeys,
    );
    final str = sanitized.toString();
    if (str.length <= limit) return sanitized;
    return '${str.substring(0, limit)}...[truncated]';
  }

  String _formatUri(Uri uri) {
    if (!uri.hasQuery) return uri.toString();
    final activeMode = overrideMode ?? TraceCloak.mode;
    if (activeMode == MaskMode.off) return uri.toString();
    final query = uri.queryParametersAll.entries.expand((e) {
      final sensitive = TraceCloak.isSensitiveKey(e.key, sensitiveKeys);
      return e.value.map((v) {
        if (!sensitive) return '${e.key}=$v';
        final redacted = TraceCloak.redact(v, overrideMode: activeMode);
        // If redact() already catches this value (e.g. a Stripe/GitHub key),
        // let emitStructuredLog() redact it once with its rule prefix intact.
        if (redacted != v) return '${e.key}=$v';
        final masked = TraceCloak.mask(v, overrideMode: activeMode);
        return '${e.key}=$masked';
      });
    }).join('&');
    final raw = uri.toString();
    final qIdx = raw.indexOf('?');
    if (qIdx < 0) return raw;
    final fragIdx = raw.indexOf('#', qIdx);
    final prefix = raw.substring(0, qIdx + 1);
    final suffix = fragIdx >= 0 ? raw.substring(fragIdx) : '';
    return '$prefix$query$suffix';
  }

  @override
  void onRequest(RequestOptions options, RequestInterceptorHandler handler) {
    // The real request is never modified: only the log copy is sanitised.
    if (_active && logRequests) {
      emitStructuredLog(
        '--> ${options.method} ${_formatUri(options.uri)}',
        tag: 'DIO-REQ',
        overrideMode: overrideMode,
        sensitiveKeys: sensitiveKeys,
        metadata: {
          if (logRequestHeaders) 'headers': options.headers,
          if (options.queryParameters.isNotEmpty)
            'query': options.queryParameters,
          if (logRequestBody && options.data != null)
            'body': _prepareBody(options.data),
        },
      );
    }
    handler.next(options);
  }

  @override
  void onResponse(Response response, ResponseInterceptorHandler handler) {
    if (_active && logResponses) {
      emitStructuredLog(
        '<-- ${response.statusCode} ${_formatUri(response.requestOptions.uri)}',
        tag: 'DIO-RES',
        overrideMode: overrideMode,
        sensitiveKeys: sensitiveKeys,
        metadata: {
          'status': response.statusCode,
          if (logResponseBody && response.data != null)
            'data': _prepareBody(response.data),
        },
      );
    }
    handler.next(response);
  }

  @override
  void onError(DioException err, ErrorInterceptorHandler handler) {
    if (_active && logErrors) {
      emitStructuredLog(
        '<-- ERROR ${_formatUri(err.requestOptions.uri)}${err.message != null ? ': ${err.message}' : ''}',
        tag: 'DIO-ERR',
        level: LogLevel.error,
        overrideMode: overrideMode,
        sensitiveKeys: sensitiveKeys,
        metadata: {
          if (err.response?.statusCode != null)
            'status': err.response!.statusCode,
          if (err.response?.data != null)
            'response': _prepareBody(err.response!.data),
        },
        error: err.error,
        stackTrace: err.stackTrace,
      );
    }
    handler.next(err);
  }
}

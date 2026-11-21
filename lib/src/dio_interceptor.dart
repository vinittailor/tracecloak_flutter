import 'package:dio/dio.dart';
import 'log_output.dart';
import 'vibeshield.dart';

/// Plug-and-play Dio interceptor that automatically scrubs sensitive credentials
/// from HTTP request headers, query parameters, request bodies, and responses in logs.
///
/// In release builds (`--release`), if [enableInRelease] is false (the default),
/// this interceptor immediately bypasses with zero overhead to protect production performance.
///
/// Usage:
/// ```dart
/// final dio = Dio();
/// dio.interceptors.add(VibeShieldDioInterceptor());
/// ```
class VibeShieldDioInterceptor extends Interceptor {
  /// Explicit masking mode for this interceptor.
  /// When null, defaults to the globally active [VibeShield.mode].
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

  /// Creates a new [VibeShieldDioInterceptor] with configurable logging options.
  ///
  /// * [overrideMode]: Optional mode override ([MaskMode.partial], [MaskMode.full], or [MaskMode.off]).
  /// * [enableInRelease]: Set to true only if you explicitly want network logs in production. Default is `false`.
  /// * [logRequests]: Enable/disable logging outgoing requests. Default is `true`.
  /// * [logResponses]: Enable/disable logging incoming responses. Default is `true`.
  /// * [logErrors]: Enable/disable logging Dio exceptions. Default is `true`.
  VibeShieldDioInterceptor({
    this.overrideMode,
    this.enableInRelease = false,
    this.logRequests = true,
    this.logResponses = true,
    this.logErrors = true,
  });

  bool get _active => kDebugMode || enableInRelease;

  @override
  void onRequest(RequestOptions options, RequestInterceptorHandler handler) {
    // The real request is never modified: only the log copy is sanitised.
    if (_active && logRequests) {
      emitStructuredLog(
        '--> ${options.method} ${options.uri}',
        tag: 'DIO-REQ',
        overrideMode: overrideMode,
        metadata: {
          'headers': options.headers,
          if (options.queryParameters.isNotEmpty)
            'query': options.queryParameters,
          if (options.data != null) 'body': options.data,
        },
      );
    }
    handler.next(options);
  }

  @override
  void onResponse(Response response, ResponseInterceptorHandler handler) {
    if (_active && logResponses) {
      emitStructuredLog(
        '<-- ${response.statusCode} ${response.requestOptions.uri}',
        tag: 'DIO-RES',
        overrideMode: overrideMode,
        metadata: {
          'status': response.statusCode,
          if (response.data != null) 'data': response.data,
        },
      );
    }
    handler.next(response);
  }

  @override
  void onError(DioException err, ErrorInterceptorHandler handler) {
    if (_active && logErrors) {
      emitStructuredLog(
        '<-- ERROR ${err.requestOptions.uri}${err.message != null ? ': ${err.message}' : ''}',
        tag: 'DIO-ERR',
        level: LogLevel.error,
        overrideMode: overrideMode,
        metadata: {
          if (err.response?.statusCode != null)
            'status': err.response!.statusCode,
          if (err.response?.data != null) 'response': err.response!.data,
        },
        error: err.error,
        stackTrace: err.stackTrace,
      );
    }
    handler.next(err);
  }
}

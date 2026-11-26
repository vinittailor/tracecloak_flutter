import 'package:dio/dio.dart';
import 'package:test/test.dart';
import 'package:tracecloak/tracecloak.dart';

class _NoopRequestHandler extends RequestInterceptorHandler {
  @override
  void next(RequestOptions requestOptions) {}
}

class _NoopResponseHandler extends ResponseInterceptorHandler {
  @override
  void next(Response response) {}
}

class _NoopErrorHandler extends ErrorInterceptorHandler {
  @override
  void next(DioException err) {}
}

void main() {
  group('Dio & TraceCloak Sensitive Keys', () {
    setUp(TraceCloak.reset);

    test('masks pass, otp, pin, cvv variants in Map payloads', () {
      final sanitized = TraceCloak.sanitize({
        'pass': 'myPass1234',
        'user_pass': 'secretPass99',
        'newPass': 'anotherPass88',
        'otp': '482910',
        'otp_code': '918273',
        'userOtp': '654321',
        'pin': '4321',
        'pin_code': '9876',
        'mpin': '1122',
        'cvv': '842',
        'cardCvv': '917',
        // Non-sensitive words containing pass/pin/etc. must stay untouched:
        'compass': 'north',
        'passenger': 'Alice',
        'shopping': 'cart',
        'opinion': 'good',
      }) as Map;

      expect(sanitized['pass'], isNot(contains('myPass1234')));
      expect(sanitized['user_pass'], isNot(contains('secretPass99')));
      expect(sanitized['newPass'], isNot(contains('anotherPass88')));
      expect(sanitized['otp'], isNot(contains('482910')));
      expect(sanitized['otp_code'], isNot(contains('918273')));
      expect(sanitized['userOtp'], isNot(contains('654321')));
      expect(sanitized['pin'], isNot(contains('4321')));
      expect(sanitized['pin_code'], isNot(contains('9876')));
      expect(sanitized['mpin'], isNot(contains('1122')));
      expect(sanitized['cvv'], isNot(contains('842')));
      expect(sanitized['cardCvv'], isNot(contains('917')));

      expect(sanitized['compass'], equals('north'));
      expect(sanitized['passenger'], equals('Alice'));
      expect(sanitized['shopping'], equals('cart'));
      expect(sanitized['opinion'], equals('good'));
    });

    test(
        'Dio interceptor masks custom sensitiveKeys in request, response, error, and FormData',
        () {
      final captured = <String>[];
      TraceCloak.customPrinter = captured.add;

      final interceptor = TraceCloak.dioInterceptor(
        sensitiveKeys: ['xyz_key', 'custom_otp'],
      );

      final reqOptions = RequestOptions(
        path: 'https://api.example.com/verify',
        method: 'POST',
        headers: {
          'X-Custom-Auth': 'keep-check',
          'xyz_key': 'header-secret-val'
        },
        queryParameters: {'xyz_key': 'query-secret-val', 'page': '1'},
        data: {
          'xyz_key': 'keyss here',
          'XYZ_KEY': 'upper case secret',
          'custom_otp': '778899',
          'public_name': 'vinit',
        },
      );
      interceptor.onRequest(reqOptions, _NoopRequestHandler());

      // Real request must remain untouched
      expect(reqOptions.data['xyz_key'], equals('keyss here'));
      expect(reqOptions.headers['xyz_key'], equals('header-secret-val'));

      // Response with raw JSON string (e.g. ResponseType.plain)
      interceptor.onResponse(
        Response(
          requestOptions: reqOptions,
          statusCode: 200,
          data: '{"xyz_key": "keyss here", "otp": "123456", "status": "ok"}',
        ),
        _NoopResponseHandler(),
      );

      // Error response
      interceptor.onError(
        DioException(
          requestOptions: reqOptions,
          response: Response(
            requestOptions: reqOptions,
            statusCode: 401,
            data: {'xyz_key': 'err-secret-val', 'pass': 'err-pass-val'},
          ),
        ),
        _NoopErrorHandler(),
      );

      // FormData request
      final formReq = RequestOptions(
        path: 'https://api.example.com/upload',
        method: 'POST',
        data: FormData.fromMap({
          'xyz_key': 'form-secret-val',
          'otp': '554433',
          'title': 'avatar',
        }),
      );
      interceptor.onRequest(formReq, _NoopRequestHandler());

      final allLogs = captured.join('\n');
      expect(allLogs, isNot(contains('keyss here')));
      expect(allLogs, isNot(contains('upper case secret')));
      expect(allLogs, isNot(contains('header-secret-val')));
      expect(allLogs, isNot(contains('query-secret-val')));
      expect(allLogs, isNot(contains('778899')));
      expect(allLogs, isNot(contains('123456')));
      expect(allLogs, isNot(contains('err-secret-val')));
      expect(allLogs, isNot(contains('err-pass-val')));
      expect(allLogs, isNot(contains('form-secret-val')));
      expect(allLogs, isNot(contains('554433')));
      expect(allLogs, contains('vinit'));
      expect(allLogs, contains('"status":"ok"'));
      expect(allLogs, contains('avatar'));
    });

    test(
        'Global TraceCloak.addSensitiveKeys and reset() work across sanitize and Dio',
        () {
      final captured = <String>[];
      TraceCloak.customPrinter = captured.add;

      TraceCloak.addSensitiveKeys(['partner_xyz_field']);
      final interceptor = TraceCloak.dioInterceptor();

      interceptor.onResponse(
        Response(
          requestOptions: RequestOptions(path: 'https://api.example.com/data'),
          statusCode: 200,
          data: {'partner_xyz_field': 'hello-world-val'},
        ),
        _NoopResponseHandler(),
      );

      expect(captured.single, isNot(contains('hello-world-val')));

      TraceCloak.clearSensitiveKeys();
      final afterClear =
          TraceCloak.sanitize({'partner_xyz_field': 'hello-world-val'}) as Map;
      expect(afterClear['partner_xyz_field'], equals('hello-world-val'));
    });

    test(
        'TraceCloak.redact masks pass and otp assignments in plain print strings',
        () {
      final out = TraceCloak.redact('login pass=mySecret99 otp=482910 ok=true');
      expect(out, isNot(contains('mySecret99')));
      expect(out, isNot(contains('482910')));
      expect(out, contains('ok=true'));
    });
  });
}

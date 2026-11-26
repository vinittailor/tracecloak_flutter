<p align="center">
  <img src="https://raw.githubusercontent.com/vinittailor/tracecloak_flutter/main/assets/TraceCloak_logo.png" alt="TraceCloak" width="100%" />
</p>

# tracecloak

[![Pub Version](https://img.shields.io/pub/v/tracecloak.svg)](https://pub.dev/packages/tracecloak)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Dart SDK](https://img.shields.io/badge/Dart-3.0+-blue.svg)](https://dart.dev)
[![Platforms](https://img.shields.io/badge/Platforms-Android%20%7C%20iOS%20%7C%20Web%20%7C%20macOS%20%7C%20Windows%20%7C%20Linux-green.svg)](https://pub.dev/packages/tracecloak)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/vinittailor/tracecloak_flutter)

> **Flutter & Dart secret redaction — pure Dart, zero custody, and no zone or log output in release builds by default. Masks API keys, tokens and passwords in `print()` output, structured logs, Dio HTTP logs, crash reports and AI prompts.**

---

## Why TraceCloak Flutter?

Every Flutter developer accidentally prints credentials during debugging: Stripe secret keys, Firebase tokens, JWTs, AWS credentials, or database URLs. These strings leak into:

1. **Terminal & IDE Logs:** Visible to anyone watching your screen or recorded in CI logs ([CWE-532](https://cwe.mitre.org/data/definitions/532.html)).
2. **AI Coding Assistants:** Tools like Cursor, GitHub Copilot, and Claude Code read your editor context and terminal output, sending raw keys to LLM servers.
3. **Crash & Telemetry Services:** Sentry or Firebase Crashlytics capture breadcrumbs with unredacted API tokens.
4. **Network Interceptors:** Dio logger interceptors print `Authorization: Bearer <secret>` and response payloads in plain text.

---

## Package Specifications

| Metric | Specification | Details |
| :--- | :--- | :--- |
| **Language** | 100% Pure Dart | No native Android or iOS code. Depends on `dio` for the interceptor. |
| **Release builds** | No zone, no log output | With `enableInRelease: false` (default) `TraceCloak.run()` calls your `body()` directly and structured logs are skipped. Explicit `redact()` / `aiSafe()` calls keep working. |
| **Platform Support** | Multiplatform | Android, iOS, Flutter Web, macOS, Windows, Linux, and Dart CLI. `protectFromAi()` uses `dart:io` and does not work on Web. |
| **Security Standards** | CWE-798 & CWE-532 | Mapped to MITRE weaknesses for hard-coded credentials and sensitive data in log files. |

---

## Table of Contents

- [Quick Start](#quick-start)
- [What is and isn't intercepted](#what-is-and-isnt-intercepted)
- [Masking Modes](#masking-modes)
- [Production Release Bypass](#production-release-bypass)
- [Structured Logging](#structured-logging)
- [Dio Network Interceptor](#dio-network-interceptor)
- [Error & Stack Trace Sanitization](#error-crash--stack-trace-sanitization)
- [Performance](#performance)
- [AI Leak Protection](#ai-leak-protection)
- [Static Security CLI Scanner](#static-security-cli-scanner)
- [Real-World Scenarios](#real-world-scenarios)
- [Testing your app](#testing-your-app)
- [Complete API Reference & Parameters](#complete-api-reference--parameters)
- [Supported Secret Rules](#supported-secret-rules)
- [License](#license)

---

## Quick Start

### 1. Add Dependency

```yaml
dependencies:
  tracecloak: ^0.1.0
```

### 2. Wrap `runApp()` in `main()`

```dart
import 'package:flutter/material.dart';
import 'package:tracecloak/tracecloak.dart';

void main() {
  TraceCloak.run(() => runApp(const MyApp()));
}
```

Now every `print(...)` that runs inside that zone — your code, packages, async callbacks, timers — is redacted in your debug console:

```dart
// Your regular print statement:
print('Calling Stripe API with: sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890'); // tracecloak-ignore

// What appears in your IDE terminal:
// Calling Stripe API with: sk_live_****7890
```

> `TraceCloak.install(...)` only stores settings (mode, exact secrets, listener). It does **not** intercept `print()`; only `TraceCloak.run()` does.

---

## What is and isn't intercepted

| Output path | Masked? |
| :--- | :--- |
| `print()` inside `TraceCloak.run()` (incl. `async`, `Future`, `Timer`, microtasks) | ✅ |
| `TraceCloak.info/warn/error/debug/print`, `TraceCloak.log(...).send()` | ✅ |
| Dio request/response/error logs via `TraceCloakDioInterceptor` | ✅ |
| Flutter `debugPrint` | ✅ after `debugPrint = TraceCloak.wrapDebugPrint(debugPrint);` |
| Uncaught errors in the zone | ✅ passed on as `RedactedError` |
| `stdout.write` / `stderr.write`, `dart:developer` `log()` | ❌ not routed through zones |
| Code running in another isolate (`Isolate.run`, `compute`) | ❌ wrap the isolate's entry point in `TraceCloak.run` |
| Errors thrown before `TraceCloak.run()` is called | ❌ |

---

## Masking Modes

| Mode | Example | Use Case |
| :--- | :--- | :--- |
| `MaskMode.partial` (Default) | `sk_live_****7890` | Keeps a known provider prefix. Other secrets show at most a third of their characters: under 16 chars → `****`, 16–23 → `****AbCd`, 24+ → `aB39****AbCd`. |
| `MaskMode.full` | `aa_aaaa_00aa00aa0a0aa…` | Shape-preserving mask: letters → `a`/`b`, digits → `0`/`1`, separators (`_ - : / . @ =` etc.) kept, every other symbol → `*`. No content character keeps its value. For screen sharing, demos and AI prompts. |
| `MaskMode.off` | `sk_live_51Hc29...` | Raw pass-through for controlled local debugging. |

### Setting or Cycling Modes

```dart
// Set globally at startup
TraceCloak.run(
  () => runApp(const MyApp()),
  mode: MaskMode.full,
);

// Or change dynamically at runtime
TraceCloak.setMode(MaskMode.full);

// Cycle through: off -> partial -> full -> off
final newMode = TraceCloak.cycleMode();

// From a build flag: flutter run --dart-define=TRACECLOAK_MODE=full
TraceCloak.setMode(MaskMode.fromEnvironment('TRACECLOAK_MODE'));
```

---

## Production Release Bypass

```dart
void main() {
  TraceCloak.run(
    () => runApp(const MyApp()),
    exactSecrets: [myEnvSecret],
    enableInRelease: false, // Default
  );
}
```

### How it works
- In **debug/profile builds** (`kDebugMode == true`), `run()` creates a Dart Zone that redacts every `print()`.
- In **release builds** (`dart.vm.product == true`) with `enableInRelease: false`, `run()` calls `body()` directly: no zone, and `TraceCloak.print`/`info`/... produce no output.
- `mode`, `exactSecrets` and `onRedactionEvent` are applied **in every build mode**, so explicit `redact()`, `sanitize()` and `aiSafe()` calls (e.g. scrubbing an LLM prompt in production) still mask your registered secrets.
- Pass `enableInRelease: true` to keep the zone and structured log output in release builds.

---

## Structured Logging

```dart
TraceCloak.info('User signed in', metadata: {'userId': 42, 'password': 'hunter2'});
// [INFO] User signed in | metadata: {userId: 42, password: ****}

TraceCloak.log('Checkout', LogLevel.warn).tag('BILLING').data({'card': cardObject}).send();
// [WARN] [BILLING] Checkout | metadata: {card: <cardObject.toString(), redacted>}
```

Metadata is sanitised recursively:
- Values under sensitive keys (`password`, `pwd`, `secret`, `token`, `apiKey`, `authorization`, `cookie`, `session`, `credential`, `privateKey`, `pin`, `otp`, `cvv`, …) are always masked, however short.
- Strings are scanned with all rules.
- Custom objects are converted with `toString()` and redacted, so they cannot leak through their own `toString()`. `SecureKey` values print their own mask.
- Numbers, booleans, enums and `null` are kept. Cycles and nesting deeper than 32 levels are replaced by a placeholder.

---

## Dio Network Interceptor

`TraceCloakDioInterceptor` sanitizes the **logged copy** of each request while **keeping the real HTTP request untouched**:

```dart
import 'package:dio/dio.dart';
import 'package:tracecloak/tracecloak.dart';

final dio = Dio();

// Add TraceCloak interceptor in ONE line
dio.interceptors.add(TraceCloak.dioInterceptor());

// Or configure with custom options & custom sensitive key names
dio.interceptors.add(TraceCloakDioInterceptor(
  overrideMode: MaskMode.partial,
  enableInRelease: false, // Default: no logging in release builds
  logRequests: true,
  logResponses: true,
  logErrors: true,
  sensitiveKeys: ['xyz_key', 'mpin'], // Always mask these keys (case-insensitive)
));
```

You can also register custom sensitive keys globally with `TraceCloak.addSensitiveKeys(['xyz_key'])` or `TraceCloak.run(sensitiveKeys: ['xyz_key'], ...)`. Built-in sensitive keys (`pass`, `password`, `otp`, `pin`, `cvv`, `token`, `secret`, `api_key`, etc.) and `FormData` fields / raw JSON string bodies are masked automatically.

### Output
```text
[INFO] [DIO-REQ] --> POST https://api.stripe.com/v1/charges | metadata: {headers: {Authorization: Bearer sk_live_****7890}, body: {clientSecret: sk_live_****7890, amount: 2000}}
```
Credential headers (`Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`, `*-Token`, …) are always masked, even short values such as `Bearer hunter2` → `Bearer ****`. The server still receives the genuine header.

---

## Error, Crash & Stack Trace Sanitization

### 1. Zone Uncaught Error Interception
Uncaught errors are wrapped in a `RedactedError`: its `toString()`/`message` are redacted, and `original` keeps the real exception so you can still branch on its type.

```dart
void main() {
  TraceCloak.run(
    () => runApp(const MyApp()),
    onError: (error, stackTrace) {
      // error is a RedactedError; error.toString() and stackTrace are redacted.
      final e = error as RedactedError;
      if (e.original is SocketException) return; // type checks still work
      FirebaseCrashlytics.instance.recordError(e, stackTrace);
    },
  );
}
```
> Don't log `e.original` directly — its own `toString()` may contain the secret.

### 2. Manual Error & Stack Trace Sanitization

```dart
try {
  await authService.login();
} catch (e, stack) {
  // Returns sanitized (String error, StackTrace? stackTrace)
  final (safeErr, safeStack) = TraceCloak.sanitizeError(e, stack);
  TraceCloak.error('Authentication failed: $safeErr', stackTrace: safeStack);
}
```

### 3. Flutter Framework Logs & `debugPrint` Hook

```dart
void main() {
  debugPrint = TraceCloak.wrapDebugPrint(debugPrint);
  TraceCloak.run(() => runApp(const MyApp()));
}
```

---

## Performance

- All rule and entropy regexes are compiled once; `redact()` allocates no rule lists per call.
- Exact matches, rules and the entropy scan each run once over the original text; overlapping hits are merged and each span is masked once.
- Every rule is tested against adversarial 100–250 KB inputs (no catastrophic backtracking).
- Rough numbers on a desktop VM: ~7 µs per short log line, ~200 ms for a 1 MB log blob.

---

## AI Leak Protection

### 1. `SecureKey` AI-Proof Wrapper

```dart
import 'package:tracecloak/tracecloak.dart';

final stripeKey = SecureKey('sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890'); // tracecloak-ignore
```

- **Safe String Interpolation:** `print('Config: $stripeKey');` prints `Config: sk_live_****7890`.
- **Safe JSON Serialization:** `jsonEncode({'key': stripeKey})` yields `{"key":"sk_live_****7890"}`.
- **Only Expose For The Real Call:**
  ```dart
  dio.options.headers['Authorization'] = 'Bearer ${stripeKey.exposeRaw()}';
  ```

### 2. AI Prompt Sanitization

```dart
final rawContext = 'Error with token: ghp_16C7e42F292c6912E7710c838347Ae178B4a'; // tracecloak-ignore

// Shape-preserving zero-overlap mask
final safePrompt = rawContext.aiSafe;
await geminiClient.prompt(safePrompt);

// Structured data (maps, lists, objects)
final safeData = TraceCloak.aiSafe(debugStateMap);
```

### 3. Project AI-Ignore Files

```bash
dart run tracecloak --shield-ai
```

Creates the files below, or refreshes the TraceCloak-managed block inside them (your own lines are left alone):

| File | Read by |
| :--- | :--- |
| `.aiignore` | JetBrains AI Assistant |
| `.aiexclude` | Gemini in Android Studio |
| `.cursorignore` | Cursor |
| `.copilotignore`, `.claudeignore` | No official vendor documentation found; written for tools that adopt the convention. GitHub Copilot content exclusion and Claude Code permission rules are configured in their own settings. |

Shielded patterns: `.env`, `.env.*`, `*.env`, `*.properties` (incl. `key.properties`, `local.properties`), `google-services.json`, `GoogleService-Info.plist`, `*.keystore`, `*.jks`, `*.p12`, `*.pem`, `*.key`, `*secret*`, `*credential*`.

---

## Static Security CLI Scanner

```bash
# Scan current project
dart run tracecloak

# Scan specific directory
dart run tracecloak --path=lib

# Output JSON for CI/CD pipelines
dart run tracecloak --json

# Also fail on entropy warnings
dart run tracecloak --fail-on-warning
```

Scans `.dart`, `.yaml`, `.yml`, `.json`, `.properties`, `.env`, `.gradle`, `.xml` and `.plist` files. Lines containing `tracecloak-ignore` are skipped. Only provider-specific rules are reported as confirmed leaks; the keyword/URL heuristics used for log redaction are not, because in source code they mostly match variable references.

### Sample Output
```text
======================================================================
      🛡️  TRACECLOAK FLUTTER & DART STATIC SECURITY SCANNER  🛡️
======================================================================
Scanning directory: /project/lib

❌ [LEAK DETECTED] src/api_client.dart:18:24
   • Variable Name: stripeSecretKey
   • Vulnerability: CWE-798 (Stripe Live Secret Key)
   • Masked Value:  sk_live_****7890
   • Recommended:   Move to .env or flutter_dotenv

----------------------------------------------------------------------
Summary:
  Files Scanned:       32
  Confirmed Leaks:     1
  Entropy Warnings:    0
----------------------------------------------------------------------

❌ TRACECLOAK SCAN FAILED: Hardcoded credentials must be resolved before deployment.
```
*Exits with code `1` when confirmed secrets are found (or warnings, with `--fail-on-warning`), in both text and `--json` mode.*

---

## Real-World Scenarios

### Scenario 1: Authentication & JWT Login Response

```dart
final response = await dio.post('/api/auth/login', data: credentials);

// Even if you or a 3rd-party package prints this inside TraceCloak.run():
print('User logged in successfully: ${response.data}');

// Terminal displays:
// User logged in successfully: {"userId": 1024, "token": "eyJ****sw5c", "refreshToken": "aB39****AbCd"}

// Your code still receives the genuine tokens:
final userToken = response.data['token'];
await flutterSecureStorage.write(key: 'jwt', value: userToken);
```

### Scenario 2: Stripe SDK & Payment Gateway

```dart
final secretKey = SecureKey('sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890'); // tracecloak-ignore

TraceCloak.log('Initializing payment intent', LogLevel.info)
    .data({'customer': 'cus_123', 'key': secretKey})
    .send();
// [INFO] Initializing payment intent | metadata: {customer: cus_123, key: sk_live_****7890}

final paymentIntent = await stripeApi.createIntent(
  secret: secretKey.exposeRaw(),
  amount: 4900,
);
```

### Scenario 3: Non-Custodial Crashlytics & Sentry

```dart
TraceCloak.onRedacted = (RedactionEvent event) {
  // event carries only the rule name, category and masked preview.
  FirebaseCrashlytics.instance.log(
    'Secret Redacted: ${event.ruleName} in category ${event.category}',
  );
};
```
Exceptions thrown by this callback are swallowed so they can never break logging.

### Scenario 4: CI/CD Pipeline Enforcement

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  secret-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: subosito/flutter-action@v2
        with:
          channel: 'stable'
      - name: Install dependencies
        run: flutter pub get
      - name: Run TraceCloak Static Audit
        run: dart run tracecloak --path=lib
```

---

## Testing your app

TraceCloak keeps global state (mode, exact secrets, custom rules, printer, listener). Reset it between tests and capture output with `customPrinter`:

```dart
setUp(TraceCloak.reset);

test('logs are masked', () {
  final lines = <String>[];
  TraceCloak.customPrinter = lines.add;
  TraceCloak.info('key sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890'); // tracecloak-ignore
  expect(lines.single, contains('sk_live_****7890'));
});
```

---

## Complete API Reference & Parameters

### `TraceCloak.run<R>(body, {...})`

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `body` | `R Function()` | **Required** | The closure to execute (e.g. `() => runApp(const MyApp())`). |
| `mode` | `MaskMode?` | `null` (keeps current, initially `partial`) | Global masking mode. |
| `enableInRelease` | `bool` | `false` | `false`: in release builds `body()` runs directly with no zone and structured logs are silent. |
| `exactSecrets` | `List<String>?` | `null` | Raw strings (≥ 4 chars) always masked, e.g. values from `.env`. Applied in every build mode. |
| `onRedactionEvent` | `Function(RedactionEvent)?` | `null` | Non-custodial callback for each redaction. |
| `onError` | `Function(Object, StackTrace)?` | `null` | Receives uncaught errors as `RedactedError` with a redacted stack trace. |

### Other `TraceCloak` members

| Member | Description |
| :--- | :--- |
| `redact(String, {overrideMode})` / `String.redacted` | Masks every secret found in a string. |
| `sanitize(value, {overrideMode})` | Recursive, key-aware sanitisation of maps, lists and objects. |
| `sanitizeHeaders(Map, {overrideMode})` | Like `sanitize`, for HTTP header maps. |
| `mask(String)` / `.masked`, `.halfMasked`, `.fullMasked`, `.maskWith(mode)` | Masks a value known to be a secret. |
| `aiSafe(value)` / `String.aiSafe` | Full-mode sanitisation for LLM prompts. |
| `addExactMatches`, `addRules`, `clearRules` | Register secrets and custom `DartSecretRule`s. A rule's capture group 1 (if any) is masked; otherwise the whole match. |
| `info`, `warn`, `error`, `debug`, `print`, `log(...).send()` | Structured logging: `[LEVEL] [tag] message \| metadata: {...} \| error: ...`. |
| `wrapDebugPrint`, `sanitizeError`, `sanitizeStackTrace` | Framework and error helpers. |
| `setMode`, `cycleMode`, `mode`, `isOff/isPartial/isFull` | Mode control. |
| `install({...})` | Stores settings only; does not intercept `print()`. |
| `reset()` | Restores all global state (for tests). |
| `customPrinter` | Redirects TraceCloak output (e.g. to a test list or a logger). |
| `onRedacted` | Audit hook; receives `RedactionEvent`s. |

### `TraceCloakDioInterceptor({...})`

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `overrideMode` | `MaskMode?` | `null` | Mode for Dio logs. Defaults to the global `TraceCloak.mode`. |
| `enableInRelease` | `bool` | `false` | `false`: calls `handler.next()` without logging in release builds. |
| `logRequests` | `bool` | `true` | Log outgoing requests (method, URI, headers, query, body). |
| `logResponses` | `bool` | `true` | Log responses (status, URI, body). |
| `logErrors` | `bool` | `true` | Log Dio exceptions. |
| `logRequestHeaders` | `bool` | `true` | Include request headers in `[DIO-REQ]` logs. |
| `logRequestBody` | `bool` | `true` | Include request body in `[DIO-REQ]` logs. |
| `logResponseBody` | `bool` | `true` | Include response body in `[DIO-RES]` logs. |
| `maxBodyLength` | `int?` | `null` | Optional max character length for sanitized bodies in logs. |
| `sensitiveKeys` | `List<String>` | `const []` | Extra key names whose values are always masked (case-insensitive) in headers, query params, bodies, and JSON responses. |

### `SecureKey(raw, {maskMode})`

| Parameter / Method | Type | Description |
| :--- | :--- | :--- |
| `raw` | `String` | The raw secret string. |
| `maskMode` | `MaskMode` | Mode used by `toString()` (default: `MaskMode.partial`). |
| `toString()` / `toJson()` | `String` | Masked value. |
| `exposeRaw()` | `String` | The raw secret, for the actual network call. |

### `RedactedError`

| Member | Description |
| :--- | :--- |
| `message` / `toString()` | Redacted error text. |
| `original` | The original error object (do not log it). |
| `originalType` | `original.runtimeType`. |

---

## Supported Secret Rules

Mapped to [CWE-798](https://cwe.mitre.org/data/definitions/798.html) and [CWE-532](https://cwe.mitre.org/data/definitions/532.html). Provider patterns are adapted from [gitleaks](https://github.com/gitleaks/gitleaks) (MIT).

**Provider rules** (also used by the CLI):
- **Stripe:** `sk_live_`, `rk_live_`, `sk_test_`/`rk_test_`/`sk_prod_`/`rk_prod_`.
- **AWS:** Access Key IDs (`AKIA`, `ASIA`, `ABIA`, `ACCA`, `A3T…`), Secret Access Keys after `aws_secret_access_key=` style keys.
- **Google:** API keys (`AIza…`).
- **OpenAI:** `sk-…`, `sk-proj-…`, `sk-svcacct-…`, `sk-admin-…`.
- **Anthropic:** `sk-ant-api03-…`, `sk-ant-admin01-…`.
- **GitHub:** `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, fine-grained `github_pat_`.
- **Slack:** `xoxb-`, `xoxp-`, `xoxa-`, `xoxe-`, `xoxr-`, `xoxs-`, `xoxo-`.
- **JWT:** three-part base64url tokens starting with `eyJ`.
- **Private keys:** `-----BEGIN … PRIVATE KEY-----` blocks (everything after BEGIN is masked if END is missing).
- **Database URLs:** PostgreSQL, MySQL, MongoDB, Redis, AMQP URLs with credentials.

**Context heuristics** (log redaction only):
- `user:password@` in any URL — the password is masked.
- Sensitive query parameters: `access_token`, `refresh_token`, `id_token`, `api_key`, `key`, `token`, `auth`, `password`, `secret`, `client_secret`, `signature`, `sig`, `code`, `session_id`.
- `Bearer` / `Basic` / `Digest` credentials.
- Keyword assignments of any length: `password=…`, `pwd: …`, `"secret_key": "…"`, `token=…`, `apiKey: …`, `cookie: …`, `session=…`, `authorization: …` (type names and `true`/`false`/`null` are ignored).

**Shannon entropy fallback:** unknown tokens of 20+ chars with entropy ≥ 4.1 bits/char (base64-like) or 32+ hex chars with entropy ≥ 3.5. UUIDs, isolated SHA-1/SHA-256/MD5 digests, and camelCase / PascalCase / snake_case identifiers are ignored.

---

## License

MIT License. See [LICENSE](LICENSE) for details.

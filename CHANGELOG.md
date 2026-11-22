# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-22

Initial release of `tracecloak`. It replaces `vibeshield_flutter` (the same code, briefly published under the old project name): change the dependency to `tracecloak`, imports to `package:tracecloak/tracecloak.dart`, and `VibeShield` to `TraceCloak`.

### Added
- **Zone interception (`TraceCloak.run`)**: masks secrets in every `print()` executed inside the zone, including async code, timers and microtasks. Uncaught errors are passed to `onError` (or the parent zone) as a `RedactedError` with redacted text and a redacted stack trace; `RedactedError.original` keeps the real exception for type checks.
- **Release builds**: with `enableInRelease: false` (default) `run()` calls `body()` directly with no zone, and structured log output is skipped. `mode`, `exactSecrets` and `onRedactionEvent` are applied in every build mode, so explicit `redact()` / `aiSafe()` calls keep masking registered secrets in production.
- **Three masking modes**:
  - `MaskMode.partial`: keeps known provider prefixes (`sk_live_****7890`) and reveals at most a third of other secrets (`****` under 16 chars).
  - `MaskMode.full`: shape-preserving mask with no content character kept (letters → `a`/`b`, digits → `0`/`1`, symbols and non-ASCII → `*`, separators kept).
  - `MaskMode.off`: raw pass-through.
- **Detection rules** (patterns adapted from gitleaks, MIT): Stripe live/test/restricted keys, AWS access key IDs and secret access keys, Google `AIza` keys, OpenAI and Anthropic keys, GitHub `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`/`github_pat_`, Slack `xox*-` tokens, JWTs, PEM private key blocks, database URLs with credentials. Log-only heuristics: `user:password@` in URLs, sensitive query parameters, Bearer/Basic/Digest credentials, and keyword assignments of any length (`password=…`, `"token": "…"`, `secret_key: …`).
- **Shannon entropy fallback** for unknown tokens, ignoring UUIDs, isolated hash digests and code identifiers.
- **Exact-match secrets** (`exactSecrets`, `addExactMatches`) and **custom rules** (`addRules`, `DartSecretRule` with `confidence`).
- **Key-aware sanitisation** (`sanitize`, `sanitizeHeaders`): values under sensitive names (`Authorization`, `Cookie`, `X-Api-Key`, `password`, `token`, `secret`, …) are always masked, custom objects are redacted via `toString()`, cycles and deep nesting are handled.
- **Structured logging**: `TraceCloak.info/warn/error/debug/print` and `TraceCloak.log(...).tag(...).data(...).send()`, formatted as `[LEVEL] [tag] message | metadata: {...}`.
- **Dio interceptor** (`TraceCloakDioInterceptor`, `TraceCloak.dioInterceptor()`): logs a sanitised copy of requests, responses and errors while the real request is untouched; supports `overrideMode` and `enableInRelease`.
- **Error helpers**: `sanitizeError`, `sanitizeStackTrace`, `wrapDebugPrint` for Flutter's `debugPrint`.
- **AI protection**: `SecureKey` wrapper (`toString()`/`toJson()` masked, `exposeRaw()` for the real call), `TraceCloak.aiSafe` / `String.aiSafe` for LLM prompts, and `protectFromAi()` / `dart run tracecloak --shield-ai` which creates or refreshes a managed block in `.aiignore`, `.aiexclude`, `.cursorignore`, `.copilotignore` and `.claudeignore`.
- **String extensions**: `.redacted`, `.masked`, `.halfMasked`, `.fullMasked`, `.maskWith(mode)`, `.aiSafe`.
- **Audit hook**: `TraceCloak.onRedacted` receives non-custodial `RedactionEvent`s (rule, category, masked preview); exceptions thrown by the hook are swallowed.
- **CLI scanner** (`dart run tracecloak`): reports hard-coded credentials with file, line, column, variable name and masked preview; `--json`, `--path=`, `--fail-on-warning`; exits with code 1 on confirmed leaks in both text and JSON mode; lines containing `tracecloak-ignore` are skipped.
- **Testing support**: `TraceCloak.reset()` and `TraceCloak.customPrinter`.
- `SecureLog` alias for `TraceCloak`.
- Runs on Android, iOS, Web (JS and WASM), macOS, Windows, Linux and the Dart VM; `protectFromAi()` needs `dart:io` and throws `UnsupportedError` on the web.

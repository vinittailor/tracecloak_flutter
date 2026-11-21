# vibeshield_flutter — Security & Code Audit

*Audit date: 2026-11-21 · Baseline: pre-release code · `dart test`: 22/22 passing · `dart analyze`: 0 issues*

A secret-masking package that silently leaks is worse than none, so any path where a raw
secret reaches log output, an LLM prompt, or a crash reporter is rated **critical** or **high**.

Status legend:
- **confirmed** — a test in `test/audit_findings_test.dart` (or `test/release_mode_test.dart`) failed on the baseline.
- **unconfirmed** — could not reproduce; not fixed.
- **design** — a maintainer decision rather than a bug.

Line numbers refer to the baseline commit.

---

## Critical

### C1 — `sanitizeHeaders()` prints short credentials raw · confirmed
`lib/src/vibeshield.dart:361-379` (and fast path at `:293`)
Headers named `Authorization`, `Cookie`, `X-Api-Key` are only passed through `redact()`, which looks for
known token *shapes*. Anything short or unrecognised is returned unchanged, and anything under 16 chars
skips scanning entirely.
```dart
VibeShield.sanitizeHeaders({'Authorization': 'Bearer hunter2', 'Cookie': 'session=abc123'});
// => {Authorization: Bearer hunter2, Cookie: session=abc123}
```

### C2 — `sanitize()` returns custom objects unchanged · confirmed
`lib/src/vibeshield.dart:282`
Non-String/Map/Iterable values are returned as-is. `VibeShield.print` then interpolates the map,
calling the object's `toString()` *after* sanitisation.
```dart
VibeShield.info('x', metadata: {'o': User('sk_live_…')}); // prints User(pw: sk_live_51Hc…) raw
```

### C3 — `sanitize()` ignores sensitive map keys · confirmed
`lib/src/vibeshield.dart:269-277`
Values are scanned without their key as context, so `{'password': 'hunter2', 'token': 'abc'}` (metadata,
Dio query parameters, Dio JSON bodies, `aiSafe` maps) is returned raw.

## High

### H1 — Short secrets next to keywords are never masked · confirmed
`lib/src/rules.dart` (no rule) + `lib/src/vibeshield.dart:293` (16-char fast path)
`password=hunter2`, `token=abc`, `{"password":"hunter2"}` all print raw.

### H2 — Custom rule without a capture group throws `RangeError` inside logging · confirmed
`lib/src/vibeshield.dart:310` — `match.group(1)` on a regex with zero groups throws. Every `print()` in
the zone, every `VibeShield.log` call and every Dio log then throws into application code.
```dart
VibeShield.addRules([DartSecretRule(..., regex: RegExp(r'ACME-[0-9]{8}'))]);
VibeShield.redact('ACME-12345678'); // RangeError
```

### H3 — Exact-match substrings leave the rest of a longer secret raw · confirmed
`lib/src/vibeshield.dart:298-304` — exact matches are replaced sequentially in insertion order. With
`['abcd1234', 'abcd1234XYZsecretvalue']` the short one is replaced first and the long one never matches:
output `ab****34XYZsecretvalue`.

### H4 — Partial mask reveals ≥40 % of short secrets · confirmed
`lib/src/masker.dart:33-34` — secrets of 7–10 chars show 2 leading + 2 trailing chars
(`hunter22` → `hu****22`, 50 % revealed; a 7-char secret reveals 57 %).

### H5 — Full mask keeps symbols and non-ASCII letters verbatim · confirmed
`lib/src/masker.dart:56-58` — everything that is not `[A-Za-z0-9]` is copied through. `пароль!#` and the
symbol positions of `p@$$w0rd!` survive "full" (0 %-overlap) mode.

### H6 — Missing detection rules · confirmed
`lib/src/rules.dart`
Leaks raw on baseline:
- PEM private key blocks (`-----BEGIN RSA PRIVATE KEY-----…`)
- `user:pass@` credentials in any non-database URL (`https://admin:hunter2@host`)
- Sensitive query parameters (`?access_token=abc123xyz&api_key=k3y`)
- AWS secret access keys (contain `/`, so the entropy tokenizer splits them below 20 chars)

Not covered by a rule (caught only by the entropy heuristic when the sample happens to be random enough,
and masked without the provider prefix, events carry no rule name): `sk_test_`, Google `AIza…`,
OpenAI `sk-`/`sk-proj-`, Anthropic `sk-ant-…`, `github_pat_`, `gho_`/`ghu_`/`ghs_`, `xoxp-`/`xoxa-`/`xoxe-`.
Patterns grounded in gitleaks `config/gitleaks.toml` (MIT, verified 2026-11-21).

### H7 — `run()`/`install()` drop configuration in release builds · confirmed
`lib/src/vibeshield.dart:105-107, 141-143` — with `enableInRelease: false` (default) the early return skips
`exactSecrets`, `mode` and `onRedactionEvent`. `VibeShield.aiSafe()` / `redact()` still run in release
(they are not debug-gated), so an app that registers exact secrets via `run()` and scrubs LLM prompts in
production sends those secrets raw. Reproduced by AOT-compiling a fixture (`test/release_mode_test.dart`).

### H8 — CLI `--json` always exits 0 · confirmed
`bin/vibeshield.dart:107-108` — the JSON branch never calls `exit()`, so CI pipelines using `--json`
pass with confirmed leaks.

## Medium

### M1 — `run(onError:)` receives a `String`, original exception type lost · confirmed
`lib/src/vibeshield.dart:159-177` — both the guarded handler and the zone's `handleUncaughtError`
pass `redact(error.toString())`. `error is DioException` checks are impossible.

### M2 — `VibeShield.print` is hard-gated on `kDebugMode` · confirmed
`lib/src/vibeshield.dart:435` — `VibeShieldDioInterceptor(enableInRelease: true)` and
`run(enableInRelease: true)` produce no structured/Dio output in release builds.
Reproduced by AOT-compiling a fixture (`test/release_mode_test.dart`).

### M3 — A `customPrinter` that calls `print()` recurses forever inside `run()` · confirmed
`lib/src/vibeshield.dart:153-154` — the printer runs inside the intercepting zone, so its own `print`
re-enters the handler → `StackOverflowError`.

### M4 — `protectFromAi()` never refreshes an existing managed block · confirmed
`lib/src/ai_shield.dart:91` — once the marker exists the file is never touched, so new rules never
reach existing projects.

### M5 — README documents APIs and protection that do not exist · confirmed
`README.md` — `VibeShield.maskMode` (does not exist; compile error), claimed rules
(`github_pat_`, `gho_`, `xoxp-`, `xoxa-`, PEM, AWS secret key) that were not implemented, entropy thresholds
(4.5/3.0) that differ from code (4.1/3.5), "every print across your entire application" (see L6),
CLI sample output text that differs from the binary, and `.aiexclude` attributed to JetBrains.

### M6 — Entropy false positives on identifiers · confirmed
`lib/src/entropy.dart:31-76` — PascalCase class names such as `AbstractSingletonProxyFactoryBeanImpl`
and `VibeShieldDioInterceptorFactoryBuilder2024` are masked.

## Low

### L1 — `LogLevel` never appears in output · confirmed
`lib/src/vibeshield.dart:427-468` — `level` is accepted and ignored.

### L2 — `MaskMode.fromEnvironment(key)` ignores `key` · confirmed
`lib/src/types.dart:49-55` — any key other than `VIBESHIELD_MODE` silently returns the fallback.
(`String.fromEnvironment` must be invoked `const`, so arbitrary keys cannot be supported reliably on AOT/web.)

### L3 — Residual duplicate in `secure_log.dart` · confirmed (partially fixed earlier)
`lib/src/secure_log.dart` — the old duplicate `SecureLog` class with its own static state was already
removed in an earlier commit; what remains is a second `typedef SecureLog` that nothing imports.

### L4 — `install()` does not intercept `print()` · confirmed (docs already corrected earlier)
`lib/src/vibeshield.dart:99-116` — `install()` only stores configuration; `isInstalled` then reports
`true` although no interception is active. The old unreachable `corePrint` was removed in an earlier commit.

### L5 — No way to reset global static state · confirmed
`lib/src/vibeshield.dart:28-33` — exact matches, custom rules, printer and listener leak between tests.

### L6 — Zone interception gaps · confirmed (documentation fix)
Not intercepted by `run()`: `stdout.write`, `dart:developer` `log()`, other isolates, Flutter's
`debugPrint` (unless wrapped), errors thrown before `run()`, callbacks registered in another zone.
`async`/`Timer`/microtask code inside `run()` **is** intercepted (verified).

### L7 — `onRedacted` callback exceptions break logging · confirmed
`lib/src/vibeshield.dart:333-341`.

### L8 — `sanitize()` overflows the stack on cyclic structures · confirmed
`lib/src/vibeshield.dart:264-283`.

### L9 — `\b` anchors drop matches at `_`/`-` boundaries · confirmed
`lib/src/rules.dart` — `sk_live_…_x` does not match the Stripe rule (only rescued by entropy); a JWT whose
signature ends in `-` leaves the last char outside the mask.

### L10 — Performance: per-call allocations · measured (not a failure)
`vibeshield.dart:307` rebuilds the rule list per call; `entropy.dart` compiles up to 6 `RegExp`s per token;
`fullMask` runs two regexes per character; each rule rebuilds the whole string. Measured on baseline:
20 000 short `redact()` calls ≈ 105 ms, one 1 MB log ≈ 60 ms, worst adversarial 100 KB input ≈ 72 ms
(no catastrophic backtracking found). Addressed as a side effect of H3/H5.

### L11 — AI-ignore files: unverified targets, JetBrains file missing · confirmed
`lib/src/ai_shield.dart:49-54` — JetBrains AI Assistant reads `.aiignore` (official docs), which is not
written. `.aiexclude` is Gemini in Android Studio, not JetBrains. No official documentation found for
`.claudeignore` or `.copilotignore`; they are kept (harmless) but documented as unverified.

### U1 — Package not web-compatible because of `dart:io` · unconfirmed
`dart compile js` of a program importing the package succeeds (dart:io is stubbed). Only
`protectFromAi()` fails at runtime on web, which is expected. Release prep: the `dart:io` import was still
moved behind a conditional import (`ai_shield_io.dart` / `ai_shield_stub.dart`) so pub.dev platform detection
lists Web; verified by `dart compile js` (run in Node) and `dart compile wasm`.

### U2 — CLI JSON output not escaped · unconfirmed
`bin/vibeshield.dart:255` — fields are interpolated without escaping, but every field is restricted to
safe characters on the platforms tested (paths are `/`-normalised, Windows forbids `"` in names). Not changed.

### D1 — `dio` is a hard dependency for every user · design (decided: keep)
Pure-Dart and non-Dio users download `dio`. Options: move the interceptor into a `vibeshield_dio` package,
or keep it. **Decision (2026-11-21): keep the interceptor in this package; no separate package.**

---

## Results (after fixes)

`dart test`: **66/66 passing** (22 original + 44 new) · `dart analyze`: **0 issues** ·
`dart pub publish --dry-run` (clean copy): 0 warnings · `dart format`: clean · lints: `package:lints/recommended.yaml`, 0 issues.

| ID | Finding | Severity | Status | Test |
| :-- | :-- | :-- | :-- | :-- |
| C1 | `sanitizeHeaders()` prints short credentials raw | critical | fixed | `audit_findings_test` › C1 sanitizeHeaders always masks credential headers… |
| C2 | `sanitize()` leaks custom objects via `toString()` | critical | fixed | › C2 sanitize() does not let custom objects leak… |
| C3 | `sanitize()` ignores sensitive map keys (metadata, Dio query/body) | critical | fixed | › C3 sanitize() masks values stored under sensitive keys; › C3 Dio query parameters and bodies… |
| H1 | Short secrets next to keywords never masked | high | fixed | › H1 short secrets next to keywords are masked |
| H2 | Custom rule without capture group throws `RangeError` | high | fixed | › H2 custom rule without a capture group… |
| H3 | Overlapping exact matches leak the longer secret | high | fixed | › H3 an exact secret that contains another… |
| H4 | Partial mask reveals ≥40 % of short secrets | high | fixed | › H4 partial mask never reveals more than a third… |
| H5 | Full mask keeps symbols / non-ASCII letters | high | fixed | › H5 full mask does not keep symbols… |
| H6 | Missing rules (PEM, URL creds, query params, AWS secret, providers) | high | fixed | › H6 PEM, URL credentials…; › H6 provider keys are matched by a named rule… |
| H7 | Release builds drop `exactSecrets` → `aiSafe` leaks | high | fixed | `release_mode_test` › H7 exactSecrets passed to run()… |
| H8 | CLI `--json` always exits 0 | high | fixed | `cli_test` › H8 --json exits 1… |
| M1 | `onError` gets a `String`, type lost | medium | fixed (`RedactedError`) | › M1 run(onError:) receives an object…; `audit_api_test` › M1 RedactedError… |
| M2 | `VibeShield.print` ignores `enableInRelease` | medium | fixed | `release_mode_test` › M2 Dio interceptor with enableInRelease… |
| M3 | `customPrinter` calling `print()` recurses | medium | fixed | › M3 a customPrinter that calls print()… |
| M4 | AI-ignore block never refreshed | medium | fixed | › M4 protectProject() refreshes a stale managed block… |
| M5 | README documents non-existent API / protection | medium | fixed | `readme_examples_test` (all) |
| M6 | Entropy false positives on identifiers | medium | fixed | › M6 class names and identifiers… |
| L1 | `LogLevel` unused | low | fixed | › L1 log level appears in output |
| L2 | `fromEnvironment` ignores key | low | fixed (assert + docs) | › L2 MaskMode.fromEnvironment rejects unsupported keys… |
| L3 | Dead duplicate `secure_log.dart` | low | fixed (file removed) | › L3 the dead secure_log.dart duplicate is gone |
| L4 | `install()` does not intercept `print()` | low | docs only (behaviour is inherent) | › L4 characterisation: install() does not intercept print() |
| L5 | No `reset()` for tests | low | fixed | `audit_api_test` › L5 VibeShield.reset()… |
| L6 | Zone gaps (stdout, isolates, developer.log…) | low | documented (README table) | › L6 characterisation: async, timer and microtask prints… |
| L7 | Throwing `onRedacted` breaks logging | low | fixed | › L7 a throwing onRedacted callback… |
| L8 | Cyclic structures overflow the stack | low | fixed | › L8 sanitize() survives cyclic structures |
| L9 | `\b` boundary misses | low | fixed | › L9 rules match at _ and - boundaries |
| L10 | Per-call allocations / regex compilation | low | fixed | › L10 redact() handles a 1 MB log…; › L10 no rule backtracks catastrophically… |
| L11 | `.aiignore` missing, unverified ignore-file claims | low | fixed | › L11 protectProject() writes the JetBrains .aiignore file |
| U1 | Not web-compatible (`dart:io`) | — | unconfirmed as a bug; conditional import added for pub.dev platform tags | manual: JS (Node) + WASM build |
| U2 | CLI JSON not escaped | — | unconfirmed, not changed | — |
| D1 | `dio` forced on every user | — | design: kept in this package (maintainer decision) | — |

### Found during fixing
- **ReDoS in the new `url-credentials` rule** (3.5–6 s on 100 KB): the unanchored scheme retried at every letter.
  Fixed with a lookbehind anchor before release; covered by the adversarial-input test in L10.
- **Compound keywords** (`secret_key: "k9F#…"`) only had the entropy tail masked, leaking the start. Fixed; covered in H1.
- **CLI `group(1)` crash** on rules without a capture group (PEM) silently aborted scanning a file. Fixed.

### Known residual limitations
- Redacting text that is *already* full-masked flips mask characters (`a`↔`b`, `0`↔`1`), so a position that
  originally held `a`/`A`/`0` can end up with its original value. VibeShield never double-masks internally
  (spans are merged and masked once, Dio logs are sanitised once); it only happens if user code feeds full-masked
  output back into `redact()`.
- Keyword heuristics also fire on code-like text (`token = options.token` → `token = ****`). A sweep over
  14 255 lines of real-world TypeScript and Dart source changed 108 lines, most of them genuine secret test fixtures.
- Measured cost: ~7 µs per short line, ~190 ms per 1 MB log (baseline ~5 µs / ~60 ms; more rules, no fast path).

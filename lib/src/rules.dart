/// Canonical secret pattern rules for Dart/Flutter SDK, mirrored from /rules/.
///
/// Provider patterns are adapted from gitleaks `config/gitleaks.toml`
/// (MIT licence, verified 2026-11-21) and widened where redaction should
/// prefer recall over precision. All rules map to CWE-798 (hard-coded
/// credentials) or CWE-532 (sensitive information in log files).
library;

/// Rule confidence: the pattern identifies a specific credential format.
const String kConfidenceConfirmed = 'confirmed';

/// Rule confidence: the pattern relies on context (keywords, URL syntax).
/// Used for log redaction, but not reported as a confirmed leak by the CLI,
/// because in source code these usually match variable references.
const String kConfidenceHeuristic = 'heuristic';

class DartSecretRule {
  final String id;
  final String name;
  final String category;
  final String cwe;

  /// Pattern to match. If it has a capture group, only group 1 is masked;
  /// otherwise the whole match is masked.
  final RegExp regex;

  /// Provider prefix kept visible in partial mode (e.g. `sk_live_`).
  final String? prefix;

  /// [kConfidenceConfirmed] (default) or [kConfidenceHeuristic].
  final String confidence;

  const DartSecretRule({
    required this.id,
    required this.name,
    required this.category,
    required this.cwe,
    required this.regex,
    this.prefix,
    this.confidence = kConfidenceConfirmed,
  });
}

// Start-of-token guard used instead of `\b`, so that tokens preceded by `_`
// or `-` and tokens ending in `-`/`_` are still matched in full.
const String _start = r'(?<![A-Za-z0-9])';

/// Keywords whose value is a secret when followed by `=` or `:`.
const String _secretKeywords =
    r'pass(?:word|wd|phrase)|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|'
    r'credentials?|session[_-]?id|session|cookie|authorization|auth';

/// Literals that follow a keyword in code or config dumps but are not secrets.
const String _nonValues =
    '(?:true|false|null|nil|none|undefined|string|boolean|bool|int|number|dynamic|object|void|required|optional)';

final List<DartSecretRule> defaultDartRules = [
  // ---- Provider-specific credentials (confirmed) ---------------------------
  DartSecretRule(
    id: 'stripe-secret-key',
    name: 'Stripe Live Secret Key',
    category: 'payment',
    cwe: 'CWE-798',
    regex: RegExp('$_start(sk_live_[0-9a-zA-Z]{24,})'),
    prefix: 'sk_live_',
  ),
  DartSecretRule(
    id: 'stripe-restricted-key',
    name: 'Stripe Live Restricted Key',
    category: 'payment',
    cwe: 'CWE-798',
    regex: RegExp('$_start(rk_live_[0-9a-zA-Z]{24,})'),
    prefix: 'rk_live_',
  ),
  DartSecretRule(
    id: 'stripe-test-key',
    name: 'Stripe Test/Prod Secret Key',
    category: 'payment',
    cwe: 'CWE-798',
    regex: RegExp('$_start((?:sk|rk)_(?:test|prod)_[0-9a-zA-Z]{10,99})'),
  ),
  DartSecretRule(
    id: 'aws-access-key-id',
    name: 'AWS Access Key ID',
    category: 'cloud',
    cwe: 'CWE-798',
    regex: RegExp(r'\b((?:A3T[A-Z0-9]|AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})\b'),
  ),
  DartSecretRule(
    id: 'aws-secret-access-key',
    name: 'AWS Secret Access Key',
    category: 'cloud',
    cwe: 'CWE-798',
    regex: RegExp(
      r'''(?:aws_secret_access_key|aws_secret_key|secret_access_key)["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])''',
      caseSensitive: false,
    ),
  ),
  DartSecretRule(
    id: 'google-api-key',
    name: 'Google API Key',
    category: 'cloud',
    cwe: 'CWE-798',
    regex: RegExp('$_start(AIza[0-9A-Za-z_-]{35})'),
    prefix: 'AIza',
  ),
  DartSecretRule(
    id: 'anthropic-api-key',
    name: 'Anthropic API Key',
    category: 'ai',
    cwe: 'CWE-798',
    regex: RegExp('$_start(sk-ant-(?:api|admin)[0-9]{2}-[A-Za-z0-9_-]{20,})'),
    prefix: 'sk-ant-',
  ),
  DartSecretRule(
    id: 'openai-api-key',
    name: 'OpenAI API Key',
    category: 'ai',
    cwe: 'CWE-798',
    regex: RegExp(
        '$_start(sk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,})'),
  ),
  DartSecretRule(
    id: 'github-pat',
    name: 'GitHub Personal Access Token',
    category: 'auth',
    cwe: 'CWE-798',
    regex: RegExp('$_start(ghp_[0-9a-zA-Z]{36,})'),
    prefix: 'ghp_',
  ),
  DartSecretRule(
    id: 'github-oauth-token',
    name: 'GitHub OAuth / App Token',
    category: 'auth',
    cwe: 'CWE-798',
    regex: RegExp('$_start((?:gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36,})'),
  ),
  DartSecretRule(
    id: 'github-fine-grained-pat',
    name: 'GitHub Fine-Grained Personal Access Token',
    category: 'auth',
    cwe: 'CWE-798',
    regex: RegExp('$_start(github_pat_[0-9A-Za-z_]{82,})'),
    prefix: 'github_pat_',
  ),
  DartSecretRule(
    id: 'slack-bot-token',
    name: 'Slack Bot Token',
    category: 'auth',
    cwe: 'CWE-798',
    regex: RegExp('$_start(xoxb-[0-9]{10,13}-[0-9]{10,13}-?[a-zA-Z0-9-]*)'),
    prefix: 'xoxb-',
  ),
  DartSecretRule(
    id: 'slack-token',
    name: 'Slack User/App/Refresh Token',
    category: 'auth',
    cwe: 'CWE-798',
    regex: RegExp('$_start(xox[aprseo]-[0-9A-Za-z-]{10,})'),
  ),
  DartSecretRule(
    id: 'jwt-token',
    name: 'JSON Web Token (JWT)',
    category: 'auth',
    cwe: 'CWE-532',
    regex: RegExp(
        '$_start(eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,})'),
    prefix: 'eyJ',
  ),
  DartSecretRule(
    id: 'private-key-block',
    name: 'Private Key Block',
    category: 'crypto',
    cwe: 'CWE-798',
    // If the END line is missing (e.g. the key was printed in chunks), mask
    // everything after BEGIN rather than leak the body.
    regex: RegExp(
      r'-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\s\S]*?(?:-----END[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----|$)',
    ),
  ),
  DartSecretRule(
    id: 'database-connection-url',
    name: 'Database Connection URL',
    category: 'database',
    cwe: 'CWE-798',
    regex: RegExp(
      r'''\b((?:postgres|postgresql|mysql|mongodb|mongodb\+srv|redis|rediss|amqp|amqps):\/\/[^:\s"']+:[^@\s"']+@[^/\s"']+(?:\/[^\s"']*)?)''',
    ),
  ),

  // ---- Context-based heuristics (log redaction only) -----------------------
  DartSecretRule(
    id: 'url-credentials',
    name: 'Credentials in URL',
    category: 'auth',
    cwe: 'CWE-532',
    // The lookbehind anchors the scheme at a token start; without it the
    // engine retries the scheme at every letter (quadratic on long words).
    regex: RegExp(
        r'''(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]{0,30}://[^\s:/?#@"']+:([^\s/?#@"']+)@'''),
    confidence: kConfidenceHeuristic,
  ),
  DartSecretRule(
    id: 'sensitive-query-param',
    name: 'Sensitive URL Query Parameter',
    category: 'auth',
    cwe: 'CWE-532',
    regex: RegExp(
      r'''[?&;](?:access_token|refresh_token|id_token|api_?key|key|token|auth|password|secret|client_secret|signature|sig|code|session_?id)=([^&\s#"'()<>\[\]{},]+)''',
      caseSensitive: false,
    ),
    confidence: kConfidenceHeuristic,
  ),
  DartSecretRule(
    id: 'auth-header-value',
    name: 'Authorization Header Credential',
    category: 'auth',
    cwe: 'CWE-532',
    regex: RegExp(r'\b(?:[Bb]earer|Basic|Digest)\s+([A-Za-z0-9\-._~+/]{4,}=*)'),
    confidence: kConfidenceHeuristic,
  ),
  DartSecretRule(
    id: 'keyword-assignment',
    name: 'Secret Keyword Assignment',
    category: 'generic',
    cwe: 'CWE-532',
    // Keyword (optionally suffixed: secret_key, auth_token, password_value),
    // `:` or `=`, then the value. Type names and boolean/null literals are not
    // treated as values (`token: string`, `isSecret: true`).
    regex: RegExp(
      '(?:$_secretKeywords)(?:[_-]?(?:key|token|value))?["\']?\\s*[:=]\\s*["\']?(?:(?:Bearer|Basic|Digest)\\s+)?'
      '(?!$_nonValues(?![A-Za-z0-9_]))([^\\s"\',;&}\\])]{3,})',
      caseSensitive: false,
    ),
    confidence: kConfidenceHeuristic,
  ),
];

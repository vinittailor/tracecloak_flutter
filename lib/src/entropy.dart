import 'dart:math' as math;

/// Shannon Entropy calculation and high-entropy secret detection for Dart/Flutter.
/// Grounded in information theory and Yelp detect-secrets heuristics.

/// Calculates Shannon entropy in bits per character.
double calculateShannonEntropy(String str) {
  if (str.isEmpty) return 0.0;

  final frequencies = <int, int>{};
  for (var i = 0; i < str.length; i++) {
    final code = str.codeUnitAt(i);
    frequencies[code] = (frequencies[code] ?? 0) + 1;
  }

  var entropy = 0.0;
  final len = str.length;
  for (final count in frequencies.values) {
    final p = count / len;
    entropy -= p * (math.log(p) / math.ln2);
  }

  return entropy;
}

final RegExp _hex = RegExp(r'^[0-9a-fA-F]+$');
final RegExp _base64 = RegExp(r'^[0-9a-zA-Z+/=_-]+$');
final RegExp _digitsOnly = RegExp(r'^[0-9]+$');
final RegExp _lowerWord = RegExp(r'^[a-z]+$');
final RegExp _uuid = RegExp(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    caseSensitive: false);
// Source identifiers: camelCase / PascalCase words (each capital followed by
// 2+ lowercase letters, optional short numeric suffix) and snake_case names.
final RegExp _camelIdentifier =
    RegExp(r'^[a-z]*(?:[A-Z][a-z]{2,})+[0-9]{0,4}$');
final RegExp _snakeIdentifier =
    RegExp(r'^(?:[a-z]+(?:_[a-z0-9]+)+|[A-Z]+(?:_[A-Z0-9]+)+)$');
final RegExp _secretKeywordContext = RegExp(
  r'(?:secret|api[_-]?key|token|auth|password|pwd|credential|private[_-]?key)\s*[:=]',
  caseSensitive: false,
);
final RegExp _tokenCandidate = RegExp(r'\b[A-Za-z0-9_=-]{16,}\b');
final RegExp _edgeSeparators = RegExp(r'^[_=-]+|[_=-]+$');
final RegExp _dataUrlContext =
    RegExp(r'data:image\/[a-zA-Z+]+;base64,$', caseSensitive: false);

bool isHexString(String str) => _hex.hasMatch(str);

bool isBase64String(String str) => _base64.hasMatch(str);

/// Determines whether a candidate token qualifies as a high-entropy secret.
bool isHighEntropyToken(
  String token, {
  double? threshold,
  int minLength = 20,
  String contextPrefix = '',
}) {
  if (token.length < minLength) return false;

  // Filter out purely numeric strings
  if (_digitsOnly.hasMatch(token)) return false;

  // Filter out simple lowercase single words
  if (_lowerWord.hasMatch(token)) return false;

  // Filter out source identifiers (class, variable and package names)
  if (_camelIdentifier.hasMatch(token) || _snakeIdentifier.hasMatch(token)) {
    return false;
  }

  // Filter out standard UUIDs
  if (_uuid.hasMatch(token)) return false;

  // Reject exact-length hex digests in isolation (SHA-1, SHA-256, MD5) unless preceded by secret keywords
  if (isHexString(token) &&
      (token.length == 32 ||
          token.length == 40 ||
          token.length == 64 ||
          token.length == 128)) {
    if (!_secretKeywordContext.hasMatch(contextPrefix)) {
      return false;
    }
  }

  final entropy = calculateShannonEntropy(token);

  if (threshold != null) {
    return entropy >= threshold;
  }

  if (isHexString(token)) {
    return token.length >= 32 && entropy >= 3.5;
  }

  if (isBase64String(token)) {
    return token.length >= 20 && entropy >= 4.1;
  }

  return false;
}

class EntropyMatch {
  final int start;
  final int end;
  final String token;
  final double entropy;

  const EntropyMatch({
    required this.start,
    required this.end,
    required this.token,
    required this.entropy,
  });
}

/// Scans text for high-entropy tokens.
List<EntropyMatch> scanHighEntropyTokens(
  String text, {
  int minLength = 20,
  double? threshold,
}) {
  final matches = <EntropyMatch>[];
  for (final match in _tokenCandidate.allMatches(text)) {
    final rawMatch = match.group(0)!;
    final token = rawMatch.replaceAll(_edgeSeparators, '');
    final startOffset = rawMatch.indexOf(token);
    final start = match.start + (startOffset >= 0 ? startOffset : 0);
    final end = start + token.length;

    final prefixStart = math.max(0, start - 35);
    final contextPrefix = text.substring(prefixStart, start);

    // Skip data:image/ or base64 data URLs
    if (_dataUrlContext.hasMatch(contextPrefix)) {
      continue;
    }

    if (token.length >= minLength &&
        isHighEntropyToken(token,
            threshold: threshold,
            minLength: minLength,
            contextPrefix: contextPrefix)) {
      final entropy = calculateShannonEntropy(token);
      matches.add(
        EntropyMatch(
          start: start,
          end: end,
          token: token,
          entropy: entropy,
        ),
      );
    }
  }

  return matches;
}

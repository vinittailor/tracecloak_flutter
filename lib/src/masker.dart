/// Masking algorithms for VibeShield: Partial preview and Full shape-preserving mask.
library;

final RegExp _knownPrefixes = RegExp(
  r'^(sk_live_|rk_live_|pk_live_|sk_test_|rk_test_|sk_prod_|rk_prod_|sk-ant-|sk-proj-|sk-svcacct-|sk-admin-|'
  r'ghp_|gho_|ghu_|ghs_|ghr_|github_pat_|xoxb-|xoxp-|xoxa-|xoxe-|xoxr-|xoxs-|xoxo-|AIza|AKIA|ASIA|eyJ)',
);

/// Characters kept as-is by [fullMask] so the shape of a token stays readable.
const String _structural = ' \t\r\n_-:/.@=\'",;';

/// Partial mask: keeps a known provider prefix, and only reveals other
/// characters when the secret is long enough that at most a third of it is shown.
///
/// - known prefix: `sk_live_51Hc29KJ8f3ks9fQ2` → `sk_live_****9fQ2`
/// - 24+ chars: first 4 and last 4 (`aB39****AbCd`)
/// - 16–23 chars: last 4 only (`****AbCd`)
/// - under 16 chars: `****`
String partialMask(String secret, {String? prefix}) {
  if (secret.isEmpty) return '';

  var p = prefix;
  if (p == null || !secret.startsWith(p)) {
    p = _knownPrefixes.firstMatch(secret)?.group(0);
  }

  if (p != null) {
    final remaining = secret.substring(p.length);
    // Reveal 4 trailing chars only if they are at most a third of the remainder.
    if (remaining.length < 12) return '$p****';
    return '$p****${remaining.substring(remaining.length - 4)}';
  }

  if (secret.length < 16) return '****';
  final suffix = secret.substring(secret.length - 4);
  if (secret.length < 24) return '****$suffix';
  return '${secret.substring(0, 4)}****$suffix';
}

/// Full shape-preserving mask:
/// ASCII letters become `a` (or `b` where the original was `a`/`A`), digits become
/// `0` (or `1` where the original was `0`), structural separators
/// (space, `_ - : / . @ = ' " , ;`) are kept, and every other character —
/// symbols and non-ASCII letters included — becomes `*` (and `*` becomes `#`).
/// Guarantees no content character survives at its original position.
/// Example: `sk_live_51Hc29KJ8f3ks9fQ2` -> `aa_aaaa_00aa00aa0a0aa0aa0`
String fullMask(String secret) {
  if (secret.isEmpty) return '';

  final out = StringBuffer();
  for (var i = 0; i < secret.length; i++) {
    final c = secret.codeUnitAt(i);
    if ((c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A)) {
      out.write(c == 0x61 || c == 0x41 ? 'b' : 'a');
    } else if (c >= 0x30 && c <= 0x39) {
      out.write(c == 0x30 ? '1' : '0');
    } else if (_structural.contains(secret[i])) {
      out.write(secret[i]);
    } else {
      out.write(c == 0x2A ? '#' : '*'); // '*' itself becomes '#'
    }
  }
  return out.toString();
}

/// Verifies whether fullMask achieved zero character-level overlap: every
/// character that is not a structural separator must differ from the original.
bool verifyZeroCharacterOverlap(String raw, String masked) {
  if (raw.length != masked.length) return false;
  for (var i = 0; i < raw.length; i++) {
    final r = raw[i];
    if (_structural.contains(r)) continue;
    if (r.toLowerCase() == masked[i].toLowerCase()) return false;
  }
  return true;
}

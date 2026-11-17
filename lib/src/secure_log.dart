/// Backward-compatibility layer for SecureLog.
/// All methods, state, and functionality are unified under [VibeShield].
library vibeshield.secure_log;

import 'vibeshield.dart';

export 'types.dart';
export 'vibeshield.dart';

/// Backward-compatibility alias pointing directly to [VibeShield].
/// Shares 100% of the active masking mode, exact matches, rules, and print pipeline.
typedef SecureLog = VibeShield;

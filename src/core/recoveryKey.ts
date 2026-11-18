/**
 * Recovery keys: 24 characters from a 32-letter alphabet (120 random bits), shown as 6 groups of 4.
 * The alphabet leaves out 0, 1, I and O so nothing can be misread. Typing is forgiving: lower case, spaces, dashes and
 * dots are ignored.
 */

export const RECOVERY_ALPHABET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';
export const RECOVERY_LENGTH = 24;
export const RECOVERY_GROUP = 4;

/** 15 random bytes → 24 characters (5 bits each). */
export function encodeRecoveryKey(random: Uint8Array): string {
  if (random.length !== 15) throw new Error('A recovery key needs 15 random bytes');
  let out = '';
  let value = 0;
  let bits = 0;
  for (const byte of random) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += RECOVERY_ALPHABET[(value >> bits) & 31]!;
    }
  }
  return out;
}

/** "K7QMRW2D…" → "K7QM-RW2D-…". Accepts already formatted input. */
export function formatRecoveryKey(key: string): string {
  const raw = key.replace(/[^0-9A-Za-z]/g, '').toUpperCase();
  const groups: string[] = [];
  for (let i = 0; i < raw.length; i += RECOVERY_GROUP) groups.push(raw.slice(i, i + RECOVERY_GROUP));
  return groups.join('-');
}

/**
 * What a person typed → the 24 canonical characters, or null when it cannot be a recovery key (wrong length or a
 * character outside the alphabet). A valid-looking key can still be the wrong one: unlockVault decides that.
 */
export function parseRecoveryKey(input: string): string | null {
  const raw = input.replace(/[\s\-_.]/g, '').toUpperCase();
  if (raw.length !== RECOVERY_LENGTH) return null;
  for (const ch of raw) if (!RECOVERY_ALPHABET.includes(ch)) return null;
  return raw;
}

/** The groups of a key, for screens that show or confirm them one by one. */
export const recoveryGroups = (key: string): string[] => formatRecoveryKey(key).split('-').filter(Boolean);

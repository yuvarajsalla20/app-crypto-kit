import { useMemo, useRef, useState } from 'react';
import { Pressable, StyleSheet, Text, TextInput, View, type StyleProp, type TextInputInstance, type TextStyle, type ViewStyle } from 'react-native';
import { RECOVERY_GROUP, RECOVERY_LENGTH, parseRecoveryKey, recoveryGroups } from './core/recoveryKey';

/**
 * Optional, generic screens parts. No words are built in: the app passes every label and its own colours, so the kit
 * looks like whichever app uses it.
 */

export interface RecoveryKeyColors {
  text: string;
  muted: string;
  /** Box background. */
  box: string;
  border: string;
  /** Border of a filled box / focus. */
  accent: string;
  error: string;
}

const MONO: TextStyle = { fontFamily: 'Menlo', fontVariant: ['tabular-nums'], letterSpacing: 2, fontWeight: '600' };

/** Shows a recovery key as 6 boxes of 4 characters (3 per row). */
export function RecoveryKeyView({
  value,
  colors,
  style,
  accessibilityLabel,
}: {
  value: string;
  colors: Pick<RecoveryKeyColors, 'text' | 'box' | 'border'>;
  style?: StyleProp<ViewStyle>;
  accessibilityLabel?: string;
}) {
  const groups = recoveryGroups(value);
  return (
    <View style={[styles.grid, style]} accessible accessibilityLabel={accessibilityLabel ?? groups.join(' ')}>
      {groups.map((g, i) => (
        <View key={i} style={[styles.cell, { backgroundColor: colors.box, borderColor: colors.border }]}>
          <Text selectable style={[styles.cellText, MONO, { color: colors.text }]}>
            {g}
          </Text>
        </View>
      ))}
    </View>
  );
}

const GROUPS = RECOVERY_LENGTH / RECOVERY_GROUP;

/**
 * Six boxes to type a recovery key. Typing moves on by itself, and pasting a whole key fills every box. Calls
 * onChange with the canonical key once all 24 valid characters are in (else null).
 */
export function RecoveryKeyInput({
  colors,
  onChange,
  error,
  style,
  groupLabel = (n) => `Group ${n}`,
}: {
  colors: RecoveryKeyColors;
  onChange: (key: string | null) => void;
  /** Shown under the boxes (e.g. "Incorrect recovery key."). */
  error?: string | null;
  style?: StyleProp<ViewStyle>;
  /** Accessibility label for each box. */
  groupLabel?: (n: number) => string;
}) {
  const [parts, setParts] = useState<string[]>(() => Array(GROUPS).fill(''));
  const refs = useRef<(TextInputInstance | null)[]>([]);
  const clean = (s: string) => s.replace(/[^0-9A-Za-z]/g, '').toUpperCase();

  const update = (next: string[]) => {
    setParts(next);
    onChange(parseRecoveryKey(next.join('')));
  };

  const onText = (i: number, text: string) => {
    const raw = clean(text);
    if (raw.length > RECOVERY_GROUP) {
      // A paste: spread it over this box and the ones after.
      const next = [...parts];
      for (let g = i, at = 0; g < GROUPS && at < raw.length; g++, at += RECOVERY_GROUP) next[g] = raw.slice(at, at + RECOVERY_GROUP);
      update(next);
      refs.current[Math.min(GROUPS - 1, i + Math.ceil(raw.length / RECOVERY_GROUP) - 1)]?.focus();
      return;
    }
    const next = [...parts];
    next[i] = raw;
    update(next);
    if (raw.length === RECOVERY_GROUP && i < GROUPS - 1) refs.current[i + 1]?.focus();
  };

  const filled = useMemo(() => parts.map((p) => p.length === RECOVERY_GROUP), [parts]);

  return (
    <View style={style}>
      <View style={styles.grid}>
        {parts.map((p, i) => (
          <TextInput
            key={i}
            ref={(r) => {
              refs.current[i] = r;
            }}
            value={p}
            onChangeText={(t) => onText(i, t)}
            onKeyPress={(e) => {
              if (e.nativeEvent.key === 'Backspace' && !p && i > 0) refs.current[i - 1]?.focus();
            }}
            autoCapitalize="characters"
            autoCorrect={false}
            autoComplete="off"
            spellCheck={false}
            importantForAutofill="no"
            textContentType="none"
            accessibilityLabel={groupLabel(i + 1)}
            style={[
              styles.cell,
              styles.cellText,
              MONO,
              { color: colors.text, backgroundColor: colors.box, borderColor: error ? colors.error : filled[i] ? colors.accent : colors.border },
            ]}
          />
        ))}
      </View>
      {error ? <Text style={[styles.error, { color: colors.error }]}>{error}</Text> : null}
    </View>
  );
}

/** A two-button row for screens that confirm groups of the key (e.g. "Group 2", "Group 5"). Picks groups at random. */
export function pickConfirmGroups(count = 2, random: () => number = Math.random): number[] {
  const all = Array.from({ length: GROUPS }, (_, i) => i);
  const picked: number[] = [];
  while (picked.length < count && all.length) picked.push(all.splice(Math.floor(random() * all.length), 1)[0]!);
  return picked.sort((a, b) => a - b);
}

/** Small press target used by apps for Copy-style buttons; optional. */
export function KeyAction({ label, onPress, color, style }: { label: string; onPress: () => void; color: string; style?: StyleProp<ViewStyle> }) {
  return (
    <Pressable onPress={onPress} accessibilityRole="button" hitSlop={6} style={({ pressed }) => [styles.action, { borderColor: color, opacity: pressed ? 0.6 : 1 }, style]}>
      <Text style={{ color, fontWeight: '600', fontSize: 15 }}>{label}</Text>
    </Pressable>
  );
}

const styles = StyleSheet.create({
  grid: { flexDirection: 'row', flexWrap: 'wrap', gap: 8 },
  cell: { flexBasis: '31%', flexGrow: 1, minHeight: 48, borderWidth: 1.5, borderRadius: 12, alignItems: 'center', justifyContent: 'center', paddingVertical: 10 },
  cellText: { fontSize: 18, textAlign: 'center' },
  error: { marginTop: 8, fontSize: 14 },
  action: { minHeight: 44, borderWidth: 1, borderRadius: 999, alignItems: 'center', justifyContent: 'center', paddingHorizontal: 16 },
});

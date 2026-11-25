import { ascii, concat, fromBase64, toBase64, wipe } from './bytes';
import { NONCE_LENGTH, assertKeyId, header, parseSealed } from './format';
import { encodeRecoveryKey, formatRecoveryKey, parseRecoveryKey } from './recoveryKey';
import {
  MissingKeyError,
  TamperedDataError,
  WrongRecoveryKeyError,
  type CryptoBackend,
  type Lockbox,
  type ScryptParams,
  type SecretStore,
  type VaultSecret,
} from './types';

/**
 * scrypt cost. The recovery key already carries 120 random bits, so the KDF only has to be "not instant"; these
 * values take about a second on a phone and stay inside Hermes' memory comfortably. They are written into every
 * lockbox, so they can be raised later without breaking old ones.
 */
export const DEFAULT_SCRYPT: ScryptParams = { N: 2 ** 14, r: 8, p: 1 };

const KEY_BYTES = 32;
const NAMESPACE = /^[A-Za-z0-9_-]{1,128}$/;

export interface CryptoKitDeps {
  crypto: CryptoBackend;
  store: SecretStore;
  scryptParams?: ScryptParams;
  /** For tests. */
  now?: () => Date;
}

export interface Namespaced {
  /** Usually the signed-in user's id. Keeps the keys of different accounts on one device apart. */
  namespace: string;
}

export type CryptoKit = ReturnType<typeof createCryptoKit>;

/** Builds the kit on a crypto backend and a secret store. The Expo build calls this with expo-crypto/expo-secure-store. */
export function createCryptoKit(deps: CryptoKitDeps) {
  const { crypto, store } = deps;
  const scryptParams = deps.scryptParams ?? DEFAULT_SCRYPT;
  const now = deps.now ?? (() => new Date());

  const names = (ns: string) => {
    if (!NAMESPACE.test(ns)) throw new Error('Invalid namespace');
    return {
      mainKey: (keyId: string) => `crypto.mainKey.${ns}.${keyId}`,
      recoveryKey: (keyId: string) => `crypto.recoveryKey.${ns}.${keyId}`,
      active: `crypto.activeKeyId.${ns}`,
      keyIds: `crypto.keyIds.${ns}`,
    };
  };

  /** Keys already read from secure storage this session (secure storage is slow for one read per photo). */
  const memory = new Map<string, Uint8Array>();
  const memoryName = (ns: string, keyId: string) => `${ns}/${keyId}`;

  async function readKeyIds(ns: string): Promise<string[]> {
    try {
      const list = JSON.parse((await store.get(names(ns).keyIds)) ?? '[]') as unknown;
      return Array.isArray(list) ? list.filter((x): x is string => typeof x === 'string') : [];
    } catch {
      return [];
    }
  }

  async function saveKey(ns: string, keyId: string, key: Uint8Array, recoveryKey: string): Promise<void> {
    const n = names(ns);
    await store.set(n.mainKey(keyId), toBase64(key));
    await store.set(n.recoveryKey(keyId), recoveryKey);
    const ids = await readKeyIds(ns);
    if (!ids.includes(keyId)) await store.set(n.keyIds, JSON.stringify([...ids, keyId]));
    memory.set(memoryName(ns, keyId), key);
  }

  async function loadKey(ns: string, keyId: string): Promise<Uint8Array | null> {
    const cached = memory.get(memoryName(ns, keyId));
    if (cached) return cached;
    const saved = await store.get(names(ns).mainKey(keyId));
    if (!saved) return null;
    const key = fromBase64(saved);
    if (key.length !== KEY_BYTES) return null;
    memory.set(memoryName(ns, keyId), key);
    return key;
  }

  /**
   * Keys in use by an encrypt / decrypt that has not finished. clearMemory and forgetKeys drop them from memory at
   * once, but zero their bytes only when that work ends: zeroing a key mid-encrypt would seal data under an all-zero
   * key (and break a decrypt).
   */
  const busy = new Map<Uint8Array, number>();
  const wipeWhenDone = new Set<Uint8Array>();
  const drop = (key: Uint8Array) => (busy.has(key) ? wipeWhenDone.add(key) : wipe(key));

  /** Runs `use` with the key (MissingKeyError when this device lacks it), keeping its bytes intact until it ends. */
  async function withKey<T>(ns: string, keyId: string, use: (key: Uint8Array) => Promise<T>): Promise<T> {
    const key = await loadKey(ns, keyId);
    if (!key) throw new MissingKeyError(keyId);
    busy.set(key, (busy.get(key) ?? 0) + 1);
    try {
      return await use(key);
    } finally {
      const left = (busy.get(key) ?? 1) - 1;
      if (left > 0) busy.set(key, left);
      else {
        busy.delete(key);
        if (wipeWhenDone.delete(key)) wipe(key);
      }
    }
  }

  const lockboxAad = (keyId: string) => ascii(`app-crypto-kit/lockbox/v1/${keyId}`);

  async function wrapKey(keyId: string, key: Uint8Array, recoveryKey: string): Promise<Lockbox> {
    const salt = crypto.randomBytes(16);
    const kek = await crypto.scrypt(ascii(recoveryKey), salt, scryptParams);
    try {
      const nonce = crypto.randomBytes(NONCE_LENGTH);
      const sealed = await crypto.aesGcmEncrypt(kek, nonce, key, lockboxAad(keyId));
      return {
        v: 1,
        keyId,
        kdf: { name: 'scrypt', ...scryptParams, salt: toBase64(salt) },
        wrapped: toBase64(concat(nonce, sealed)),
        createdAt: now().toISOString(),
      };
    } finally {
      wipe(kek);
    }
  }

  /** A fresh main key and recovery key under keyId; becomes the key for new data. */
  async function newKey(ns: string, keyId: string): Promise<VaultSecret> {
    assertKeyId(keyId);
    const key = crypto.randomBytes(KEY_BYTES);
    const recoveryKey = encodeRecoveryKey(crypto.randomBytes(15));
    const lockbox = await wrapKey(keyId, key, recoveryKey);
    await saveKey(ns, keyId, key, recoveryKey);
    await store.set(names(ns).active, keyId);
    return { lockbox, recoveryKey: formatRecoveryKey(recoveryKey), keyId };
  }

  async function activeKeyId({ namespace }: Namespaced): Promise<string | null> {
    return store.get(names(namespace).active);
  }

  return {
    /**
     * First use on the first device: makes the main key (k1) and a recovery key. Save the lockbox where the user's
     * data lives, and show the recovery key once. Throws if this device already has an active key for the namespace.
     */
    async createVault({ namespace, keyId = 'k1' }: Namespaced & { keyId?: string }): Promise<VaultSecret> {
      if (await activeKeyId({ namespace })) throw new Error('A vault already exists on this device');
      return newKey(namespace, keyId);
    },

    /**
     * Starts a new key when the old recovery key is lost (old data stays encrypted with the old key). Pass every key
     * id the app has seen, so the new id never collides: k1, k2 → k3.
     */
    async startNewKey({ namespace, existingKeyIds = [] }: Namespaced & { existingKeyIds?: readonly string[] }): Promise<VaultSecret> {
      const ids = new Set([...existingKeyIds, ...(await readKeyIds(namespace))]);
      let n = 1;
      for (const id of ids) {
        const m = /^k(\d+)$/.exec(id);
        if (m) n = Math.max(n, Number(m[1]) + 1);
      }
      return newKey(namespace, `k${n}`);
    },

    /**
     * New device: opens a lockbox with the recovery key and stores the same main key here. Throws
     * WrongRecoveryKeyError for a key that does not open it (or cannot be a recovery key at all).
     */
    async unlockVault({ namespace, lockbox, recoveryKey }: Namespaced & { lockbox: Lockbox; recoveryKey: string }): Promise<{ keyId: string }> {
      const canonical = parseRecoveryKey(recoveryKey);
      if (!canonical || lockbox?.v !== 1 || lockbox.kdf?.name !== 'scrypt') throw new WrongRecoveryKeyError();
      assertKeyId(lockbox.keyId);
      const { N, r, p, salt } = lockbox.kdf;
      const kek = await crypto.scrypt(ascii(canonical), fromBase64(salt), { N, r, p });
      let key: Uint8Array;
      try {
        const wrapped = fromBase64(lockbox.wrapped);
        key = await crypto.aesGcmDecrypt(kek, wrapped.subarray(0, NONCE_LENGTH), wrapped.subarray(NONCE_LENGTH), lockboxAad(lockbox.keyId));
      } catch {
        throw new WrongRecoveryKeyError();
      } finally {
        wipe(kek);
      }
      if (key.length !== KEY_BYTES) throw new WrongRecoveryKeyError();
      await saveKey(namespace, lockbox.keyId, key, canonical);
      if (!(await activeKeyId({ namespace }))) await store.set(names(namespace).active, lockbox.keyId);
      return { keyId: lockbox.keyId };
    },

    /** Same main key, new recovery key and new lockbox. Replace the stored lockbox; the old recovery key stops working. */
    async rotateRecoveryKey({ namespace, keyId }: Namespaced & { keyId?: string }): Promise<VaultSecret> {
      const id = keyId ?? (await activeKeyId({ namespace }));
      if (!id) throw new MissingKeyError('active');
      const recoveryKey = encodeRecoveryKey(crypto.randomBytes(15));
      const lockbox = await withKey(namespace, id, (key) => wrapKey(id, key, recoveryKey));
      await store.set(names(namespace).recoveryKey(id), recoveryKey);
      return { lockbox, recoveryKey: formatRecoveryKey(recoveryKey), keyId: id };
    },

    /** The key id new data is encrypted with on this device, or null before createVault / unlockVault. */
    activeKeyId,

    /** Whether this device holds the key (the active one when keyId is left out). */
    async hasKey({ namespace, keyId }: Namespaced & { keyId?: string }): Promise<boolean> {
      const id = keyId ?? (await activeKeyId({ namespace }));
      return !!id && !!(await loadKey(namespace, id));
    },

    /** Key ids stored on this device. */
    keyIds: ({ namespace }: Namespaced) => readKeyIds(namespace),

    /** The recovery key for display ("View recovery key"), formatted; null when this device does not have it. */
    async getRecoveryKey({ namespace, keyId }: Namespaced & { keyId?: string }): Promise<string | null> {
      const id = keyId ?? (await activeKeyId({ namespace }));
      if (!id) return null;
      const saved = await store.get(names(namespace).recoveryKey(id));
      return saved ? formatRecoveryKey(saved) : null;
    },

    /** Encrypts with the active key. */
    async encryptBytes({ namespace, data }: Namespaced & { data: Uint8Array }): Promise<Uint8Array> {
      const keyId = await activeKeyId({ namespace });
      if (!keyId) throw new MissingKeyError('active');
      const head = header(keyId);
      const nonce = crypto.randomBytes(NONCE_LENGTH);
      const body = await withKey(namespace, keyId, (key) => crypto.aesGcmEncrypt(key, nonce, data, head));
      return concat(head, nonce, body);
    },

    /** Decrypts with the key named in the data. MissingKeyError when this device lacks it; TamperedDataError when it fails. */
    async decryptBytes({ namespace, data }: Namespaced & { data: Uint8Array }): Promise<Uint8Array> {
      const parsed = parseSealed(data);
      return withKey(namespace, parsed.keyId, async (key) => {
        try {
          return await crypto.aesGcmDecrypt(key, parsed.nonce, parsed.body, parsed.header);
        } catch {
          throw new TamperedDataError();
        }
      });
    },

    /**
     * Drops keys held in memory (call on app lock); they are read again from secure storage when needed. A key still
     * in use by an unfinished encrypt / decrypt is zeroed when that ends, so that work is never corrupted.
     */
    clearMemory(): void {
      for (const key of memory.values()) drop(key);
      memory.clear();
    },

    /** Removes every key of the namespace from this device (sign-out on a shared phone, account deletion). */
    async forgetKeys({ namespace }: Namespaced): Promise<void> {
      const n = names(namespace);
      for (const id of await readKeyIds(namespace)) {
        await store.delete(n.mainKey(id));
        await store.delete(n.recoveryKey(id));
        const m = memory.get(memoryName(namespace, id));
        if (m) drop(m);
        memory.delete(memoryName(namespace, id));
      }
      await store.delete(n.keyIds);
      await store.delete(n.active);
    },
  };
}

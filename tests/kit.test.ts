import { scryptAsync } from '@noble/hashes/scrypt';
import { webcrypto } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  MissingKeyError,
  NotEncryptedError,
  RECOVERY_ALPHABET,
  TamperedDataError,
  WrongRecoveryKeyError,
  createCryptoKit,
  encodeRecoveryKey,
  formatRecoveryKey,
  fromBase64,
  isSealed,
  parseRecoveryKey,
  readKeyId,
  toBase64,
  type CryptoBackend,
  type SecretStore,
} from '../src/core';

const subtle = webcrypto.subtle;
const nodeCrypto: CryptoBackend = {
  randomBytes: (n) => webcrypto.getRandomValues(new Uint8Array(n)),
  async aesGcmEncrypt(key, nonce, plaintext, aad) {
    const k = await subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt']);
    return new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 }, k, plaintext));
  },
  async aesGcmDecrypt(key, nonce, ct, aad) {
    const k = await subtle.importKey('raw', key, 'AES-GCM', false, ['decrypt']);
    return new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 }, k, ct));
  },
  scrypt: (pw, salt, { N, r, p }) => scryptAsync(pw, salt, { N, r, p, dkLen: 32 }),
};

const memoryStore = (): SecretStore & { data: Map<string, string> } => {
  const data = new Map<string, string>();
  return {
    data,
    get: async (n) => data.get(n) ?? null,
    set: async (n, v) => void data.set(n, v),
    delete: async (n) => void data.delete(n),
  };
};

// Cheap scrypt for tests; real default is tested separately for its values only.
const device = () => createCryptoKit({ crypto: nodeCrypto, store: memoryStore(), scryptParams: { N: 1024, r: 8, p: 1 } });
const ns = { namespace: 'user_123' };
const photo = new TextEncoder().encode('pretend this is a JPEG');

describe('recovery keys', () => {
  it('encodes 15 bytes into 24 characters from the safe alphabet', () => {
    const key = encodeRecoveryKey(nodeCrypto.randomBytes(15));
    expect(key).toHaveLength(24);
    for (const ch of key) expect(RECOVERY_ALPHABET).toContain(ch);
    expect(RECOVERY_ALPHABET).not.toMatch(/[01IO]/);
  });

  it('formats and parses forgivingly', () => {
    const key = 'K7QMRW2DHP4XT9NBZC3FLV8J';
    expect(formatRecoveryKey(key)).toBe('K7QM-RW2D-HP4X-T9NB-ZC3F-LV8J');
    expect(parseRecoveryKey(' k7qm rw2d-hp4x.t9nb zc3f lv8j ')).toBe(key);
    expect(parseRecoveryKey('K7QM-RW2D')).toBeNull();
    expect(parseRecoveryKey('K7QM-RW2D-HP4X-T9NB-ZC3F-LV8O')).toBeNull(); // O is not in the alphabet
  });
});

describe('base64', () => {
  it('round-trips every length', () => {
    for (let n = 0; n < 40; n++) {
      const b = nodeCrypto.randomBytes(n);
      expect(Buffer.from(toBase64(b), 'base64')).toEqual(Buffer.from(b));
      expect(fromBase64(Buffer.from(b).toString('base64'))).toEqual(b);
    }
  });
});

describe('vault', () => {
  it('encrypts on one device and decrypts there', async () => {
    const kit = device();
    const secret = await kit.createVault(ns);
    expect(secret.keyId).toBe('k1');
    expect(secret.recoveryKey).toMatch(/^([2-9A-HJ-NP-Z]{4}-){5}[2-9A-HJ-NP-Z]{4}$/);
    const sealed = await kit.encryptBytes({ ...ns, data: photo });
    expect(isSealed(sealed)).toBe(true);
    expect(readKeyId(sealed)).toBe('k1');
    expect(Buffer.from(sealed).includes(Buffer.from(photo))).toBe(false);
    expect(await kit.decryptBytes({ ...ns, data: sealed })).toEqual(photo);
  });

  it('uses a new nonce every time', async () => {
    const kit = device();
    await kit.createVault(ns);
    const a = await kit.encryptBytes({ ...ns, data: photo });
    const b = await kit.encryptBytes({ ...ns, data: photo });
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });

  it('refuses to create a second vault on the same device', async () => {
    const kit = device();
    await kit.createVault(ns);
    await expect(kit.createVault(ns)).rejects.toThrow();
  });

  it('moves to a new device with the recovery key (same main key, old data opens)', async () => {
    const oldPhone = device();
    const { lockbox, recoveryKey } = await oldPhone.createVault(ns);
    const sealed = await oldPhone.encryptBytes({ ...ns, data: photo });

    const newPhone = device();
    expect(await newPhone.hasKey(ns)).toBe(false);
    await expect(newPhone.decryptBytes({ ...ns, data: sealed })).rejects.toBeInstanceOf(MissingKeyError);
    await newPhone.unlockVault({ ...ns, lockbox, recoveryKey: recoveryKey.toLowerCase().replace(/-/g, ' ') });
    expect(await newPhone.hasKey(ns)).toBe(true);
    expect(await newPhone.decryptBytes({ ...ns, data: sealed })).toEqual(photo);
    expect(await newPhone.getRecoveryKey(ns)).toBe(recoveryKey);
  });

  it('rejects a wrong recovery key', async () => {
    const { lockbox } = await device().createVault(ns);
    const other = await device().createVault(ns);
    await expect(device().unlockVault({ ...ns, lockbox, recoveryKey: other.recoveryKey })).rejects.toBeInstanceOf(WrongRecoveryKeyError);
    await expect(device().unlockVault({ ...ns, lockbox, recoveryKey: 'nonsense' })).rejects.toBeInstanceOf(WrongRecoveryKeyError);
  });

  it('rejects a lockbox whose key id was changed', async () => {
    const { lockbox, recoveryKey } = await device().createVault(ns);
    await expect(device().unlockVault({ ...ns, lockbox: { ...lockbox, keyId: 'k9' }, recoveryKey })).rejects.toBeInstanceOf(WrongRecoveryKeyError);
  });

  it('reset recovery key: same main key, old recovery key stops working, data untouched', async () => {
    const phone = device();
    const first = await phone.createVault(ns);
    const sealed = await phone.encryptBytes({ ...ns, data: photo });
    const second = await phone.rotateRecoveryKey(ns);
    expect(second.keyId).toBe('k1');
    expect(second.recoveryKey).not.toBe(first.recoveryKey);
    expect(await phone.getRecoveryKey(ns)).toBe(second.recoveryKey);

    await expect(device().unlockVault({ ...ns, lockbox: second.lockbox, recoveryKey: first.recoveryKey })).rejects.toBeInstanceOf(WrongRecoveryKeyError);
    const newPhone = device();
    await newPhone.unlockVault({ ...ns, lockbox: second.lockbox, recoveryKey: second.recoveryKey });
    expect(await newPhone.decryptBytes({ ...ns, data: sealed })).toEqual(photo);
  });

  it('lost recovery key: new key k2 for new data, k1 data stays locked until the old key is found', async () => {
    const oldPhone = device();
    const k1 = await oldPhone.createVault(ns);
    const oldPhoto = await oldPhone.encryptBytes({ ...ns, data: photo });

    const newPhone = device();
    const k2 = await newPhone.startNewKey({ ...ns, existingKeyIds: [k1.keyId] });
    expect(k2.keyId).toBe('k2');
    const newPhoto = await newPhone.encryptBytes({ ...ns, data: photo });
    expect(readKeyId(newPhoto)).toBe('k2');
    await expect(newPhone.decryptBytes({ ...ns, data: oldPhoto })).rejects.toBeInstanceOf(MissingKeyError);

    // Old key found later: k1 opens again, k2 stays the active key.
    await newPhone.unlockVault({ ...ns, lockbox: k1.lockbox, recoveryKey: k1.recoveryKey });
    expect(await newPhone.decryptBytes({ ...ns, data: oldPhoto })).toEqual(photo);
    expect(await newPhone.activeKeyId(ns)).toBe('k2');
    expect((await newPhone.keyIds(ns)).sort()).toEqual(['k1', 'k2']);
  });

  it('detects changed data', async () => {
    const kit = device();
    await kit.createVault(ns);
    const sealed = await kit.encryptBytes({ ...ns, data: photo });
    const changed = sealed.slice();
    changed[changed.length - 20]! ^= 1;
    await expect(kit.decryptBytes({ ...ns, data: changed })).rejects.toBeInstanceOf(TamperedDataError);
    await expect(kit.decryptBytes({ ...ns, data: photo })).rejects.toBeInstanceOf(NotEncryptedError);
  });

  it('keeps accounts apart on one device', async () => {
    const store = memoryStore();
    const kit = createCryptoKit({ crypto: nodeCrypto, store, scryptParams: { N: 1024, r: 8, p: 1 } });
    await kit.createVault({ namespace: 'alice' });
    await kit.createVault({ namespace: 'bob' });
    const sealed = await kit.encryptBytes({ namespace: 'alice', data: photo });
    await expect(kit.decryptBytes({ namespace: 'bob', data: sealed })).rejects.toBeInstanceOf(TamperedDataError);
  });

  it('forgetKeys removes everything of a namespace, from storage and memory', async () => {
    const store = memoryStore();
    const kit = createCryptoKit({ crypto: nodeCrypto, store, scryptParams: { N: 1024, r: 8, p: 1 } });
    await kit.createVault(ns);
    await kit.forgetKeys(ns);
    expect([...store.data.keys()].filter((k) => k.includes('user_123'))).toEqual([]);
    expect(await kit.hasKey(ns)).toBe(false);
  });

  it('never stores the main key or recovery key in the lockbox', async () => {
    const store = memoryStore();
    const kit = createCryptoKit({ crypto: nodeCrypto, store, scryptParams: { N: 1024, r: 8, p: 1 } });
    const { lockbox, recoveryKey } = await kit.createVault(ns);
    const json = JSON.stringify(lockbox);
    const mainKey = store.data.get('crypto.mainKey.user_123.k1')!;
    expect(json).not.toContain(mainKey);
    expect(json).not.toContain(recoveryKey.replace(/-/g, ''));
    expect(lockbox.kdf).toMatchObject({ name: 'scrypt', N: 1024, r: 8, p: 1 });
  });

  it('rejects unsafe namespaces', async () => {
    await expect(device().createVault({ namespace: 'a/b' })).rejects.toThrow();
  });
});

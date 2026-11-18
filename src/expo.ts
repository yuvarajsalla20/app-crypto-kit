import { scryptAsync } from '@noble/hashes/scrypt';
import { AESEncryptionKey, AESSealedData, aesDecryptAsync, aesEncryptAsync, getRandomBytes } from 'expo-crypto';
import * as SecureStore from 'expo-secure-store';
import type { CryptoBackend, SecretStore } from './core/types';

/**
 * The real platform pieces: expo-crypto's native AES-256-GCM (CommonCrypto on iOS, javax.crypto on Android),
 * @noble/hashes scrypt (audited, pure JS), and expo-secure-store (iOS Keychain / Android Keystore).
 */
export const expoCrypto: CryptoBackend = {
  randomBytes: (length) => getRandomBytes(length),

  async aesGcmEncrypt(key, nonce, plaintext, aad) {
    const sealed = await aesEncryptAsync(plaintext, await AESEncryptionKey.import(key), {
      nonce: { bytes: nonce },
      tagLength: 16,
      additionalData: aad,
    });
    return sealed.ciphertext({ includeTag: true, encoding: 'bytes' });
  },

  async aesGcmDecrypt(key, nonce, ciphertextWithTag, aad) {
    const sealed = AESSealedData.fromParts(nonce, ciphertextWithTag, 16);
    return aesDecryptAsync(sealed, await AESEncryptionKey.import(key), { additionalData: aad, output: 'bytes' });
  },

  scrypt: (password, salt, { N, r, p }) => scryptAsync(password, salt, { N, r, p, dkLen: 32, asyncTick: 10 }),
};

/**
 * Keys stay on this device: readable after the phone's first unlock (so background work can run), never synced to
 * iCloud Keychain or restored to another device. A new device gets the key through the recovery key.
 */
const OPTIONS: SecureStore.SecureStoreOptions = { keychainAccessible: SecureStore.AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY };

export const expoSecretStore: SecretStore = {
  get: (name) => SecureStore.getItemAsync(name, OPTIONS),
  set: (name, value) => SecureStore.setItemAsync(name, value, OPTIONS),
  delete: (name) => SecureStore.deleteItemAsync(name, OPTIONS),
};

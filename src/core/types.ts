/**
 * The two things the kit needs from the platform. The Expo build (src/expo.ts) uses expo-crypto and expo-secure-store;
 * tests pass Node's WebCrypto and an in-memory store. Nothing here knows about any app or backend.
 */

/** AES-256-GCM and secure random bytes. */
export interface CryptoBackend {
  randomBytes(length: number): Uint8Array;
  /** Encrypts with a 32-byte key and a 12-byte nonce; returns ciphertext with the 16-byte tag appended. */
  aesGcmEncrypt(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Promise<Uint8Array>;
  /** Reverses aesGcmEncrypt. Must throw when the tag does not match (wrong key or changed data). */
  aesGcmDecrypt(key: Uint8Array, nonce: Uint8Array, ciphertextWithTag: Uint8Array, aad: Uint8Array): Promise<Uint8Array>;
  /** scrypt key derivation (32-byte output). */
  scrypt(password: Uint8Array, salt: Uint8Array, params: ScryptParams): Promise<Uint8Array>;
}

/** Device secure storage (iOS Keychain / Android Keystore). Names use only letters, digits, ".", "-", "_". */
export interface SecretStore {
  get(name: string): Promise<string | null>;
  set(name: string, value: string): Promise<void>;
  delete(name: string): Promise<void>;
}

export interface ScryptParams {
  N: number;
  r: number;
  p: number;
}

/**
 * The main key, encrypted with a key derived from the recovery key. Safe to keep on a server: it is useless without
 * the recovery key. The app decides where to store it (the kit never talks to a backend).
 */
export interface Lockbox {
  v: 1;
  keyId: string;
  kdf: { name: 'scrypt'; N: number; r: number; p: number; salt: string };
  /** base64 of nonce (12) | ciphertext | tag (16). */
  wrapped: string;
  createdAt: string;
}

/** What createVault, rotateRecoveryKey and startNewKey hand back: save the lockbox, show the recovery key once. */
export interface VaultSecret {
  lockbox: Lockbox;
  /** Formatted for display: 6 groups of 4, joined by "-". */
  recoveryKey: string;
  keyId: string;
}

export class WrongRecoveryKeyError extends Error {
  constructor() {
    super('Incorrect recovery key.');
    this.name = 'WrongRecoveryKeyError';
  }
}

export class MissingKeyError extends Error {
  constructor(readonly keyId: string) {
    super(`No key ${keyId} on this device.`);
    this.name = 'MissingKeyError';
  }
}

export class TamperedDataError extends Error {
  constructor() {
    super('Encrypted data is damaged or was changed.');
    this.name = 'TamperedDataError';
  }
}

export class NotEncryptedError extends Error {
  constructor() {
    super('Data is not in the app-crypto-kit format.');
    this.name = 'NotEncryptedError';
  }
}

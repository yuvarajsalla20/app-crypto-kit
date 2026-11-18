import { createCryptoKit } from './core/vault';
import { expoCrypto, expoSecretStore } from './expo';
import { fileHelpers } from './files';

export * from './core';
export { expoCrypto, expoSecretStore } from './expo';
export { fileHelpers } from './files';
export { RecoveryKeyView, RecoveryKeyInput, KeyAction, pickConfirmGroups, type RecoveryKeyColors } from './ui';

/** Ready-to-use kit on expo-crypto + expo-secure-store + expo-file-system. */
const kit = createCryptoKit({ crypto: expoCrypto, store: expoSecretStore });
const files = fileHelpers(kit);

export const {
  createVault,
  unlockVault,
  startNewKey,
  rotateRecoveryKey,
  activeKeyId,
  hasKey,
  keyIds,
  getRecoveryKey,
  encryptBytes,
  decryptBytes,
  clearMemory,
  forgetKeys,
} = kit;
export const { encryptFile, decryptFile, isEncryptedFile, clearFolder } = files;

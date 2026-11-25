# Changelog

## 1.0.1 (2026-11-25)

- Fix: `clearMemory` (and `forgetKeys`) no longer zero a key that an unfinished `encryptBytes` / `decryptBytes` / `rotateRecoveryKey` is still using. Before, locking the app while a file was being sealed could seal it under an all-zero key. Keys in use are dropped from memory at once and zeroed when that work ends. No API change.

## 1.0.0 (2026-11-18)

- First release: AES-256-GCM file and byte encryption on the device, main key in the Keychain / Keystore (`expo-secure-store`, this device only), recovery key (24 characters, 120 bits) wrapping the main key with scrypt + AES-GCM in a portable lockbox, recovery-key rotation without re-encryption, new keys after a lost recovery key (`k2`, `k3` …) with old data still openable later, key id in every file, optional generic UI (`RecoveryKeyView`, `RecoveryKeyInput`).

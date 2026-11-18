# Changelog

## 1.0.0 (2026-11-18)

- First release: AES-256-GCM file and byte encryption on the device, main key in the Keychain / Keystore (`expo-secure-store`, this device only), recovery key (24 characters, 120 bits) wrapping the main key with scrypt + AES-GCM in a portable lockbox, recovery-key rotation without re-encryption, new keys after a lost recovery key (`k2`, `k3` …) with old data still openable later, key id in every file, optional generic UI (`RecoveryKeyView`, `RecoveryKeyInput`).

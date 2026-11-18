import { ascii, concat, fromAscii } from './bytes';
import { NotEncryptedError } from './types';

/**
 * Encrypted data, version 1:
 *
 *   "ACK1" | keyId length (1 byte) | keyId (ASCII) | nonce (12) | ciphertext | GCM tag (16)
 *
 * The header ("ACK1" + key id) is also the GCM additional data, so the key id cannot be swapped without the tag
 * failing.
 */
export const MAGIC = ascii('ACK1');
export const NONCE_LENGTH = 12;
export const TAG_LENGTH = 16;

const KEY_ID = /^[A-Za-z0-9_-]{1,32}$/;

export function assertKeyId(keyId: string): void {
  if (!KEY_ID.test(keyId)) throw new Error(`Invalid key id "${keyId}"`);
}

export function header(keyId: string): Uint8Array {
  assertKeyId(keyId);
  const id = ascii(keyId);
  return concat(MAGIC, Uint8Array.of(id.length), id);
}

export interface ParsedSealed {
  keyId: string;
  header: Uint8Array;
  nonce: Uint8Array;
  body: Uint8Array;
}

/** True when the bytes start like app-crypto-kit data (cheap check, no key needed). */
export function isSealed(data: Uint8Array): boolean {
  if (data.length < MAGIC.length + 2) return false;
  for (let i = 0; i < MAGIC.length; i++) if (data[i] !== MAGIC[i]) return false;
  return true;
}

export function parseSealed(data: Uint8Array): ParsedSealed {
  if (!isSealed(data)) throw new NotEncryptedError();
  const idLength = data[MAGIC.length]!;
  const headerEnd = MAGIC.length + 1 + idLength;
  if (idLength === 0 || data.length < headerEnd + NONCE_LENGTH + TAG_LENGTH) throw new NotEncryptedError();
  const keyId = fromAscii(data.subarray(MAGIC.length + 1, headerEnd));
  if (!KEY_ID.test(keyId)) throw new NotEncryptedError();
  return {
    keyId,
    header: data.subarray(0, headerEnd),
    nonce: data.subarray(headerEnd, headerEnd + NONCE_LENGTH),
    body: data.subarray(headerEnd + NONCE_LENGTH),
  };
}

/** The key id written in encrypted data, without decrypting it. */
export const readKeyId = (data: Uint8Array): string => parseSealed(data).keyId;

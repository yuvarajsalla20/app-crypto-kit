import { Directory, File } from 'expo-file-system';
import { isSealed } from './core/format';
import type { CryptoKit, Namespaced } from './core/vault';

/** File helpers on top of the byte API, using expo-file-system's File class. */
export function fileHelpers(kit: Pick<CryptoKit, 'encryptBytes' | 'decryptBytes'>) {
  const ensureParent = (file: File) => {
    const parent = file.parentDirectory;
    if (!parent.exists) parent.create({ intermediates: true });
  };

  return {
    /** Reads `from`, writes the encrypted copy to `to` (both file URIs). Returns `to`. */
    async encryptFile({ namespace, from, to }: Namespaced & { from: string; to: string }): Promise<string> {
      const data = await new File(from).bytes();
      const sealed = await kit.encryptBytes({ namespace, data });
      const out = new File(to);
      ensureParent(out);
      await out.write(sealed);
      return out.uri;
    },

    /** Reads encrypted `from`, writes the plain copy to `to`. Returns `to`. */
    async decryptFile({ namespace, from, to }: Namespaced & { from: string; to: string }): Promise<string> {
      const data = await new File(from).bytes();
      const plain = await kit.decryptBytes({ namespace, data });
      const out = new File(to);
      ensureParent(out);
      await out.write(plain);
      return out.uri;
    },

    /** Whether a file is in the kit's encrypted format (reads it; fine for photo-sized files). */
    async isEncryptedFile(uri: string): Promise<boolean> {
      return isSealed(await new File(uri).bytes());
    },

    /** Deletes a folder of decrypted copies (call on app lock and sign-out). Never throws. */
    clearFolder(dir: string | Directory): void {
      try {
        const d = typeof dir === 'string' ? new Directory(dir) : dir;
        if (d.exists) d.delete();
      } catch {
        // Nothing more to do.
      }
    },
  };
}

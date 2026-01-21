import { join } from 'path';
import { readdir, readFile, writeFile, unlink } from 'fs/promises';
import type { StoredKey } from './types';

/**
 * KeyStore persists keys to the filesystem as JSON.
 *
 * Design choices:
 * - Each key is stored as a single file named by its fingerprint.
 *   This makes lookups O(1) (no index file) and avoids collisions.
 * - We store OpenPGP "armored" key text (public and optional private).
 * - We store timestamps as ISO strings in JSON, then revive them into `Date` objects
 *   when reading, because JSON has no native Date type.
 *
 * Security note:
 * - Private keys are passphrase-protected by OpenPGP.js at creation time, but the
 *   encrypted private key blob is still sensitive data and should be protected on disk.
 */
export class KeyStore {
  constructor(private keyStorePath: string) {}

  private getKeyPath(fingerprint: string): string {
    // The fingerprint is treated as the canonical identifier for this keystore entry.
    return join(this.keyStorePath, `${fingerprint}.json`);
  }

  async saveKey(key: StoredKey): Promise<void> {
    const keyPath = this.getKeyPath(key.fingerprint);
    // Pretty-print JSON for human inspectability/debugging.
    const keyData = JSON.stringify(key, null, 2);
    await writeFile(keyPath, keyData, 'utf-8');
  }

  async getKey(fingerprint: string): Promise<StoredKey | null> {
    try {
      const keyPath = this.getKeyPath(fingerprint);
      const keyData = await readFile(keyPath, 'utf-8');
      const key = JSON.parse(keyData);
      // JSON stores dates as strings; revive into a Date to match our types/UI usage.
      key.created = new Date(key.created);
      return key;
    } catch (error) {
      // We intentionally return `null` for any failure (missing file, invalid JSON, etc.)
      // so callers can treat "not found" and "unreadable" uniformly.
      return null;
    }
  }

  async listKeys(): Promise<StoredKey[]> {
    try {
      // Enumerate all JSON files under the keystore directory.
      const files = await readdir(this.keyStorePath);
      const keyFiles = files.filter(f => f.endsWith('.json'));
      
      const keys: StoredKey[] = [];
      for (const file of keyFiles) {
        const keyPath = join(this.keyStorePath, file);
        const keyData = await readFile(keyPath, 'utf-8');
        const key = JSON.parse(keyData);
        // Revive date fields for consistent downstream formatting and sorting.
        key.created = new Date(key.created);
        keys.push(key);
      }
      
      // Sort newest-first so the most recently created keys show up first in the UI.
      return keys.sort((a, b) => b.created.getTime() - a.created.getTime());
    } catch (error) {
      // If the directory is missing/unreadable, treat as empty keystore.
      return [];
    }
  }

  async deleteKey(fingerprint: string): Promise<boolean> {
    try {
      const keyPath = this.getKeyPath(fingerprint);
      await unlink(keyPath);
      return true;
    } catch (error) {
      // Return false rather than throwing, so the UI can present a friendly message.
      return false;
    }
  }

  async keyExists(fingerprint: string): Promise<boolean> {
    // Existence is defined as "we can successfully load it".
    const key = await this.getKey(fingerprint);
    return key !== null;
  }
}

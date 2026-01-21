import { join } from 'path';
import { readdir, readFile, writeFile } from 'fs/promises';
import type { NoteRecord, StoredNote } from './types';

/**
 * NoteStore persists "secure notes" to the filesystem.
 *
 * A note is stored as:
 * - metadata: id + created/updated timestamps
 * - encrypted payload: an armored PGP message string
 *
 * Important: NoteStore does *not* do any cryptography. It only stores and retrieves
 * encrypted blobs. The Menu + PGPOperations layers decide how to encrypt/decrypt.
 */
export class NoteStore {
  constructor(private vaultPath: string) {}

  private getNotePath(id: string): string {
    // Note IDs are generated UUIDs, so they are safe as file names.
    return join(this.vaultPath, `${id}.json`);
  }

  async saveNote(note: NoteRecord): Promise<void> {
    // Convert runtime-friendly `Date` objects into JSON-serializable strings.
    const stored: StoredNote = {
      id: note.id,
      created: note.created.toISOString(),
      updated: note.updated.toISOString(),
      encrypted: note.encrypted,
    };

    const notePath = this.getNotePath(note.id);
    // Pretty-print JSON for easier manual inspection/debugging.
    await writeFile(notePath, JSON.stringify(stored, null, 2), 'utf-8');
  }

  async getNote(id: string): Promise<NoteRecord | null> {
    try {
      const notePath = this.getNotePath(id);
      const data = await readFile(notePath, 'utf-8');
      const parsed = JSON.parse(data) as StoredNote;
      // Revive date strings back into `Date` objects for sorting/formatting in the UI.
      return {
        id: parsed.id,
        created: new Date(parsed.created),
        updated: new Date(parsed.updated),
        encrypted: parsed.encrypted,
      };
    } catch {
      // Missing file, invalid JSON, etc. are treated as "not found".
      return null;
    }
  }

  async listNotes(): Promise<NoteRecord[]> {
    try {
      // Enumerate JSON note records from the vault directory.
      const files = await readdir(this.vaultPath);
      const noteFiles = files.filter((file) => file.endsWith('.json'));
      const notes: NoteRecord[] = [];

      for (const file of noteFiles) {
        try {
          const data = await readFile(join(this.vaultPath, file), 'utf-8');
          const parsed = JSON.parse(data) as StoredNote;
          notes.push({
            id: parsed.id,
            created: new Date(parsed.created),
            updated: new Date(parsed.updated),
            encrypted: parsed.encrypted,
          });
        } catch {
          // Skip unreadable entries.
        }
      }

      // Show most recently updated notes first.
      return notes.sort((a, b) => b.updated.getTime() - a.updated.getTime());
    } catch {
      // If the directory is missing/unreadable, treat as no notes.
      return [];
    }
  }
}

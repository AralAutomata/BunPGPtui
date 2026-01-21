import { join } from 'path';
import { homedir } from 'os';
import type { Config } from './types';

/**
 * Compute the application configuration.
 *
 * This app follows the common XDG-style layout on Linux/macOS by using:
 *   ~/.config/tui-pgp/
 *
 * We keep configuration intentionally simple: paths + a default algorithm.
 * There is no config file; paths are derived from the current user's home directory.
 */
export const getConfig = (): Config => {
  // `homedir()` resolves the OS user home (e.g. /home/alice or /Users/alice).
  const homeDir = homedir();

  // Base config directory for the app.
  const configDir = join(homeDir, '.config', 'tui-pgp');

  // Keys are stored as JSON files by fingerprint under `keys/`.
  const keyStorePath = join(configDir, 'keys');

  // "Vault" is the directory for encrypted note records (also JSON files).
  const vaultPath = join(configDir, 'vault');

  return {
    keyStorePath,
    defaultAlgorithm: 'rsa4096',
    vaultPath,
  };
};

/**
 * Ensure the app's on-disk directories exist.
 *
 * Why this exists:
 * - `KeyStore` and `NoteStore` assume their directories exist.
 * - Creating them up-front means later operations can focus on their core logic
 *   without handling "missing directory" everywhere.
 */
export const ensureConfigDirs = async (config: Config): Promise<void> => {
  // Dynamic import keeps startup lightweight and avoids creating a hard dependency
  // on node/bun FS types in the module graph until needed.
  const fs = await import('fs/promises');
  
  try {
    // `recursive: true` makes this idempotent: it does nothing if the folder exists.
    await fs.mkdir(config.keyStorePath, { recursive: true });
    await fs.mkdir(config.vaultPath, { recursive: true });
  } catch (error) {
    // At this point we can't reasonably continue: persistence would fail everywhere.
    console.error('Failed to create configuration directories:', error);
    throw error;
  }
};

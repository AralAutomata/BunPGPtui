#!/usr/bin/env bun
/**
 * Application entry point.
 *
 * This file is intentionally small: it wires together configuration + persistence
 * (KeyStore/NoteStore) + crypto operations (PGPOperations) + the interactive UI (Menu).
 *
 * The rest of the codebase is organized so that:
 * - `Menu` contains user interaction flows (prompts, printing, choosing actions).
 * - `KeyStore` and `NoteStore` are thin filesystem persistence layers.
 * - `PGPOperations` is a wrapper around OpenPGP.js providing a small, app-friendly API.
 */
import { getConfig, ensureConfigDirs } from './config';
import { KeyStore } from './keyStore';
import { NoteStore } from './noteStore';
import { PGPOperations } from './pgpOperations';
import { Menu } from './menu';
import { displayError } from './uiUtils';

async function main() {
  try {
    // Resolve OS-specific config locations (e.g. ~/.config/tui-pgp/...) and defaults.
    const config = getConfig();

    // Ensure the on-disk folders exist before we do anything that reads/writes keys/notes.
    await ensureConfigDirs(config);

    // Persistence layers: these read/write JSON files under the configured directories.
    const keyStore = new KeyStore(config.keyStorePath);
    const noteStore = new NoteStore(config.vaultPath);

    // Stateless crypto helper: wraps OpenPGP.js calls for keygen/encrypt/decrypt/sign/verify.
    const pgp = new PGPOperations();

    // UI controller: orchestrates prompts and uses the stores + crypto helper to do work.
    const menu = new Menu(keyStore, noteStore, pgp);

    // Hand over control to the interactive loop.
    await menu.show();
  } catch (error) {
    // Anything thrown at the top-level is treated as fatal and terminates the process.
    displayError(`Fatal error: ${error instanceof Error ? error.message : 'Unknown error'}`);
    process.exit(1);
  }
}

// Kick off the program. Because we are in an ESM module, top-level await is possible,
// but we keep an explicit `main()` for clarity and centralized error handling.
main();

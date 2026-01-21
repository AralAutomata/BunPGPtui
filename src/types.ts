/**
 * Central type definitions for the app.
 *
 * These types serve two purposes:
 * 1) Document the shape of the data passed between the UI, persistence layers, and crypto wrapper.
 * 2) Provide strong typing over OpenPGP.js inputs/outputs (especially around streaming file APIs).
 */
export interface KeyPair {
  /** ASCII-armored public key (shareable). */
  publicKey: string;
  /** ASCII-armored private key (passphrase-protected by OpenPGP.js). */
  privateKey: string;
  /** Full fingerprint of the public key; used as stable identifier. */
  fingerprint: string;
  /** Key ID (shorter identifier derived from the key). */
  keyId: string;
  /** Human-readable user ID, typically "Name <email>". */
  userId: string;
  /** Creation timestamp for display/sorting (stored as ISO when persisted). */
  created: Date;
  /** Algorithm label used for display (e.g. rsa4096, ecc). */
  algorithm: string;
}

export interface StoredKey {
  /** Display name parsed from the user ID. */
  name: string;
  /** Display email parsed from the user ID (may be empty for imported keys). */
  email: string;
  fingerprint: string;
  keyId: string;
  publicKey: string;
  /**
   * Optional private key armor. Imported keys are public-only; generated keys have both.
   * Stored as passphrase-protected armor.
   */
  privateKey?: string;
  created: Date;
  algorithm: string;
}

export interface EncryptOptions {
  /** Plaintext to encrypt (for message mode). */
  message: string;
  /** Recipient public keys (armored); message will be decryptable by any recipient. */
  publicKeys: string[];
  /** If true, include a signature in the encrypted message. */
  sign?: boolean;
  /** Private key used for signing (armored). */
  privateKey?: string;
  /** Passphrase to unlock the signing private key. */
  passphrase?: string;
}

export interface DecryptOptions {
  /** Armored encrypted message to decrypt. */
  message: string;
  /** Recipient private key (armored). */
  privateKey: string;
  /** Passphrase for the private key (if required). */
  passphrase?: string;
  /** If true, attempt to verify a signature (if present). */
  verifySignature?: boolean;
  /** Candidate public keys used for signature verification. */
  publicKeys?: string[];
}

export interface SignOptions {
  /** Plaintext to sign. */
  message: string;
  /** Signing private key (armored). */
  privateKey: string;
  /** Passphrase for the private key (if required). */
  passphrase?: string;
  /** If true, produce a detached signature rather than a clearsigned message. */
  detached?: boolean;
}

export interface VerifyOptions {
  /**
   * Signed message to verify.
   * Note: the current UI passes the same string for `message` and `signature` to OpenPGP.js,
   * because OpenPGP.js can parse clearsigned messages directly via `readMessage`.
   */
  message: string;
  signature: string;
  /** Candidate public keys to verify against. */
  publicKeys: string[];
}

/** Supported key generation algorithms exposed in the UI. */
export type KeyAlgorithm = 'rsa2048' | 'rsa4096' | 'ecc';

/** Output format for file/folder encryption. */
export type PgpOutputFormat = 'armored' | 'binary';

/**
 * OpenPGP.js returns different types depending on format + environment:
 * - For `armored`, it may return a string or a ReadableStream<string>.
 * - For `binary`, it may return Uint8Array or ReadableStream<Uint8Array>.
 *
 * We normalize downstream handling by treating these as a union.
 */
export type FileEncryptResult =
  | ReadableStream<Uint8Array>
  | ReadableStream<string>
  | Uint8Array
  | string;

export interface FileEncryptOptions {
  /** Input bytes stream for the file contents. */
  input: ReadableStream<Uint8Array>;
  /** Recipient public keys (armored). */
  publicKeys: string[];
  /** Whether output should be armored text or binary bytes. */
  format: PgpOutputFormat;
  /** If true, include a signature in the encrypted output. */
  sign?: boolean;
  /** Private key used for signing (armored). */
  privateKey?: string;
  /** Passphrase to unlock the signing private key. */
  passphrase?: string;
  /** Original filename to embed in the PGP message metadata (optional). */
  filename?: string;
}

export interface FileDecryptOptions {
  /** Encrypted content stream (either bytes or text depending on input format). */
  input: ReadableStream<Uint8Array> | ReadableStream<string>;
  /** Declares whether `input` is armored text or binary bytes. */
  inputFormat: PgpOutputFormat;
  /** Recipient private key (armored). */
  privateKey: string;
  /** Passphrase for the private key (if required). */
  passphrase?: string;
  /** If true, verify signature if present. */
  verifySignature?: boolean;
  /** Candidate public keys used for signature verification. */
  publicKeys?: string[];
}

export interface FileDecryptResult {
  /** Decrypted bytes (streaming or buffered). */
  data: ReadableStream<Uint8Array> | Uint8Array;
  /** Signature verification outcome (only set when verification is requested and a signature exists). */
  verified?: boolean;
  /** Optional embedded filename carried in the PGP message. */
  filename?: string;
}

/** On-disk representation of a note (JSON-friendly strings). */
export interface StoredNote {
  id: string;
  created: string;
  updated: string;
  encrypted: string;
}

/** Runtime representation of a note (Date objects for sorting/formatting). */
export interface NoteRecord {
  id: string;
  created: Date;
  updated: Date;
  encrypted: string;
}

export interface Config {
  /** Directory where `KeyStore` stores `<fingerprint>.json` files. */
  keyStorePath: string;
  defaultAlgorithm: KeyAlgorithm;
  /** Directory where `NoteStore` stores `<uuid>.json` files. */
  vaultPath: string;
}

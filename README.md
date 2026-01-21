# TUI PGP Tool

![PrettyGood TUI](prettygoodtui.png)

A Terminal User Interface (TUI) for OpenPGP encryption, signing, and local key management, built with TypeScript and Bun.

This is an interactive, prompt-driven app (not a traditional flags-only CLI). It stores keys and encrypted “notes” on disk under your user config directory and uses `openpgp` (OpenPGP.js) for all cryptography.

## Table of Contents

- Features
- Quick start
- Installation
- Usage
  - Keys
  - Messages
  - Files
  - Folders
  - Secure notes
- Storage layout
- Data formats
- Interoperability
- Security considerations
- Troubleshooting
- Development
- Project structure
- Dependencies
- License

## Features

- 🔑 **Generate PGP Key Pairs** - RSA 2048/4096 or ECC Curve25519
- 🔒 **Encrypt Messages** - Encrypt for one or multiple recipients
- 🔓 **Decrypt Messages** - Decrypt with your private key
- ✍️ **Sign Messages** - Digitally sign your messages
- ✅ **Verify Signatures** - Verify signed messages
- 📄 **Encrypt/Decrypt Files** - Armored (`.asc`) or binary (`.pgp`) output
- 🗂️ **Encrypt/Decrypt Folders** - Batch process directories recursively with filters
- 📝 **Secure Notes Vault** - Save encrypted notes locally and decrypt on demand
- 📋 **Key Management** - List, view, import, export, and delete keys
- 💾 **Local Storage** - Keys/notes stored under `~/.config/tui-pgp/`
- 📋 **Clipboard Support** - Copy keys and messages to clipboard (macOS/Linux, via `pbcopy/pbpaste` or `xclip`)

## Prerequisites

- [Bun](https://bun.sh) runtime installed.

## Quick start

```bash
bun install
bun run dev
```

## Installation

### From source (recommended for development)

1. Clone the repository (or copy it locally):
```bash
git clone <your-repo-url>
cd tui-pgp
```

2. Install dependencies:
```bash
bun install
```

3. Run in development mode:
```bash
bun run dev
```

### Build and run

```bash
bun run build
bun run start
```

### Install as a command (`tui-pgp`)

This project defines a `bin` entry (`tui-pgp`) that points to the built output in `dist/`.

One common workflow:

```bash
bun run build
bun install -g .
tui-pgp
```

## Usage

Run the app and follow the interactive prompts:

```bash
bun run dev
```

If installed globally:

```bash
tui-pgp
```

### Keys

- **Generate new key pair**: Creates an RSA (2048/4096) or Curve25519 key pair with a passphrase-encrypted private key.
- **List all keys**: Shows all keys in your local keystore. A “private key available” indicator is shown per key.
- **View key details**: Displays fingerprint and key ID; can copy public/private key armor to clipboard (or prints it if clipboard is unavailable).
- **Import public key**: From clipboard, file, or manual paste. Imported keys are stored as “public-only”.
- **Export public key**: Copy to clipboard, save to a file, or both.
- **Delete key**: Removes the JSON entry from your keystore (public-only or both public+private).

Notes:
- Fingerprints are used as the on-disk identifier.
- The keystore is local to this app; it does not integrate with `gpg`’s keyring.

### Messages

- **Encrypt message**: Select one or more recipients (public keys). Optional signing is supported if you have a private key and provide its passphrase.
- **Decrypt message**: Decrypts an armored PGP message using a selected private key and passphrase. Input can come from clipboard or a file path.
- **Sign message**: Creates an armored signed message using a selected private key.
- **Verify signature**: Verifies an armored signed message using all public keys currently in your keystore.

### Files

- **Encrypt file**:
  - Choose recipients, pick output format:
    - `armored` → ASCII armored output (commonly saved as `.asc`)
    - `binary` → binary output (commonly saved as `.pgp`)
  - Optional signing uses your selected private key + passphrase.
  - The original filename is embedded in the PGP message (when supported by the format).
- **Decrypt file**:
  - Choose your private key and provide passphrase.
  - Select input format (armored vs binary) and output path.
  - Can optionally verify signatures during decryption using all known public keys.

### Folders

- **Encrypt folder**:
  - Recursively walks the input directory.
  - Optional extension filter (e.g. `.pdf,.txt`) to limit which files are processed.
  - Writes output to a new directory (default: `<input>-encrypted`) while preserving relative paths.
  - Output files get an added extension based on format (`.asc` or `.pgp`).
  - Supports overwrite/skip/abort policies if output files already exist.
- **Decrypt folder**:
  - Recursively walks the input directory and decrypts matching files.
  - Auto-detects format by extension (`.asc`→armored, `.pgp/.gpg`→binary) or lets you force a mode.
  - Writes output to a new directory (default: `<input>-decrypted`) while preserving relative paths.
  - Strips `.asc/.pgp/.gpg` from filenames; if a file has an unexpected extension, a `.decrypted` suffix is used.
  - Optional signature verification flags failures separately from decryption failures.

### Secure notes

- **Create secure note**: Prompts for a title and body, encrypts the JSON payload to a selected key’s public key, and stores it in the vault.
- **List notes**: Lists note IDs and timestamps.
- **View note**: Decrypts a note using a selected private key and passphrase, then displays title/body if the decrypted payload is JSON.

Secure notes are just encrypted payloads stored locally; there is no syncing or sharing layer built in.

## Key Storage

Keys are stored in `~/.config/tui-pgp/keys/`.

Each key is saved as a JSON file named by its fingerprint (e.g. `<fingerprint>.json`). Public keys are stored as ASCII-armored text. Private keys are stored as ASCII-armored text that is encrypted with your passphrase by OpenPGP.js (the passphrase itself is never stored).

## Notes Storage

Encrypted notes are stored in `~/.config/tui-pgp/vault/` as JSON files keyed by a random UUID.

## Storage layout

```
~/.config/tui-pgp/
├── keys/
│   └── <fingerprint>.json
└── vault/
    └── <note-id>.json
```

Backup/restore is as simple as copying that directory, but treat it as sensitive data.

## Data formats

### Key JSON

Each key is stored as JSON. Dates are persisted as strings and parsed back into `Date` objects at runtime.

Example shape:

```json
{
  "name": "Alice",
  "email": "alice@example.com",
  "fingerprint": "abcd1234...",
  "keyId": "deadbeef...",
  "publicKey": "-----BEGIN PGP PUBLIC KEY BLOCK-----\n...\n-----END PGP PUBLIC KEY BLOCK-----",
  "privateKey": "-----BEGIN PGP PRIVATE KEY BLOCK-----\n...\n-----END PGP PRIVATE KEY BLOCK-----",
  "created": "2026-01-21T12:34:56.789Z",
  "algorithm": "rsa4096"
}
```

Notes:
- Imported public keys omit `privateKey`.
- `privateKey` is passphrase-protected armor (your passphrase is not stored).

### Note JSON

Notes are stored as an ID plus timestamps and an armored encrypted payload:

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "created": "2026-01-21T12:34:56.789Z",
  "updated": "2026-01-21T12:34:56.789Z",
  "encrypted": "-----BEGIN PGP MESSAGE-----\n...\n-----END PGP MESSAGE-----"
}
```

The decrypted payload is usually a JSON object with `title`, `body`, `created`, and `updated`.

## Interoperability

- **With GnuPG / other OpenPGP tools**: Use **Export public key** to write an armored `.asc` file and import it elsewhere. Likewise, you can **Import public key** from an armored block exported by another tool.
- **Private keys**: This app stores passphrase-protected private key armor inside JSON files. If you need to move a private key to another tool, you can copy it from **View key details** (clipboard or terminal output) and import it there. Test interoperability carefully in your environment.

## Security considerations

This is a convenience tool and is not a security-audited product. Use it with appropriate caution.

- Use strong passphrases (minimum 8 characters is enforced; longer is better).
- Private keys are passphrase-encrypted, but the encrypted private key material is still sensitive (offline guessing is possible if an attacker gets the files).
- Clipboard contents may be readable by other processes; avoid copying secrets on shared systems.
- Avoid leaving decrypted plaintext in terminal scrollback or shell logs (e.g. if you redirect output).
- Prefer full-disk encryption and proper OS account hygiene to protect files under `~/.config/tui-pgp/`.
- Verify fingerprints out-of-band when importing keys.

## Project Structure

```
tui-pgp/
├── src/
│   ├── index.ts          # Main entry point
│   ├── menu.ts           # Interactive menu system
│   ├── pgpOperations.ts  # PGP cryptographic operations
│   ├── keyStore.ts       # Key storage management
│   ├── noteStore.ts      # Encrypted notes storage
│   ├── config.ts         # Configuration management
│   ├── uiUtils.ts        # UI helper functions
│   └── types.ts          # TypeScript type definitions
├── package.json
├── tsconfig.json
└── readme.md
```

## Dependencies

- **@clack/prompts** - Beautiful TUI prompts
- **chalk** - Terminal string styling
- **openpgp** - OpenPGP implementation
- **commander** - Included in dependencies but not currently used (reserved for future non-interactive CLI modes)

## Development

Run with auto-reload:
```bash
bun run dev
```

Type checking:
```bash
bun run type-check
```

Build for production:
```bash
bun run build
```

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Troubleshooting

### Clipboard not working
- **macOS**: Uses `pbcopy` (built-in)
- **Linux**: Requires `xclip` - install with `sudo apt-get install xclip`

### Keys not persisting
Check that `~/.config/tui-pgp/keys/` exists and has proper permissions. The app attempts to create `~/.config/tui-pgp/keys/` and `~/.config/tui-pgp/vault/` automatically on startup.

### Decryption fails
- Ensure you’re entering the correct passphrase used when generating the key.
- If you see an error like “Misformed armored text”, make sure you copied the entire armored block including the `BEGIN/END` lines and didn’t add extra whitespace.

### Signature verification fails
- A signature failure means decryption may still succeed, but the decrypted content could not be verified against any public key in your keystore.
- Make sure you have imported the signer’s public key and that you are verifying the exact signed message output.

import * as clack from '@clack/prompts';
import chalk from 'chalk';
import { mkdir, readFile, readdir, stat, writeFile } from 'fs/promises';
import { homedir } from 'os';
import { basename, dirname, extname, join, relative, resolve, sep } from 'path';
import { KeyStore } from './keyStore';
import { NoteStore } from './noteStore';
import { PGPOperations } from './pgpOperations';
import type { KeyAlgorithm, StoredKey } from './types';
import {
  displayHeader,
  displaySuccess,
  displayError,
  displayInfo,
  displayWarning,
  displayKeyInfo,
  formatFingerprint,
  copyToClipboard,
  readFromClipboard,
} from './uiUtils';

/**
 * Menu is the "controller" of the application.
 *
 * It owns the interactive loop and translates user intent (selections + inputs)
 * into calls to:
 * - `KeyStore` (persist keys)
 * - `NoteStore` (persist encrypted notes)
 * - `PGPOperations` (crypto: keygen, encrypt/decrypt, sign/verify)
 *
 * Most methods follow the same high-level pattern:
 * 1) Prompt user for required inputs (and allow cancellation at any point).
 * 2) Validate inputs early so OpenPGP.js errors are less confusing.
 * 3) Do the operation (often with a spinner).
 * 4) Present results and offer optional clipboard/file outputs.
 *
 * This file is intentionally UI-heavy; the non-UI logic is pushed into helper methods
 * at the bottom (path resolution, folder walking, stream/file writing, validation).
 */
export class Menu {
  constructor(
    private keyStore: KeyStore,
    private noteStore: NoteStore,
    private pgp: PGPOperations
  ) {}

  async show(): Promise<void> {
    // The main loop keeps the app "alive" until the user chooses Exit or cancels.
    let running = true;

    while (running) {
      // Clear and redraw the header each loop to keep the UI tidy.
      displayHeader();

      // Present the top-level actions as a select list.
      const action = await clack.select({
        message: 'What would you like to do?',
        options: [
          { value: 'generate', label: '🔑 Generate new key pair' },
          { value: 'list', label: '📋 List all keys' },
          { value: 'view', label: '👁️  View key details' },
          { value: 'encrypt', label: '🔒 Encrypt message' },
          { value: 'decrypt', label: '🔓 Decrypt message' },
          { value: 'encrypt-file', label: '📁 Encrypt file' },
          { value: 'decrypt-file', label: '📂 Decrypt file' },
          { value: 'encrypt-folder', label: '🗂️  Encrypt folder' },
          { value: 'decrypt-folder', label: '🗃️  Decrypt folder' },
          { value: 'sign', label: '✍️  Sign message' },
          { value: 'verify', label: '✅ Verify signature' },
          { value: 'note-create', label: '📝 Create secure note' },
          { value: 'note-list', label: '📚 List notes' },
          { value: 'note-view', label: '🔍 View note' },
          { value: 'import', label: '📥 Import public key' },
          { value: 'export', label: '📤 Export public key' },
          { value: 'delete', label: '🗑️  Delete key' },
          { value: 'exit', label: '👋 Exit' },
        ],
      });

      // clack returns a special "cancel" sentinel when the user hits Esc/Ctrl+C.
      if (clack.isCancel(action) || action === 'exit') {
        running = false;
        clack.outro(chalk.cyan('Thanks for using TUI PGP! 👋'));
        continue;
      }

      // Dispatch to the chosen workflow.
      switch (action) {
        case 'generate':
          await this.generateKey();
          break;
        case 'list':
          await this.listKeys();
          break;
        case 'view':
          await this.viewKey();
          break;
        case 'encrypt':
          await this.encryptMessage();
          break;
        case 'decrypt':
          await this.decryptMessage();
          break;
        case 'encrypt-file':
          await this.encryptFile();
          break;
        case 'decrypt-file':
          await this.decryptFile();
          break;
        case 'encrypt-folder':
          await this.encryptFolder();
          break;
        case 'decrypt-folder':
          await this.decryptFolder();
          break;
        case 'sign':
          await this.signMessage();
          break;
        case 'verify':
          await this.verifySignature();
          break;
        case 'note-create':
          await this.createNote();
          break;
        case 'note-list':
          await this.listNotes();
          break;
        case 'note-view':
          await this.viewNote();
          break;
        case 'import':
          await this.importPublicKey();
          break;
        case 'export':
          await this.exportPublicKey();
          break;
        case 'delete':
          await this.deleteKey();
          break;
      }

      if (running) {
        // A simple pause so results don't flash away immediately when the menu redraws.
        await clack.text({
          message: 'Press Enter to continue...',
          placeholder: '',
        });
      }
    }
  }

  private async generateKey(): Promise<void> {
    clack.intro(chalk.bold('Generate New Key Pair'));

    // Collect identity fields that become the OpenPGP user ID.
    const name = await clack.text({
      message: 'Enter your name:',
      placeholder: 'John Doe',
      validate: (value) => {
        if (!value) return 'Name is required';
      },
    });

    if (clack.isCancel(name)) return;

    const email = await clack.text({
      message: 'Enter your email:',
      placeholder: 'john@example.com',
      validate: (value) => {
        if (!value) return 'Email is required';
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) return 'Invalid email format';
      },
    });

    if (clack.isCancel(email)) return;

    // Offer a small set of secure defaults and tradeoffs (RSA strength vs speed, ECC modern).
    const algorithm = await clack.select({
      message: 'Select algorithm:',
      options: [
        { value: 'rsa4096', label: 'RSA 4096 (Recommended)' },
        { value: 'rsa2048', label: 'RSA 2048 (Faster)' },
        { value: 'ecc', label: 'ECC Curve25519 (Modern)' },
      ],
    }) as KeyAlgorithm;

    if (clack.isCancel(algorithm)) return;

    // The passphrase encrypts the private key material (the passphrase itself is never stored).
    const passphrase = await clack.password({
      message: 'Enter passphrase for private key:',
      validate: (value) => {
        if (!value) return 'Passphrase is required';
        if (value.length < 8) return 'Passphrase must be at least 8 characters';
      },
    });

    if (clack.isCancel(passphrase)) return;

    const spinner = clack.spinner();
    spinner.start('Generating key pair...');

    try {
      // Crypto work happens in PGPOperations; it returns armored keys + fingerprint + key ID.
      const keyPair = await this.pgp.generateKeyPair(name, email, passphrase, algorithm);

      // Persist the result into the local keystore.
      const storedKey: StoredKey = {
        name,
        email,
        fingerprint: keyPair.fingerprint,
        keyId: keyPair.keyId,
        publicKey: keyPair.publicKey,
        privateKey: keyPair.privateKey,
        created: keyPair.created,
        algorithm: keyPair.algorithm,
      };

      await this.keyStore.saveKey(storedKey);

      spinner.stop('Key pair generated successfully! ✅');

      // Show a friendly summary (fingerprint, ID, algorithm, timestamps).
      displayKeyInfo({
        name,
        email,
        fingerprint: keyPair.fingerprint,
        keyId: keyPair.keyId,
        created: keyPair.created,
        algorithm: keyPair.algorithm,
      });

      displaySuccess('Your key pair has been saved securely.');
    } catch (error) {
      spinner.stop('Failed to generate key pair');
      displayError(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private async listKeys(): Promise<void> {
    clack.intro(chalk.bold('Your PGP Keys'));

    // Read the complete keystore and display each entry. (No pagination for now.)
    const keys = await this.keyStore.listKeys();

    if (keys.length === 0) {
      displayInfo('No keys found. Generate a new key pair to get started.');
      return;
    }

    console.log(chalk.dim('─'.repeat(80)));
    for (const key of keys) {
      // A simple indicator: green dot means private key is present (can decrypt/sign).
      const hasPrivateKey = key.privateKey ? chalk.green('●') : chalk.red('○');
      console.log(
        `${hasPrivateKey} ${chalk.bold(key.name)} ${chalk.dim('<' + key.email + '>')}`
      );
      console.log(`  ${chalk.dim('Key ID:')} ${chalk.yellow(key.keyId.toUpperCase())}`);
      console.log(`  ${chalk.dim('Fingerprint:')} ${chalk.cyan(formatFingerprint(key.fingerprint))}`);
      console.log(`  ${chalk.dim('Created:')} ${key.created.toLocaleDateString()}`);
      console.log(chalk.dim('─'.repeat(80)));
    }

    console.log(
      `\n${chalk.green('●')} = Private key available | ${chalk.red('○')} = Public key only\n`
    );
  }

  private async viewKey(): Promise<void> {
    // Viewing key details starts by selecting an entry from the local keystore.
    const keys = await this.keyStore.listKeys();

    if (keys.length === 0) {
      displayError('No keys found.');
      return;
    }

    const selected = await clack.select({
      message: 'Select a key to view:',
      options: keys.map((key) => ({
        value: key.fingerprint,
        label: `${key.name} <${key.email}> [${key.keyId.substring(0, 8).toUpperCase()}]`,
      })),
    });

    if (clack.isCancel(selected)) return;

    const key = await this.keyStore.getKey(selected as string);
    if (!key) {
      displayError('Key not found.');
      return;
    }

    displayKeyInfo(key);

    const action = await clack.select({
      message: 'What would you like to do?',
      options: [
          { value: 'copy-public', label: 'Copy public key to clipboard' },
        ...(key.privateKey
          ? [{ value: 'copy-private', label: 'Copy private key to clipboard' }]
          : []),
        { value: 'back', label: 'Back to menu' },
      ],
    });

    if (clack.isCancel(action) || action === 'back') return;

    if (action === 'copy-public') {
      // Prefer copying to clipboard, but fall back to printing if clipboard isn't available.
      const success = await copyToClipboard(key.publicKey);
      if (success) {
        displaySuccess('Public key copied to clipboard!');
      } else {
        console.log('\n' + chalk.dim('─'.repeat(50)));
        console.log(key.publicKey);
        console.log(chalk.dim('─'.repeat(50)) + '\n');
      }
    } else if (action === 'copy-private' && key.privateKey) {
      // Private key material is sensitive; clipboard may expose it to other processes.
      const success = await copyToClipboard(key.privateKey);
      if (success) {
        displaySuccess('Private key copied to clipboard!');
      } else {
        console.log('\n' + chalk.dim('─'.repeat(50)));
        console.log(key.privateKey);
        console.log(chalk.dim('─'.repeat(50)) + '\n');
      }
    }
  }

  private async encryptMessage(): Promise<void> {
    clack.intro(chalk.bold('Encrypt Message'));

    const keys = await this.keyStore.listKeys();
    if (keys.length === 0) {
      displayError('No keys found. Import or generate a key first.');
      return;
    }

    // Recipients are chosen by fingerprint; later we map fingerprints to public key armor.
    const selectedKeys = await clack.multiselect({
      message: 'Select recipient(s):',
      options: keys.map((key) => ({
        value: key.fingerprint,
        label: `${key.name} <${key.email}>`,
      })),
      required: true,
    });

    if (clack.isCancel(selectedKeys)) return;

    // For message encryption, we encrypt a plaintext string.
    const message = await clack.text({
      message: 'Enter message to encrypt:',
      placeholder: 'Your secret message...',
      validate: (value) => {
        if (!value) return 'Message cannot be empty';
      },
    });

    if (clack.isCancel(message)) return;

    // Signing is optional: it proves the message was produced by the holder of a private key.
    const shouldSign = await clack.confirm({
      message: 'Sign the message?',
    });

    if (clack.isCancel(shouldSign)) return;

    let signingKey: StoredKey | undefined;
    let passphrase: string | undefined;

    if (shouldSign) {
      // Only keys with private material can sign.
      const keysWithPrivate = keys.filter((k) => k.privateKey);
      if (keysWithPrivate.length === 0) {
        displayError('No private keys available for signing.');
        return;
      }

      const selectedSigningKey = await clack.select({
        message: 'Select signing key:',
        options: keysWithPrivate.map((key) => ({
          value: key.fingerprint,
          label: `${key.name} <${key.email}>`,
        })),
      });

      if (clack.isCancel(selectedSigningKey)) return;

      const selectedKey = await this.keyStore.getKey(selectedSigningKey as string);
      if (!selectedKey || !selectedKey.privateKey) {
        displayError('Key not found or missing private key.');
        return;
      }
      signingKey = selectedKey;

      // We ask for the passphrase at the moment it's needed (not earlier).
      const passphraseInput = await clack.password({
        message: 'Enter passphrase for signing key:',
      });

      if (clack.isCancel(passphraseInput)) return;
      if (typeof passphraseInput !== 'string') return;
      passphrase = passphraseInput;
    }

    const spinner = clack.spinner();
    spinner.start('Encrypting message...');

    try {
      // Map selected fingerprints -> public key armor strings.
      const publicKeys = await Promise.all(
        (selectedKeys as string[]).map(async (fp) => {
          const key = await this.keyStore.getKey(fp);
          return key!.publicKey;
        })
      );

      // Perform the actual encryption (and optional signing) via OpenPGP.js wrapper.
      const encrypted = await this.pgp.encrypt({
        message,
        publicKeys,
        sign: shouldSign,
        privateKey: signingKey?.privateKey,
        passphrase,
      });

      spinner.stop('Message encrypted successfully! ✅');

      // Present the armored output so users can copy/share/save it.
      console.log('\n' + chalk.dim('─'.repeat(50)));
      console.log(chalk.dim('Encrypted message:'));
      console.log(encrypted);
      console.log(chalk.dim('─'.repeat(50)) + '\n');

      // Convenience: offer to copy the ciphertext to clipboard.
      const copyEncrypted = await clack.confirm({
        message: 'Copy encrypted message to clipboard?',
        initialValue: false,
      });

      if (!clack.isCancel(copyEncrypted) && copyEncrypted) {
        const copied = await copyToClipboard(encrypted);
        if (copied) {
          displaySuccess('Encrypted message copied to clipboard!');
        } else {
          displayWarning('Failed to copy encrypted message to clipboard.');
        }
      }
    } catch (error) {
      spinner.stop('Encryption failed');
      displayError(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private async decryptMessage(): Promise<void> {
    clack.intro(chalk.bold('Decrypt Message'));

    // Decryption requires a private key; public-only entries are filtered out.
    const keys = await this.keyStore.listKeys();
    const keysWithPrivate = keys.filter((k) => k.privateKey);

    if (keysWithPrivate.length === 0) {
      displayError('No private keys available for decryption.');
      return;
    }

    const selectedKey = await clack.select({
      message: 'Select your key:',
      options: keysWithPrivate.map((key) => ({
        value: key.fingerprint,
        label: `${key.name} <${key.email}>`,
      })),
    });

    if (clack.isCancel(selectedKey)) return;

    const key = await this.keyStore.getKey(selectedKey as string);
    if (!key || !key.privateKey) {
      displayError('Key not found or missing private key.');
      return;
    }

    // Support multiple input sources to reduce copy/paste friction.
    const inputSource = await clack.select({
      message: 'Select encrypted message source:',
      options: [
        { value: 'clipboard', label: 'Clipboard' },
        { value: 'file', label: 'File' },
      ],
    });

    if (clack.isCancel(inputSource)) return;

    let encryptedMessage: string | null = null;
    const showClipboardMessage = inputSource === 'clipboard';
    const showFileMessage = inputSource === 'file';
    if (inputSource === 'clipboard') {
      // Clipboard may be unavailable; we treat that as an error, not as empty message.
      encryptedMessage = await readFromClipboard();
      if (!encryptedMessage) {
        displayError('Clipboard is empty or unavailable.');
        return;
      }
    } else if (inputSource === 'file') {
      const pathInput = await clack.text({
        message: 'Enter path to file containing the encrypted message:',
        placeholder: './message.asc',
        validate: (value) => {
          if (!value) return 'File path is required';
        },
      });

      if (clack.isCancel(pathInput)) return;
      if (typeof pathInput !== 'string') return;

      const filePath = this.resolveInputPath(pathInput.trim());
      try {
        // File input enables decryption of previously saved `.asc` text blobs.
        encryptedMessage = await readFile(filePath, 'utf-8');
      } catch (error) {
        const errorMsg = error instanceof Error ? error.message : 'Unknown error';
        displayError(`Failed to read file: ${errorMsg}`);
        return;
      }
    }

    if (!encryptedMessage) {
      displayError('No encrypted message provided.');
      return;
    }

    // Sanitize the input: trim and normalize line endings to what OpenPGP.js expects.
    const sanitizedMessage = encryptedMessage.trim().replace(/\r\n/g, '\n');
    const validationError = this.validateArmoredMessage(sanitizedMessage);
    if (validationError) {
      displayError(validationError);
      return;
    }

    if (showClipboardMessage || showFileMessage) {
      const sourceLabel = showClipboardMessage ? 'clipboard' : 'file';
      console.log('\n' + chalk.dim('─'.repeat(50)));
      console.log(chalk.dim(`Encrypted message from ${sourceLabel}:`));
      console.log(sanitizedMessage);
      console.log(chalk.dim('─'.repeat(50)) + '\n');
    }

    const passphrase = await clack.password({
      message: 'Enter passphrase:',
    });

    if (clack.isCancel(passphrase)) return;

    const spinner = clack.spinner();
    spinner.start('Decrypting message...');

    try {
      /**
       * Decrypt the message and (optionally) verify a signature.
       *
       * For signature verification we pass every known public key as a candidate; if the
       * message was signed by a key we have, OpenPGP.js can validate it.
       */
      const result = await this.pgp.decrypt({
        message: sanitizedMessage,
        privateKey: key.privateKey,
        passphrase,
        verifySignature: true,
        publicKeys: keys.map((k) => k.publicKey),
      });

      spinner.stop('Message decrypted successfully! ✅');

      console.log('\n' + chalk.dim('─'.repeat(50)));
      console.log(chalk.bold('Decrypted message:'));
      console.log(chalk.white(result.data));
      console.log(chalk.dim('─'.repeat(50)));

      // `verified` is only defined if the decrypted message had signatures attached.
      if (result.verified !== undefined) {
        if (result.verified) {
          displaySuccess('✅ Signature verified successfully!');
        } else {
          displayError('❌ Signature verification failed!');
        }
      }
      console.log();

      // Convenience: allow copying plaintext back to clipboard.
      const copyDecrypted = await clack.confirm({
        message: 'Copy decrypted message to clipboard?',
        initialValue: false,
      });

      if (!clack.isCancel(copyDecrypted) && copyDecrypted) {
        const copied = await copyToClipboard(result.data);
        if (copied) {
          displaySuccess('Decrypted message copied to clipboard!');
        } else {
          displayWarning('Failed to copy decrypted message to clipboard.');
        }
      }
    } catch (error) {
      spinner.stop('Decryption failed');
      const errorMsg = error instanceof Error ? error.message : 'Unknown error';
      displayError(`Error: ${errorMsg}`);
      
      // Some OpenPGP.js errors are cryptic; provide targeted hints for common cases.
      if (errorMsg.includes('Misformed armored text')) {
        console.log(chalk.yellow('\nTroubleshooting tips:'));
        console.log(chalk.dim('• Make sure the entire message is copied (including BEGIN/END lines)'));
        console.log(chalk.dim('• Check for extra spaces or line breaks'));
        console.log(chalk.dim('• Verify you\'re using the correct recipient key'));
        console.log(chalk.dim('• Try copying the message again\n'));
      } else if (errorMsg.includes('passphrase') || errorMsg.includes('decrypt')) {
        console.log(chalk.yellow('\n• Check if you entered the correct passphrase\n'));
      }
    }
  }

  private async encryptFile(): Promise<void> {
    clack.intro(chalk.bold('Encrypt File'));

    const keys = await this.keyStore.listKeys();
    if (keys.length === 0) {
      displayError('No keys found. Import or generate a key first.');
      return;
    }

    // Choose recipients for file encryption.
    const selectedKeys = await clack.multiselect({
      message: 'Select recipient(s):',
      options: keys.map((key) => ({
        value: key.fingerprint,
        label: `${key.name} <${key.email}>`,
      })),
      required: true,
    });

    if (clack.isCancel(selectedKeys)) return;

    const inputPathInput = await clack.text({
      message: 'Enter path to file to encrypt:',
      placeholder: './secret.txt',
      validate: (value) => {
        if (!value) return 'File path is required';
      },
    });

    if (clack.isCancel(inputPathInput)) return;
    if (typeof inputPathInput !== 'string') return;

    const inputPath = this.resolveInputPath(inputPathInput.trim());
    const inputFile = Bun.file(inputPath);
    if (!(await inputFile.exists())) {
      displayError('File not found.');
      return;
    }

    // Armored is text-friendly; binary is smaller and more "native" for file handling.
    const outputFormat = (await clack.select({
      message: 'Select output format:',
      options: [
        { value: 'armored', label: 'ASCII armored (.asc)' },
        { value: 'binary', label: 'Binary (.pgp)' },
      ],
    })) as 'armored' | 'binary';

    if (clack.isCancel(outputFormat)) return;

    const defaultOutputPath = `${inputPath}.${outputFormat === 'armored' ? 'asc' : 'pgp'}`;
    const outputPathInput = await clack.text({
      message: 'Enter output file path:',
      placeholder: defaultOutputPath,
    });

    if (clack.isCancel(outputPathInput)) return;
    if (typeof outputPathInput !== 'string') return;

    const outputPath = this.resolveInputPath(
      outputPathInput.trim() || defaultOutputPath
    );

    // Signing is optional for files as well; it provides authenticity/integrity.
    const shouldSign = await clack.confirm({
      message: 'Sign the file?',
    });

    if (clack.isCancel(shouldSign)) return;

    let signingKey: StoredKey | undefined;
    let passphrase: string | undefined;

    if (shouldSign) {
      const keysWithPrivate = keys.filter((k) => k.privateKey);
      if (keysWithPrivate.length === 0) {
        displayError('No private keys available for signing.');
        return;
      }

      const selectedSigningKey = await clack.select({
        message: 'Select signing key:',
        options: keysWithPrivate.map((key) => ({
          value: key.fingerprint,
          label: `${key.name} <${key.email}>`,
        })),
      });

      if (clack.isCancel(selectedSigningKey)) return;

      const selectedKey = await this.keyStore.getKey(selectedSigningKey as string);
      if (!selectedKey || !selectedKey.privateKey) {
        displayError('Key not found or missing private key.');
        return;
      }
      signingKey = selectedKey;

      const passphraseInput = await clack.password({
        message: 'Enter passphrase for signing key:',
      });

      if (clack.isCancel(passphraseInput)) return;
      if (typeof passphraseInput !== 'string') return;
      passphrase = passphraseInput;
    }

    const spinner = clack.spinner();
    spinner.start('Encrypting file...');

    try {
      // Load recipient public keys.
      const publicKeys = await Promise.all(
        (selectedKeys as string[]).map(async (fp) => {
          const key = await this.keyStore.getKey(fp);
          return key!.publicKey;
        })
      );

      /**
       * Encrypt the file as a stream.
       *
       * `Bun.file(...).stream()` returns a ReadableStream<Uint8Array>. OpenPGP.js can
       * consume that and produce either a stream or a buffered output depending on format.
       */
      const encrypted = await this.pgp.encryptFile({
        input: inputFile.stream(),
        publicKeys,
        sign: shouldSign,
        privateKey: signingKey?.privateKey,
        passphrase,
        format: outputFormat,
        // Embed original filename metadata (helpful when decrypting).
        filename: basename(inputPath),
      });

      // Write out encrypted content, supporting strings/bytes/streams.
      await this.writeOutputToFile(encrypted, outputPath, outputFormat);
      spinner.stop('File encrypted successfully! ✅');
      displaySuccess(`Encrypted file saved to ${outputPath}`);
    } catch (error) {
      spinner.stop('Encryption failed');
      displayError(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private async decryptFile(): Promise<void> {
    clack.intro(chalk.bold('Decrypt File'));

    const keys = await this.keyStore.listKeys();
    const keysWithPrivate = keys.filter((k) => k.privateKey);

    if (keysWithPrivate.length === 0) {
      displayError('No private keys available for decryption.');
      return;
    }

    const selectedKey = await clack.select({
      message: 'Select your key:',
      options: keysWithPrivate.map((key) => ({
        value: key.fingerprint,
        label: `${key.name} <${key.email}>`,
      })),
    });

    if (clack.isCancel(selectedKey)) return;

    const key = await this.keyStore.getKey(selectedKey as string);
    if (!key || !key.privateKey) {
      displayError('Key not found or missing private key.');
      return;
    }

    const inputPathInput = await clack.text({
      message: 'Enter path to encrypted file:',
      placeholder: './secret.pgp',
      validate: (value) => {
        if (!value) return 'File path is required';
      },
    });

    if (clack.isCancel(inputPathInput)) return;
    if (typeof inputPathInput !== 'string') return;

    const inputPath = this.resolveInputPath(inputPathInput.trim());
    const inputFile = Bun.file(inputPath);
    if (!(await inputFile.exists())) {
      displayError('File not found.');
      return;
    }

    // The app needs to know whether to treat input as armored text or raw bytes.
    const inputFormat = (await clack.select({
      message: 'Select input format:',
      options: [
        { value: 'armored', label: 'ASCII armored (.asc)' },
        { value: 'binary', label: 'Binary (.pgp/.gpg)' },
      ],
    })) as 'armored' | 'binary';

    if (clack.isCancel(inputFormat)) return;

    const defaultOutputPath = this.suggestDecryptedOutputPath(inputPath);
    const outputPathInput = await clack.text({
      message: 'Enter output file path:',
      placeholder: defaultOutputPath,
    });

    if (clack.isCancel(outputPathInput)) return;
    if (typeof outputPathInput !== 'string') return;

    const outputPath = this.resolveInputPath(
      outputPathInput.trim() || defaultOutputPath
    );

    const passphraseInput = await clack.password({
      message: 'Enter passphrase:',
    });

    if (clack.isCancel(passphraseInput)) return;
    if (typeof passphraseInput !== 'string') return;

    const spinner = clack.spinner();
    spinner.start('Decrypting file...');

    try {
      const encryptedStream = inputFile.stream();
      const messageStream =
        inputFormat === 'armored'
          ? encryptedStream.pipeThrough(new TextDecoderStream())
          : encryptedStream;

      /**
       * Decrypt and optionally verify signatures.
       *
       * - If `verifySignature` is true, we pass all known public keys as candidates.
       * - Output is always binary bytes (files), so we later write using `binary` mode.
       */
      const result = await this.pgp.decryptFile({
        input: messageStream,
        inputFormat,
        privateKey: key.privateKey,
        passphrase: passphraseInput,
        verifySignature: true,
        publicKeys: keys.map((k) => k.publicKey),
      });

      spinner.stop('File decrypted successfully! ✅');

      const writeSpinner = clack.spinner();
      writeSpinner.start('Writing decrypted file...');
      await this.writeOutputToFile(result.data, outputPath, 'binary');
      writeSpinner.stop('Decrypted file written successfully! ✅');
      displaySuccess(`Decrypted file saved to ${outputPath}`);

      // Show embedded filename metadata if present (useful for identifying content).
      if (result.filename && result.filename.trim()) {
        displayInfo(`Embedded filename: ${result.filename}`);
      }

      if (result.verified !== undefined) {
        if (result.verified) {
          displaySuccess('✅ Signature verified successfully!');
        } else {
          displayError('❌ Signature verification failed!');
        }
      }
    } catch (error) {
      spinner.stop('Decryption failed');
      displayError(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private async createNote(): Promise<void> {
    clack.intro(chalk.bold('Create Secure Note'));

    const keys = await this.keyStore.listKeys();
    const keysWithPrivate = keys.filter((k) => k.privateKey);

    if (keysWithPrivate.length === 0) {
      displayError('No private keys available to encrypt notes.');
      return;
    }

    /**
     * Notes are encrypted to a public key, but creating notes is currently restricted
     * to users who also have at least one private key (so they can decrypt later).
     *
     * You can think of notes as "self-encrypted blobs" stored in the vault directory.
     */
    const selectedKey = await clack.select({
      message: 'Select key to encrypt this note:',
      options: keysWithPrivate.map((key) => ({
        value: key.fingerprint,
        label: `${key.name} <${key.email}>`,
      })),
    });

    if (clack.isCancel(selectedKey)) return;

    const key = await this.keyStore.getKey(selectedKey as string);
    if (!key || !key.privateKey) {
      displayError('Key not found or missing private key.');
      return;
    }

    const titleInput = await clack.text({
      message: 'Enter note title:',
      placeholder: 'Private note',
      validate: (value) => {
        if (!value) return 'Title is required';
      },
    });

    if (clack.isCancel(titleInput)) return;
    if (typeof titleInput !== 'string') return;

    const bodyInput = await clack.text({
      message: 'Enter note body:',
      placeholder: 'Your secret note...',
      validate: (value) => {
        if (!value) return 'Body cannot be empty';
      },
    });

    if (clack.isCancel(bodyInput)) return;
    if (typeof bodyInput !== 'string') return;

    // Notes are stored as a JSON payload so we can display title/body/metadata on decrypt.
    const notePayload = {
      title: titleInput,
      body: bodyInput,
      created: new Date().toISOString(),
      updated: new Date().toISOString(),
    };

    const spinner = clack.spinner();
    spinner.start('Encrypting note...');

    try {
      // Encrypt the JSON payload to the selected key's public key.
      const encrypted = await this.pgp.encrypt({
        message: JSON.stringify(notePayload, null, 2),
        publicKeys: [key.publicKey],
      });

      // The note ID is a random UUID; the encrypted payload is stored under that filename.
      const noteId = crypto.randomUUID();
      const now = new Date();
      await this.noteStore.saveNote({
        id: noteId,
        created: now,
        updated: now,
        encrypted,
      });

      spinner.stop('Note saved successfully! ✅');
      displaySuccess(`Note ID: ${noteId}`);
    } catch (error) {
      spinner.stop('Failed to create note');
      displayError(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private async listNotes(): Promise<void> {
    clack.intro(chalk.bold('Secure Notes Vault'));

    // This only lists note metadata (IDs + timestamps); it never decrypts payloads.
    const notes = await this.noteStore.listNotes();
    if (notes.length === 0) {
      displayInfo('No notes found. Create one to get started.');
      return;
    }

    console.log(chalk.dim('─'.repeat(80)));
    for (const note of notes) {
      console.log(chalk.bold(`Note ID: ${note.id}`));
      console.log(
        `  ${chalk.dim('Created:')} ${note.created.toLocaleString()}`
      );
      console.log(
        `  ${chalk.dim('Updated:')} ${note.updated.toLocaleString()}`
      );
      console.log(chalk.dim('─'.repeat(80)));
    }
  }

  private async viewNote(): Promise<void> {
    clack.intro(chalk.bold('View Secure Note'));

    const notes = await this.noteStore.listNotes();
    if (notes.length === 0) {
      displayError('No notes found.');
      return;
    }

    // Choose which note (by ID) to decrypt.
    const selectedNote = await clack.select({
      message: 'Select a note to view:',
      options: notes.map((note) => ({
        value: note.id,
        label: `${note.id} (Updated: ${note.updated.toLocaleDateString()})`,
      })),
    });

    if (clack.isCancel(selectedNote)) return;

    const note = await this.noteStore.getNote(selectedNote as string);
    if (!note) {
      displayError('Note not found.');
      return;
    }

    const keys = await this.keyStore.listKeys();
    const keysWithPrivate = keys.filter((k) => k.privateKey);

    if (keysWithPrivate.length === 0) {
      displayError('No private keys available for decryption.');
      return;
    }

    // Ask which private key to use for decrypting this note.
    const selectedKey = await clack.select({
      message: 'Select key to decrypt this note:',
      options: keysWithPrivate.map((key) => ({
        value: key.fingerprint,
        label: `${key.name} <${key.email}>`,
      })),
    });

    if (clack.isCancel(selectedKey)) return;

    const key = await this.keyStore.getKey(selectedKey as string);
    if (!key || !key.privateKey) {
      displayError('Key not found or missing private key.');
      return;
    }

    const passphraseInput = await clack.password({
      message: 'Enter passphrase:',
    });

    if (clack.isCancel(passphraseInput)) return;
    if (typeof passphraseInput !== 'string') return;

    const spinner = clack.spinner();
    spinner.start('Decrypting note...');

    try {
      // Decrypt the armored payload into plaintext.
      const result = await this.pgp.decrypt({
        message: note.encrypted,
        privateKey: key.privateKey,
        passphrase: passphraseInput,
      });

      spinner.stop('Note decrypted successfully! ✅');

      // Notes are *expected* to be JSON, but we allow arbitrary plaintext fallback.
      let title = 'Untitled';
      let body = result.data;
      let created = '';
      let updated = '';

      try {
        const parsed = JSON.parse(result.data);
        title = parsed.title || title;
        body = parsed.body || result.data;
        created = parsed.created || '';
        updated = parsed.updated || '';
      } catch {
        // Fallback to raw text.
      }

      console.log('\n' + chalk.dim('─'.repeat(60)));
      console.log(chalk.bold('Title: ') + chalk.white(title));
      if (created) {
        console.log(chalk.dim('Created: ') + chalk.white(created));
      }
      if (updated) {
        console.log(chalk.dim('Updated: ') + chalk.white(updated));
      }
      console.log(chalk.dim('─'.repeat(60)));
      console.log(chalk.white(body));
      console.log(chalk.dim('─'.repeat(60)) + '\n');
    } catch (error) {
      spinner.stop('Failed to decrypt note');
      displayError(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private async encryptFolder(): Promise<void> {
    clack.intro(chalk.bold('Encrypt Folder'));

    const keys = await this.keyStore.listKeys();
    if (keys.length === 0) {
      displayError('No keys found. Import or generate a key first.');
      return;
    }

    // Choose recipients; encryption will be performed per-file with the same recipient set.
    const selectedKeys = await clack.multiselect({
      message: 'Select recipient(s):',
      options: keys.map((key) => ({
        value: key.fingerprint,
        label: `${key.name} <${key.email}>`,
      })),
      required: true,
    });

    if (clack.isCancel(selectedKeys)) return;

    const inputDirInput = await clack.text({
      message: 'Enter path to folder to encrypt:',
      placeholder: './private-files',
      validate: (value) => {
        if (!value) return 'Folder path is required';
      },
    });

    if (clack.isCancel(inputDirInput)) return;
    if (typeof inputDirInput !== 'string') return;

    const inputDir = this.resolveInputPath(inputDirInput.trim());
    if (!(await this.isDirectory(inputDir))) {
      displayError('Folder not found or not a directory.');
      return;
    }

    // Optional filter: limits processing to specific file extensions.
    const extensionInput = await clack.text({
      message: 'Filter by extensions (comma-separated, leave blank for all):',
      placeholder: '.pdf,.txt',
    });

    if (clack.isCancel(extensionInput)) return;
    if (typeof extensionInput !== 'string') return;

    const extensionFilter = this.parseExtensionFilter(extensionInput, []);

    // Choose armored vs binary output for every file in the batch.
    const outputFormat = (await clack.select({
      message: 'Select output format:',
      options: [
        { value: 'armored', label: 'ASCII armored (.asc)' },
        { value: 'binary', label: 'Binary (.pgp)' },
      ],
    })) as 'armored' | 'binary';

    if (clack.isCancel(outputFormat)) return;

    const defaultOutputDir = `${inputDir}-encrypted`;
    const outputDirInput = await clack.text({
      message: 'Enter output folder path:',
      placeholder: defaultOutputDir,
    });

    if (clack.isCancel(outputDirInput)) return;
    if (typeof outputDirInput !== 'string') return;

    const outputDir = this.resolveInputPath(
      outputDirInput.trim() || defaultOutputDir
    );

    // Decide what to do if an output file already exists.
    const outputPolicy = (await clack.select({
      message: 'If output file exists:',
      options: [
        { value: 'overwrite', label: 'Overwrite' },
        { value: 'skip', label: 'Skip' },
        { value: 'abort', label: 'Abort batch' },
      ],
    })) as 'overwrite' | 'skip' | 'abort';

    if (clack.isCancel(outputPolicy)) return;

    // Optional signing: requires a private key and passphrase.
    const shouldSign = await clack.confirm({
      message: 'Sign the files?',
    });

    if (clack.isCancel(shouldSign)) return;

    let signingKey: StoredKey | undefined;
    let passphrase: string | undefined;

    if (shouldSign) {
      const keysWithPrivate = keys.filter((k) => k.privateKey);
      if (keysWithPrivate.length === 0) {
        displayError('No private keys available for signing.');
        return;
      }

      const selectedSigningKey = await clack.select({
        message: 'Select signing key:',
        options: keysWithPrivate.map((key) => ({
          value: key.fingerprint,
          label: `${key.name} <${key.email}>`,
        })),
      });

      if (clack.isCancel(selectedSigningKey)) return;

      const selectedKey = await this.keyStore.getKey(selectedSigningKey as string);
      if (!selectedKey || !selectedKey.privateKey) {
        displayError('Key not found or missing private key.');
        return;
      }
      signingKey = selectedKey;

      const passphraseInput = await clack.password({
        message: 'Enter passphrase for signing key:',
      });

      if (clack.isCancel(passphraseInput)) return;
      if (typeof passphraseInput !== 'string') return;
      passphrase = passphraseInput;
    }

    const files = await this.listFilesRecursive(inputDir, outputDir);
    const filteredFiles =
      extensionFilter.length === 0
        ? files
        : files.filter((filePath) =>
            extensionFilter.includes(extname(filePath).toLowerCase())
          );

    if (filteredFiles.length === 0) {
      displayError('No files matched your filter.');
      return;
    }

    const spinner = clack.spinner();
    spinner.start('Encrypting folder...');

    let encryptedCount = 0;
    let skippedCount = 0;
    const failures: { file: string; error: string }[] = [];

    try {
      // Load recipient public keys once, reusing them for all file encryptions.
      const publicKeys = await Promise.all(
        (selectedKeys as string[]).map(async (fp) => {
          const key = await this.keyStore.getKey(fp);
          return key!.publicKey;
        })
      );

      const outputExtension = outputFormat === 'armored' ? '.asc' : '.pgp';

      /**
       * Process each file independently.
       *
       * We preserve directory structure by using relative paths from the input root.
       * Each input file becomes: <outputDir>/<relativePath><outputExtension>
       */
      for (const filePath of filteredFiles) {
        const relPath = relative(inputDir, filePath);
        const outputPath = join(outputDir, `${relPath}${outputExtension}`);

        try {
          // Ensure output directory exists for nested paths.
          await mkdir(dirname(outputPath), { recursive: true });
          const outputFile = Bun.file(outputPath);
          if (await outputFile.exists()) {
            if (outputPolicy === 'skip') {
              skippedCount += 1;
              continue;
            }
            if (outputPolicy === 'abort') {
              throw new Error('Output file exists; aborting batch.');
            }
          }

          // Encrypt the file as a stream; this avoids buffering entire files into memory.
          const encrypted = await this.pgp.encryptFile({
            input: Bun.file(filePath).stream(),
            publicKeys,
            sign: shouldSign,
            privateKey: signingKey?.privateKey,
            passphrase,
            format: outputFormat,
            filename: basename(filePath),
          });

          await this.writeOutputToFile(encrypted, outputPath, outputFormat);
          encryptedCount += 1;
        } catch (error) {
          // Collect per-file failures so one bad file doesn't stop the whole batch.
          failures.push({
            file: filePath,
            error: error instanceof Error ? error.message : 'Unknown error',
          });
        }
      }

      spinner.stop('Folder encryption complete ✅');
    } catch (error) {
      spinner.stop('Folder encryption failed');
      displayError(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
      return;
    }

    displaySuccess(`Encrypted files: ${encryptedCount}`);
    if (skippedCount > 0) {
      displayInfo(`Skipped files: ${skippedCount}`);
    }
    if (failures.length > 0) {
      displayWarning(`Failed files: ${failures.length}`);
      // Only show a handful to keep terminal output readable.
      failures.slice(0, 5).forEach((failure) => {
        displayWarning(`${failure.file}: ${failure.error}`);
      });
    }
  }

  private async decryptFolder(): Promise<void> {
    clack.intro(chalk.bold('Decrypt Folder'));

    const keys = await this.keyStore.listKeys();
    const keysWithPrivate = keys.filter((k) => k.privateKey);

    if (keysWithPrivate.length === 0) {
      displayError('No private keys available for decryption.');
      return;
    }

    const selectedKey = await clack.select({
      message: 'Select your key:',
      options: keysWithPrivate.map((key) => ({
        value: key.fingerprint,
        label: `${key.name} <${key.email}>`,
      })),
    });

    if (clack.isCancel(selectedKey)) return;

    const key = await this.keyStore.getKey(selectedKey as string);
    if (!key || !key.privateKey) {
      displayError('Key not found or missing private key.');
      return;
    }

    const inputDirInput = await clack.text({
      message: 'Enter path to folder to decrypt:',
      placeholder: './encrypted-files',
      validate: (value) => {
        if (!value) return 'Folder path is required';
      },
    });

    if (clack.isCancel(inputDirInput)) return;
    if (typeof inputDirInput !== 'string') return;

    const inputDir = this.resolveInputPath(inputDirInput.trim());
    if (!(await this.isDirectory(inputDir))) {
      displayError('Folder not found or not a directory.');
      return;
    }

    /**
     * Encrypted folder inputs can contain mixed formats.
     *
     * - `auto`: decide armored vs binary per-file by extension
     * - `armored`: treat all selected files as armored
     * - `binary`: treat all selected files as binary
     */
    const formatHandling = (await clack.select({
      message: 'Select input format handling:',
      options: [
        { value: 'auto', label: 'Auto-detect by extension (.asc/.pgp/.gpg)' },
        { value: 'armored', label: 'Force ASCII armored (.asc)' },
        { value: 'binary', label: 'Force binary (.pgp/.gpg)' },
      ],
    })) as 'auto' | 'armored' | 'binary';

    if (clack.isCancel(formatHandling)) return;

    const defaultFilter =
      formatHandling === 'armored'
        ? ['.asc']
        : formatHandling === 'binary'
        ? ['.pgp', '.gpg']
        : ['.pgp', '.gpg', '.asc'];

    const extensionInput = await clack.text({
      message: 'Filter by extensions (comma-separated, leave blank for default):',
      placeholder: defaultFilter.join(','),
    });

    if (clack.isCancel(extensionInput)) return;
    if (typeof extensionInput !== 'string') return;

    const extensionFilter = this.parseExtensionFilter(extensionInput, defaultFilter);

    const defaultOutputDir = `${inputDir}-decrypted`;
    const outputDirInput = await clack.text({
      message: 'Enter output folder path:',
      placeholder: defaultOutputDir,
    });

    if (clack.isCancel(outputDirInput)) return;
    if (typeof outputDirInput !== 'string') return;

    const outputDir = this.resolveInputPath(
      outputDirInput.trim() || defaultOutputDir
    );

    const outputPolicy = (await clack.select({
      message: 'If output file exists:',
      options: [
        { value: 'overwrite', label: 'Overwrite' },
        { value: 'skip', label: 'Skip' },
        { value: 'abort', label: 'Abort batch' },
      ],
    })) as 'overwrite' | 'skip' | 'abort';

    if (clack.isCancel(outputPolicy)) return;

    // Signature verification is optional; it may fail even when decryption succeeds.
    const verifySignatures = await clack.confirm({
      message: 'Verify signatures during decryption?',
      initialValue: true,
    });

    if (clack.isCancel(verifySignatures)) return;

    const passphraseInput = await clack.password({
      message: 'Enter passphrase:',
    });

    if (clack.isCancel(passphraseInput)) return;
    if (typeof passphraseInput !== 'string') return;

    const files = await this.listFilesRecursive(inputDir, outputDir);
    const filteredFiles = files.filter((filePath) =>
      extensionFilter.includes(extname(filePath).toLowerCase())
    );

    if (filteredFiles.length === 0) {
      displayError('No files matched your filter.');
      return;
    }

    const spinner = clack.spinner();
    spinner.start('Decrypting folder...');

    let decryptedCount = 0;
    let skippedCount = 0;
    const failures: { file: string; error: string }[] = [];
    const signatureFailures: string[] = [];

    try {
      for (const filePath of filteredFiles) {
        const relPath = relative(inputDir, filePath);
        // Strip known encrypted extensions so output filenames match originals.
        const outputRelPath = this.stripEncryptedExtension(relPath);
        const outputPath = join(outputDir, outputRelPath);

        try {
          await mkdir(dirname(outputPath), { recursive: true });
          const outputFile = Bun.file(outputPath);
          if (await outputFile.exists()) {
            if (outputPolicy === 'skip') {
              skippedCount += 1;
              continue;
            }
            if (outputPolicy === 'abort') {
              throw new Error('Output file exists; aborting batch.');
            }
          }

          // Decide how to parse the encrypted file for OpenPGP.js.
          const format = this.resolveInputFormat(filePath, formatHandling);
          const encryptedStream = Bun.file(filePath).stream();
          const messageStream =
            format === 'armored'
              ? encryptedStream.pipeThrough(new TextDecoderStream())
              : encryptedStream;

          // Decrypt file (and optionally verify signature) to bytes.
          const result = await this.pgp.decryptFile({
            input: messageStream,
            inputFormat: format,
            privateKey: key.privateKey,
            passphrase: passphraseInput,
            verifySignature: verifySignatures,
            publicKeys: verifySignatures ? keys.map((k) => k.publicKey) : undefined,
          });

          await this.writeOutputToFile(result.data, outputPath, 'binary');
          decryptedCount += 1;

          if (verifySignatures && result.verified === false) {
            // Keep separate accounting for "decrypted but signature invalid/unknown".
            signatureFailures.push(filePath);
          }
        } catch (error) {
          failures.push({
            file: filePath,
            error: error instanceof Error ? error.message : 'Unknown error',
          });
        }
      }

      spinner.stop('Folder decryption complete ✅');
    } catch (error) {
      spinner.stop('Folder decryption failed');
      displayError(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
      return;
    }

    displaySuccess(`Decrypted files: ${decryptedCount}`);
    if (skippedCount > 0) {
      displayInfo(`Skipped files: ${skippedCount}`);
    }
    if (signatureFailures.length > 0) {
      displayWarning(`Signature failures: ${signatureFailures.length}`);
      // Only show a handful to keep terminal output readable.
      signatureFailures.slice(0, 5).forEach((filePath) => {
        displayWarning(`Signature failed: ${filePath}`);
      });
    }
    if (failures.length > 0) {
      displayWarning(`Failed files: ${failures.length}`);
      // Only show a handful to keep terminal output readable.
      failures.slice(0, 5).forEach((failure) => {
        displayWarning(`${failure.file}: ${failure.error}`);
      });
    }
  }

  private resolveInputPath(inputPath: string): string {
    /**
     * Resolve user-provided paths into absolute paths.
     *
     * Why this helper exists:
     * - Users often paste paths like `~/file.txt` which `path.resolve` does not expand.
     * - Relative paths should be interpreted relative to the current working directory.
     */
    if (inputPath.startsWith('~/')) {
      return resolve(homedir(), inputPath.slice(2));
    }

    return resolve(process.cwd(), inputPath);
  }

  private async writeOutputToFile(
    data:
      | ReadableStream<Uint8Array>
      | ReadableStream<string>
      | Uint8Array
      | string,
    outputPath: string,
    format: 'armored' | 'binary'
  ): Promise<void> {
    /**
     * Write OpenPGP.js output to disk.
     *
     * OpenPGP.js can return:
     * - a string (armored)
     * - a Uint8Array (binary)
     * - a ReadableStream<string> (armored streaming)
     * - a ReadableStream<Uint8Array> (binary streaming)
     *
     * This helper normalizes all cases and writes to `outputPath`.
     */
    if (typeof data === 'string') {
      await mkdir(dirname(outputPath), { recursive: true });
      await writeFile(outputPath, data, 'utf-8');
      return;
    }

    if (data instanceof Uint8Array) {
      await mkdir(dirname(outputPath), { recursive: true });
      await writeFile(outputPath, data);
      return;
    }

    const stream = data as ReadableStream<Uint8Array> | ReadableStream<string>;
    if (!stream || typeof stream.getReader !== 'function') {
      throw new Error('Unsupported stream type for file output.');
    }

    /**
     * Convert armored text streams into byte streams.
     *
     * - For armored output, OpenPGP.js may stream strings; files want bytes, so we encode.
     * - For binary output, we already have bytes.
     */
    const byteStream =
      format === 'armored'
        ? (stream as ReadableStream<string>).pipeThrough(new TextEncoderStream())
        : (stream as ReadableStream<Uint8Array>);

    // Pull-based streaming: read chunks and write them incrementally.
    const reader = byteStream.getReader();
    const writer = Bun.file(outputPath).writer();

    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        if (!value) continue;
        // Bun's file writer can return a Promise if it needs to flush/backpressure.
        const writeResult = writer.write(value);
        if (writeResult instanceof Promise) {
          await writeResult;
        }
      }
    } finally {
      // Always release resources, even if a read/write throws.
      if (typeof reader.releaseLock === 'function') {
        reader.releaseLock();
      }
      const endResult = writer.end();
      if (endResult instanceof Promise) {
        await endResult;
      }
    }
  }

  private suggestDecryptedOutputPath(inputPath: string): string {
    /**
     * Suggest a default output path for decrypting a single file.
     *
     * - If the input ends with a known encrypted extension, strip it.
     * - Otherwise append ".decrypted" as a safe fallback.
     */
    const stripped = inputPath.replace(/\.(pgp|gpg|asc)$/i, '');
    if (stripped !== inputPath) {
      return stripped;
    }

    return `${inputPath}.decrypted`;
  }

  private async listFilesRecursive(
    rootDir: string,
    excludeDir?: string
  ): Promise<string[]> {
    /**
     * Recursively list files under `rootDir`.
     *
     * We use this for folder encryption/decryption and support an `excludeDir` so that
     * users can choose an output directory inside the input tree without re-processing
     * already-produced outputs (which would cause exponential growth).
     */
    const normalizedExclude = excludeDir ? resolve(excludeDir) : null;
    const entries = await readdir(rootDir, { withFileTypes: true });
    const files: string[] = [];

    for (const entry of entries) {
      const entryPath = join(rootDir, entry.name);
      const resolvedEntry = resolve(entryPath);

      if (
        normalizedExclude &&
        (resolvedEntry === normalizedExclude ||
          resolvedEntry.startsWith(normalizedExclude + sep))
      ) {
        // Skip the excluded directory and everything under it.
        continue;
      }

      if (entry.isDirectory()) {
        // Recurse into subdirectories.
        files.push(
          ...(await this.listFilesRecursive(
            entryPath,
            normalizedExclude ?? undefined
          ))
        );
      } else if (entry.isFile()) {
        // Only include plain files (skip other entry types like symlinks/sockets).
        files.push(entryPath);
      }
    }

    return files;
  }

  private parseExtensionFilter(input: string, defaults: string[]): string[] {
    /**
     * Parse comma-separated extension filters into normalized ".ext" lowercase values.
     *
     * Examples:
     * - ".pdf,.txt" -> [".pdf", ".txt"]
     * - "pdf,txt"   -> [".pdf", ".txt"]
     * - ""          -> defaults
     */
    const raw = input
      .split(',')
      .map((value) => value.trim())
      .filter(Boolean);

    if (raw.length === 0) {
      return defaults;
    }

    return raw.map((value) =>
      value.startsWith('.') ? value.toLowerCase() : `.${value.toLowerCase()}`
    );
  }

  private resolveInputFormat(
    filePath: string,
    mode: 'auto' | 'armored' | 'binary'
  ): 'armored' | 'binary' {
    /**
     * Decide how to parse encrypted files for OpenPGP.js.
     *
     * - In forced modes, we always return that mode.
     * - In auto mode, use common extensions:
     *   - .asc => armored
     *   - .pgp/.gpg => binary
     * - Unknown extensions default to binary (a reasonable guess for many cases).
     */
    if (mode === 'armored') return 'armored';
    if (mode === 'binary') return 'binary';

    const extension = extname(filePath).toLowerCase();
    if (extension === '.asc') return 'armored';
    if (extension === '.pgp' || extension === '.gpg') return 'binary';
    return 'binary';
  }

  private stripEncryptedExtension(pathValue: string): string {
    /**
     * Compute output file names during folder decryption.
     *
     * If a path ends with known encrypted extensions, strip them; otherwise add a suffix
     * so we never overwrite an unrelated file with the same name.
     */
    const stripped = pathValue.replace(/\.(pgp|gpg|asc)$/i, '');
    if (stripped !== pathValue) {
      return stripped;
    }

    return `${pathValue}.decrypted`;
  }

  private async isDirectory(pathValue: string): Promise<boolean> {
    // Helper used to validate folder paths before attempting recursive reads.
    try {
      const stats = await stat(pathValue);
      return stats.isDirectory();
    } catch {
      return false;
    }
  }

  private validateArmoredMessage(message: string): string | undefined {
    /**
     * Lightweight sanity check for armored encrypted messages.
     *
     * This does not fully parse the message; it only checks for the expected headers
     * to catch common copy/paste issues early.
     */
    if (!message) return 'Message cannot be empty';
    const trimmed = message.trim();
    if (!trimmed) return 'Message cannot be empty';
    if (!trimmed.includes('-----BEGIN PGP MESSAGE-----'))
      return 'Missing BEGIN header';
    if (!trimmed.includes('-----END PGP MESSAGE-----'))
      return 'Missing END footer';
    return undefined;
  }

  private validatePublicKeyBlock(publicKey: string): string | undefined {
    /**
     * Lightweight sanity check for armored public key blocks.
     *
     * Similar to validateArmoredMessage, we only verify the presence of the header/footer.
     * OpenPGP.js will still do the real parsing and throw on invalid key material.
     */
    if (!publicKey) return 'Public key cannot be empty';
    if (!publicKey.includes('-----BEGIN PGP PUBLIC KEY BLOCK-----'))
      return 'Invalid public key format';
    if (!publicKey.includes('-----END PGP PUBLIC KEY BLOCK-----'))
      return 'Invalid public key format';
    return undefined;
  }

  private async signMessage(): Promise<void> {
    clack.intro(chalk.bold('Sign Message'));

    const keys = await this.keyStore.listKeys();
    const keysWithPrivate = keys.filter((k) => k.privateKey);

    if (keysWithPrivate.length === 0) {
      displayError('No private keys available for signing.');
      return;
    }

    // Choose which private key will produce the signature.
    const selectedKey = await clack.select({
      message: 'Select signing key:',
      options: keysWithPrivate.map((key) => ({
        value: key.fingerprint,
        label: `${key.name} <${key.email}>`,
      })),
    });

    if (clack.isCancel(selectedKey)) return;

    const key = await this.keyStore.getKey(selectedKey as string);
    if (!key || !key.privateKey) {
      displayError('Key not found or missing private key.');
      return;
    }

    const message = await clack.text({
      message: 'Enter message to sign:',
      placeholder: 'Your message...',
      validate: (value) => {
        if (!value) return 'Message cannot be empty';
      },
    });

    if (clack.isCancel(message)) return;

    const passphrase = await clack.password({
      message: 'Enter passphrase:',
    });

    if (clack.isCancel(passphrase)) return;

    const spinner = clack.spinner();
    spinner.start('Signing message...');

    try {
      // Produce a clearsigned message (not a detached signature) for easy copy/paste sharing.
      const signed = await this.pgp.sign({
        message,
        privateKey: key.privateKey,
        passphrase,
        detached: false,
      });

      spinner.stop('Message signed successfully! ✅');

      console.log('\n' + chalk.dim('─'.repeat(50)));
      console.log(chalk.dim('Signed message:'));
      console.log(signed);
      console.log(chalk.dim('─'.repeat(50)) + '\n');

      // Convenience: allow copying the signed output to clipboard.
      const copySigned = await clack.confirm({
        message: 'Copy signed message to clipboard?',
        initialValue: false,
      });

      if (!clack.isCancel(copySigned) && copySigned) {
        const copied = await copyToClipboard(signed);
        if (copied) {
          displaySuccess('Signed message copied to clipboard!');
        } else {
          displayWarning('Failed to copy signed message to clipboard.');
        }
      }
    } catch (error) {
      spinner.stop('Signing failed');
      displayError(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private async verifySignature(): Promise<void> {
    clack.intro(chalk.bold('Verify Signature'));

    const keys = await this.keyStore.listKeys();
    if (keys.length === 0) {
      displayError('No keys found. Import a public key first.');
      return;
    }

    // Verification requires a signed message. We support clipboard or manual paste.
    const inputSource = await clack.select({
      message: 'Select signed message source:',
      options: [
        { value: 'clipboard', label: 'Clipboard' },
        { value: 'paste', label: 'Paste manually' },
      ],
    });

    if (clack.isCancel(inputSource)) return;

    let signedMessage: string | null = null;
    if (inputSource === 'clipboard') {
      signedMessage = await readFromClipboard();
      if (!signedMessage) {
        displayError('Clipboard is empty or unavailable.');
        return;
      }
    } else {
      const signedMessageInput = await clack.text({
        message: 'Paste signed message:',
        placeholder: '-----BEGIN PGP SIGNED MESSAGE-----...',
        validate: (value) => {
          if (!value) return 'Message cannot be empty';
        },
      });

      if (clack.isCancel(signedMessageInput)) return;
      if (typeof signedMessageInput !== 'string') return;
      signedMessage = signedMessageInput;
    }

    if (!signedMessage) {
      displayError('No signed message provided.');
      return;
    }

    if (inputSource === 'clipboard') {
      // Show what we're verifying so users can sanity-check they copied the right thing.
      console.log('\n' + chalk.dim('─'.repeat(50)));
      console.log(chalk.dim('Signed message from clipboard:'));
      console.log(signedMessage);
      console.log(chalk.dim('─'.repeat(50)) + '\n');
    }

    const spinner = clack.spinner();
    spinner.start('Verifying signature...');

    try {
      /**
       * Verify against all known public keys.
       *
       * This is convenient for a small keystore: we don't require the user to pick
       * which key signed the message; OpenPGP.js tries them.
       */
      const result = await this.pgp.verify({
        message: signedMessage,
        signature: signedMessage,
        publicKeys: keys.map((k) => k.publicKey),
      });

      spinner.stop('Verification complete');

      if (result.verified) {
        displaySuccess(`✅ Signature verified! Signed by key: ${result.signedBy}`);
      } else {
        displayError('❌ Signature verification failed!');
      }
    } catch (error) {
      spinner.stop('Verification failed');
      displayError(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private async importPublicKey(): Promise<void> {
    clack.intro(chalk.bold('Import Public Key'));

    // Offer multiple input sources to minimize friction when exchanging keys.
    const inputSource = await clack.select({
      message: 'Select public key source:',
      options: [
        { value: 'clipboard', label: 'Clipboard' },
        { value: 'file', label: 'File' },
        { value: 'paste', label: 'Paste manually' },
      ],
    });

    if (clack.isCancel(inputSource)) return;

    let publicKey: string | null = null;
    if (inputSource === 'clipboard') {
      publicKey = await readFromClipboard();
      if (!publicKey) {
        displayError('Clipboard is empty or unavailable.');
        return;
      }
    } else if (inputSource === 'file') {
      const pathInput = await clack.text({
        message: 'Enter path to public key file:',
        placeholder: './public-key.asc',
        validate: (value) => {
          if (!value) return 'File path is required';
        },
      });

      if (clack.isCancel(pathInput)) return;
      if (typeof pathInput !== 'string') return;

      const filePath = this.resolveInputPath(pathInput.trim());
      try {
        // Read the full armored key block from disk.
        publicKey = await readFile(filePath, 'utf-8');
      } catch (error) {
        const errorMsg = error instanceof Error ? error.message : 'Unknown error';
        displayError(`Failed to read file: ${errorMsg}`);
        return;
      }
    } else {
      const publicKeyInput = await clack.text({
        message: 'Paste public key:',
        placeholder: '-----BEGIN PGP PUBLIC KEY BLOCK-----...',
        // Quick header/footer check so users get immediate feedback before parsing.
        validate: (value) => this.validatePublicKeyBlock(value),
      });

      if (clack.isCancel(publicKeyInput)) return;
      if (typeof publicKeyInput !== 'string') return;
      publicKey = publicKeyInput;
    }

    if (!publicKey) {
      displayError('Public key cannot be empty.');
      return;
    }

    const publicKeyValidationError = this.validatePublicKeyBlock(publicKey);
    if (publicKeyValidationError) {
      displayError(publicKeyValidationError);
      return;
    }

    // Print the key block so users can sanity-check what they're about to import.
    console.log('\n' + chalk.dim('─'.repeat(50)));
    console.log(chalk.dim('Public key preview:'));
    console.log(publicKey);
    console.log(chalk.dim('─'.repeat(50)) + '\n');

    const spinner = clack.spinner();
    spinner.start('Importing public key...');

    try {
      // Parse fingerprint/keyId/userId/creation time before writing to disk.
      const keyInfo = await this.pgp.readPublicKeyInfo(publicKey);

      // Fingerprint is the unique identity; refuse duplicates.
      const exists = await this.keyStore.keyExists(keyInfo.fingerprint);
      if (exists) {
        spinner.stop('Key already exists');
        displayError('This key is already in your keystore.');
        return;
      }

      // Extract name/email from a typical userId string "Name <email>" for nicer display.
      const userIdMatch = keyInfo.userId.match(/^(.+?)\s*<(.+?)>$/);
      const name = userIdMatch ? userIdMatch[1] : keyInfo.userId;
      const email = userIdMatch ? userIdMatch[2] : '';

      const storedKey: StoredKey = {
        name,
        email,
        fingerprint: keyInfo.fingerprint,
        keyId: keyInfo.keyId,
        publicKey,
        created: keyInfo.created,
        algorithm: 'unknown',
      };

      await this.keyStore.saveKey(storedKey);

      spinner.stop('Public key imported successfully! ✅');

      displayKeyInfo({
        name,
        email,
        fingerprint: keyInfo.fingerprint,
        keyId: keyInfo.keyId,
        created: keyInfo.created,
        algorithm: 'unknown',
      });
    } catch (error) {
      spinner.stop('Import failed');
      displayError(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private async exportPublicKey(): Promise<void> {
    const keys = await this.keyStore.listKeys();

    if (keys.length === 0) {
      displayError('No keys found.');
      return;
    }

    // Choose which key's public portion to export/share.
    const selected = await clack.select({
      message: 'Select key to export:',
      options: keys.map((key) => ({
        value: key.fingerprint,
        label: `${key.name} <${key.email}>`,
      })),
    });

    if (clack.isCancel(selected)) return;

    const key = await this.keyStore.getKey(selected as string);
    if (!key) {
      displayError('Key not found.');
      return;
    }

    // Show the public key block; users often want to visually verify header/footer.
    console.log('\n' + chalk.dim('─'.repeat(50)));
    console.log(chalk.dim('Public key preview:'));
    console.log(key.publicKey);
    console.log(chalk.dim('─'.repeat(50)) + '\n');

    const exportTarget = await clack.select({
      message: 'Export public key to:',
      options: [
        { value: 'clipboard', label: 'Clipboard' },
        { value: 'file', label: 'File' },
        { value: 'both', label: 'Clipboard and file' },
      ],
    });

    if (clack.isCancel(exportTarget)) return;

    let clipboardSuccess = true;
    if (exportTarget === 'clipboard' || exportTarget === 'both') {
      // Best-effort clipboard copy (falls back to warning if unavailable).
      clipboardSuccess = await copyToClipboard(key.publicKey);
      if (clipboardSuccess) {
        displaySuccess('Public key copied to clipboard!');
      } else {
        displayWarning('Failed to copy public key to clipboard.');
      }
    }

    if (exportTarget === 'file' || exportTarget === 'both') {
      const pathInput = await clack.text({
        message: 'Enter path to save public key:',
        placeholder: `./${key.keyId.toUpperCase()}.asc`,
        validate: (value) => {
          if (!value) return 'File path is required';
        },
      });

      if (clack.isCancel(pathInput)) return;
      if (typeof pathInput !== 'string') return;

      const filePath = this.resolveInputPath(pathInput.trim());
      try {
        // Write armored public key block to disk for sharing/import into other tools.
        await writeFile(filePath, key.publicKey, 'utf-8');
        displaySuccess(`Public key saved to ${filePath}`);
      } catch (error) {
        const errorMsg = error instanceof Error ? error.message : 'Unknown error';
        displayError(`Failed to write file: ${errorMsg}`);
      }
    }
  }

  private async deleteKey(): Promise<void> {
    const keys = await this.keyStore.listKeys();

    if (keys.length === 0) {
      displayError('No keys found.');
      return;
    }

    // Choose which keystore entry to delete by fingerprint.
    const selected = await clack.select({
      message: 'Select key to delete:',
      options: keys.map((key) => ({
        value: key.fingerprint,
        label: `${key.name} <${key.email}> [${key.keyId.substring(0, 8).toUpperCase()}]`,
      })),
    });

    if (clack.isCancel(selected)) return;

    const key = await this.keyStore.getKey(selected as string);
    if (!key) {
      displayError('Key not found.');
      return;
    }

    displayKeyInfo(key);

    // Deleting a private key is higher-stakes; we adjust the prompt accordingly.
    const confirm = await clack.confirm({
      message: key.privateKey
        ? 'This will delete both public and private keys. Are you sure?'
        : 'Delete this public key?',
    });

    if (clack.isCancel(confirm) || !confirm) {
      displayInfo('Deletion cancelled.');
      return;
    }

    // Delete is a filesystem operation; KeyStore returns a boolean for friendly UX.
    const success = await this.keyStore.deleteKey(selected as string);
    if (success) {
      displaySuccess('Key deleted successfully!');
    } else {
      displayError('Failed to delete key.');
    }
  }
}

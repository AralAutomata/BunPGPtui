import * as openpgp from 'openpgp';
import type {
  KeyPair,
  EncryptOptions,
  DecryptOptions,
  SignOptions,
  VerifyOptions,
  KeyAlgorithm,
  FileEncryptOptions,
  FileEncryptResult,
  FileDecryptOptions,
  FileDecryptResult,
} from './types';

/**
 * PGPOperations is the cryptography boundary of the app.
 *
 * It wraps OpenPGP.js (`openpgp`) with a small, app-specific API that:
 * - Takes/returns plain strings and streams that are easy for the UI layer to work with.
 * - Encapsulates OpenPGP.js object construction (readKey/readMessage/readPrivateKey/etc.).
 * - Normalizes signature verification results into simple booleans.
 *
 * Key concept: OpenPGP.js works with parsed key/message objects; our UI stores and
 * transports ASCII-armored text. This class is where armored text becomes objects.
 */
export class PGPOperations {
  async generateKeyPair(
    name: string,
    email: string,
    passphrase: string,
    algorithm: KeyAlgorithm = 'rsa4096'
  ): Promise<KeyPair> {
    /**
     * OpenPGP.js key generation options.
     *
     * - `userIDs` becomes the primary user ID packet for the key ("name <email>").
     * - `passphrase` encrypts the private key material (so the key file is not plaintext).
     *
     * We use `any` here because OpenPGP.js option types differ by algorithm and are
     * slightly more permissive than the TS types exposed by the package.
     */
    const keyOptions: any = {
      userIDs: [{ name, email }],
      passphrase,
    };

    // Map our UI-friendly algorithm selection to OpenPGP.js keygen parameters.
    if (algorithm === 'rsa2048') {
      keyOptions.type = 'rsa';
      keyOptions.rsaBits = 2048;
    } else if (algorithm === 'rsa4096') {
      keyOptions.type = 'rsa';
      keyOptions.rsaBits = 4096;
    } else if (algorithm === 'ecc') {
      keyOptions.type = 'ecc';
      keyOptions.curve = 'curve25519';
    }

    // `generateKey` returns armored key blocks (strings) for both public and private keys.
    const { privateKey, publicKey } = await openpgp.generateKey(keyOptions);

    // Parse the public key so we can compute a stable fingerprint and key ID.
    const publicKeyObj = await openpgp.readKey({ armoredKey: publicKey });
    const fingerprint = publicKeyObj.getFingerprint();
    const keyId = publicKeyObj.getKeyID().toHex();

    return {
      publicKey,
      privateKey,
      fingerprint,
      keyId,
      userId: `${name} <${email}>`,
      // OpenPGP.js can expose creation time from the key; we store "now" for UI ordering.
      created: new Date(),
      algorithm,
    };
  }

  async encrypt(options: EncryptOptions): Promise<string> {
    // Convert each armored public key string into a parsed key object OpenPGP.js can use.
    const publicKeys = await Promise.all(
      options.publicKeys.map(key => openpgp.readKey({ armoredKey: key }))
    );

    /**
     * OpenPGP.js encryption parameters.
     *
     * `message` is a structured OpenPGP message object created from plaintext.
     * `encryptionKeys` is an array so the same ciphertext can be decrypted by any recipient.
     */
    const encryptOptions: any = {
      message: await openpgp.createMessage({ text: options.message }),
      encryptionKeys: publicKeys,
    };

    if (options.sign && options.privateKey && options.passphrase) {
      /**
       * Signing requires unlocking (decrypting) the private key with its passphrase.
       * The decrypted key object is used as `signingKeys`.
       */
      const privateKey = await openpgp.decryptKey({
        privateKey: await openpgp.readPrivateKey({ armoredKey: options.privateKey }),
        passphrase: options.passphrase,
      });
      encryptOptions.signingKeys = privateKey;
    }

    // Returns ASCII-armored encrypted message by default.
    const encrypted = await openpgp.encrypt(encryptOptions);
    return encrypted as string;
  }

  async decrypt(options: DecryptOptions): Promise<{ data: string; verified?: boolean }> {
    /**
     * Step 1: parse and unlock the private key.
     *
     * Note: Passing an empty string for passphrase is a convenient default for
     * "unprotected keys", but if the key is actually encrypted, OpenPGP.js will fail.
     */
    const privateKey = await openpgp.decryptKey({
      privateKey: await openpgp.readPrivateKey({ armoredKey: options.privateKey }),
      passphrase: options.passphrase || '',
    });

    // Step 2: parse the armored PGP message into an OpenPGP.js message object.
    const message = await openpgp.readMessage({ armoredMessage: options.message });

    const decryptOptions: any = {
      message,
      decryptionKeys: privateKey,
    };

    if (options.verifySignature && options.publicKeys) {
      // Signature verification requires one or more public keys that might match the signer.
      const publicKeys = await Promise.all(
        options.publicKeys.map(key => openpgp.readKey({ armoredKey: key }))
      );
      decryptOptions.verificationKeys = publicKeys;
    }

    /**
     * `openpgp.decrypt` returns:
     * - `data`: decrypted plaintext
     * - `signatures`: signature objects (if the message was signed)
     */
    const { data, signatures } = await openpgp.decrypt(decryptOptions);

    // Normalize signature verification into a boolean, but only if signatures exist.
    let verified = undefined;
    if (signatures && signatures.length > 0) {
      try {
        // OpenPGP.js signature verification is async; it rejects if verification fails.
        await signatures[0].verified;
        verified = true;
      } catch {
        verified = false;
      }
    }

    return { data: data as string, verified };
  }

  async sign(options: SignOptions): Promise<string> {
    // Parse + unlock the signing private key.
    const privateKey = await openpgp.decryptKey({
      privateKey: await openpgp.readPrivateKey({ armoredKey: options.privateKey }),
      passphrase: options.passphrase || '',
    });

    // Create a message object from plaintext for signing.
    const message = await openpgp.createMessage({ text: options.message });

    // `detached: false` produces a clearsigned message; `true` produces a detached signature.
    const signed = await openpgp.sign({
      message,
      signingKeys: privateKey,
      detached: options.detached || false,
    });

    return signed as string;
  }

  async verify(options: VerifyOptions): Promise<{ verified: boolean; signedBy?: string }> {
    // Convert candidate public keys into parsed key objects for OpenPGP.js.
    const publicKeys = await Promise.all(
      options.publicKeys.map(key => openpgp.readKey({ armoredKey: key }))
    );

    // Parse the signed message. For clearsigned text, OpenPGP.js can parse this directly.
    const message = await openpgp.readMessage({ armoredMessage: options.message });

    const verificationResult = await openpgp.verify({
      message,
      verificationKeys: publicKeys,
    });

    // The first signature is used for reporting; multi-signature messages could be extended later.
    const { verified, keyID } = verificationResult.signatures[0];

    try {
      await verified;
      return { verified: true, signedBy: keyID.toHex() };
    } catch {
      return { verified: false };
    }
  }

  async readPublicKeyInfo(armoredKey: string): Promise<{
    fingerprint: string;
    keyId: string;
    userId: string;
    created: Date;
  }> {
    // Parse an armored public key so we can show identity/fingerprint before importing.
    const key = await openpgp.readKey({ armoredKey });
    const user = key.users[0];
    const userId = user?.userID?.userID || 'Unknown';

    return {
      fingerprint: key.getFingerprint(),
      keyId: key.getKeyID().toHex(),
      userId,
      created: key.getCreationTime(),
    };
  }

  async encryptFile(options: FileEncryptOptions): Promise<FileEncryptResult> {
    // Parse recipient public keys.
    const publicKeys = await Promise.all(
      options.publicKeys.map((key) => openpgp.readKey({ armoredKey: key }))
    );

    /**
     * Create a message object from a byte stream.
     *
     * - `binary` accepts a ReadableStream<Uint8Array> which allows streaming encryption
     *   without loading the whole file into memory.
     * - `filename` is optional metadata embedded in the message (useful on decrypt).
     */
    const message = await openpgp.createMessage({
      binary: options.input,
      filename: options.filename,
    });

    const encryptOptions: any = {
      message,
      encryptionKeys: publicKeys,
      format: options.format,
    };

    if (options.sign && options.privateKey && options.passphrase) {
      // Same pattern as message signing: unlock private key and provide as signingKeys.
      const privateKey = await openpgp.decryptKey({
        privateKey: await openpgp.readPrivateKey({ armoredKey: options.privateKey }),
        passphrase: options.passphrase,
      });
      encryptOptions.signingKeys = privateKey;
    }

    // OpenPGP.js returns either streams or fully-buffered values depending on environment/format.
    const encrypted = await openpgp.encrypt(encryptOptions);
    return encrypted as FileEncryptResult;
  }

  async decryptFile(options: FileDecryptOptions): Promise<FileDecryptResult> {
    /**
     * Parse the encrypted message.
     * - Armored input is a text stream (ReadableStream<string>).
     * - Binary input is a byte stream (ReadableStream<Uint8Array>).
     */
    const message =
      options.inputFormat === 'armored'
        ? await openpgp.readMessage({
            armoredMessage: options.input as ReadableStream<string>,
          })
        : await openpgp.readMessage({
            binaryMessage: options.input as ReadableStream<Uint8Array>,
          });

    // Unlock the private key so OpenPGP.js can use it for decryption.
    const privateKey = await openpgp.decryptKey({
      privateKey: await openpgp.readPrivateKey({ armoredKey: options.privateKey }),
      passphrase: options.passphrase || '',
    });

    // For file output we force binary, since decrypted files are bytes.
    const decryptOptions: any = {
      message,
      decryptionKeys: privateKey,
      format: 'binary',
    };

    if (options.verifySignature && options.publicKeys) {
      // Optional signature verification, using known public keys.
      const publicKeys = await Promise.all(
        options.publicKeys.map((key) => openpgp.readKey({ armoredKey: key }))
      );
      decryptOptions.verificationKeys = publicKeys;
    }

    // Decrypt to bytes; OpenPGP.js may return a stream or a Uint8Array.
    const { data, signatures, filename } = await openpgp.decrypt(decryptOptions);

    // Normalize signature verification into an optional boolean.
    let verified = undefined;
    if (signatures && signatures.length > 0) {
      try {
        await signatures[0].verified;
        verified = true;
      } catch {
        verified = false;
      }
    }

    return {
      data: data as ReadableStream<Uint8Array> | Uint8Array,
      verified,
      // If the sender embedded a filename during encryption, we surface it for display.
      filename,
    };
  }
}

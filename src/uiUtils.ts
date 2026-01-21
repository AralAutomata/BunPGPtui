import chalk from 'chalk';
import * as clack from '@clack/prompts';

/**
 * UI helper utilities.
 *
 * These functions centralize:
 * - Presentation: consistent header and status messages
 * - Formatting: fingerprints, truncation, etc.
 * - Clipboard access: best-effort integration on macOS/Linux
 *
 * The `Menu` class uses these helpers to keep interaction code readable.
 */
export const displayHeader = () => {
  // Clear the screen to make this feel like a "full-screen-ish" TUI.
  console.clear();
  console.log(chalk.bold.cyan('\n╔════════════════════════════════════╗'));
  console.log(chalk.bold.cyan('║        TUI PGP Tool v1.0.0         ║'));
  console.log(chalk.bold.cyan('╚════════════════════════════════════╝\n'));
};

export const displaySuccess = (message: string) => {
  // clack provides consistent status styling + spacing; we layer chalk colors on top.
  clack.log.success(chalk.green(message));
};

export const displayError = (message: string) => {
  clack.log.error(chalk.red(message));
};

export const displayInfo = (message: string) => {
  clack.log.info(chalk.blue(message));
};

export const displayWarning = (message: string) => {
  clack.log.warn(chalk.yellow(message));
};

export const formatFingerprint = (fingerprint: string): string => {
  // Format fingerprint as: XXXX XXXX XXXX XXXX XXXX  XXXX XXXX XXXX XXXX XXXX
  // This improves readability and matches common OpenPGP tooling conventions.
  return fingerprint
    .toUpperCase()
    .match(/.{1,4}/g)
    ?.join(' ') || fingerprint;
};

export const truncateText = (text: string, maxLength: number): string => {
  // Simple UI utility for long blobs (armored keys/messages) in narrow terminal widths.
  if (text.length <= maxLength) return text;
  return text.substring(0, maxLength - 3) + '...';
};

export const displayKeyInfo = (key: {
  name: string;
  email: string;
  fingerprint: string;
  keyId: string;
  created: Date;
  algorithm: string;
}) => {
  // Human-friendly view of the selected key; used after generating/importing/viewing.
  console.log(chalk.bold('\nKey Information:'));
  console.log(chalk.dim('─'.repeat(50)));
  console.log(chalk.bold('Name:       ') + chalk.white(key.name));
  console.log(chalk.bold('Email:      ') + chalk.white(key.email));
  console.log(chalk.bold('Key ID:     ') + chalk.yellow(key.keyId.toUpperCase()));
  console.log(chalk.bold('Fingerprint:') + chalk.cyan(formatFingerprint(key.fingerprint)));
  console.log(chalk.bold('Algorithm:  ') + chalk.white(key.algorithm.toUpperCase()));
  console.log(chalk.bold('Created:    ') + chalk.white(key.created.toLocaleString()));
  console.log(chalk.dim('─'.repeat(50)) + '\n');
};

export const copyToClipboard = async (text: string): Promise<boolean> => {
  /**
   * Clipboard writes are OS-specific.
   *
   * We implement a best-effort approach:
   * - macOS: `pbcopy`
   * - Linux: `xclip -selection clipboard`
   *
   * This is intentionally dependency-free: no native modules, no extra packages.
   *
   * Note: Clipboard content may be visible to other processes; treat it as sensitive.
   */
  const writeToClipboard = async (
    command: string,
    args: string[]
  ): Promise<boolean> => {
    // Spawn a process and stream the text into its stdin.
    const proc = Bun.spawn([command, ...args], {
      stdin: 'pipe',
    });

    const stdin = proc.stdin;
    if (!stdin || typeof stdin === 'number') return false;

    // Bun's stream writer APIs can return Promises depending on buffering.
    const writeResult = stdin.write(text);
    if (writeResult instanceof Promise) await writeResult;

    const endResult = stdin.end();
    if (endResult instanceof Promise) await endResult;

    // Exit code 0 indicates the clipboard program accepted the input.
    const exitCode = await proc.exited;
    return exitCode === 0;
  };

  try {
    if (await writeToClipboard('pbcopy', [])) return true;
  } catch {
    // Ignore and try the Linux fallback.
  }

  try {
    if (await writeToClipboard('xclip', ['-selection', 'clipboard'])) return true;
  } catch {
    return false;
  }

  return false;
};

export const readFromClipboard = async (): Promise<string | null> => {
  /**
   * Clipboard reads mirror the write strategy:
   * - macOS: `pbpaste`
   * - Linux: `xclip -selection clipboard -o`
   */
  const readClipboard = async (
    command: string,
    args: string[]
  ): Promise<string | null> => {
    // Spawn the process and capture stdout; ignore stderr to reduce noisy output.
    const proc = Bun.spawn([command, ...args], {
      stdout: 'pipe',
      stderr: 'ignore',
    });

    const stdout = proc.stdout;
    if (!stdout) return null;

    // Convert the stdout stream into a string.
    const output = await new Response(stdout).text();
    const exitCode = await proc.exited;
    if (exitCode !== 0) return null;

    return output;
  };

  try {
    const output = await readClipboard('pbpaste', []);
    if (output && output.trim()) return output;
  } catch {
    // Ignore and try the Linux fallback.
  }

  try {
    const output = await readClipboard('xclip', ['-selection', 'clipboard', '-o']);
    if (output && output.trim()) return output;
  } catch {
    return null;
  }

  return null;
};

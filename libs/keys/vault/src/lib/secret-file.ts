import { closeSync, fstatSync, openSync, readFileSync } from 'node:fs';

import type { KekWarning } from '@qauth-labs/server-keys/custody';
import { InvalidConfigurationError } from '@qauth-labs/shared-errors';

/** Mode bits that let group or others read, write or run a file. */
const OPEN_TO_OTHERS = 0o077;

/** The longest file a token or secret ID is read from, in bytes. */
const MAX_SECRET_FILE_BYTES = 16 * 1024;

/**
 * Read a Vault token or AppRole secret ID from the file `variable` names
 * (ADR-019 Decision 9, #578), trimmed.
 *
 * The file is read again at every login, so an agent or an orchestrator that
 * rewrites it hands QAuth the new value. No message or detail ever carries the
 * file's content.
 *
 * @param warn - receives a warning when group or others can read the file;
 *   pass it at boot only, so the warning is logged once
 * @throws InvalidConfigurationError naming the variable when the file is
 *   missing, unreadable, not a regular file, empty or too large
 */
export function readSecretFile(
  path: string,
  variable: string,
  warn?: (warning: KekWarning) => void
): string {
  let fd: number;
  try {
    fd = openSync(path, 'r');
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    throw new InvalidConfigurationError(
      code === 'ENOENT'
        ? `The file ${variable} names does not exist.`
        : code === 'EACCES'
          ? `The file ${variable} names cannot be read: permission denied.`
          : `The file ${variable} names could not be opened. See this error's "details" for the reason.`,
      { variable, path, code }
    );
  }

  try {
    // Checked on the open descriptor, so the file checked is the file read.
    const stat = fstatSync(fd);
    if (!stat.isFile()) {
      throw new InvalidConfigurationError(`${variable} must name a regular file.`, {
        variable,
        path,
      });
    }
    if (stat.size > MAX_SECRET_FILE_BYTES) {
      throw new InvalidConfigurationError(
        `The file ${variable} names is larger than ${MAX_SECRET_FILE_BYTES} bytes; it must hold only the value.`,
        { variable, path }
      );
    }
    if (warn !== undefined && process.platform !== 'win32' && (stat.mode & OPEN_TO_OTHERS) !== 0) {
      warn({
        variable,
        message: `${variable} names a file that group or others can read or write (mode ${(stat.mode & 0o777).toString(8)}). Restrict it to its owner, for example with \`chmod 600\`.`,
      });
    }
    const text = readFileSync(fd, 'utf8').trim();
    if (text === '') {
      throw new InvalidConfigurationError(`The file ${variable} names is empty.`, {
        variable,
        path,
      });
    }
    // Vault tokens and secret IDs are printable ASCII; anything else could not
    // be sent in a header and would fail every call as if Vault were down.
    if (!/^[\x21-\x7e]+$/.test(text)) {
      throw new InvalidConfigurationError(
        `The file ${variable} names must hold one value of printable ASCII characters, with no spaces or line breaks inside it.`,
        { variable, path }
      );
    }
    return text;
  } finally {
    closeSync(fd);
  }
}

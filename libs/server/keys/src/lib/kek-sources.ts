import { createHash, createSecretKey, type KeyObject, timingSafeEqual } from 'node:crypto';
import { closeSync, fstatSync, openSync, readFileSync } from 'node:fs';

import { InvalidConfigurationError } from '@qauth-labs/shared-errors';

import type { KekEnv, KekWarning } from './kek-provider';

/**
 * Reading the default provider's KEKs from the environment (ADR-019
 * Decision 9).
 *
 * A KEK is the base64 encoding of 32 random bytes, in a variable or in a file
 * a `*_PATH` variable names. The file wins over the variable, as it does for
 * `JWT_PRIVATE_KEY_PATH`. Generate one with `openssl rand -base64 32`.
 *
 * Nothing here logs or reports a KEK. Errors and warnings name the variable and
 * never carry its value.
 */

/** A KEK is 256 bits. */
export const KEK_BYTES = 32;

/**
 * The development KEK: the base64 of `qauth-dev-kek-never-in-prod-0001`.
 *
 * Used when `KEK` and `KEK_PATH` are both unset outside production, so a local
 * stack needs no setup. It is published here, so a key wrapped with it is not
 * protected. `NODE_ENV=production` refuses it as `KEK` and as `KEK_PREVIOUS`,
 * the way the auth server refuses `DEV_SESSION_COOKIE_SECRET_DEFAULT`.
 */
export const DEV_KEK_DEFAULT = 'cWF1dGgtZGV2LWtlay1uZXZlci1pbi1wcm9kLTAwMDE=';

/** The bytes of the fingerprint: the first 8 of the KEK's SHA-256. */
const KEK_REF_BYTES = 8;

/**
 * The `kekRef` of a KEK: the first 8 bytes of its SHA-256, in lowercase hex.
 *
 * Short and safe to store and log. The KEK it was computed from is not.
 */
export function computeKekRef(kek: Uint8Array): string {
  return createHash('sha256').update(kek).digest().subarray(0, KEK_REF_BYTES).toString('hex');
}

/** One KEK as the provider holds it. */
export interface LocalKek {
  /** The KEK, as a key object: inspecting or logging it shows no bytes. */
  readonly key: KeyObject;
  /** Its fingerprint. See {@link computeKekRef}. */
  readonly ref: string;
}

/** A pair of variables that set one KEK. */
interface KekSetting {
  readonly variable: string;
  readonly pathVariable: string;
}

const CURRENT: KekSetting = { variable: 'KEK', pathVariable: 'KEK_PATH' };
const PREVIOUS: KekSetting = { variable: 'KEK_PREVIOUS', pathVariable: 'KEK_PREVIOUS_PATH' };

/** Standard base64, padding optional. */
const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;

/** Group-read and other-read permission bits. */
const READABLE_BY_OTHERS = 0o044;

/** Decode a KEK, or refuse one that is not base64 of exactly 32 bytes. */
function decodeKek(text: string, variable: string): Buffer {
  const bytes = BASE64.test(text) ? Buffer.from(text, 'base64') : undefined;
  // Node's decoder skips characters it does not expect, so a value is accepted
  // only when it is exactly what encoding its bytes gives back.
  if (
    bytes === undefined ||
    bytes.toString('base64').replace(/=+$/, '') !== text.replace(/=+$/, '')
  ) {
    throw new InvalidConfigurationError(
      `${variable} must be the base64 encoding of ${KEK_BYTES} random bytes, for example from \`openssl rand -base64 ${KEK_BYTES}\`.`,
      { variable }
    );
  }
  if (bytes.length !== KEK_BYTES) {
    const length = bytes.length;
    bytes.fill(0);
    throw new InvalidConfigurationError(
      `${variable} must decode to exactly ${KEK_BYTES} bytes, a 256-bit key. See this error's "details" for the length it has.`,
      { variable, bytes: length }
    );
  }
  return bytes;
}

/** Read the base64 text of a KEK file, warning when others can read the file. */
function readKekFile(
  path: string,
  pathVariable: string,
  warn: (warning: KekWarning) => void
): string {
  let fd: number;
  try {
    fd = openSync(path, 'r');
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    throw new InvalidConfigurationError(
      code === 'ENOENT'
        ? `The file ${pathVariable} names does not exist.`
        : code === 'EACCES'
          ? `The file ${pathVariable} names cannot be read: permission denied.`
          : `The file ${pathVariable} names could not be opened. See this error's "details" for the reason.`,
      { variable: pathVariable, path, code }
    );
  }

  try {
    // Checked on the open descriptor, so the file checked is the file read.
    const stat = fstatSync(fd);
    if (!stat.isFile()) {
      throw new InvalidConfigurationError(`${pathVariable} must name a regular file.`, {
        variable: pathVariable,
        path,
      });
    }
    if (process.platform !== 'win32' && (stat.mode & READABLE_BY_OTHERS) !== 0) {
      warn({
        variable: pathVariable,
        message: `${pathVariable} names a file that group or others can read (mode ${(stat.mode & 0o777).toString(8)}). Restrict it to its owner, for example with \`chmod 600\`.`,
      });
    }
    const text = readFileSync(fd, 'utf8').trim();
    if (text === '') {
      throw new InvalidConfigurationError(`The file ${pathVariable} names is empty.`, {
        variable: pathVariable,
        path,
      });
    }
    return text;
  } finally {
    closeSync(fd);
  }
}

/**
 * Read one KEK setting: the file when its `*_PATH` variable is set, else the
 * variable. A blank value counts as unset, since Docker Compose passes an
 * absent variable as `''`.
 *
 * @returns the KEK bytes, or `undefined` when neither variable is set. The
 *   caller zeroes them once they are in a key object.
 */
function readKekSetting(
  env: KekEnv,
  setting: KekSetting,
  warn: (warning: KekWarning) => void
): { readonly bytes: Buffer; readonly variable: string } | undefined {
  const path = env[setting.pathVariable]?.trim();
  if (path) {
    return {
      bytes: decodeKek(readKekFile(path, setting.pathVariable, warn), setting.pathVariable),
      variable: setting.pathVariable,
    };
  }
  const value = env[setting.variable]?.trim();
  if (value) {
    return { bytes: decodeKek(value, setting.variable), variable: setting.variable };
  }
  return undefined;
}

function toLocalKek(bytes: Buffer): LocalKek {
  const kek = Object.freeze({ key: createSecretKey(bytes), ref: computeKekRef(bytes) });
  bytes.fill(0);
  return kek;
}

/** Refuse the development KEK in production, zeroing the bytes first. */
function refuseDevelopmentKek(
  kek: { readonly bytes: Buffer; readonly variable: string },
  production: boolean
): void {
  if (production && timingSafeEqual(kek.bytes, Buffer.from(DEV_KEK_DEFAULT, 'base64'))) {
    kek.bytes.fill(0);
    throw new InvalidConfigurationError(
      `${kek.variable} holds the published development KEK, which NODE_ENV=production does not allow. Generate a KEK with \`openssl rand -base64 ${KEK_BYTES}\`.`,
      { variable: kek.variable }
    );
  }
}

/** The KEKs the default provider holds. */
export interface LocalKeks {
  /** Wraps every new data key. */
  readonly current: LocalKek;
  /** Still unwraps data keys wrapped before a KEK rotation. */
  readonly previous: LocalKek | undefined;
}

/**
 * Read `KEK` or `KEK_PATH`, and `KEK_PREVIOUS` or `KEK_PREVIOUS_PATH`.
 *
 * - The file wins over the variable.
 * - A KEK that is not base64 of exactly 32 bytes is refused.
 * - A file that group or others can read gives a warning.
 * - With neither `KEK` nor `KEK_PATH` set, outside production, the KEK is
 *   {@link DEV_KEK_DEFAULT}, with a warning.
 * - `NODE_ENV=production` refuses a missing KEK and the development KEK.
 *
 * @throws InvalidConfigurationError naming the variable at fault
 */
export function readLocalKeks(env: KekEnv, warn: (warning: KekWarning) => void): LocalKeks {
  const production = env['NODE_ENV'] === 'production';

  const configured = readKekSetting(env, CURRENT, warn);
  if (configured === undefined && production) {
    throw new InvalidConfigurationError(
      'KEK or KEK_PATH must be set when NODE_ENV=production; the development KEK is not allowed there.',
      { variable: CURRENT.variable }
    );
  }
  if (configured === undefined) {
    warn({
      variable: CURRENT.variable,
      message:
        'KEK and KEK_PATH are unset, so keys are wrapped with the published development KEK. Set a KEK before this deployment stores real keys; NODE_ENV=production refuses the development KEK.',
    });
  }
  const current = configured ?? {
    bytes: Buffer.from(DEV_KEK_DEFAULT, 'base64'),
    variable: CURRENT.variable,
  };

  refuseDevelopmentKek(current, production);

  let previous: ReturnType<typeof readKekSetting>;
  try {
    previous = readKekSetting(env, PREVIOUS, warn);
    if (previous !== undefined) refuseDevelopmentKek(previous, production);
  } catch (error) {
    current.bytes.fill(0);
    throw error;
  }

  if (previous !== undefined && timingSafeEqual(previous.bytes, current.bytes)) {
    warn({
      variable: previous.variable,
      message: `${previous.variable} holds the same KEK as the current one, so it opens nothing more. Remove it, or set it to the KEK in use before the rotation.`,
    });
  }

  return Object.freeze({
    current: toLocalKek(current.bytes),
    previous: previous === undefined ? undefined : toLocalKek(previous.bytes),
  });
}

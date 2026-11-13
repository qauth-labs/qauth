import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

import {
  type Clock,
  SYSTEM_CLOCK,
  TOTP_SEALED_MAX_LENGTH,
  type TotpAccount,
  type TotpBinding,
  type TotpCredentials,
  type TotpDisplay,
  type TotpEnrolmentStart,
  type TotpSetupCheck,
  type TotpVerification,
} from './ports';
import type { RandomBytes } from './recovery-codes';

/**
 * TOTP (#653; ADR-017 Decisions 7 and 8, ADR-020 §3, RFC 6238): a second
 * factor an authenticator app answers with a code that changes every 30
 * seconds. The parameters are fixed: HMAC-SHA-1, 6 digits, a 30-second step
 * and one step of tolerance either way. Other values break common
 * authenticator apps without a real security gain (ADR-020 §3).
 *
 * The secret is 160 bits from a CSPRNG (RFC 4226 §4 asks for at least 128,
 * and recommends 160), shown as unpadded uppercase base32 (RFC 4648 §6) and as
 * an `otpauth://` URI. It is reversible, so it is stored only as a
 * `data_at_rest` ciphertext of the realm (ADR-019 Decision 9), through a
 * {@link TotpCipher}: this module never writes, logs or returns it in clear,
 * except as the set-up step's personal data, which the round's answer alone
 * carries. Each credential keeps the last time step it accepted, and a code
 * for that step or an earlier one is refused, so an accepted value is never
 * accepted twice (RFC 6238 §5.2).
 */

/** The HMAC algorithm (ADR-020 §3): what the `totp_setup` step's params say. */
export const TOTP_ALGORITHM = 'SHA1';
/** The digits of a code (ADR-020 §3). */
export const TOTP_DIGITS = 6;
/** The seconds of a time step (ADR-020 §3). */
export const TOTP_PERIOD_SECONDS = 30;
/** The steps of tolerance either way (ADR-020 §3): a code of the step before or after now is valid too. */
export const TOTP_TOLERANCE_STEPS = 1;
/** The bytes of a secret: 160 bits. */
export const TOTP_SECRET_BYTES = 20;

/** The longest issuer and account names an `otpauth://` URI's label carries, in characters. */
const LABEL_PART_MAX = 128;

/** A code as the step grammar reads it: exactly six digits. */
const CODE_PATTERN = /^[0-9]{6}$/;

/** RFC 4648 §6's base32 alphabet. */
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** Encode `bytes` in uppercase base32, with no padding: 20 bytes make 32 characters. */
export function base32Encode(bytes: Uint8Array): string {
  let out = '';
  let buffer = 0;
  let bits = 0;
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32_ALPHABET[(buffer >>> (bits - 5)) & 31];
      bits -= 5;
    }
    buffer &= (1 << bits) - 1;
  }
  if (bits > 0) out += BASE32_ALPHABET[(buffer << (5 - bits)) & 31];
  return out;
}

/** The time step `nowMs` falls in: whole periods since the Unix epoch (RFC 6238 §4.2, T0 = 0). */
export function totpStep(nowMs: number): number {
  return Math.floor(nowMs / 1000 / TOTP_PERIOD_SECONDS);
}

/**
 * The HOTP value of `secret` for `counter` (RFC 4226 §5.3): HMAC-SHA-1 over
 * the 8-byte big-endian counter, dynamically truncated, modulo 10^6, padded
 * with zeros to six digits.
 */
export function hotp(secret: Uint8Array, counter: number): string {
  if (!Number.isSafeInteger(counter) || counter < 0) throw new Error('totp: a bad counter');
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  const mac = createHmac('sha1', secret).update(message).digest();
  const offset = (mac[mac.length - 1] as number) & 0x0f;
  const binary = mac.readUInt32BE(offset) & 0x7fffffff;
  return String(binary % 10 ** TOTP_DIGITS).padStart(TOTP_DIGITS, '0');
}

/** The code of `secret` for the time step `step`. */
export function totpCode(secret: Uint8Array, step: number): string {
  return hotp(secret, step);
}

/**
 * The time step `code` is valid for, within {@link TOTP_TOLERANCE_STEPS} of
 * the step `nowMs` falls in and later than `lastStep`, or `null`. Every step
 * of the window is computed and compared in constant time, whatever matched,
 * so the time says nothing of which step a code was for. A code of a step at
 * or before `lastStep` is refused: an accepted value is never accepted twice.
 *
 * @param lastStep - the last step the credential accepted; `-1` for a secret
 *   that accepted none yet
 */
export function matchTotpCode(
  secret: Uint8Array,
  code: string,
  nowMs: number,
  lastStep: number
): number | null {
  const presented = Buffer.from(CODE_PATTERN.test(code) ? code : '000000', 'utf8');
  const now = totpStep(nowMs);
  let matched: number | null = null;
  for (let step = now - TOTP_TOLERANCE_STEPS; step <= now + TOTP_TOLERANCE_STEPS; step += 1) {
    if (step < 0) continue;
    const equal = timingSafeEqual(Buffer.from(totpCode(secret, step), 'utf8'), presented);
    if (equal && step > lastStep && matched === null) matched = step;
  }
  return CODE_PATTERN.test(code) ? matched : null;
}

/**
 * The `otpauth://totp/` URI of a secret, for an authenticator app's QR code
 * (the de-facto Key URI Format): the label `issuer:account`, and the
 * secret, the issuer and the fixed parameters as query parameters. Every
 * part is percent-encoded, so the URI holds only the characters the step
 * grammar's pattern allows.
 */
export function otpauthUri(input: {
  readonly secret: string;
  readonly issuer: string;
  readonly account: string;
}): string {
  const issuer = encodeURIComponent(input.issuer.slice(0, LABEL_PART_MAX));
  const account = encodeURIComponent(input.account.slice(0, LABEL_PART_MAX));
  const query = [
    `secret=${input.secret}`,
    `issuer=${issuer}`,
    `algorithm=${TOTP_ALGORITHM}`,
    `digits=${TOTP_DIGITS}`,
    `period=${TOTP_PERIOD_SECONDS}`,
  ].join('&');
  return `otpauth://totp/${issuer}:${account}?${query}`;
}

/**
 * Where a secret is sealed and opened: the signer's `data_at_rest` key of the
 * realm (ADR-019 Decision 9), under a context that names the realm and the
 * user, so a ciphertext opens only for the account it was made for. A throw
 * is an outage, which refuses the round.
 */
export interface TotpCipher {
  /** The secret as a `data_at_rest` ciphertext. */
  seal(input: TotpAccount & { readonly secret: Uint8Array }): Promise<string>;
  /** The secret a ciphertext {@link seal} made for the same account holds. */
  open(input: TotpAccount & { readonly sealed: string }): Promise<Uint8Array>;
}

/** One account's TOTP, as the store holds it. */
export interface StoredTotp {
  /** The secret's ciphertext. */
  readonly sealed: string;
  /** The last time step it accepted. */
  readonly lastStep: number;
  /** Whether the ladder's hard action disabled it (`user_credentials.disabled_at`). */
  readonly disabled: boolean;
}

/** Where the accounts' TOTPs live: the auth server's are `user_credentials` rows of the type `totp`. */
export interface TotpStore {
  /** The account's TOTP, or `null` when it holds none. */
  read(account: TotpAccount): Promise<StoredTotp | null>;
  /**
   * Move the TOTP's last accepted step forward to `step`, in one write that
   * only an enabled TOTP whose last step is lower passes: `true` when this
   * call took the step, `false` when another round took it (or a later one)
   * first, or the TOTP is disabled or gone.
   */
  accept(account: TotpAccount & { readonly step: number }): Promise<boolean>;
  /**
   * Bind `sealed` as the account's TOTP, with `step` as its last accepted
   * step, replacing one it holds (a disabled one, after a recovery code), in
   * one write, while the account is enabled and claimed. `isNew` (#1064):
   * the store records when the TOTP stops being new, the realm's
   * `accounts.newFactorWindowDays` from now, and returns its credential id.
   */
  bind(
    account: TotpAccount & {
      readonly sealed: string;
      readonly step: number;
      readonly isNew?: boolean;
    }
  ): Promise<TotpBinding>;
}

/** What the TOTP's notices and hard action need: the auth server mails, disables and counts. */
export interface TotpNotices {
  /** A TOTP was bound: the "TOTP added" notice, which no realm can switch off. */
  bound(input: TotpAccount & { readonly clientId: string }): Promise<void>;
  /** See {@link TotpCredentials.ceilingReached}. */
  ceilingReached(input: TotpAccount): Promise<void>;
  /** See {@link TotpCredentials.failedAfterPassword}. */
  failedAfterPassword(input: TotpAccount & { readonly clientId: string }): Promise<void>;
}

/** What {@link createTotpService} is built from. */
export interface TotpServiceDependencies {
  readonly store: TotpStore;
  readonly cipher: TotpCipher;
  readonly notices: TotpNotices;
  /** The issuer name an authenticator app shows beside the account: the realm's. */
  readonly issuerOf: (realmId: string) => Promise<string>;
  /** A notice that failed after a binding: reported, and the binding stands. */
  readonly report?: (error: unknown, what: string) => void;
  readonly clock?: Clock;
  /** The source of random bytes; a CSPRNG. Tests only. */
  readonly random?: RandomBytes;
}

/** A ciphertext the cipher returned, checked: anything else is a store fault. */
function checkedSealed(sealed: unknown): string {
  if (typeof sealed !== 'string' || sealed.length === 0 || sealed.length > TOTP_SEALED_MAX_LENGTH) {
    throw new Error('totp: not a ciphertext');
  }
  return sealed;
}

/**
 * The engine's TOTP port over a store and a cipher.
 *
 * - `verify` opens the account's secret, matches the code within the window
 *   and later than the last accepted step, and takes the step in one write
 *   only a lower last step passes: two rounds with the same code take it
 *   once. A disabled TOTP, or none, refuses every code; a code that cannot
 *   be one is matched as long.
 * - `start` draws a new secret and seals it at once: the transaction keeps
 *   the ciphertext, and the round shows the secret. `display` opens a held
 *   ciphertext to show it again. `check` matches a first code against a held
 *   ciphertext, with no last step, and binds nothing.
 * - `bind` binds a held ciphertext with the step its first code matched, then
 *   sends the "TOTP added" notice; a notice that fails is reported.
 *
 * Each opened secret is overwritten once it is used.
 */
export function createTotpService(deps: TotpServiceDependencies): TotpCredentials {
  const { store, cipher, notices } = deps;
  const clock = deps.clock ?? SYSTEM_CLOCK;
  const random = deps.random ?? randomBytes;
  const open = async (account: TotpAccount, sealed: string): Promise<Uint8Array> => {
    const secret: unknown = await cipher.open({ ...account, sealed });
    if (!(secret instanceof Uint8Array) || secret.length !== TOTP_SECRET_BYTES) {
      throw new Error('totp: the ciphertext holds no secret');
    }
    return secret;
  };
  const displayOf = async (
    { realmId }: TotpAccount,
    identifier: string,
    secret: Uint8Array
  ): Promise<TotpDisplay> => {
    const text = base32Encode(secret);
    const issuer = await deps.issuerOf(realmId);
    return Object.freeze({
      secret: text,
      otpauthUri: otpauthUri({ secret: text, issuer, account: identifier }),
    });
  };
  const refused: TotpVerification = Object.freeze({ kind: 'refused' });

  const service: TotpCredentials = {
    async verify({ realmId, userId, code }): Promise<TotpVerification> {
      const account = { realmId, userId };
      const stored = await store.read(account);
      if (stored === null || stored.disabled) return refused;
      const secret = await open(account, stored.sealed);
      try {
        const step = matchTotpCode(secret, code, clock.now(), stored.lastStep);
        if (step === null) return refused;
        return (await store.accept({ ...account, step }))
          ? Object.freeze({ kind: 'accepted' })
          : refused;
      } finally {
        secret.fill(0);
      }
    },

    async start({ realmId, userId, identifier }): Promise<TotpEnrolmentStart> {
      const account = { realmId, userId };
      const drawn = random(TOTP_SECRET_BYTES);
      const secret = Uint8Array.from(drawn);
      drawn.fill(0);
      if (secret.length !== TOTP_SECRET_BYTES) throw new Error('totp: short random');
      try {
        const sealed = checkedSealed(await cipher.seal({ ...account, secret }));
        return Object.freeze({ sealed, display: await displayOf(account, identifier, secret) });
      } finally {
        secret.fill(0);
      }
    },

    async display({ realmId, userId, identifier, sealed }): Promise<TotpDisplay> {
      const account = { realmId, userId };
      const secret = await open(account, sealed);
      try {
        return await displayOf(account, identifier, secret);
      } finally {
        secret.fill(0);
      }
    },

    async check({ realmId, userId, sealed, code }): Promise<TotpSetupCheck> {
      const secret = await open({ realmId, userId }, sealed);
      try {
        const step = matchTotpCode(secret, code, clock.now(), -1);
        return step === null
          ? Object.freeze({ kind: 'refused' })
          : Object.freeze({ kind: 'valid', step });
      } finally {
        secret.fill(0);
      }
    },

    async bind({ realmId, userId, clientId, sealed, step, isNew }): Promise<TotpBinding> {
      // The ciphertext opens for this account, or nothing is bound.
      (await open({ realmId, userId }, sealed)).fill(0);
      const bound = await store.bind({
        realmId,
        userId,
        sealed,
        step,
        ...(isNew === true ? { isNew: true } : {}),
      });
      if (bound.kind === 'bound') {
        try {
          await notices.bound({ realmId, userId, clientId });
        } catch (error) {
          deps.report?.(error, 'the TOTP-added notice');
        }
      }
      return bound;
    },

    ceilingReached: (input: TotpAccount) => notices.ceilingReached(input),

    failedAfterPassword: (input: TotpAccount & { readonly clientId: string }) =>
      notices.failedAfterPassword(input),
  };
  return Object.freeze(service);
}

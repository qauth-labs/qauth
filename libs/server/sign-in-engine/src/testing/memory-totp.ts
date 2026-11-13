import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

import type { Clock, TotpAccount, TotpBinding, TotpCredentials } from '../lib/ports';
import {
  createTotpService,
  type StoredTotp,
  TOTP_SECRET_BYTES,
  type TotpCipher,
  totpCode,
  type TotpNotices,
  totpStep,
  type TotpStore,
} from '../lib/totp';

/**
 * TEST SUPPORT — TOTPs in memory (#653): {@link createTotpService} itself,
 * over a store with the auth server's rules (one TOTP per account, a step
 * taken in one conditional write, a binding that replaces the TOTP held), an
 * AES-256-GCM cipher whose key lives in the memory and whose associated data
 * names the account, and notices that are only recorded. Not for production:
 * nothing is shared between processes, and the key dies with the memory.
 */

/** One account's TOTP, as the memory holds it. */
export interface MemoryTotpRow extends StoredTotp {
  readonly realmId: string;
  readonly userId: string;
  /** Whether the binding that wrote it was new (#1064). */
  readonly isNew?: boolean;
}

/** A notice the memory recorded, in order. */
export interface MemoryTotpNotice {
  readonly kind: 'bound' | 'ceiling_reached' | 'failed_after_password';
  readonly realmId: string;
  readonly userId: string;
}

export interface MemoryTotp extends TotpCredentials {
  /** Every account's TOTP, by `realm:user`. */
  readonly rows: Map<string, MemoryTotpRow>;
  /** Every notice, in order. */
  readonly notices: MemoryTotpNotice[];
  /** Every ciphertext the cipher made, in order. */
  readonly sealed: string[];
  /** Every failure the service reported, as `what: message`. */
  readonly reports: string[];
  /**
   * Bind a TOTP to `userId` with `secret` (a new one by default), as a set-up
   * would have: its last accepted step is two before now, so every code of
   * the window is open. Returns the
   * secret, for the test to compute codes.
   */
  enrol(userId: string, options?: { realmId?: string; secret?: Uint8Array }): Uint8Array;
  /** The secret of the TOTP `userId` holds, opened. */
  secretOf(userId: string, realmId?: string): Uint8Array;
  /** The code of `secret` for the step `offset` steps from now. */
  codeFor(secret: Uint8Array, offset?: number): string;
  /**
   * The hard action at the ceiling: `true` (the default) disables the TOTP,
   * as the auth server does while it is armed; `false` leaves it, as when it
   * is not.
   */
  armed: boolean;
  /** Called once a TOTP is bound or disabled, for the test's directory to show it. */
  onChange?: (row: MemoryTotpRow) => void;
  /** What a binding finds instead of binding: the account is disabled, gone or unclaimed. */
  bindRefusal?: Extract<TotpBinding, { kind: 'refused' }>['reason'];
  /** Make the next notice of this kind throw, once. */
  failNext?: MemoryTotpNotice['kind'];
  /**
   * Name the credential a binding wrote, as the auth server's store does
   * (#1064): `totp:<realm>:<user>`. Off by default, as before #1064.
   */
  namesCredentials?: boolean;
}

const keyOf = ({ realmId, userId }: TotpAccount) => `${realmId}:${userId}`;
const contextOf = ({ realmId, userId }: TotpAccount) => `totp-secret:${realmId}:${userId}`;

/** An AES-256-GCM cipher in memory, in the signer's `v1.<kid>.<iv>.<ct+tag>` shape; synchronous under the port. */
function memoryCipher(sealed: string[]) {
  const key = randomBytes(32);
  const sealNow = (account: TotpAccount, secret: Uint8Array): string => {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    cipher.setAAD(Buffer.from(contextOf(account), 'utf8'));
    const body = Buffer.concat([cipher.update(secret), cipher.final(), cipher.getAuthTag()]);
    const out = `v1.memory.${iv.toString('base64url')}.${body.toString('base64url')}`;
    sealed.push(out);
    return out;
  };
  const openNow = (account: TotpAccount, value: string): Uint8Array => {
    const [version, kid, iv, body] = value.split('.');
    if (version !== 'v1' || kid !== 'memory' || iv === undefined || body === undefined) {
      throw new Error('memory cipher: not a ciphertext');
    }
    const bytes = Buffer.from(body, 'base64url');
    const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'base64url'));
    decipher.setAAD(Buffer.from(contextOf(account), 'utf8'));
    decipher.setAuthTag(bytes.subarray(bytes.length - 16));
    return new Uint8Array(
      Buffer.concat([decipher.update(bytes.subarray(0, bytes.length - 16)), decipher.final()])
    );
  };
  const port: TotpCipher = {
    seal: async (input) => sealNow(input, input.secret),
    open: async (input) => openNow(input, input.sealed),
  };
  return { port, sealNow, openNow };
}

/** TOTPs in memory, on `clock`. */
export function createMemoryTotp(
  clock: Clock,
  options: { readonly issuer?: string } = {}
): MemoryTotp {
  const rows = new Map<string, MemoryTotpRow>();
  const notices: MemoryTotpNotice[] = [];
  const sealed: string[] = [];
  const reports: string[] = [];
  const cipher = memoryCipher(sealed);
  // The fields a test sets after the build, read at each call.
  const memory = { armed: true } as Pick<
    MemoryTotp,
    'armed' | 'onChange' | 'bindRefusal' | 'failNext' | 'namesCredentials'
  >;
  const put = (row: MemoryTotpRow) => {
    rows.set(keyOf(row), row);
    memory.onChange?.(row);
  };
  const record = async (kind: MemoryTotpNotice['kind'], account: TotpAccount) => {
    if (memory.failNext === kind) {
      memory.failNext = undefined;
      throw new Error(`memory totp: the ${kind} notice failed`);
    }
    notices.push({ kind, realmId: account.realmId, userId: account.userId });
  };
  const store: TotpStore = {
    async read(account) {
      const row = rows.get(keyOf(account));
      return row === undefined
        ? null
        : { sealed: row.sealed, lastStep: row.lastStep, disabled: row.disabled };
    },
    async accept(input) {
      const row = rows.get(keyOf(input));
      if (row === undefined || row.disabled || row.lastStep >= input.step) return false;
      rows.set(keyOf(input), { ...row, lastStep: input.step });
      return true;
    },
    async bind(input) {
      if (memory.bindRefusal !== undefined) {
        return { kind: 'refused', reason: memory.bindRefusal };
      }
      put({
        realmId: input.realmId,
        userId: input.userId,
        sealed: input.sealed,
        lastStep: input.step,
        disabled: false,
        ...(input.isNew === true ? { isNew: true } : {}),
      });
      return memory.namesCredentials === true
        ? { kind: 'bound', credentialId: `totp:${keyOf(input)}` }
        : { kind: 'bound' };
    },
  };
  const totpNotices: TotpNotices = {
    bound: (input) => record('bound', input),
    async ceilingReached(input) {
      const row = rows.get(keyOf(input));
      if (!memory.armed || row === undefined || row.disabled) return;
      put({ ...row, disabled: true });
      await record('ceiling_reached', input);
    },
    failedAfterPassword: (input) => record('failed_after_password', input),
  };
  const service = createTotpService({
    store,
    cipher: cipher.port,
    notices: totpNotices,
    issuerOf: async () => options.issuer ?? 'auth.example.com',
    report: (error, what) => {
      reports.push(`${what}: ${error instanceof Error ? error.message : String(error)}`);
    },
    clock,
  });
  return Object.assign(memory, service, {
    rows,
    notices,
    sealed,
    reports,
    enrol(userId: string, enrolOptions: { realmId?: string; secret?: Uint8Array } = {}) {
      const account = { realmId: enrolOptions.realmId ?? 'realm', userId };
      const secret = enrolOptions.secret ?? new Uint8Array(randomBytes(TOTP_SECRET_BYTES));
      put({
        ...account,
        sealed: cipher.sealNow(account, secret),
        lastStep: totpStep(clock.now()) - 2,
        disabled: false,
      });
      return Uint8Array.from(secret);
    },
    secretOf(userId: string, realmId = 'realm') {
      const row = rows.get(keyOf({ realmId, userId }));
      if (row === undefined) throw new Error('memory totp: no TOTP');
      return cipher.openNow({ realmId, userId }, row.sealed);
    },
    codeFor(secret: Uint8Array, offset = 0) {
      return totpCode(secret, totpStep(clock.now()) + offset);
    },
  }) as MemoryTotp;
}

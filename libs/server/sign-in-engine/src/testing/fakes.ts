import { createHmac } from 'node:crypto';

import type {
  AccountDirectory,
  AddressVerification,
  AddressVerifier,
  BoundFactor,
  EmailCodeDigest,
  IdentifierDigest,
  MfaPolicy,
  MfaPolicyReader,
  PasswordVerifier,
  SignInAccount,
  SignInAuditRecord,
  SignInCandidate,
} from '../lib/ports';
import type { EmailCodeSender, EmailCodeSendOutcome } from '../lib/round';

/**
 * Fakes of the engine's ports, for tests of the engine and of the
 * transports that call it. Each records what it was asked, so a test can
 * prove what the engine did not do (no verification, no read).
 */

/** The hash a {@link FakePasswords} accepts `password` against. */
export function fakeHash(password: string): string {
  return `fake-argon2id$${Buffer.from(password, 'utf8').toString('base64url')}`;
}

/** A password verifier over {@link fakeHash}, counting real and dummy verifications. */
export class FakePasswords implements PasswordVerifier {
  readonly verified: string[] = [];
  decoys = 0;

  async verify(hash: string, presented: string): Promise<boolean> {
    this.verified.push(hash);
    return hash === fakeHash(presented);
  }

  async verifyDecoy(): Promise<void> {
    this.decoys += 1;
  }

  /** How many Argon2id verifications ran, real or dummy. */
  get verifications(): number {
    return this.verified.length + this.decoys;
  }
}

/** One account of a {@link FakeDirectory}: what both of its reads return, in one record. */
export interface FakeAccount {
  readonly userId: string;
  readonly enabled: boolean;
  readonly verified: boolean;
  readonly admin: boolean;
  /** The password, as `SignInCandidate` holds it; `null` for an account without one. */
  readonly password: SignInCandidate['password'];
  /** Every other bound factor: passkeys, TOTP. */
  readonly others: readonly BoundFactor[];
}

/** An account directory over a map of normalised identifiers, recording each read. */
export class FakeDirectory implements AccountDirectory {
  readonly reads: string[] = [];

  constructor(readonly accounts: Map<string, FakeAccount> = new Map()) {}

  async findByIdentifier(realmId: string, identifier: string): Promise<SignInCandidate | null> {
    this.reads.push(`identifier:${realmId}:${identifier}`);
    const account = this.accounts.get(identifier);
    if (account === undefined) return null;
    const { userId, enabled, verified, password } = account;
    return { userId, enabled, verified, password };
  }

  async findByUserId(realmId: string, userId: string): Promise<SignInAccount | null> {
    this.reads.push(`user:${realmId}:${userId}`);
    const account = [...this.accounts.values()].find((entry) => entry.userId === userId);
    if (account === undefined) return null;
    return {
      userId,
      enabled: account.enabled,
      admin: account.admin,
      verified: account.verified,
      factors: [
        ...(account.password === null
          ? []
          : [{ type: 'password' as const, disabled: account.password.disabled }]),
        ...account.others,
      ],
    };
  }
}

/** A policy reader that returns `policy`, counting its reads. */
export class FakePolicy implements MfaPolicyReader {
  reads = 0;

  constructor(public policy: MfaPolicy = { realm: 'off', client: 'off' }) {}

  async read(): Promise<MfaPolicy> {
    this.reads += 1;
    return this.policy;
  }
}

/** The identifier HMAC under a fixed test key. */
export const fakeIdentifierDigest: IdentifierDigest = async ({ realmId, identifier }) =>
  createHmac('sha256', 'sign-in-engine-test-key')
    .update(`${realmId}\u0000${identifier}`)
    .digest('base64url');

/** The email code's HMAC under a fixed test key, as the plugin's digest computes it. */
export const fakeEmailCodeDigest: EmailCodeDigest = async ({ realmId, salt, code }) =>
  createHmac('sha256', 'sign-in-engine-test-email-code-key')
    .update(`${realmId}\u0000${salt}\u0000${code}`)
    .digest('base64url');

/** One code a {@link FakeCodeSender} was handed. */
export type SentCode = Parameters<EmailCodeSender>[0];

/**
 * A capped sender that keeps every code it was handed, as the mailbox would,
 * and answers `outcome` (accepted by default).
 */
export class FakeCodeSender {
  readonly sent: SentCode[] = [];
  outcome: EmailCodeSendOutcome = { kind: 'accepted' };

  readonly send: EmailCodeSender = async (mail) => {
    this.sent.push(Object.freeze({ ...mail }));
    return this.outcome;
  };

  /** The last code mailed. */
  get last(): string {
    const mail = this.sent.at(-1);
    if (mail === undefined) throw new Error('fake sender: no code was sent');
    return mail.code;
  }
}

/**
 * An address verifier over a {@link FakeDirectory}: it marks the account the
 * identifier names verified when it is the user's and enabled, recording
 * each call.
 */
export class FakeAddresses implements AddressVerifier {
  readonly calls: {
    readonly realmId: string;
    readonly userId: string;
    readonly identifier: string;
  }[] = [];

  constructor(readonly directory: FakeDirectory) {}

  async markVerified(input: {
    readonly realmId: string;
    readonly userId: string;
    readonly identifier: string;
  }): Promise<AddressVerification> {
    this.calls.push(Object.freeze({ ...input }));
    const account = this.directory.accounts.get(input.identifier);
    if (account === undefined || account.userId !== input.userId || account.password === null) {
      return { kind: 'refused', reason: 'subject_mismatch' };
    }
    if (!account.enabled) return { kind: 'refused', reason: 'account_disabled' };
    this.directory.accounts.set(input.identifier, { ...account, verified: true });
    return { kind: 'verified' };
  }
}

/** An audit sink that keeps every record. */
export function recordingAudit(): {
  readonly records: SignInAuditRecord[];
  readonly sink: (record: SignInAuditRecord) => Promise<void>;
} {
  const records: SignInAuditRecord[] = [];
  return {
    records,
    sink: async (record) => {
      records.push(record);
    },
  };
}

/** A password-only account: enabled, verified, not an admin. */
export function passwordAccount(
  userId: string,
  password: string,
  overrides: Partial<FakeAccount> = {}
): FakeAccount {
  return {
    userId,
    enabled: true,
    verified: true,
    admin: false,
    password: { disabled: false, hash: fakeHash(password) },
    others: [],
    ...overrides,
  };
}

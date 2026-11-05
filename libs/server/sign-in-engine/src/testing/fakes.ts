import { createHmac } from 'node:crypto';

import {
  createPasswordPolicyValidator,
  type PasswordNormalization,
} from '@qauth-labs/shared-validation';

import type {
  AccountDirectory,
  AccountRegistration,
  AccountRegistrations,
  AccountReset,
  AccountResetOutcome,
  AccountResets,
  AddressVerification,
  AddressVerifier,
  BoundFactor,
  BreachCheckVerdict,
  BreachedPasswordCheck,
  EmailCodeDigest,
  IdentifierDigest,
  MfaPolicy,
  MfaPolicyReader,
  NewPasswordCheck,
  PasswordReplacement,
  PasswordUpdates,
  PasswordVerifier,
  RequiredAction,
  SessionEpochReader,
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
  /** The required actions it holds (#635); none when absent. */
  readonly requiredActions?: readonly RequiredAction[];
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
      requiredActions: [...(account.requiredActions ?? [])],
    };
  }
}

/**
 * A breach list over a set of passwords (#635), recording every password it
 * was asked about. `failure` makes every check fail with it; `throws` makes
 * the port throw.
 */
export class FakeBreachList implements BreachedPasswordCheck {
  readonly checked: { readonly realmId: string; readonly password: string }[] = [];
  failure: Extract<BreachCheckVerdict, { kind: 'failed' }>['failure'] | undefined;
  throws = false;
  off = false;

  constructor(readonly listed: Set<string> = new Set()) {}

  async check(input: {
    readonly realmId: string;
    readonly password: string;
  }): Promise<BreachCheckVerdict> {
    this.checked.push(Object.freeze({ ...input }));
    if (this.throws) throw new Error('fake breach list: down');
    if (this.off) return { kind: 'off' };
    if (this.failure !== undefined) return { kind: 'failed', failure: this.failure };
    return this.listed.has(input.password) ? { kind: 'listed' } : { kind: 'not_listed' };
  }
}

/**
 * The forced update's ports over a {@link FakeDirectory} (#635): the real
 * password policy at `minLength`, and a replacement that rewrites the
 * account's hash and clears its `update_password` required action.
 */
export class FakePasswordUpdates implements PasswordUpdates {
  readonly checks: string[] = [];
  readonly replaced: {
    readonly realmId: string;
    readonly userId: string;
    readonly identifier: string;
    readonly password: string;
    readonly normalization: PasswordNormalization;
  }[] = [];

  constructor(
    readonly directory: FakeDirectory,
    public minimum = 15
  ) {}

  async minLength(): Promise<number> {
    return this.minimum;
  }

  async check(input: {
    readonly realmId: string;
    readonly identifier: string;
    readonly password: string;
  }): Promise<NewPasswordCheck> {
    this.checks.push(input.password);
    const checked = createPasswordPolicyValidator({ minLength: this.minimum }).check(
      input.password,
      { email: input.identifier }
    );
    return checked.valid
      ? { kind: 'accepted', password: checked.password, normalization: checked.normalization }
      : { kind: 'rejected', reasons: checked.reasons };
  }

  async replace(input: {
    readonly realmId: string;
    readonly userId: string;
    readonly identifier: string;
    readonly password: string;
    readonly normalization: PasswordNormalization;
  }): Promise<PasswordReplacement> {
    const account = this.directory.accounts.get(input.identifier);
    if (account === undefined || account.userId !== input.userId || account.password === null) {
      return { kind: 'refused', reason: 'subject_mismatch' };
    }
    if (!account.enabled) return { kind: 'refused', reason: 'account_disabled' };
    this.replaced.push(Object.freeze({ ...input }));
    this.directory.accounts.set(input.identifier, {
      ...account,
      password: {
        disabled: false,
        hash: fakeHash(input.password),
        normalization: input.normalization,
      },
      requiredActions: (account.requiredActions ?? []).filter(
        (action) => action !== 'update_password'
      ),
    });
    return { kind: 'replaced' };
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
 * each call. For an upstream provider's account (`upstream` set, #639) it
 * marks the user's account, whatever its key.
 */
export class FakeAddresses implements AddressVerifier {
  readonly calls: {
    readonly realmId: string;
    readonly userId: string;
    readonly identifier: string;
    readonly upstream?: string;
  }[] = [];

  constructor(readonly directory: FakeDirectory) {}

  async markVerified(input: {
    readonly realmId: string;
    readonly userId: string;
    readonly identifier: string;
    readonly upstream?: string;
  }): Promise<AddressVerification> {
    this.calls.push(Object.freeze({ ...input }));
    if (input.upstream !== undefined) {
      const entry = [...this.directory.accounts].find(([, held]) => held.userId === input.userId);
      if (entry === undefined) return { kind: 'refused', reason: 'subject_mismatch' };
      const [key, held] = entry;
      if (!held.enabled) return { kind: 'refused', reason: 'account_disabled' };
      this.directory.accounts.set(key, { ...held, verified: true });
      return { kind: 'verified' };
    }
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

/**
 * Registration's ports over a {@link FakeDirectory} (#640): a gate that
 * answers `allows`, and a creation that adds a verified password account,
 * recording each call. An address the directory holds, or `conflict`, is a
 * unique-constraint race.
 */
export class FakeRegistrations implements AccountRegistrations {
  allows = true;
  conflict = false;
  readonly gates: { readonly realmId: string; readonly clientId: string }[] = [];
  readonly created: {
    readonly realmId: string;
    readonly clientId: string;
    readonly identifier: string;
    readonly password: string;
    readonly normalization: PasswordNormalization;
    readonly userId: string;
  }[] = [];

  constructor(readonly directory: FakeDirectory) {}

  async allowed(input: { readonly realmId: string; readonly clientId: string }): Promise<boolean> {
    this.gates.push(Object.freeze({ ...input }));
    return this.allows;
  }

  async create(input: {
    readonly realmId: string;
    readonly clientId: string;
    readonly identifier: string;
    readonly password: string;
    readonly normalization: PasswordNormalization;
  }): Promise<AccountRegistration> {
    if (this.conflict || this.directory.accounts.has(input.identifier)) return { kind: 'conflict' };
    const userId = `0199fa20-5e1a-7000-8000-${String(900 + this.created.length).padStart(12, '0')}`;
    this.created.push(Object.freeze({ ...input, userId }));
    this.directory.accounts.set(input.identifier, {
      userId,
      enabled: true,
      verified: true,
      admin: false,
      password: {
        disabled: false,
        hash: fakeHash(input.password),
        normalization: input.normalization,
      },
      others: [],
    });
    return { kind: 'created', userId };
  }
}

/**
 * The reset's ports over a {@link FakeDirectory} (#642): a gate that answers
 * `allows`, and a write that replaces the password of the account the
 * address names when it is the user's and enabled, clearing its disabled
 * mark and its `update_password` action and verifying its address, and
 * advancing the user's epoch in `epochs` at `now()`. Each call is recorded.
 */
export class FakeResets implements AccountResets {
  allows = true;
  readonly gates: { readonly realmId: string; readonly clientId: string }[] = [];
  readonly resets: AccountReset[] = [];

  constructor(
    readonly directory: FakeDirectory,
    readonly epochs?: FakeSessionEpochs,
    readonly now: () => number = Date.now
  ) {}

  async allowed(input: { readonly realmId: string; readonly clientId: string }): Promise<boolean> {
    this.gates.push(Object.freeze({ ...input }));
    return this.allows;
  }

  async reset(input: AccountReset): Promise<AccountResetOutcome> {
    const account = this.directory.accounts.get(input.identifier);
    if (account === undefined || account.userId !== input.userId || account.password === null) {
      return { kind: 'refused', reason: 'subject_mismatch' };
    }
    if (!account.enabled) return { kind: 'refused', reason: 'account_disabled' };
    this.resets.push(Object.freeze({ ...input }));
    this.directory.accounts.set(input.identifier, {
      ...account,
      verified: true,
      password: {
        disabled: false,
        hash: fakeHash(input.password),
        normalization: input.normalization,
      },
      requiredActions: (account.requiredActions ?? []).filter(
        (action) => action !== 'update_password'
      ),
    });
    this.epochs?.advance(input.userId, this.now());
    return { kind: 'reset' };
  }
}

/** Session epochs in memory (#642): `notBefore` is the last advance, recording each read. */
export class FakeSessionEpochs implements SessionEpochReader {
  readonly reads: string[] = [];
  readonly advancedAt = new Map<string, number>();

  advance(userId: string, at: number): void {
    this.advancedAt.set(userId, at);
  }

  async notBefore(input: {
    readonly realmId: string;
    readonly userId: string;
  }): Promise<number | null> {
    this.reads.push(input.userId);
    return this.advancedAt.get(input.userId) ?? null;
  }
}

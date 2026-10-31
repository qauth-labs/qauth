import { createHmac } from 'node:crypto';

import type {
  AccountDirectory,
  IdentifierDigest,
  MfaPolicy,
  MfaPolicyReader,
  PasswordVerifier,
  SignInAccount,
  SignInAuditRecord,
} from '../lib/ports';

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

/** An account directory over a map of normalised identifiers. */
export class FakeDirectory implements AccountDirectory {
  readonly reads: string[] = [];

  constructor(readonly accounts: Map<string, SignInAccount> = new Map()) {}

  async findByIdentifier(realmId: string, identifier: string): Promise<SignInAccount | null> {
    this.reads.push(`${realmId}:${identifier}`);
    return this.accounts.get(identifier) ?? null;
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
  overrides: Partial<SignInAccount> = {}
): SignInAccount {
  return {
    userId,
    enabled: true,
    verified: true,
    admin: false,
    factors: [{ type: 'password', disabled: false, hash: fakeHash(password) }],
    ...overrides,
  };
}

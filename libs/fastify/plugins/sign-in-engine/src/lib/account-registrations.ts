import {
  buildPasswordCredentialData,
  EMAIL_ATTR_KEY,
  PASSWORD_PROVIDER_TYPE,
  SELF_REPORTED_SOURCE,
} from '@qauth-labs/server-federation';
import type { AccountRegistration, AccountRegistrations } from '@qauth-labs/server-sign-in-engine';

/**
 * The repositories a registration writes through, by shape, so this library
 * takes the auth server's decorated repositories as they are and depends on
 * no database library. `Tx` is the database transaction they share.
 */
export interface AccountRegistrationRepositories<Tx> {
  readonly users: {
    /**
     * The account and the credential that creates it, its primary identity
     * (ADR-015 Decision 8, #846), in one call.
     */
    create(
      data: { readonly realmId: string },
      primary: {
        readonly providerType: string;
        readonly externalSub: string;
        readonly credentialData: Record<string, unknown>;
      },
      tx?: Tx
    ): Promise<{ readonly id: string }>;
  };
  readonly userAttributes: {
    upsertMany(
      userId: string,
      attributes: readonly {
        readonly source: string;
        readonly attrKey: string;
        readonly attrValue: string;
        readonly verified: boolean;
        readonly expiresAt?: number | null;
      }[],
      tx?: Tx
    ): Promise<unknown>;
  };
}

/** One database transaction: `work` commits with it, and a throw rolls it back. */
export type AccountRegistrationTransaction<Tx> = <T>(work: (tx: Tx) => Promise<T>) => Promise<T>;

/** What a registration reads of the realm and the client, and how it hashes and records. */
export interface AccountRegistrationPolicy<Tx> {
  /** Whether the realm and the client both allow registration (#640). */
  allowed(input: { readonly realmId: string; readonly clientId: string }): Promise<boolean>;
  /**
   * Whether the realm or the client requires the bot challenge at sign-up
   * (#643): the realm's `botChallenge.requiredAtSignUp`, or the client's own
   * requirement. Absent: none does.
   */
  challengeRequired?(input: {
    readonly realmId: string;
    readonly clientId: string;
  }): Promise<boolean>;
  /** The Argon2id hash of a password already in its stored form. */
  hash(password: string): Promise<string>;
  /** Whether `error` is the database's refusal of a duplicate credential. */
  isUniqueViolation(error: unknown): boolean;
  /**
   * Record the account's `user.registered` event in the registration's
   * transaction, so it commits with the account and a rolled-back
   * registration leaves none (ADR-019 Decision 8).
   */
  registered(
    input: { readonly realmId: string; readonly clientId: string; readonly userId: string },
    tx: Tx
  ): Promise<void>;
}

/** Thrown inside the transaction when the address is taken, so it rolls back. */
class AddressTaken extends Error {
  constructor() {
    super('address already registered');
    this.name = 'AddressTaken';
  }
}

/**
 * The sign-in engine's registration over the auth server's repositories
 * (#640; ADR-017 Decision 8; ADR-002: `users` is a pure identity anchor, a
 * password lives in its `user_credentials` row, the address in the
 * self-reported `email` attribute).
 *
 * `create` hashes the password first, outside the transaction (Argon2id is
 * slow), then in one database transaction writes the `users` row, the
 * `password` credential (its primary identity, #846) whose `external_sub` is
 * the address, holding the hash,
 * `email_verified: true` and the normalisation marker, the verified `email`
 * attribute, and the account's event. The engine calls it only once the
 * transaction proved the mailbox, so the account is verified from its first
 * moment. The credentials' unique index (realm, provider type, external sub)
 * is the one duplicate guard: an address another account took first rolls
 * everything back and answers `conflict`.
 */
export function createRepositoryAccountRegistrations<Tx>(
  stores: AccountRegistrationRepositories<Tx>,
  transaction: AccountRegistrationTransaction<Tx>,
  policy: AccountRegistrationPolicy<Tx>
): AccountRegistrations {
  const { challengeRequired } = policy;
  const registrations: AccountRegistrations = {
    allowed: (input) => policy.allowed(input),
    ...(challengeRequired === undefined
      ? {}
      : { challengeRequired: (input) => challengeRequired.call(policy, input) }),
    async create({ realmId, clientId, identifier, password, normalization }) {
      const passwordHash = await policy.hash(password);
      try {
        return await transaction(async (tx): Promise<AccountRegistration> => {
          // The password credential is the account's primary identity.
          const user = await stores.users
            .create(
              { realmId },
              {
                providerType: PASSWORD_PROVIDER_TYPE,
                externalSub: identifier,
                credentialData: {
                  ...buildPasswordCredentialData(passwordHash, true, normalization),
                },
              },
              tx
            )
            .catch((error: unknown) => {
              if (policy.isUniqueViolation(error)) throw new AddressTaken();
              throw error;
            });
          await stores.userAttributes.upsertMany(
            user.id,
            [
              {
                source: SELF_REPORTED_SOURCE,
                attrKey: EMAIL_ATTR_KEY,
                attrValue: identifier,
                verified: true,
                expiresAt: null,
              },
            ],
            tx
          );
          await policy.registered({ realmId, clientId, userId: user.id }, tx);
          return { kind: 'created', userId: user.id };
        });
      } catch (error) {
        if (error instanceof AddressTaken) return { kind: 'conflict' };
        throw error;
      }
    },
  };
  return Object.freeze(registrations);
}

import {
  EMAIL_ATTR_KEY,
  PASSWORD_PROVIDER_TYPE,
  SELF_REPORTED_SOURCE,
  upstreamCredentialDataSchema,
} from '@qauth-labs/server-federation';
import {
  type AddressVerification,
  type AddressVerifier,
  readIdentifier,
} from '@qauth-labs/server-sign-in-engine';

/**
 * The repositories the address verifier writes through, by shape, so this
 * library takes the auth server's decorated repositories as they are and
 * depends on no database library. `Tx` is the database transaction they share.
 */
export interface AddressVerifierRepositories<Tx> {
  readonly userCredentials: {
    findByRealmProviderSub(
      realmId: string,
      providerType: string,
      externalSub: string,
      tx?: Tx
    ): Promise<{ readonly id: string; readonly userId: string } | undefined>;
    setEmailVerified(id: string, tx?: Tx): Promise<unknown>;
    /** The user's credentials of one type: an upstream provider's (#639). */
    findAllByUserIdAndType(
      userId: string,
      providerType: string,
      tx?: Tx
    ): Promise<
      readonly {
        readonly id: string;
        readonly realmId: string;
        readonly credentialData: Record<string, unknown>;
      }[]
    >;
    updateCredentialData(
      id: string,
      credentialData: Record<string, unknown>,
      tx?: Tx
    ): Promise<unknown>;
  };
  readonly users: {
    findById(
      realmId: string,
      id: string,
      tx?: Tx
    ): Promise<{ readonly id: string; readonly enabled: boolean } | undefined>;
  };
  readonly userAttributes: {
    /** Every attribute one source holds for the user: an upstream provider's (#639). */
    findByUserIdAndSource(
      userId: string,
      source: string,
      tx?: Tx
    ): Promise<readonly { readonly attrKey: string; readonly attrValue: string }[]>;
    setVerified(
      userId: string,
      source: string,
      attrKey: string,
      verified: boolean,
      tx?: Tx
    ): Promise<unknown>;
  };
}

/** One database transaction: `work` commits with it, and a throw rolls it back. */
export type AddressVerifierTransaction<Tx> = <T>(work: (tx: Tx) => Promise<T>) => Promise<T>;

/** Where the verifier reports a missing attribute row: data inconsistency, never a user's doing. */
export interface AddressVerifierLog {
  warn(details: Record<string, unknown>, message: string): void;
}

/**
 * The sign-in engine's address verifier over the auth server's repositories
 * (#638; ADR-002: the verified state of a password account's address is its
 * credential's `email_verified`, and the self-reported `email` attribute's
 * verified flag mirrors it).
 *
 * In one database transaction it reads the `password` credential whose
 * `external_sub` is the address in the realm and the user behind it, and,
 * only when that credential is the subject's and the user is enabled, sets
 * both flags, as `POST /auth/verify` does once its token and password are
 * proved. Another user's credential, or none, writes nothing
 * (`subject_mismatch`); so does a disabled user (`account_disabled`). A
 * missing attribute row is reported and does not fail the verification: the
 * credential's flag is the authoritative one. Marking an address verified
 * again changes nothing.
 *
 * For an account an upstream provider created with its verified switch off
 * (#639, `upstream` set), the address is the provider's `email` attribute of
 * the user: only when that attribute holds the address, and the user holds a
 * credential of the provider in the realm, are both marked verified, the
 * credential's `verified` and the attribute's flag, in one transaction.
 * Anything else writes nothing (`subject_mismatch`).
 */
export function createRepositoryAddressVerifier<Tx>(
  stores: AddressVerifierRepositories<Tx>,
  transaction: AddressVerifierTransaction<Tx>,
  log: AddressVerifierLog
): AddressVerifier {
  /** {@link AddressVerifier.markVerified} for an upstream provider's account (#639). */
  const markUpstreamVerified = (
    realmId: string,
    userId: string,
    identifier: string,
    upstream: string
  ): Promise<AddressVerification> =>
    transaction(async (tx): Promise<AddressVerification> => {
      const credentials = (
        await stores.userCredentials.findAllByUserIdAndType(userId, upstream, tx)
      ).filter((row) => row.realmId === realmId);
      if (credentials.length === 0) return { kind: 'refused', reason: 'subject_mismatch' };
      const user = await stores.users.findById(realmId, userId, tx);
      if (user === undefined) return { kind: 'refused', reason: 'subject_mismatch' };
      if (!user.enabled) return { kind: 'refused', reason: 'account_disabled' };
      const attributes = await stores.userAttributes.findByUserIdAndSource(userId, upstream, tx);
      const email = attributes.find((attribute) => attribute.attrKey === EMAIL_ATTR_KEY);
      if (email === undefined || readIdentifier(email.attrValue) !== identifier) {
        return { kind: 'refused', reason: 'subject_mismatch' };
      }
      for (const credential of credentials) {
        const data = upstreamCredentialDataSchema.safeParse(credential.credentialData);
        if (!data.success) return { kind: 'refused', reason: 'subject_mismatch' };
        if (!data.data.verified) {
          await stores.userCredentials.updateCredentialData(
            credential.id,
            { ...credential.credentialData, verified: true },
            tx
          );
        }
      }
      await stores.userAttributes.setVerified(userId, upstream, EMAIL_ATTR_KEY, true, tx);
      return { kind: 'verified' };
    });

  const verifier: AddressVerifier = {
    markVerified: ({ realmId, userId, identifier, upstream }) =>
      upstream !== undefined
        ? markUpstreamVerified(realmId, userId, identifier, upstream)
        : transaction(async (tx): Promise<AddressVerification> => {
            const credential = await stores.userCredentials.findByRealmProviderSub(
              realmId,
              PASSWORD_PROVIDER_TYPE,
              identifier,
              tx
            );
            if (credential === undefined || credential.userId !== userId) {
              return { kind: 'refused', reason: 'subject_mismatch' };
            }
            const user = await stores.users.findById(realmId, userId, tx);
            if (user === undefined) return { kind: 'refused', reason: 'subject_mismatch' };
            if (!user.enabled) return { kind: 'refused', reason: 'account_disabled' };
            await stores.userCredentials.setEmailVerified(credential.id, tx);
            const attribute = await stores.userAttributes.setVerified(
              userId,
              SELF_REPORTED_SOURCE,
              EMAIL_ATTR_KEY,
              true,
              tx
            );
            if (attribute === undefined) {
              log.warn({ userId }, 'no self_reported email attribute to mark verified');
            }
            return { kind: 'verified' };
          }),
  };
  return Object.freeze(verifier);
}

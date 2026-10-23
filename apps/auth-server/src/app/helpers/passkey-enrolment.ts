import {
  WEBAUTHN_PROVIDER_TYPE,
  type WebAuthnEnrolment,
} from '@qauth-labs/fastify-plugin-federation';
import type { FastifyInstance } from 'fastify';

/** A stored `user_credentials` row. */
type UserCredential = Awaited<
  ReturnType<FastifyInstance['repositories']['userCredentials']['create']>
>;

/** What {@link storePasskeyEnrolment} writes through. */
export interface PasskeyEnrolmentDependencies {
  readonly db: Pick<FastifyInstance['db'], 'transaction'>;
  readonly realms: FastifyInstance['repositories']['realms'];
  readonly userCredentials: FastifyInstance['repositories']['userCredentials'];
}

/**
 * Store a verified passkey registration (ADR-017 Decision 14, ADR-019
 * Decision 2, issue #467).
 *
 * The `WebAuthnProvider` checks the registration; this writes its result, in
 * one transaction:
 *
 * 1. lock the realm's RP ID to the one the passkey was created under. The
 *    realm's first passkey writes the lock; a later one must match it, so a
 *    realm never holds passkeys under two RP IDs. Two first enrolments that
 *    race under different RP IDs are serialised on the realm row, and one of
 *    them is refused;
 * 2. insert the `user_credentials` row: `provider_type` `webauthn`,
 *    `external_sub` the credential id. The unique index on `(realm_id,
 *    provider_type, external_sub)` refuses a credential id the realm already
 *    has, for any account, as a `UniqueConstraintError`; the lock in step 1 is
 *    rolled back with it.
 *
 * The enrolment routes of phase F2b call this. It writes no audit row: the
 * caller records the enrolment with its own context (who, from which client).
 *
 * @throws BadRequestError when the realm is locked to another RP ID
 * @throws UniqueConstraintError when the realm already has the credential id
 */
export async function storePasskeyEnrolment(
  deps: PasskeyEnrolmentDependencies,
  input: {
    readonly realmId: string;
    readonly userId: string;
    readonly enrolment: WebAuthnEnrolment;
  }
): Promise<UserCredential> {
  type Transaction = Parameters<
    Parameters<PasskeyEnrolmentDependencies['db']['transaction']>[0]
  >[0];
  return deps.db.transaction(async (tx: Transaction) => {
    await deps.realms.lockWebAuthnRpId(input.realmId, input.enrolment.rpId, tx);
    return deps.userCredentials.create(
      {
        userId: input.userId,
        realmId: input.realmId,
        providerType: WEBAUTHN_PROVIDER_TYPE,
        externalSub: input.enrolment.externalSub,
        credentialData: { ...input.enrolment.credentialData },
      },
      tx
    );
  });
}

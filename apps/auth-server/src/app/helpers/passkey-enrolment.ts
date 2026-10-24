import {
  WEBAUTHN_PROVIDER_TYPE,
  type WebAuthnEnrolment,
} from '@qauth-labs/fastify-plugin-federation';
import { BadRequestError } from '@qauth-labs/shared-errors';
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
 * Decision 2, issues #467 and #553).
 *
 * The `WebAuthnProvider` checks the registration; this writes its result, in
 * one transaction:
 *
 * 1. lock the realm's RP ID with `lockRpIdForEnrolment`, which returns the RP
 *    ID to store the passkey under. The realm's first passkey takes the lock;
 *    a later one finds it. Two first enrolments that race are serialised on
 *    the realm row: one locks, and both get the same RP ID;
 * 2. refuse a passkey created under another RP ID: the ceremony started under
 *    `resolveRpId(realm)`, so this is a setting changed before the realm's
 *    first passkey, between the ceremony's start and its end. A realm never
 *    holds passkeys under two RP IDs;
 * 3. insert the `user_credentials` row: `provider_type` `webauthn`,
 *    `external_sub` the credential id. The unique index on `(realm_id,
 *    provider_type, external_sub)` refuses a credential id the realm already
 *    has, for any account, as a `UniqueConstraintError`.
 *
 * A refusal in step 2 or 3 rolls back the lock with it.
 *
 * The enrolment routes of phase F2b call this. It writes no audit row: the
 * caller records the enrolment with its own context (who, from which client).
 *
 * @throws BadRequestError when the passkey was created under another RP ID
 * than the realm's
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
    const lock = await deps.realms.lockRpIdForEnrolment(tx, input.realmId);
    if (lock.rpId !== input.enrolment.rpId) {
      throw new BadRequestError(
        "Passkey was created under another RP ID than the realm's; start the enrolment again"
      );
    }
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

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
    /**
     * The rebind after a lost passkey (#655): after step 3, every other
     * enabled passkey of the account in the realm is disabled, in the same
     * transaction, so the lost one signs in no more.
     */
    readonly replacing?: boolean;
  }
): Promise<UserCredential> {
  return deps.db.transaction(async (tx: EnrolmentTransaction) => {
    const created = await writePasskey(deps, tx, input);
    if (input.replacing === true) {
      const passkeys = await deps.userCredentials.findAllByUserIdAndType(
        input.userId,
        WEBAUTHN_PROVIDER_TYPE,
        tx
      );
      const at = Date.now();
      for (const other of passkeys) {
        if (
          other.realmId !== input.realmId ||
          other.externalSub === created.externalSub ||
          (other.disabledAt !== null && other.disabledAt !== undefined)
        ) {
          continue;
        }
        await deps.userCredentials.setDisabledAt(
          input.realmId,
          WEBAUTHN_PROVIDER_TYPE,
          other.externalSub,
          at,
          tx
        );
      }
    }
    return created;
  });
}

/** The database transaction an enrolment writes in. */
export type EnrolmentTransaction = Parameters<
  Parameters<PasskeyEnrolmentDependencies['db']['transaction']>[0]
>[0];

/** Steps 1 to 3 of {@link storePasskeyEnrolment}, in the caller's transaction. */
async function writePasskey(
  deps: PasskeyEnrolmentDependencies,
  tx: EnrolmentTransaction,
  input: {
    readonly realmId: string;
    readonly userId: string;
    readonly enrolment: WebAuthnEnrolment;
  }
): Promise<UserCredential> {
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
}

/**
 * Create an account whose primary identity is a passkey, with no address
 * (#655; ADR-017 Decision 8, question 30), from a verified registration: in
 * one transaction, the `users` row, the passkey as {@link storePasskeyEnrolment}
 * stores one (the realm's RP ID locked and checked, the `webauthn`
 * credential), and the caller's `recorded` write (the account's
 * `user.registered` event), so a refusal or a failure rolls back the user
 * with it. No email attribute and no password credential are written.
 *
 * @returns the new account's user id
 * @throws BadRequestError when the passkey was created under another RP ID
 * than the realm's
 * @throws UniqueConstraintError when the realm already has the credential id
 */
export async function storePasskeyAccount(
  deps: PasskeyEnrolmentDependencies & {
    readonly users: Pick<FastifyInstance['repositories']['users'], 'create'>;
  },
  input: {
    readonly realmId: string;
    readonly enrolment: WebAuthnEnrolment;
    readonly recorded: (tx: EnrolmentTransaction, userId: string) => Promise<void>;
  }
): Promise<string> {
  return deps.db.transaction(async (tx: EnrolmentTransaction) => {
    const user = await deps.users.create({ realmId: input.realmId }, tx);
    await writePasskey(deps, tx, {
      realmId: input.realmId,
      userId: user.id,
      enrolment: input.enrolment,
    });
    await input.recorded(tx, user.id);
    return user.id;
  });
}

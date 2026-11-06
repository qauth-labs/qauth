import { createHash } from 'node:crypto';

import {
  PASSWORD_PROVIDER_TYPE,
  WEBAUTHN_PROVIDER_TYPE,
} from '@qauth-labs/fastify-plugin-federation';
import { argon2idDigest } from '@qauth-labs/fastify-plugin-password';
import {
  createRepositoryRecoveryCodes,
  type RepositoryRecoveryCodes,
} from '@qauth-labs/fastify-plugin-sign-in-engine';
import type { FastifyInstance, FastifyRequest } from 'fastify';

import type { EngineMailer, MailRealm } from './engine-mail';
import { EVENT_CLIENT_ID_MAX_LENGTH } from './interaction-record';
import { emitUserEvent, type EventTransaction } from './user-events';

/**
 * THE ACCOUNTS' RECOVERY CODES IN THE AUTH SERVER (#649; ADR-017 Decisions 7
 * and 8, ADR-018 §3): the sign-in engine's `recoveryCodes` port over
 * `user_recovery_codes` and the password hasher (Argon2id), and the three
 * notices, none of which a realm can switch off.
 *
 * - **A code used.** The take and its `user.recovery_code_used` event commit
 *   together; the "a recovery code was used" mail follows the commit, to the
 *   account's address, saying how many codes are left.
 * - **A set regenerated** (`regenerate`, called by the account API's
 *   regeneration, ACC-02, #687, after a fresh authentication): the
 *   "recovery codes were regenerated" mail follows the new set.
 * - **100 wrong codes in a row** (the recovery-code ladder's hard ceiling,
 *   counted per account across transactions and IPs): at most once a day per
 *   account, the "recovery codes failed 100 times" mail, the operator's alert
 *   ({@link RECOVERY_CODES_FAILED_ALERT}) and the
 *   `user.recovery_codes_failed` event.
 *
 * The account's address is its password credential's identifier: the
 * address it signs in with and the reset's codes go to. An account without
 * one (an account whose primary identity is a passkey, #655) gets no mail;
 * the event, which its security log shows, and the alert still go.
 *
 * The sets of an account whose every credential is a passkey also carry
 * each code's lookup digest ({@link recoveryCodeLookupDigest}), so a code
 * alone finds the account when its passkey is lost (#655).
 */

/**
 * The realm's salt of the recovery codes' lookup digests (#655): 16 bytes of
 * SHA-256 over a fixed label and the realm id, so the same code has another
 * digest in every realm and no table of digests serves two realms. Not a
 * secret: the digest's cost is Argon2id's.
 */
export function recoveryCodeLookupSalt(realmId: string): Uint8Array {
  return createHash('sha256')
    .update('urn:qauth:recovery-code-lookup:v1-rc.0')
    .update('\u0000')
    .update(realmId)
    .digest()
    .subarray(0, 16);
}

/** The lookup digest of a recovery code, normalized, in its realm (#655). */
export function recoveryCodeLookupDigest(realmId: string, code: string): Promise<string> {
  return argon2idDigest(code, recoveryCodeLookupSalt(realmId));
}

/** The message of the operator's alert when an account's wrong recovery codes reach 100 in a row. */
export const RECOVERY_CODES_FAILED_ALERT = "an account's wrong recovery codes reached the ceiling";

/** What the recovery codes work with, besides the process. */
export interface ServerRecoveryCodesDependencies {
  readonly mailer: EngineMailer;
  /** The realm row a notice is sent for. */
  readonly realmOf: (realmId: string) => Promise<MailRealm>;
  /** The request the engine's round runs for, which the events carry. */
  readonly requestOf: () => FastifyRequest | undefined;
}

/** The recovery codes of this process. */
export function createServerRecoveryCodes(
  fastify: FastifyInstance,
  deps: ServerRecoveryCodesDependencies
): RepositoryRecoveryCodes {
  const { mailer, realmOf } = deps;
  const requestOf = (what: string): FastifyRequest => {
    const request = deps.requestOf();
    if (request === undefined) throw new Error(`${what} outside the request that asked for it`);
    return request;
  };
  const addressOf = async (realmId: string, userId: string): Promise<string | undefined> => {
    const credential = await fastify.repositories.userCredentials.findByUserIdAndType(
      userId,
      PASSWORD_PROVIDER_TYPE
    );
    return credential !== undefined && credential.realmId === realmId
      ? credential.externalSub
      : undefined;
  };
  const mail = async (
    realmId: string,
    userId: string,
    notice: Parameters<EngineMailer['sendUncounted']>[2]
  ): Promise<void> => {
    const address = await addressOf(realmId, userId);
    if (address !== undefined) mailer.sendUncounted(await realmOf(realmId), address, notice);
  };

  return createRepositoryRecoveryCodes<EventTransaction>(
    { userRecoveryCodes: fastify.repositories.userRecoveryCodes },
    (work) => fastify.db.transaction(work),
    {
      hasher: {
        hash: (code) => fastify.passwordHasher.hashPassword(code),
        verify: (hash, code) => fastify.passwordHasher.verifyPassword(hash, code),
      },
      // An account with no address and no password, whose credentials are
      // passkeys, is found by a code alone when its passkey is lost (#655).
      lookup: {
        digest: ({ realmId, code }) => recoveryCodeLookupDigest(realmId, code),
        findable: async ({ realmId, userId }) => {
          const credentials = (
            await fastify.repositories.userCredentials.findAllByUserId(userId)
          ).filter((credential) => credential.realmId === realmId);
          return (
            credentials.length > 0 &&
            credentials.every((credential) => credential.providerType === WEBAUTHN_PROVIDER_TYPE)
          );
        },
      },
      // The use commits with the take (ADR-019 Decision 8).
      used: async ({ realmId, userId, clientId, unusedCodes }, tx) => {
        await emitUserEvent(
          requestOf('a recovery code taken'),
          'urn:qauth:event:user.recovery_code_used:v1-rc.0',
          { remaining: unusedCodes },
          {
            tx,
            realmId,
            userId,
            clientId: clientId.length <= EVENT_CLIENT_ID_MAX_LENGTH ? clientId : null,
            actor: 'user',
          }
        );
      },
      committed: ({ realmId, userId, unusedCodes }) =>
        mail(realmId, userId, { template: 'recovery_code_used', unusedCodes }),
      regenerated: ({ realmId, userId }) =>
        mail(realmId, userId, { template: 'recovery_codes_regenerated' }),
      ceilingReached: async ({ realmId, userId }) => {
        const realm = await realmOf(realmId);
        const address = await addressOf(realmId, userId);
        const claimed = await mailer.recoveryCodesFailed({
          realm,
          userId,
          ...(address === undefined ? {} : { address }),
        });
        // Told once a day per account: the run's later failures add nothing.
        if (!claimed) return;
        // The operator's alert: this log line is the alerting hook.
        fastify.log.error({ realmId, userId }, RECOVERY_CODES_FAILED_ALERT);
        await emitUserEvent(
          requestOf('a recovery-code ceiling'),
          'urn:qauth:event:user.recovery_codes_failed:v1-rc.0',
          {},
          { realmId, userId, actor: 'user' }
        );
      },
      report: (error, what) =>
        fastify.log.error(
          { err: error, step: what },
          'a recovery code write committed, but a step after it failed'
        ),
    }
  );
}

import {
  PASSWORD_PROVIDER_TYPE,
  WEBAUTHN_PROVIDER_TYPE,
} from '@qauth-labs/fastify-plugin-federation';
import {
  createRepositoryTotp,
  type RecoveryCodes,
  type RedisFailureLadder,
  type TotpCipher,
  type TotpCredentials,
} from '@qauth-labs/fastify-plugin-sign-in-engine';
import { TOTP_SECRET_CONTEXT_PREFIX } from '@qauth-labs/fastify-plugin-signer';
import type { FastifyInstance } from 'fastify';

import type { EngineMailer, MailRealm } from './engine-mail';
import { realmIssuer } from './realm-url';

/**
 * TOTP AT SIGN-IN ON THE AUTH SERVER (#653; ADR-017 Decisions 7 and 8,
 * ADR-020 §3).
 *
 * The engine's `TotpCredentials` port over `user_credentials`
 * (`createRepositoryTotp`), with what only the server knows:
 *
 * - **The cipher**: the signer's `data_at_rest` key of the realm, under the
 *   context `totp-secret:<realm id>:<user id>` ({@link totpSecretContext}),
 *   so a ciphertext opens only for the account it was made for. The engine
 *   runs where the `api` role's mail sender does, and calls as `api`, the one
 *   role that may decrypt this prefix (`SIGNER_POLICY`). A secret opened is
 *   copied out of the signer's buffer, which is overwritten at once.
 * - **The issuer** an authenticator app shows: the host of the realm's
 *   issuer.
 * - **The hard action's arming** (ADR-017 Decision 7): the hosted pages are
 *   on (`INTERACTION_UI_ENABLED`, where a recovery code is redeemed), and the
 *   account keeps an unused recovery code or another usable second factor (a
 *   passkey that is not disabled, while passkey sign-in is on). Otherwise the
 *   100th wrong code disables nothing, and the ladder alone holds the guesses
 *   back.
 * - **The notices**, to the address of the account's password, as a passkey's
 *   are: "an authenticator app was added" after a binding, which also ends
 *   the TOTP counter's run; "your authenticator app was turned off" after the
 *   hard action; and "a wrong code was entered after your password", claimed
 *   once a day per account. None can be switched off by a realm.
 */

/** The `data_at_rest` context of an account's TOTP secret. */
export function totpSecretContext(realmId: string, userId: string): string {
  return `${TOTP_SECRET_CONTEXT_PREFIX}${realmId}:${userId}`;
}

/** The signer caller every TOTP secret is sealed and opened as. */
const TOTP_SIGNER_CALLER = 'api' as const;

/** The TOTP cipher over the process's signer. */
export function totpCipher(fastify: Pick<FastifyInstance, 'signer'>): TotpCipher {
  const cipher: TotpCipher = {
    seal: ({ realmId, userId, secret }) =>
      fastify.signer.encrypt(TOTP_SIGNER_CALLER, {
        realmId,
        plaintext: secret,
        context: totpSecretContext(realmId, userId),
      }),
    async open({ realmId, userId, sealed }) {
      const plaintext = await fastify.signer.decrypt(TOTP_SIGNER_CALLER, {
        realmId,
        ciphertext: sealed,
        context: totpSecretContext(realmId, userId),
      });
      try {
        return Uint8Array.from(plaintext);
      } finally {
        plaintext.fill(0);
      }
    },
  };
  return Object.freeze(cipher);
}

/** What {@link createServerTotp} works with. */
export interface ServerTotpDependencies {
  readonly mailer: EngineMailer;
  readonly realmOf: (realmId: string) => Promise<MailRealm>;
  /** The accounts' recovery codes: an unused one arms the hard action. */
  readonly recoveryCodes: Pick<RecoveryCodes, 'status'>;
  /** The failure ladder: a binding ends the TOTP counter's run. */
  readonly ladder: Pick<RedisFailureLadder, 'resetAccount'>;
  /**
   * Whether the hosted pages are on (`INTERACTION_UI_ENABLED`): a recovery
   * code is redeemed there, so without them the hard action is never armed.
   */
  readonly hostedPages: boolean;
  /** Whether passkey sign-in is on, so a passkey is a usable second factor. */
  readonly passkeys: boolean;
}

/** The accounts' TOTPs of this process. */
export function createServerTotp(
  fastify: FastifyInstance,
  deps: ServerTotpDependencies
): TotpCredentials {
  const credentials = fastify.repositories.userCredentials;
  const addressOf = async (realmId: string, userId: string): Promise<string | undefined> => {
    const credential = await credentials.findByUserIdAndType(userId, PASSWORD_PROVIDER_TYPE);
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
    if (address !== undefined)
      deps.mailer.sendUncounted(await deps.realmOf(realmId), address, notice);
  };
  const report = (error: unknown, what: string) =>
    fastify.log.error(
      { err: error, step: what },
      'a TOTP write committed, but a step after it failed'
    );

  return createRepositoryTotp(
    { userCredentials: credentials, users: fastify.repositories.users },
    (work) => fastify.db.transaction(work),
    {
      cipher: totpCipher(fastify),
      issuerOf: async (realmId) => new URL(realmIssuer(await deps.realmOf(realmId))).host,
      async hardActionArmed({ realmId, userId }) {
        if (!deps.hostedPages) return false;
        // Only a set the person confirmed counts as a way back: one nobody
        // confirmed (a closed tab, a lost answer) was never seen for sure.
        const status = await deps.recoveryCodes.status({ realmId, userId });
        if (status.confirmed && status.unused > 0) return true;
        if (!deps.passkeys) return false;
        const passkeys = await credentials.findAllByUserIdAndType(userId, WEBAUTHN_PROVIDER_TYPE);
        return passkeys.some(
          (row) =>
            row.realmId === realmId && (row.disabledAt === undefined || row.disabledAt === null)
        );
      },
      async bound({ realmId, userId }) {
        // The run counted the old secret's codes: the new one starts afresh.
        try {
          await deps.ladder.resetAccount({ realmId, userId, factor: 'totp' });
        } catch (error) {
          report(error, 'the TOTP counter reset');
        }
        await mail(realmId, userId, { template: 'totp_added' });
      },
      disabled: ({ realmId, userId }) =>
        mail(realmId, userId, { template: 'second_factor_disabled' }),
      async failedAfterPassword({ realmId, userId }) {
        const realm = await deps.realmOf(realmId);
        const address = await addressOf(realmId, userId);
        await deps.mailer.secondFactorFailed({
          realm,
          userId,
          ...(address === undefined ? {} : { address }),
        });
      },
      report,
    }
  );
}

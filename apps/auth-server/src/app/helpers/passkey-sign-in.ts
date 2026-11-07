import {
  createPasskeyProvider,
  generateWebAuthnUserHandle,
  PASSWORD_PROVIDER_TYPE,
  WEBAUTHN_PROVIDER_TYPE,
  type WebAuthnCeremonyState,
  webauthnCeremonyStateSchema,
  type WebAuthnChallengeStore,
  webauthnCredentialDataAfterAssertion,
  webauthnCredentialDataSchema,
  type WebAuthnEnrolment,
  type WebAuthnProvider,
  type WebAuthnRawClaims,
  WebAuthnRejection,
} from '@qauth-labs/fastify-plugin-federation';
import type {
  AccountRegistration,
  AccountRegistrations,
  PasskeyAssertion,
  PasskeyBinding,
  PasskeyCeremonies,
  PasskeyRegistration,
  PasskeyRegistrationStart,
} from '@qauth-labs/fastify-plugin-sign-in-engine';
import { BadRequestError, UniqueConstraintError } from '@qauth-labs/shared-errors';
import { DISPLAY_TEXT_PATTERN } from '@qauth-labs/shared-interaction-contract';
import { resolveRpId } from '@qauth-labs/shared-validation';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';

import { REDIS_KEYS } from '../constants/redis-keys';
import type { EngineMailer } from './engine-mail';
import {
  type EnrolmentTransaction,
  storePasskeyAccount,
  storePasskeyEnrolment,
} from './passkey-enrolment';
import { emitUserEvent } from './user-events';
import { passkeyCeremonyOrigins } from './webauthn-relying-party';

/**
 * The passkey ceremonies of the sign-in engine (#651; ADR-017 Decisions 4, 10
 * and 14), over the WebAuthn provider, the realm's `webauthn` credentials and
 * Redis.
 *
 * - Every ceremony runs under the realm's RP ID (`resolveRpId`, the lock its
 *   first passkey took) and the realm's own origin, with the client's
 *   operator-set `webauthn_allowed_origins` beside it. Nothing comes from the
 *   request (ADR-019 Decision 1).
 * - A ceremony's state waits in Redis under the realm and the engine's
 *   ceremony key, and is taken before any answer is checked, so a challenge
 *   answers once: an answer that names no passkey of the realm, or a
 *   disabled one, burns it too.
 * - An assertion is a sign-in: user verification is required by the
 *   ceremony, and the UV flag of the signed authenticator data is reported
 *   to the engine, which refuses an assertion without it again. A verified
 *   assertion updates the passkey's counter and last use; a counter that did
 *   not grow is recorded and logged, not refused (the provider's rule).
 * - A registration is checked first, then held in the engine's transaction
 *   while the mailbox is proved, and bound last: one transaction locks the
 *   realm's RP ID and writes the `user_credentials` row. The owner is told
 *   at their password credential's address ("passkey added"), after the
 *   answer; an account with no address is told nothing by mail.
 * - A registration's own ceremony (#655) names no account: a new user
 *   handle, nothing excluded, and a name made from the handle. Its
 *   verified registration creates the account with
 *   {@link createServerPasskeyAccounts}.
 *
 * Every refusal is the same `refused` for the engine; the provider's reason
 * goes to the log only.
 */

/** Longest name or display name the step grammar lets a ceremony carry. */
const DISPLAY_NAME_MAX_LENGTH = 64;

/** The most passkeys a registration names in `excludeCredentials` (the grammar's bound). */
const MAX_EXCLUDED_CREDENTIALS = 32;

/** Longest credential id a response may name: 1023 bytes, base64url. */
const MAX_CREDENTIAL_ID_LENGTH = 1366;

/** A verified registration as the engine holds it, until it is bound. */
const heldRegistrationSchema = z
  .object({
    externalSub: z.string().min(1).max(MAX_CREDENTIAL_ID_LENGTH),
    credentialData: webauthnCredentialDataSchema,
    rpId: z.string().min(1),
    purpose: z.literal('sign-in'),
    attestationFormat: z.string().max(64),
  })
  .strict();

/** A ceremony's state in Redis: `SET … PX` to start, `GETDEL` to take. */
export function createRedisWebAuthnChallenges(
  fastify: Pick<FastifyInstance, 'redis' | 'log'>
): WebAuthnChallengeStore {
  return {
    async begin(transactionId, state, ttlMs) {
      await fastify.redis.set(
        REDIS_KEYS.WEBAUTHN_CEREMONY(transactionId),
        JSON.stringify(state),
        'PX',
        ttlMs
      );
    },
    async take(transactionId): Promise<WebAuthnCeremonyState | undefined> {
      const raw = await fastify.redis.getdel(REDIS_KEYS.WEBAUTHN_CEREMONY(transactionId));
      if (raw === null) return undefined;
      let value: unknown;
      try {
        value = JSON.parse(raw);
      } catch {
        value = undefined;
      }
      const parsed = webauthnCeremonyStateSchema.safeParse(value);
      if (!parsed.success) {
        fastify.log.error('a WebAuthn ceremony state that is not well formed');
        return undefined;
      }
      return parsed.data;
    },
  };
}

/** Hangul fillers: letters that render as nothing, which the grammar refuses. */
const HANGUL_FILLERS = /[\u115F\u1160\u3164\uFFA0]/gu;

/** The grammar's display text, compiled once. */
const DISPLAY_TEXT = new RegExp(DISPLAY_TEXT_PATTERN, 'u');

/**
 * `value` as one line of display text the grammar takes: no markup, no
 * control characters, no fillers, and at most 64 UTF-16 units, as the
 * grammar counts them, never cut inside a surrogate pair. A value that is
 * left blank, or that the grammar still refuses, gives `fallback`.
 */
function displayName(value: string, fallback: string): string {
  let cleaned = value
    .replace(/[<>\p{C}]/gu, '')
    .replace(HANGUL_FILLERS, '')
    .replace(/\p{Z}+/gu, ' ')
    .trim();
  if (cleaned.length > DISPLAY_NAME_MAX_LENGTH) {
    const last = cleaned.charCodeAt(DISPLAY_NAME_MAX_LENGTH - 1);
    const highSurrogate = last >= 0xd800 && last <= 0xdbff;
    cleaned = cleaned
      .slice(0, highSurrogate ? DISPLAY_NAME_MAX_LENGTH - 1 : DISPLAY_NAME_MAX_LENGTH)
      .trim();
  }
  return cleaned !== '' && DISPLAY_TEXT.test(cleaned) ? cleaned : fallback;
}

/**
 * The name of an account with no address in its passkey (#655): `account-`
 * and the first 8 characters of its user handle (base64url, random), which
 * names nobody and tells two such accounts on one authenticator apart.
 */
export function accountNameOf(handle: string): string {
  return `account-${handle.slice(0, 8)}`;
}

/** The `id` a browser's JSON response names, without trusting anything else in it. */
function responseCredentialId(response: unknown): string | undefined {
  if (typeof response !== 'object' || response === null) return undefined;
  const id = (response as { id?: unknown }).id;
  return typeof id === 'string' && id.length > 0 && id.length <= MAX_CREDENTIAL_ID_LENGTH
    ? id
    : undefined;
}

function parseJson(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
}

/** What {@link createServerPasskeys} needs besides the server. */
export interface ServerPasskeyOptions {
  readonly mailer: Pick<EngineMailer, 'sendUncounted'>;
  /**
   * The request the engine's round runs for, which a binding's
   * `user.credential_added` event carries (#844). A binding outside one
   * fails, closed: its transaction rolls back.
   */
  readonly requestOf: () => FastifyRequest | undefined;
  /** The provider; built over Redis by default. */
  readonly provider?: WebAuthnProvider;
  /** Where ceremonies wait; Redis by default. Must be the provider's. */
  readonly challenges?: WebAuthnChallengeStore;
  /** Clock, epoch milliseconds. */
  readonly now?: () => number;
}

/** The engine's passkey ceremonies over the server's repositories and Redis. */
export function createServerPasskeys(
  fastify: FastifyInstance,
  options: ServerPasskeyOptions
): PasskeyCeremonies {
  const challenges = options.challenges ?? createRedisWebAuthnChallenges(fastify);
  const provider = options.provider ?? createPasskeyProvider(challenges);
  const now = options.now ?? Date.now;
  const credentials = fastify.repositories.userCredentials;

  /** The provider's transaction id: the realm and the engine's ceremony key. */
  const transactionOf = (realmId: string, key: string) => `${realmId}:${key}`;

  const relyingParty = async (realmId: string, clientId: string) => {
    const realm = await fastify.repositories.realms.findById(realmId);
    if (realm === undefined) throw new Error('a passkey ceremony for a realm that does not exist');
    const client = await fastify.repositories.oauthClients.findByClientId(realmId, clientId);
    const clientOrigins = Array.isArray(client?.webauthnAllowedOrigins)
      ? (client.webauthnAllowedOrigins as unknown[]).filter(
          (origin): origin is string => typeof origin === 'string'
        )
      : [];
    return {
      realm,
      rpId: resolveRpId(realm),
      origins: passkeyCeremonyOrigins(realm, clientOrigins),
    };
  };

  /** Burn the ceremony an answer cannot be checked against, and refuse it. */
  const refuseAndBurn = async (realmId: string, key: string, reason: string) => {
    await challenges.take(transactionOf(realmId, key));
    fastify.log.info({ realmId, reason }, 'a passkey answer was refused');
    return { kind: 'refused' } as const;
  };

  /** The user's passkeys in the realm, with their stored records. */
  const passkeysOf = async (realmId: string, userId: string) => {
    const rows = await credentials.findAllByUserIdAndType(userId, WEBAUTHN_PROVIDER_TYPE);
    return rows
      .filter((row) => row.realmId === realmId)
      .map((row) => ({ row, data: webauthnCredentialDataSchema.safeParse(row.credentialData) }));
  };

  const ceremonies: PasskeyCeremonies = {
    async startAssertion({ realmId, clientId, key }) {
      const { rpId, origins } = await relyingParty(realmId, clientId);
      const started = await provider.startAuthentication({
        transactionId: transactionOf(realmId, key),
        purpose: 'sign-in',
        rpId,
        origins,
      });
      // No `allowCredentials`: the options name no account (passkey-first).
      return {
        challenge: started.challenge,
        rpId: started.rpId,
        timeout: started.timeout,
        userVerification: 'required',
      };
    },

    async verifyAssertion({ realmId, key, response }): Promise<PasskeyAssertion> {
      const answer = parseJson(response);
      const credentialId = responseCredentialId(answer);
      if (credentialId === undefined) return refuseAndBurn(realmId, key, 'malformed-response');
      const row = await credentials.findByRealmProviderSub(
        realmId,
        WEBAUTHN_PROVIDER_TYPE,
        credentialId
      );
      // A passkey the realm does not hold, or one that was disabled: refused
      // as any wrong answer, and the ceremony is spent.
      if (row === undefined) return refuseAndBurn(realmId, key, 'unknown-credential');
      if (row.disabledAt !== null && row.disabledAt !== undefined) {
        return refuseAndBurn(realmId, key, 'disabled-credential');
      }
      let claims: WebAuthnRawClaims;
      try {
        const verified = await provider.verify({
          transactionId: transactionOf(realmId, key),
          response: answer,
          credential: { externalSub: row.externalSub, credentialData: row.credentialData },
        });
        claims = verified.rawClaims as WebAuthnRawClaims;
      } catch (error) {
        if (!(error instanceof WebAuthnRejection)) throw error;
        fastify.log.info({ realmId, reason: error.reason }, 'a passkey assertion was refused');
        return { kind: 'refused' };
      }
      const stored = webauthnCredentialDataSchema.parse(row.credentialData);
      if (claims.sign_counter_regressed) {
        fastify.log.warn(
          { realmId, credentialId: row.id },
          'a passkey signature counter did not grow: the authenticator may have been cloned'
        );
      }
      await credentials.updateCredentialData(
        row.id,
        webauthnCredentialDataAfterAssertion(stored, claims, now())
      );
      return { kind: 'verified', userId: row.userId, userVerified: claims.user_verified };
    },

    async startRegistration({
      realmId,
      clientId,
      key,
      userId,
      identifier,
    }): Promise<PasskeyRegistrationStart> {
      const { realm, rpId, origins } = await relyingParty(realmId, clientId);
      // A registration's ceremony (#655) names no account yet: nothing to exclude.
      const existing = userId === undefined ? [] : await passkeysOf(realmId, userId);
      // One user handle per account: an authenticator that already holds a
      // passkey of the account replaces it rather than adding a second.
      const handle =
        existing
          .map(({ data }) => (data.success ? data.data.user_handle : undefined))
          .find((stored) => stored !== undefined) ?? generateWebAuthnUserHandle();
      // An account with no address is named by its handle, which tells two
      // such accounts on one authenticator apart.
      const name =
        identifier === undefined
          ? accountNameOf(handle)
          : displayName(identifier, accountNameOf(handle));
      const started = await provider.startRegistration({
        transactionId: transactionOf(realmId, key),
        purpose: 'sign-in',
        rp: {
          id: rpId,
          name: displayName(
            fastify.policyStore.ofRealm(realm).policies.mail.fromName,
            displayName(realm.name, 'QAuth')
          ),
        },
        origins,
        user: { handle, name, displayName: name },
        excludeCredentials: existing.slice(0, MAX_EXCLUDED_CREDENTIALS).map(({ row, data }) => ({
          id: row.externalSub,
          ...(data.success ? { transports: data.data.transports } : {}),
        })),
      });
      return {
        options: {
          challenge: started.challenge,
          rp: started.rp,
          pubKeyCredParams: started.pubKeyCredParams.map((param) => ({ ...param })),
          timeout: started.timeout,
          authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
          attestation: 'none',
        },
        personal: {
          user: { ...started.user },
          excludeCredentials: started.excludeCredentials.map((credential) => ({
            type: credential.type,
            id: credential.id,
            ...(credential.transports === undefined
              ? {}
              : { transports: [...credential.transports] }),
          })),
        },
      };
    },

    async verifyRegistration({ realmId, key, response }): Promise<PasskeyRegistration> {
      const answer = parseJson(response);
      if (answer === undefined) return refuseAndBurn(realmId, key, 'malformed-response');
      let enrolment: WebAuthnEnrolment;
      try {
        enrolment = await provider.finishRegistration({
          transactionId: transactionOf(realmId, key),
          response: answer,
        });
      } catch (error) {
        if (!(error instanceof WebAuthnRejection)) throw error;
        fastify.log.info({ realmId, reason: error.reason }, 'a passkey registration was refused');
        return { kind: 'refused' };
      }
      return { kind: 'verified', registration: JSON.stringify(enrolment) };
    },

    async bind({ realmId, userId, registration, replacing }): Promise<PasskeyBinding> {
      const held = heldRegistrationSchema.safeParse(parseJson(registration));
      if (!held.success) throw new Error('a held passkey registration that is not well formed');
      const user = await fastify.repositories.users.findById(realmId, userId);
      if (user === undefined || !user.enabled) {
        return { kind: 'refused', reason: 'account_disabled' };
      }
      try {
        await storePasskeyEnrolment(
          {
            db: fastify.db,
            realms: fastify.repositories.realms,
            userCredentials: credentials,
          },
          {
            realmId,
            userId,
            enrolment: held.data,
            ...(replacing === true ? { replacing } : {}),
            // The binding's record commits with it (ADR-019 Decision 8).
            recorded: async (credential, tx) => {
              const request = options.requestOf();
              if (request === undefined) {
                throw new Error('a passkey bound outside the request that asked for it');
              }
              await emitUserEvent(
                request,
                'urn:qauth:event:user.credential_added:v1-rc.0',
                { type: 'passkey', credentialId: credential.id },
                { tx, realmId, userId, actor: 'user' }
              );
            },
          }
        );
      } catch (error) {
        // The realm already holds the credential id, for this account or
        // another; or the realm's RP ID changed under the ceremony. Either
        // way nothing was written, and a new ceremony may bind another.
        if (error instanceof UniqueConstraintError || error instanceof BadRequestError) {
          return { kind: 'refused', reason: 'credential_exists' };
        }
        throw error;
      }
      // The binding notice (NIST SP 800-63B-4 §4.1.2.1), after the answer: to
      // the address of the account's password, which the enrolment followed.
      try {
        const password = await credentials.findByUserIdAndType(userId, PASSWORD_PROVIDER_TYPE);
        const realm = await fastify.repositories.realms.findById(realmId);
        if (password !== undefined && password.realmId === realmId && realm !== undefined) {
          options.mailer.sendUncounted(realm, password.externalSub, { template: 'passkey_added' });
        }
      } catch (error) {
        fastify.log.error({ err: error, realmId }, 'a passkey was bound, but its notice failed');
      }
      return { kind: 'bound' };
    },
  };
  return Object.freeze(ceremonies);
}

/** What {@link createServerPasskeyAccounts} records with a new account. */
export interface ServerPasskeyAccountOptions {
  /** Record the account's `user.registered` event, in the transaction that creates it. */
  readonly registered: (
    input: { readonly realmId: string; readonly clientId: string; readonly userId: string },
    tx: EnrolmentTransaction
  ) => Promise<void>;
}

/**
 * The registration's passkey write (#655; ADR-017 Decision 8, question 30):
 * an account whose primary identity is a passkey, from a registration
 * {@link createServerPasskeys}' `verifyRegistration` verified with no
 * account named. One transaction writes the `users` row, the realm's RP ID
 * lock and the `webauthn` credential, and the `user.registered` event; no
 * email attribute and no password. A credential id the realm holds by then,
 * or an RP ID that changed under the ceremony, writes nothing and answers
 * `conflict`.
 */
export function createServerPasskeyAccounts(
  fastify: FastifyInstance,
  options: ServerPasskeyAccountOptions
): NonNullable<AccountRegistrations['createWithPasskey']> {
  return async ({ realmId, clientId, registration }): Promise<AccountRegistration> => {
    const held = heldRegistrationSchema.safeParse(parseJson(registration));
    if (!held.success) throw new Error('a held passkey registration that is not well formed');
    try {
      const userId = await storePasskeyAccount(
        {
          db: fastify.db,
          realms: fastify.repositories.realms,
          users: fastify.repositories.users,
          userCredentials: fastify.repositories.userCredentials,
        },
        {
          realmId,
          enrolment: held.data,
          recorded: (tx, created) => options.registered({ realmId, clientId, userId: created }, tx),
        }
      );
      return { kind: 'created', userId };
    } catch (error) {
      if (error instanceof UniqueConstraintError || error instanceof BadRequestError) {
        return { kind: 'conflict' };
      }
      throw error;
    }
  };
}

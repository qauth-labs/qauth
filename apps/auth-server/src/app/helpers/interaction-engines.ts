import {
  createArgon2PasswordVerifier,
  createCheckedSignInEngine,
  createRepositoryAccountDirectory,
  createRepositoryAddressVerifier,
  createRepositoryPasswordUpdates,
  type EmailCodeSender,
  NO_SECOND_FACTOR_POLICY,
  type RoundResult,
  type SignInEngine,
  storedStepOf,
} from '@qauth-labs/fastify-plugin-sign-in-engine';
import { TemporarilyUnavailableError, TooManyRequestsError } from '@qauth-labs/shared-errors';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

import { accountPoliciesOf } from './account-policies';
import { type BackgroundTasks } from './background-tasks';
import { createEngineMailer, type EngineMailer } from './engine-mail';
import type { InteractionDecision } from './interaction';
import { InvalidAnswerError } from './interaction-errors';
import { createServerEmailCodeDigest, createServerLadderParts } from './password-attempts';
import { requestRealm } from './request-realm';
import { upstreamProviderDirectory } from './upstream-providers';

/**
 * The sign-in engines of the browser transports, shared by the Interaction
 * API (`routes/interaction-api.ts`) and the upstream sign-in flow (#639),
 * which completes an interaction's sign-in at a provider's callback
 * (`helpers/upstream-sign-in.ts`), and the interaction's next state for an
 * engine round's result.
 */

/** The `Retry-After` of an answer the engine refused because a store it needs failed. */
export const ENGINE_UNAVAILABLE_RETRY_SECONDS = 5;

/** The engines of a process, one per verified-account policy of a realm (#528). */
export interface InteractionEngines {
  readonly of: (requireVerifiedAccount: boolean) => SignInEngine;
  /** The capped sender of email codes (PRO-14, #637), bound to one request. */
  readonly sendCode: (request: FastifyRequest) => EmailCodeSender;
}

/**
 * The engine's email codes through the process's capped mailer, for one
 * request: counted on every send cap that applies and, unless a tier stops
 * it, mailed after the answer is built. A code after the password skips the
 * per-address ceiling, so it never meets the ceiling notice whose pass the
 * flow names; the flow is the registration a verification completes, or the
 * reset a forced password update's recovery code stands for (#635).
 */
function engineCodeSender(mailer: EngineMailer, request: FastifyRequest): EmailCodeSender {
  return async (mail) => {
    const realm = requestRealm(request);
    if (mail.realmId !== realm.id) throw new Error('an email code for another realm');
    const outcome = await mailer.sendCode(request, {
      realm,
      address: mail.address,
      mail: {
        template: 'code',
        purpose: mail.purpose,
        code: mail.code,
        expiresInSeconds: mail.expiresInSeconds,
      },
      flow: mail.purpose === 'recovery' ? 'reset' : 'register',
      afterFirstFactor: mail.afterFirstFactor,
    });
    return outcome.kind === 'capped'
      ? { kind: 'capped', retryAfterSeconds: outcome.retryAfterSeconds }
      : { kind: 'accepted' };
  };
}

/**
 * The sign-in engine over the process's repositories, password hasher and
 * the per-account failure ladder its legacy login routes share (#615): one
 * account run of failures counts across every front door.
 *
 * Both engines verify an unverified account inline after its password, with
 * an emailed code (#638, ADR-017 Decision 8): `REQUIRE_VERIFIED_ACCOUNT` no
 * longer decides the Interaction API's answer, and an unverified account
 * never completes a sign-in here without its code.
 *
 * Both check a right password against the realm's breach list and ask for a
 * new one before completing when it is listed or the account holds an
 * `update_password` required action (#635, ADR-020 §3): after the account's
 * second factor, or after an 8-digit recovery code to its address. The new
 * password meets the realm's password policy and the breach list too.
 *
 * Building them registers an `onClose` hook for the mail's background tasks,
 * which Fastify refuses once the server started: a route that builds them
 * on its first request passes `tasks` it created while it registered.
 */
export function createInteractionEngines(
  fastify: FastifyInstance,
  options: { readonly tasks?: BackgroundTasks } = {}
): InteractionEngines {
  const mailer = createEngineMailer(fastify, options.tasks);
  const ladder = createServerLadderParts(fastify, mailer.passwordDisabledNotices);
  const emailCodes = {
    digest: createServerEmailCodeDigest(fastify),
    addresses: createRepositoryAddressVerifier(
      {
        userCredentials: fastify.repositories.userCredentials,
        users: fastify.repositories.users,
        userAttributes: fastify.repositories.userAttributes,
      },
      (work) => fastify.db.transaction(work),
      fastify.log
    ),
  };
  const realmOf = async (realmId: string) => {
    const realm = await fastify.repositories.realms.findById(realmId);
    if (realm === undefined) throw new Error('a password update for a realm that does not exist');
    return realm;
  };
  const passwordUpdates = createRepositoryPasswordUpdates(
    {
      userCredentials: fastify.repositories.userCredentials,
      users: fastify.repositories.users,
      userRequiredActions: fastify.repositories.userRequiredActions,
    },
    (work) => fastify.db.transaction(work),
    {
      minLength: async (realmId) =>
        accountPoliciesOf(fastify, await realmOf(realmId)).passwordMinLength,
      // The one password policy (#634), as registration checks it: NFC, the
      // minimum length, the blocklist with the address and the service and
      // realm names as context words, and the score floor.
      check: async ({ realmId, identifier, password }) => {
        const realm = await realmOf(realmId);
        const policies = accountPoliciesOf(fastify, realm);
        const checked = fastify.passwordValidators
          .forPolicy({ minLength: policies.passwordMinLength, minScore: policies.passwordMinScore })
          .check(password, {
            email: identifier,
            serviceName: policies.serviceName,
            realmName: realm.name,
          });
        return checked.valid
          ? { kind: 'accepted', password: checked.password, normalization: checked.normalization }
          : { kind: 'rejected', reasons: checked.reasons };
      },
      hash: (password) => fastify.passwordHasher.hashPassword(password),
    }
  );
  const build = (requireVerifiedAccount: boolean) =>
    createCheckedSignInEngine({
      accounts: createRepositoryAccountDirectory(
        {
          users: fastify.repositories.users,
          userCredentials: fastify.repositories.userCredentials,
          adminGrants: fastify.repositories.adminGrants,
          userRequiredActions: fastify.repositories.userRequiredActions,
        },
        fastify.log,
        { hardActionArmed: ladder.hardActionArmed }
      ),
      passwords: createArgon2PasswordVerifier(fastify.passwordHasher, fastify.log),
      // No MFA policy is stored yet: the password is the whole sign-in.
      policy: NO_SECOND_FACTOR_POLICY,
      identifierDigest: ladder.identifierDigest,
      requireVerifiedAccount,
      emailCodes,
      breachCheck: fastify.breachedPasswords.engine,
      passwordUpdates,
      // The realm's upstream identity providers (#639), offered beside the
      // identifier step on a round whose transport can start one.
      upstream: upstreamProviderDirectory(fastify),
      hooks: { ladder: ladder.ladder },
      passwordHardAction: ladder.hardAction,
      onUnavailable: (error) =>
        fastify.log.error({ err: error, port: error.port }, 'sign-in engine store unavailable'),
    });
  const verified = build(true);
  const unverified = build(false);
  return {
    of: (requireVerifiedAccount) => (requireVerifiedAccount ? verified : unverified),
    sendCode: (request) => engineCodeSender(mailer, request),
  };
}

/** The interaction's next state for an engine round's result. */
export function decisionOf(
  reply: FastifyReply,
  result: RoundResult,
  receivedAt: number
): InteractionDecision {
  switch (result.kind) {
    // An upstream provider was picked (#639): the step stays as it was
    // offered, the way back from the provider, with the engine's transaction
    // that names the provider; the transport sends the browser on.
    case 'upstream':
    case 'step': {
      const stored = storedStepOf(result.offer);
      return {
        kind: 'step',
        step: {
          ...stored,
          params: { ...stored.params },
          alternatives: [...stored.alternatives],
          ...(stored.alternativeParams === undefined
            ? {}
            : { alternativeParams: { ...stored.alternativeParams } }),
        },
        personal: { ...result.personal },
        signInTransaction: result.transaction,
      };
    }
    case 'complete':
      // The sign-in is done: the interaction finishes with it, under a new
      // browser session (`authenticated` with no next step). The session's
      // issue time is when the request came, before the account was read
      // (#748).
      return {
        kind: 'authenticated',
        signIn: {
          userId: result.signIn.subject,
          ...(result.signIn.identifier === undefined
            ? {}
            : { identifier: result.signIn.identifier }),
          amr: [...result.signIn.amr],
          issuedAt: receivedAt,
        },
      };
    case 'refused':
      switch (result.reason) {
        case 'throttled':
          reply.header('Retry-After', String(result.retryAfterSeconds));
          throw new TooManyRequestsError('The sign-in is throttled.');
        case 'unavailable':
          throw new TemporarilyUnavailableError(ENGINE_UNAVAILABLE_RETRY_SECONDS, {
            reason: 'sign-in engine store unavailable',
          });
        case 'invalid_answer':
          throw new InvalidAnswerError('the engine refused the answer');
        default:
          // `transaction_ended` again after a fresh start, or a request check
          // this transport does not register: an engine fault.
          throw new Error(`the sign-in engine refused a round: ${result.reason}`);
      }
    case 'redirect':
      // The Interaction API serves every step and registers no request check.
      throw new Error(`the sign-in engine asked to continue elsewhere: ${result.reason}`);
  }
}

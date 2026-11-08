import { AsyncLocalStorage } from 'node:async_hooks';

import {
  type AccountRegistrations,
  type AccountResets,
  createArgon2PasswordVerifier,
  createCaptchaStep,
  createCheckedSignInEngine,
  createRepositoryAccountDirectory,
  createRepositoryAccountRegistrations,
  createRepositoryAccountResets,
  createRepositoryAddressVerifier,
  createRepositoryPasswordUpdates,
  type EmailCodeSender,
  NO_SECOND_FACTOR_POLICY,
  REGISTRATION_NOT_ALLOWED,
  type RepositoryRecoveryCodes,
  RESET_NOT_ALLOWED,
  type RoundResult,
  type SignInEngine,
  storedStepOf,
} from '@qauth-labs/fastify-plugin-sign-in-engine';
import {
  TemporarilyUnavailableError,
  TooManyRequestsError,
  UniqueConstraintError,
} from '@qauth-labs/shared-errors';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

import { env } from '../../config/env';
import { accountPoliciesOf } from './account-policies';
import { type BackgroundTasks } from './background-tasks';
import { createServerBotChallenge, registrationChallengeRequired } from './bot-challenge';
import { endBrowserSessions } from './browser-session';
import { type CodeMail, createEngineMailer, type EngineMailer } from './engine-mail';
import type { InteractionDecision } from './interaction';
import { InvalidAnswerError } from './interaction-errors';
import { InteractionExpiredError } from './interaction-expired';
import { EVENT_CLIENT_ID_MAX_LENGTH } from './interaction-record';
import { createServerPasskeyAccounts, createServerPasskeys } from './passkey-sign-in';
import { createServerEmailCodeDigest, createServerLadderParts } from './password-attempts';
import { resetAllowed, signInNotBefore } from './password-reset';
import { createServerRecoveryCodes } from './recovery-codes';
import { registrationAllowed } from './registration';
import { requestRealm } from './request-realm';
import { createServerRoundLimiter } from './round-limits';
import { createServerTotp } from './totp-sign-in';
import { upstreamProviderDirectory } from './upstream-providers';
import { emitUserEvent, type EventTransaction } from './user-events';

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
  /**
   * Run `rounds` (the engine's rounds for one request) as that request's
   * (#640): a registration they complete records its `user.registered` event,
   * and a reset its `user.password_reset` (#642), with the request's trace
   * id, address and user agent. A registration or a reset outside it fails,
   * closed: its transaction rolls back.
   */
  readonly forRequest: <T>(request: FastifyRequest, rounds: () => Promise<T>) => Promise<T>;
  /**
   * The accounts' recovery codes (#649), which the engines redeem and show
   * once. The account API's regeneration (ACC-02, #687) calls `regenerate`,
   * inside {@link forRequest}, after a fresh authentication.
   */
  readonly recoveryCodes: RepositoryRecoveryCodes;
  /**
   * The engine's mail of the process: the link of an upstream account
   * (#670) tells the owner through it.
   */
  readonly mailer: EngineMailer;
}

/**
 * The request the engine's rounds run for, while one of them registers an
 * account (#640), resets a password (#642) or takes a recovery code (#649). The engine's ports live as long as the process and a
 * request one round, so the registration port reads the request here rather
 * than through a parameter, as the wallet verifier's status audit does
 * (`wallet-verification.ts`).
 */
const roundRequests = new AsyncLocalStorage<FastifyRequest>();

/**
 * The mail a code goes out in, by what the engine decided for the address: a
 * registration's (#640), or a reset's (#642).
 */
export function codeMailOf(mail: Parameters<EmailCodeSender>[0]): CodeMail | undefined {
  // An address a reset may not change (no account, no password, a disabled
  // user): counted as any other, mailed nothing (ADR-017 Decision 8).
  if (mail.reset === 'withheld') return undefined;
  switch (mail.registration) {
    // A disabled account's address: counted as any other, mailed nothing
    // (ADR-017 Decision 8; the answer is the same either way).
    case 'withheld':
      return undefined;
    // An address that already has an account: the code, and the notice that
    // the account exists, which helps its owner sign in.
    case 'account_exists':
      return {
        template: 'account_exists',
        code: mail.code,
        expiresInSeconds: mail.expiresInSeconds,
      };
    default:
      return {
        template: 'code',
        purpose: mail.purpose,
        code: mail.code,
        expiresInSeconds: mail.expiresInSeconds,
      };
  }
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
    const codeMail = codeMailOf(mail);
    const outcome = await mailer.sendCode(request, {
      realm,
      address: mail.address,
      ...(codeMail === undefined ? {} : { mail: codeMail }),
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
 * an emailed code, under the realm's gate (#638, ADR-017 Decision 8 amended
 * 2026-11-08), and only where a code can arrive (#1051): where none can, the
 * gate refuses the account like a wrong password; with the gate off, it
 * signs in unverified. Binding a first passkey or TOTP needs a verified
 * account, never a mailed code.
 *
 * Both meet the round limits (#636, ADR-017 Decision 7) before the ladder:
 * every round from an end-user IP inside its hard block is refused, and each
 * credential round is counted per end-user IP and per IP bucket before its
 * credential is checked.
 *
 * Both check a right password against the realm's breach list and ask for a
 * new one before completing when it is listed or the account holds an
 * `update_password` required action (#635, ADR-020 §3): after the account's
 * second factor, or after an 8-digit recovery code to its address. The new
 * password meets the realm's password policy and the breach list too.
 *
 * Both register a password account when the round's request asks for it
 * (`prompt=create`, #640; ADR-017 Decision 8): only while the realm and the
 * client both allow it (`registrationAllowed`), read again on every round,
 * after an 8-digit code proved the mailbox and a new password met the realm's
 * policy. The account, its verified password credential, its verified email
 * attribute and its `user.registered` event commit in one transaction.
 *
 * Both reset a password (#642; ADR-017 Decision 8) from the password step,
 * while the hosted pages are on and the client is usable (`resetAllowed`),
 * read again on every round: an 8-digit recovery code to an enabled account
 * with a password, any other authenticator the account holds, then a new
 * password that meets the realm's policy. The new password, the verified
 * address, the refresh families' revocation, the session epoch and the
 * `user.password_reset` event commit in one transaction; then the browser
 * sessions end, the epoch's cache is written, the password's failure ladder
 * is cleared and the "password changed" notice goes out. Both read the
 * session epoch on every round of a sign-in that holds a user, so a reset
 * ends every sign-in in progress for its account.
 *
 * Both ask for the bot challenge (#643; ADR-017 Decision 7, rule 5): the
 * `captcha` step before a credential round while a soft threshold of the
 * round limits or the failure ladder holds, and before a registration while
 * the realm's `botChallenge.requiredAtSignUp` or the client's
 * `registration_challenge` asks for it. The provider is the deployment's
 * (`createServerBotChallenge`); a provider that cannot answer refuses the
 * round, and the challenge is never waved through.
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
  // The round limits (#636): the end-user IP's and its bucket's. The
  // Interaction API's client is not authenticated, so no client row.
  const limits = createServerRoundLimiter(fastify, { perClient: false });
  const emailCodes = {
    // Whether a code can reach anyone in the realm (#1051): its mail
    // transport sends. A mock sends nothing in production, as the
    // password-disabled notice counts it (engine-mail.ts); elsewhere a test
    // reads its codes off the mock.
    deliverable: (realmId: string) =>
      fastify.emailService.canSend(realmId, { mockSends: env.NODE_ENV !== 'production' }),
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
  // The bot challenge (#643): the deployment's provider, built once; the
  // proof of work's difficulty is read from the realm row on every challenge.
  const captcha = createCaptchaStep(
    createServerBotChallenge(fastify, async (realmId) => {
      const realm = await fastify.repositories.realms.findById(realmId);
      if (realm === undefined) throw new Error('a bot challenge for a realm that does not exist');
      return realm;
    })
  );
  // The recovery codes (#649): taken with their event, and told to the user.
  const recoveryCodes = createServerRecoveryCodes(fastify, {
    mailer,
    realmOf,
    requestOf: () => roundRequests.getStore(),
  });
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
  /**
   * Record a new account's `user.registered` event: it commits with the
   * account (ADR-019 Decision 8).
   */
  const recordRegistered = async (
    {
      realmId,
      clientId,
      userId,
    }: { readonly realmId: string; readonly clientId: string; readonly userId: string },
    tx: EventTransaction,
    method: 'password' | 'passkey'
  ): Promise<void> => {
    const request = roundRequests.getStore();
    if (request === undefined) {
      throw new Error('an account registered outside the request that asked for it');
    }
    await emitUserEvent(
      request,
      'urn:qauth:event:user.registered:v1-rc.0',
      { method },
      {
        tx,
        realmId,
        userId,
        clientId: clientId.length <= EVENT_CLIENT_ID_MAX_LENGTH ? clientId : null,
        actor: 'user',
      }
    );
  };
  const passwordRegistrations: AccountRegistrations =
    createRepositoryAccountRegistrations<EventTransaction>(
      {
        users: fastify.repositories.users,
        userAttributes: fastify.repositories.userAttributes,
      },
      (work) => fastify.db.transaction(work),
      {
        allowed: async ({ realmId, clientId }) => {
          const realm = await fastify.repositories.realms.findById(realmId);
          if (realm === undefined) return false;
          const client = await fastify.repositories.oauthClients.findByClientId(realmId, clientId);
          return registrationAllowed(accountPoliciesOf(fastify, realm), client);
        },
        // Read again on every round, as `allowed` is. A realm that does not
        // exist asks for the challenge: nothing registers there anyway.
        challengeRequired: async ({ realmId, clientId }) => {
          const realm = await fastify.repositories.realms.findById(realmId);
          if (realm === undefined) return true;
          const client = await fastify.repositories.oauthClients.findByClientId(realmId, clientId);
          return registrationChallengeRequired(
            fastify.policyStore.ofRealm(realm).policies.botChallenge,
            client
          );
        },
        hash: (password) => fastify.passwordHasher.hashPassword(password),
        isUniqueViolation: (error) => error instanceof UniqueConstraintError,
        registered: (input, tx) => recordRegistered(input, tx, 'password'),
      }
    );
  const resets: AccountResets = createRepositoryAccountResets<EventTransaction>(
    {
      userCredentials: fastify.repositories.userCredentials,
      users: fastify.repositories.users,
      userAttributes: fastify.repositories.userAttributes,
      userRequiredActions: fastify.repositories.userRequiredActions,
      refreshTokens: fastify.repositories.refreshTokens,
      authorizationCodes: fastify.repositories.authorizationCodes,
      userSessionEpochs: fastify.repositories.userSessionEpochs,
    },
    (work) => fastify.db.transaction(work),
    {
      allowed: async ({ realmId, clientId }) =>
        resetAllowed(await fastify.repositories.oauthClients.findByClientId(realmId, clientId)),
      hash: (password) => fastify.passwordHasher.hashPassword(password),
      recorded: async ({ realmId, clientId, userId }, tx) => {
        const request = roundRequests.getStore();
        if (request === undefined) {
          throw new Error('a password reset outside the request that asked for it');
        }
        // The reset's event commits with the new password (ADR-019 Decision 8).
        await emitUserEvent(
          request,
          'urn:qauth:event:user.password_reset:v1-rc.0',
          {},
          {
            tx,
            realmId,
            userId,
            clientId: clientId.length <= EVENT_CLIENT_ID_MAX_LENGTH ? clientId : null,
            actor: 'user',
          }
        );
      },
      // None of these can undo the reset, and none may fail it: each failure
      // is logged. The epoch in Postgres refuses every older session and
      // sign-in, but a reader that finds the user's epoch cached keeps the
      // old value until the publish replaces it or it expires (60 s), and
      // the sessions the step below ends stay in their own cache if it fails.
      committed: async ({ realmId, userId, identifier, advancedAt }) => {
        const after = async (step: string, work: () => Promise<unknown>) => {
          try {
            await work();
          } catch (error) {
            fastify.log.error(
              { err: error, realmId, step },
              'a password reset committed, but a step after it failed'
            );
          }
        };
        await after('epoch_cache', () =>
          fastify.sessionEpochs.publish({ realmId, userId, advancedAt })
        );
        await after('browser_sessions', () =>
          endBrowserSessions(fastify, realmId, userId, { reason: 'reset' })
        );
        // The password's run of failures, never a second factor's.
        await after('failure_ladder', async () =>
          ladder.ladder.reset({
            realmId,
            identifierHmac: await ladder.identifierDigest({ realmId, identifier }),
            factor: 'password',
          })
        );
        await after('notice', async () =>
          mailer.sendUncounted(await realmOf(realmId), identifier, {
            template: 'password_changed',
          })
        );
      },
    }
  );
  // Passkeys (#651): offered only while passkey sign-in is on
  // (`WEBAUTHN_ENABLED`). Off, an account that holds a passkey still owes it
  // after its password (the downgrade rule): only a recovery code stands in
  // for it, and without one the round ends.
  const passkeys =
    fastify.passkeySignIn === true
      ? createServerPasskeys(fastify, { mailer, requestOf: () => roundRequests.getStore() })
      : undefined;
  // A registration by passkey alone, with no address (#655), while passkeys
  // are on: the same gate and challenge as a password registration.
  const registrations: AccountRegistrations =
    passkeys === undefined
      ? passwordRegistrations
      : Object.freeze({
          ...passwordRegistrations,
          createWithPasskey: createServerPasskeyAccounts(fastify, {
            registered: (input, tx) => recordRegistered(input, tx, 'passkey'),
          }),
        });
  // The authenticator app (#653): asked after the first factor of an account
  // that holds one, set up when the MFA policy needs a second factor the
  // account lacks. Its hard action is armed only while the hosted pages,
  // where a recovery code is redeemed, are on.
  const totp = createServerTotp(fastify, {
    mailer,
    realmOf,
    recoveryCodes,
    ladder: ladder.ladder,
    hostedPages: env.INTERACTION_UI_ENABLED === true,
    passkeys: passkeys !== undefined,
    requestOf: () => roundRequests.getStore(),
  });
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
      // No MFA policy is stored yet (Foundations): none is required, but for
      // a suite's test switch.
      policy: fastify.signInMfaPolicy ?? NO_SECOND_FACTOR_POLICY,
      identifierDigest: ladder.identifierDigest,
      requireVerifiedAccount,
      emailCodes,
      breachCheck: fastify.breachedPasswords.engine,
      passwordUpdates,
      // The realm's upstream identity providers (#639), offered beside the
      // identifier step on a round whose transport can start one.
      upstream: upstreamProviderDirectory(fastify),
      registrations,
      resets,
      recoveryCodes,
      // The session epoch (#642): a sign-in in progress that began before
      // its account's last reset ends, as does one that began before the
      // account page last changed its password (#844).
      sessionEpochs: {
        notBefore: ({ realmId, userId }) => signInNotBefore(fastify, realmId, userId),
      },
      hooks: { ladder: ladder.ladder, limits },
      steps: [captcha],
      ...(passkeys === undefined ? {} : { passkeys }),
      totp,
      passwordHardAction: ladder.hardAction,
      onUnavailable: (error) =>
        fastify.log.error({ err: error, port: error.port }, 'sign-in engine store unavailable'),
    });
  const verified = build(true);
  const unverified = build(false);
  return {
    of: (requireVerifiedAccount) => (requireVerifiedAccount ? verified : unverified),
    sendCode: (request) => engineCodeSender(mailer, request),
    forRequest: (request, rounds) => roundRequests.run(request, rounds),
    recoveryCodes,
    mailer,
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
      if (result.signIn.registered === true || result.signIn.recovered === true) {
        // A registration (#640; ADR-017 Decisions 8 and 10): the account
        // exists, verified, and nobody signed in. Or a password reset (#642):
        // the mailbox, not a factor, proved the account. Either way the
        // interaction finishes for the account with no browser session, no
        // `amr` and no `auth_time`, as a request decided for it with no
        // sign-in: a step-up, `max_age` or `prompt=login` asks for one. The
        // session epoch it leaves the account at goes with the request: a
        // later reset ends it (a new account has none).
        return {
          kind: 'registered',
          userId: result.signIn.subject,
          sessionEpoch: result.signIn.recovered === true ? result.signIn.epoch : 0,
        };
      }
      // The sign-in is done: the interaction finishes with it, under a new
      // browser session (`authenticated` with no next step). The session's
      // issue time is when the request came, before the account was read
      // (#748). It holds the engine's `amr` and `auth_time`, which the code
      // carries to the tokens (#662).
      return {
        kind: 'authenticated',
        signIn: {
          userId: result.signIn.subject,
          ...(result.signIn.identifier === undefined
            ? {}
            : { identifier: result.signIn.identifier }),
          amr: [...result.signIn.amr],
          authTime: result.signIn.authTime,
          issuedAt: receivedAt,
          // A recovery code in place of a lost factor, which no `amr` value
          // says (#663): the session records it.
          ...(result.signIn.recoveryCode === true ? { recoveryCodeUsed: true } : {}),
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
        case 'request_refused':
          // The realm or the client stopped allowing registration (#640), or
          // the client a reset (#642), since the interaction started: it ends
          // as an expired one does, and nothing was created or changed.
          if (result.code === REGISTRATION_NOT_ALLOWED || result.code === RESET_NOT_ALLOWED) {
            throw new InteractionExpiredError();
          }
          throw new Error(`the sign-in engine refused a round: ${result.code}`);
        default:
          // `transaction_ended` again after a fresh start, or a request check
          // this transport does not register: an engine fault.
          throw new Error(`the sign-in engine refused a round: ${result.reason}`);
      }
    case 'redirect':
      // The Interaction API serves every step and registers no request check,
      // so the sign-in cannot go on anywhere: no step can complete it (a
      // passkey-bound account whose passkeys are all disabled, with no
      // recovery code, #651). It ends as an expired interaction does, and
      // nothing was changed.
      reply.log.warn(
        { reason: result.reason },
        'the sign-in engine asked to continue elsewhere: the interaction ends'
      );
      throw new InteractionExpiredError();
  }
}

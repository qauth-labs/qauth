import { AsyncLocalStorage } from 'node:async_hooks';

import {
  createRepositoryAccountDirectory,
  type RepositoryRecoveryCodes,
  type TotpCredentials,
} from '@qauth-labs/fastify-plugin-sign-in-engine';
import { TemporarilyUnavailableError } from '@qauth-labs/shared-errors';
import type { FastifyInstance, FastifyRequest } from 'fastify';

import { env } from '../../config/env';
import { REDIS_KEYS } from '../constants/redis-keys';
import { type AccountOwner, isSecondFactor } from './account-credentials';
import { InsufficientUserAuthenticationError } from './account-operation-errors';
import { bindsNewFactor, tokenSessionOf } from './account-operation-guard';
import { accountCredentials } from './account-sign-in-methods';
import type { EngineMailer } from './engine-mail';
import { createServerFactorPorts } from './factor-ports';
import { ACCOUNT_PAGES_ENGINE_CLIENT_ID } from './interaction-record';
import { createServerLadderParts } from './password-attempts';
import { emitUserEvent } from './user-events';

/**
 * THE AUTHENTICATOR APP AND THE RECOVERY CODES OF AN ACCOUNT (#844, #1109;
 * ADR-017 Decision 8, ADR-020 §3): the account API's enrolment of an
 * authenticator app (`account.totp.enrollment.create` and `.confirm`), its
 * reads and regeneration of the recovery codes (`account.recoveryCodes.get`
 * and `.regenerate`), and the regeneration the hosted account page shares
 * with it. The removal of the app is `removeCredential`'s
 * (`account-credentials.ts`), as a passkey's.
 *
 * The secret, its binding and the sets are the sign-in engine's own ports
 * (`factor-ports.ts`), with the rules the engine applies at its set-up step:
 *
 * - **A secret is drawn and sealed at once.** 160 bits from a CSPRNG, sealed
 *   under the realm's `data_at_rest` key for this account; the enrolment
 *   keeps only the ciphertext, in Redis, until it is confirmed or lapses
 *   ({@link TOTP_ENROLMENT_LIFETIME_MS}). The secret and its `otpauth://` URI
 *   are answered once, at the start, and never logged.
 * - **Nothing binds before a first valid code.** A wrong one binds nothing
 *   and leaves the enrolment to try again; a code guesses nothing of the
 *   account, as the person holds the secret.
 * - **The account decides, never a channel** (ADR-017 Decision 8, amended
 *   2026-11-08): a claimed account binds its first second factor with no
 *   mailed code; an unclaimed one binds none.
 * - **New after a password-only sign-in** (#1064; amended 2026-11-12): an app
 *   bound under a sign-in that proved nothing beyond the password that is not
 *   new itself is new for the realm's window, and the session behind the
 *   token names it, so the password alone may remove it and its removal ends
 *   that session and what its sign-in opened.
 * - **The first set.** Binding an account's second factor issues a set of
 *   recovery codes where the account holds none it confirmed, as the
 *   engine's binding does; it is answered once.
 *
 * The API answers a set it issues once, with nothing to confirm, so it marks
 * the set confirmed as it answers it: a set left unconfirmed would be
 * replaced by the next sign-in on the hosted pages that owes one, and the
 * codes the caller showed would stop working.
 */

/** How long a started enrolment waits for its first code: ten minutes. */
export const TOTP_ENROLMENT_LIFETIME_MS = 10 * 60 * 1000;

/** The `Retry-After` of a call refused because the enrolment's store could not be reached. */
export const TOTP_ENROLMENT_RETRY_SECONDS = 5;

/** The ports the account API's changes of these factors use. */
export interface AccountFactors {
  readonly totp: TotpCredentials;
  readonly recoveryCodes: RepositoryRecoveryCodes;
  /** Run `work` as `request`'s: a binding's event carries its trace id and client. */
  readonly forRequest: <T>(request: FastifyRequest, work: () => Promise<T>) => Promise<T>;
  /** The account as the sign-in engine reads it: claimed, its address, its factors. */
  readonly accounts: ReturnType<typeof createRepositoryAccountDirectory>;
}

/**
 * The account API's ports, built once while its routes register, over the
 * engine's mail of the module (`mailer`): a binding's event names the client
 * of the token behind it.
 */
export function createAccountFactors(
  fastify: FastifyInstance,
  mailer: EngineMailer
): AccountFactors {
  const requests = new AsyncLocalStorage<FastifyRequest>();
  const ladder = createServerLadderParts(fastify, mailer.passwordDisabledNotices);
  const realmOf = async (realmId: string) => {
    const realm = await fastify.repositories.realms.findById(realmId);
    if (realm === undefined) throw new Error('a notice for a realm that does not exist');
    return realm;
  };
  const { totp, recoveryCodes } = createServerFactorPorts(fastify, {
    mailer,
    realmOf,
    ladder: ladder.ladder,
    requestOf: () => requests.getStore(),
    clientIdOf: (request) => request.jwtPayload?.clientId ?? null,
    // `bindingOfToken` found this session, signed in at the token's
    // `auth_time`, before a new binding was let through.
    nameNewBinding: async (request, { realmId, userId, credentialId }, tx) => {
      const sid = request.jwtPayload?.sid;
      if (typeof sid !== 'string' || sid.length === 0) return false;
      return fastify.repositories.sessions.nameNewCredential(
        realmId,
        sid,
        userId,
        credentialId,
        tx
      );
    },
    hostedPages: env.INTERACTION_UI_ENABLED === true,
    passkeys: fastify.passkeySignIn === true,
  });
  const accounts = createRepositoryAccountDirectory(
    {
      users: fastify.repositories.users,
      userCredentials: fastify.repositories.userCredentials,
      adminGrants: fastify.repositories.adminGrants,
      userRequiredActions: fastify.repositories.userRequiredActions,
    },
    fastify.log,
    { hardActionArmed: ladder.hardActionArmed }
  );
  const factors: AccountFactors = {
    totp,
    recoveryCodes,
    forRequest: (request, work) => requests.run(request, work),
    accounts,
  };
  return Object.freeze(factors);
}

/** A store the enrolment needs could not be reached: 503, with `Retry-After`. */
function enrolmentStoreUnavailable(fastify: FastifyInstance, cause: unknown) {
  fastify.log.error({ err: cause }, 'the authenticator app enrolment store could not be reached');
  return new TemporarilyUnavailableError(TOTP_ENROLMENT_RETRY_SECONDS, {
    reason: 'authenticator app enrolment unavailable',
  });
}

// ── The enrolment ────────────────────────────────────────────────────────────

/** A started enrolment, as Redis keeps it: the sealed secret, never the secret. */
interface HeldEnrolment {
  readonly sealed: string;
  readonly expiresAt: number;
}

/** The held enrolment `raw` holds, or `undefined` for anything else. */
function heldEnrolmentOf(raw: string | null): HeldEnrolment | undefined {
  if (raw === null) return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return undefined;
  }
  const { sealed, expiresAt } = (parsed ?? {}) as Partial<Record<keyof HeldEnrolment, unknown>>;
  if (typeof sealed !== 'string' || sealed.length === 0) return undefined;
  if (typeof expiresAt !== 'number' || !Number.isSafeInteger(expiresAt)) return undefined;
  return { sealed, expiresAt };
}

/** Delete `key` only while it still holds `value`: one confirmation takes an enrolment. */
const TAKE_ENROLMENT = `
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('DEL', KEYS[1])
end
return 0
`;

/** What starting an enrolment did. */
export type TotpEnrolmentStart =
  | {
      readonly kind: 'started';
      /** The secret, base32: answered once, never kept in clear. */
      readonly secret: string;
      /** The same secret as an `otpauth://totp/` URI, the realm as issuer. */
      readonly otpauthUri: string;
      readonly expiresAt: number;
    }
  /**
   * The account holds an authenticator app already, is unclaimed, or has no
   * address an authenticator app could show beside the code.
   */
  | { readonly kind: 'conflict'; readonly reason: 'bound' | 'unclaimed' | 'no_address' };

/**
 * Start an authenticator-app enrolment for the account
 * (`account.totp.enrollment.create`): draw a secret, seal it, keep the
 * ciphertext for {@link TOTP_ENROLMENT_LIFETIME_MS}, replacing an enrolment
 * not yet confirmed, and answer the secret once. The caller has checked a
 * fresh sign-in.
 *
 * An account that holds an authenticator app, disabled or not, gets
 * `conflict`: it removes that one first. A sign-in that used a recovery code
 * in place of a lost one is the exception (ADR-017 Decision 8: only a rebind
 * after a lost factor lets a recovery code stand in for it): its enrolment
 * replaces the app once confirmed, so a realm whose MFA policy refuses the
 * removal of the last second factor still lets the person rebind. So does
 * an unclaimed account, which binds no factor (ADR-017 Decision 8), and one
 * with no address, which an authenticator app shows beside the code, as the
 * hosted page's set-up skips it.
 */
export async function startTotpEnrolment(
  fastify: FastifyInstance,
  request: FastifyRequest,
  factors: AccountFactors,
  owner: AccountOwner,
  now: number = Date.now()
): Promise<TotpEnrolmentStart> {
  const { realmId, userId } = owner;
  const account = await factors.accounts.findByUserId(realmId, userId);
  if (account === null || account.userId !== userId) {
    // The token guard found an enabled user of the realm a moment ago.
    throw new Error('an enrolment for an account that does not exist');
  }
  if (
    account.factors.some((factor) => factor.type === 'totp') &&
    !(await rebindsLostFactor(request, realmId, now))
  ) {
    return { kind: 'conflict', reason: 'bound' };
  }
  if (!account.verified) return { kind: 'conflict', reason: 'unclaimed' };
  const label = account.identifier;
  if (label === undefined) return { kind: 'conflict', reason: 'no_address' };
  // A binding this sign-in would make new must have a session to name it:
  // refused now, before the person scans a secret that could not bind.
  await bindingOfToken(request, realmId, userId, now);
  const started = await factors.totp.start({ realmId, userId, identifier: label });
  const expiresAt = now + TOTP_ENROLMENT_LIFETIME_MS;
  const held: HeldEnrolment = { sealed: started.sealed, expiresAt };
  try {
    await fastify.redis.set(
      REDIS_KEYS.ACCOUNT_TOTP_ENROLMENT(realmId, userId),
      JSON.stringify(held),
      'PX',
      TOTP_ENROLMENT_LIFETIME_MS
    );
  } catch (cause) {
    throw enrolmentStoreUnavailable(fastify, cause);
  }
  return {
    kind: 'started',
    secret: started.display.secret,
    otpauthUri: started.display.otpauthUri,
    expiresAt,
  };
}

/** A new set of recovery codes, as the API answers it once. */
export interface IssuedRecoveryCodes {
  readonly codes: readonly string[];
  readonly issuedAt: number;
}

/** What confirming an enrolment did. */
export type TotpEnrolmentConfirmation =
  | {
      readonly kind: 'bound';
      readonly enabledAt: number;
      /** The account's first set, where its binding issued one. */
      readonly recoveryCodes?: IssuedRecoveryCodes;
    }
  /** No enrolment of the account waits, it lapsed, or it can no longer bind. */
  | { readonly kind: 'not_found' }
  /** The code is not the enrolment's secret's, now. Nothing was bound. */
  | { readonly kind: 'invalid_code' };

/**
 * Bind the account's started enrolment with its first code
 * (`account.totp.enrollment.confirm`). The caller has checked a fresh
 * sign-in. The code is checked against the held ciphertext; a valid one
 * takes the enrolment (a second confirmation finds none) and binds the
 * secret with the time step it matched as its last accepted one, so the same
 * code never signs in. The binding and its `user.credential_added` event
 * commit together; the "authenticator app added" notice follows, and the
 * account's TOTP counter starts afresh.
 *
 * The binding is new (#1064) when the sign-in behind the token proved
 * nothing beyond the password that is not new itself
 * (`bindsNewFactor`), and the token's session then names it. The account's
 * first set of recovery codes is issued where it holds no set it confirmed,
 * marked confirmed and answered once; a set that cannot be issued is logged,
 * and the binding stands: the next sign-in on the hosted pages shows one.
 */
export async function confirmTotpEnrolment(
  fastify: FastifyInstance,
  request: FastifyRequest,
  factors: AccountFactors,
  owner: AccountOwner,
  code: string,
  now: number = Date.now()
): Promise<TotpEnrolmentConfirmation> {
  const { realmId, userId } = owner;
  const key = REDIS_KEYS.ACCOUNT_TOTP_ENROLMENT(realmId, userId);
  let raw: string | null;
  try {
    raw = await fastify.redis.get(key);
  } catch (cause) {
    throw enrolmentStoreUnavailable(fastify, cause);
  }
  const held = heldEnrolmentOf(raw);
  if (held === undefined || held.expiresAt <= now) return { kind: 'not_found' };
  const checked = await factors.totp.check({ realmId, userId, sealed: held.sealed, code });
  if (checked.kind !== 'valid') return { kind: 'invalid_code' };
  // Read before the enrolment is taken, so a read that fails leaves it to
  // confirm again. The account as it is now: an app bound meanwhile voids
  // the enrolment, unless this is the rebind of a lost one, which replaces it.
  const account = await factors.accounts.findByUserId(realmId, userId);
  if (
    account === null ||
    (account.factors.some((factor) => factor.type === 'totp') &&
      !(await rebindsLostFactor(request, realmId, now)))
  ) {
    return { kind: 'not_found' };
  }
  const { isNew } = await bindingOfToken(request, realmId, userId, now);
  let taken: unknown;
  try {
    taken = await fastify.redis.eval(TAKE_ENROLMENT, 1, key, raw as string);
  } catch (cause) {
    throw enrolmentStoreUnavailable(fastify, cause);
  }
  // Another confirmation took it first, or a new enrolment replaced it.
  if (taken !== 1) return { kind: 'not_found' };
  const binding = await factors.forRequest(request, () =>
    factors.totp.bind({
      realmId,
      userId,
      clientId: owner.clientId ?? ACCOUNT_PAGES_ENGINE_CLIENT_ID,
      sealed: held.sealed,
      step: checked.step,
      ...(isNew ? { isNew: true } : {}),
    })
  );
  // Disabled, unclaimed or gone since the start: nothing is bound. A new
  // one was named on the token's session in the binding's transaction.
  if (binding.kind !== 'bound') return { kind: 'not_found' };
  const enabledAt = Date.now();
  const recoveryCodes = await firstRecoveryCodes(fastify, request, factors, owner);
  return {
    kind: 'bound',
    enabledAt,
    ...(recoveryCodes === undefined ? {} : { recoveryCodes }),
  };
}

/**
 * What the sign-in behind the request's token makes of a factor bound under
 * it (#1064): whether it is new. A new one is named on the browser session
 * that sign-in started, live or ended (an ended session's refresh-token
 * families outlive it, and the password's undo ends them too), so a token
 * that names no such session binds none: it gets the step-up challenge with
 * `max_age="0"`, and the sign-in it sends the person through names one. A
 * refreshed token names none.
 */
async function bindingOfToken(
  request: FastifyRequest,
  realmId: string,
  userId: string,
  now: number
): Promise<{ readonly isNew: boolean }> {
  const claims = request.jwtPayload;
  if (claims === undefined) throw new Error('an account change without its token');
  const credentials = await accountCredentials(request.server, realmId, userId);
  const session = await tokenSessionOf(request, claims, realmId, now);
  const isNew = bindsNewFactor(
    { amr: claims.amr ?? [], ...(session === undefined ? {} : { session }) },
    credentials,
    realmId,
    now
  );
  if (isNew && session === undefined && !(await namesSignIn(request, realmId, userId))) {
    throw new InsufficientUserAuthenticationError(0);
  }
  return { isNew };
}

/**
 * Whether the request is the rebind of a lost factor (ADR-017 Decision 8):
 * the live session behind its token took a recovery code in place of the
 * factor, as the operation guard let it through on.
 */
async function rebindsLostFactor(
  request: FastifyRequest,
  realmId: string,
  now: number
): Promise<boolean> {
  const claims = request.jwtPayload;
  if (claims === undefined) return false;
  return (await tokenSessionOf(request, claims, realmId, now))?.recoveryCodeUsed === true;
}

/**
 * Whether the token's `sid` names a session of `userId` in the realm signed
 * in at the token's `auth_time` (to the second the claim keeps), live or
 * ended: the sign-in the token came from.
 */
async function namesSignIn(
  request: FastifyRequest,
  realmId: string,
  userId: string
): Promise<boolean> {
  const { sid, authTime } = request.jwtPayload ?? {};
  if (typeof sid !== 'string' || sid.length === 0 || authTime === undefined) return false;
  const session = await request.server.repositories.sessions.findById(realmId, sid);
  return (
    session !== undefined &&
    session.userId === userId &&
    Math.floor(session.authTime / 1000) * 1000 === authTime
  );
}

/**
 * The account's first set of recovery codes after a binding, as the
 * engine's binding owes one: where the account holds no set it confirmed.
 * Marked confirmed as it is answered. `undefined` where none is owed, or one
 * could not be issued (logged).
 */
async function firstRecoveryCodes(
  fastify: FastifyInstance,
  request: FastifyRequest,
  factors: AccountFactors,
  owner: AccountOwner
): Promise<IssuedRecoveryCodes | undefined> {
  const account = { realmId: owner.realmId, userId: owner.userId };
  try {
    const status = await factors.recoveryCodes.status(account);
    if (status.issued && status.confirmed) return undefined;
    const set = await factors.forRequest(request, () => factors.recoveryCodes.issue(account));
    // A sign-in showed and confirmed one meanwhile: that set stands.
    if (set === null) return undefined;
    return await answeredSet(fastify, factors, owner, set);
  } catch (error) {
    fastify.log.error(
      { err: error, realmId: owner.realmId },
      'an authenticator app was bound, but its first recovery codes could not be issued'
    );
    return undefined;
  }
}

/**
 * Mark `set` confirmed and read when it was issued: the set as the API
 * answers it once. `undefined` when another issuance replaced it meanwhile:
 * its codes no longer work.
 */
async function answeredSet(
  fastify: FastifyInstance,
  factors: AccountFactors,
  owner: AccountOwner,
  set: { readonly codes: readonly string[]; readonly setId: string }
): Promise<IssuedRecoveryCodes | undefined> {
  const { realmId, userId } = owner;
  const confirmed = await factors.recoveryCodes.confirm({ realmId, userId, setId: set.setId });
  if (!confirmed) return undefined;
  const current = await fastify.repositories.userRecoveryCodes.currentSet(realmId, userId);
  if (current === undefined) return undefined;
  return { codes: set.codes, issuedAt: current.issuedAt };
}

// ── Recovery codes ───────────────────────────────────────────────────────────

/** What the account holds of recovery codes, without the codes. */
export interface RecoveryCodeSummary {
  /** How many unused codes are left: 0 without a set. */
  readonly remaining: number;
  /** When the current set was issued; `null` without one. */
  readonly issuedAt: number | null;
}

/** The account's recovery codes, as `account.recoveryCodes.get` reads them: never the codes. */
export async function readRecoveryCodeSummary(
  fastify: FastifyInstance,
  realmId: string,
  userId: string
): Promise<RecoveryCodeSummary> {
  const set = await fastify.repositories.userRecoveryCodes.currentSet(realmId, userId);
  return set === undefined
    ? { remaining: 0, issuedAt: null }
    : { remaining: set.unused, issuedAt: set.issuedAt };
}

/** The ports a regeneration uses: the hosted page's engines, or the account API's. */
export interface RecoveryCodePorts {
  readonly recoveryCodes: Pick<RepositoryRecoveryCodes, 'regenerate'>;
  readonly forRequest: <T>(request: FastifyRequest, work: () => Promise<T>) => Promise<T>;
}

/** What a regeneration did. */
export type RecoveryCodesResult =
  | { readonly kind: 'issued'; readonly codes: readonly string[]; readonly setId: string }
  /** The account holds no second factor and no passkey: a set would stand in for nothing. */
  | { readonly kind: 'conflict' };

/**
 * Issue a new set of recovery codes (`account.recoveryCodes.regenerate`),
 * returned once: every code of the old set stops working, and the notice
 * goes out. The caller has checked a fresh sign-in with the strongest factor
 * (and, on the page, the CSRF token), and answers the codes with
 * `Cache-Control: no-store`. The store writes the set itself, so
 * `user.recovery_codes_regenerated` is recorded right after it, naming the
 * client the change came through; a record that fails is logged, and the
 * codes are still answered: the old set is gone either way.
 */
export async function regenerateRecoveryCodes(
  fastify: FastifyInstance,
  request: FastifyRequest,
  ports: RecoveryCodePorts,
  owner: AccountOwner
): Promise<RecoveryCodesResult> {
  const { realmId, userId } = owner;
  const held = (await fastify.repositories.userCredentials.findAllByUserId(userId)).filter(
    (row) => row.realmId === realmId
  );
  if (!held.some(isSecondFactor)) return { kind: 'conflict' };
  const set = await ports.forRequest(request, () =>
    ports.recoveryCodes.regenerate({ realmId, userId })
  );
  try {
    await emitUserEvent(
      request,
      'urn:qauth:event:user.recovery_codes_regenerated:v1-rc.0',
      {},
      { realmId, userId, clientId: owner.clientId ?? null, actor: 'user' }
    );
  } catch (error) {
    fastify.log.error({ err: error, realmId }, 'recovery codes were regenerated, but not recorded');
  }
  return { kind: 'issued', codes: set.codes, setId: set.setId };
}

/**
 * The account API's regeneration: {@link regenerateRecoveryCodes}, then the
 * set marked confirmed as it is answered once. `'conflict'` for an account
 * with no second factor or passkey, or a set another regeneration replaced
 * before it could be answered.
 */
export async function regenerateAnsweredRecoveryCodes(
  fastify: FastifyInstance,
  request: FastifyRequest,
  factors: AccountFactors,
  owner: AccountOwner
): Promise<IssuedRecoveryCodes | 'conflict'> {
  const result = await regenerateRecoveryCodes(fastify, request, factors, owner);
  if (result.kind === 'conflict') return 'conflict';
  return (await answeredSet(fastify, factors, owner, result)) ?? 'conflict';
}

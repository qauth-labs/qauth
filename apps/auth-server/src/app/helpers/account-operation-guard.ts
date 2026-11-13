import { WEBAUTHN_PROVIDER_TYPE } from '@qauth-labs/fastify-plugin-federation';
import type { JWTPayload } from '@qauth-labs/fastify-plugin-jwt';
import { TOTP_PROVIDER_TYPE } from '@qauth-labs/fastify-plugin-sign-in-engine';
import { TemporarilyUnavailableError } from '@qauth-labs/shared-errors';
import type { FastifyReply, FastifyRequest } from 'fastify';

import type { FamilyOperationClass } from '../api-conventions/families';
import {
  DelegatedTokenRefusedError,
  InsufficientUserAuthenticationError,
} from './account-operation-errors';
import { familyOperation } from './family-token';
import { isNewCredential } from './new-factors';
import { requestRealm } from './request-realm';
import { emitUserEvent } from './user-events';

/**
 * THE ACCOUNT API'S OPERATION GUARD (#663): the one place that decides whether
 * a call to an account operation may proceed, from the rules the account
 * contract gives the operation (`libs/shared/account-contract`,
 * `x-qauth-fresh-authentication` and `x-qauth-act-chain`).
 *
 * In order:
 *
 * 1. The family's token guard (`requireFamilyToken`): a token whose only
 *    audience is the account API, of an enabled user of the request's realm,
 *    that carries the account scope of the operation's class (#933,
 *    `familyOperation`): `qauth:account:read` or `qauth:account:write`. A
 *    token without it gets 403 `forbidden` with an `insufficient_scope`
 *    challenge, before the rules below, which no new sign-in would lift
 *    for it.
 * 2. An act-chain token (RFC 8693 `act`) at an operation that takes none gets
 *    403 `delegated_token_refused` (ADR-019 Decision 7), before any
 *    fresh-authentication check, so a delegated caller never gets a challenge
 *    it cannot meet. An act-chain token never counts as the person's fresh
 *    authentication either, so an operation that asks for one refuses it too.
 * 3. An operation that asks for fresh authentication (ADR-017 Decision 8)
 *    needs a sign-in at most {@link FRESH_AUTHENTICATION_MAX_AGE_SECONDS} old
 *    (the token's `auth_time`) whose `amr` holds the account's strongest bound
 *    factor ({@link requiredFactorOf}). A sign-in too old, one the token says
 *    nothing of, or one dated ahead of the server's clock by more than
 *    {@link AUTH_TIME_CLOCK_SKEW_LEEWAY_SECONDS}, gets the RFC 9470 §3
 *    challenge with `max_age="300"`; a recent one without the factor gets it
 *    with `max_age="0"`.
 * 4. Where the operation takes `strongest-factor-or-recovery-code`, a recent
 *    sign-in that used a recovery code in place of a lost factor passes too.
 *    A recovery code adds no `amr` value, so the guard reads the browser
 *    session the token names in `sid`, which records it.
 * 5. A removal of a passkey or the authenticator app that is still new
 *    (#1064; ADR-017 Decision 8, amended 2026-11-12) passes on a recent
 *    sign-in that proved the password alone, as the hosted account page's
 *    removal does (#1108): the route names the credential it removes
 *    ({@link AccountOperationOptions.removing}).
 *
 * A failed read of the account's factors or of the session refuses the call
 * with 503 and `Retry-After`: the guard never lets a call through on what it
 * could not read. Every refusal is recorded as a
 * `request.account_operation_refused` event, and a failed write of it fails
 * the request.
 *
 * The values below copy the account contract's; the contract is a
 * development-time library the server does not ship, and
 * `account-operation-guard.test.ts` keeps the copies equal to it.
 */

/** How old a sign-in may be, in seconds, where an operation asks for fresh authentication. */
export const FRESH_AUTHENTICATION_MAX_AGE_SECONDS = 300;

/**
 * How far, in seconds, a token's `auth_time` may lie ahead of the server's
 * clock and still count: the leeway the server gives a client assertion's
 * `iat` (`CLIENT_ASSERTION_CLOCK_SKEW_LEEWAY_SECONDS`), for nodes whose clocks
 * disagree a little. A time further ahead is one no sign-in had: a node whose
 * clock ran ahead dated it, and taking it would stretch the five minutes by
 * as much as that clock was off. The guard's own value, not the contract's.
 */
export const AUTH_TIME_CLOCK_SKEW_LEEWAY_SECONDS = 60;

/** What an operation needs of the sign-in behind the token: `x-qauth-fresh-authentication`. */
export const FRESH_AUTHENTICATION_RULES = [
  'none',
  'strongest-factor',
  'strongest-factor-or-recovery-code',
] as const;

export type FreshAuthenticationRule = (typeof FRESH_AUTHENTICATION_RULES)[number];

/** Whether an operation takes an act-chain token: `x-qauth-act-chain`. */
export const ACT_CHAIN_RULES = ['accepted', 'refused'] as const;

export type ActChainRule = (typeof ACT_CHAIN_RULES)[number];

/** An account operation's rules, as the contract states them. */
export interface AccountOperationRules {
  /** The contract's `operationId`, such as `account.password.change`. */
  readonly operationId: string;
  /** The contract's `x-qauth-class`: its scope is the account scope of this class (#933). */
  readonly operationClass: FamilyOperationClass;
  /** The contract's `x-qauth-permission`, such as `password.write`. */
  readonly permission: string;
  readonly freshAuthentication: FreshAuthenticationRule;
  readonly actChain: ActChainRule;
}

/**
 * The RFC 8176 `amr` value of an account's strongest bound factor: `pop` for
 * a passkey, `otp` for an authenticator app (TOTP), `pwd` otherwise.
 */
export type AccountFactor = 'pop' | 'otp' | 'pwd';

/** The `Retry-After` of a call refused because the guard could not read what it decides on. */
export const ACCOUNT_LOOKUP_RETRY_SECONDS = 5;

/** An operation id of the account API: `account.` and dotted camelCase words. */
const OPERATION_ID = /^account(?:\.[a-z][A-Za-z]*)+$/;

/** The refusals the event records, with the code of each. */
type RefusalReason =
  | 'delegated_token'
  | 'authentication_too_old'
  | 'strongest_factor_missing'
  | 'lookup_failed';

const REFUSED_EVENT = 'urn:qauth:event:request.account_operation_refused:v1-rc.0';

/** The credential a removal names: one passkey, or the account's authenticator app. */
export type CredentialTarget =
  | { readonly type: 'passkey'; readonly id: string }
  | { readonly type: 'totp' };

/** Whether `row` is the credential `target` names. */
export function isTargetCredential(
  row: { readonly id?: string; readonly providerType: string },
  target: CredentialTarget
): boolean {
  return target.type === 'passkey'
    ? row.id === target.id && row.providerType === WEBAUTHN_PROVIDER_TYPE
    : row.providerType === TOTP_PROVIDER_TYPE;
}

/** A credential row, as far as {@link requiredFactorOf} reads it. */
export interface BoundCredential {
  readonly id?: string;
  readonly providerType: string;
  readonly realmId: string;
  /** When the credential stops being new (#1064); `null` or absent for one that never was. */
  readonly newUntil?: number | null;
}

/**
 * The factor a fresh sign-in must prove for an account holding `credentials`
 * in `realmId` (ADR-017 Decision 8): `pop` when a passkey is bound, else `otp`
 * when an authenticator app is, else `pwd`. A disabled factor still counts as
 * bound: disabling one never lowers what a sign-in must prove (ADR-017, the
 * downgrade rule). A row of another realm is no factor here (#489), nor is a
 * credential that is new at `now` (#1064; ADR-017 Decision 8, amended
 * 2026-11-12): bound after a sign-in that proved only the password, it is not
 * the account's strongest factor until its window ends.
 */
export function requiredFactorOf(
  credentials: readonly BoundCredential[],
  realmId: string,
  now: number = Date.now()
): AccountFactor {
  const held = new Set(
    credentials
      .filter((row) => row.realmId === realmId && !isNewCredential(row, now))
      .map((row) => row.providerType)
  );
  if (held.has(WEBAUTHN_PROVIDER_TYPE)) return 'pop';
  if (held.has(TOTP_PROVIDER_TYPE)) return 'otp';
  return 'pwd';
}

/** The `amr` value a credential of `providerType` proves at a sign-in: `pop` or `otp`, else none. */
function factorOfProvider(providerType: string): AccountFactor | undefined {
  if (providerType === WEBAUTHN_PROVIDER_TYPE) return 'pop';
  if (providerType === TOTP_PROVIDER_TYPE) return 'otp';
  return undefined;
}

/**
 * Whether the account holds a credential in `realmId` that is new at `now`
 * and proves `factor` (#1064): only then may a sign-in's `factor` have come
 * from a new credential alone.
 */
export function holdsNewFactor(
  factor: AccountFactor,
  credentials: readonly BoundCredential[],
  realmId: string,
  now: number
): boolean {
  return credentials.some(
    (row) =>
      row.realmId === realmId &&
      isNewCredential(row, now) &&
      factorOfProvider(row.providerType) === factor
  );
}

/**
 * Whether a sign-in proved `factor` only through a new credential (#1064):
 * its session names (`named`, the session's `new_credential_ids`) a
 * credential of the account that is still new at `now` and proves `factor`.
 * The engine names a credential it proved only while it is new, so such a
 * sign-in proved no other credential of that factor.
 */
export function provedOnlyThroughNew(
  factor: AccountFactor,
  named: readonly string[],
  credentials: readonly BoundCredential[],
  realmId: string,
  now: number
): boolean {
  if (named.length === 0) return false;
  return credentials.some(
    (row) =>
      row.realmId === realmId &&
      row.id !== undefined &&
      named.includes(row.id) &&
      isNewCredential(row, now) &&
      factorOfProvider(row.providerType) === factor
  );
}

/**
 * Whether the sign-in behind a token, at `authTime` (epoch ms, from the
 * token's `auth_time`), is fresh at `now`: at most
 * {@link FRESH_AUTHENTICATION_MAX_AGE_SECONDS} old. A token that says nothing
 * of when its sign-in happened is not fresh, nor is one that dates it more
 * than {@link AUTH_TIME_CLOCK_SKEW_LEEWAY_SECONDS} ahead of `now`.
 */
export function isFreshSignIn(authTime: number | undefined, now: number): boolean {
  if (typeof authTime !== 'number' || !Number.isFinite(authTime)) return false;
  if (authTime - now > AUTH_TIME_CLOCK_SKEW_LEEWAY_SECONDS * 1000) return false;
  return now - authTime <= FRESH_AUTHENTICATION_MAX_AGE_SECONDS * 1000;
}

/** Whether a token carries an act chain (RFC 8693 `act`). */
function isDelegated(claims: JWTPayload): boolean {
  return claims.act !== undefined && claims.act !== null;
}

/** The token's own subject: the family guard has resolved it to a user of the realm. */
function subjectOf(claims: JWTPayload | undefined): string {
  if (typeof claims?.sub !== 'string' || claims.sub.length === 0) {
    throw new Error('the account operation guard ran before the token guard');
  }
  return claims.sub;
}

/** Record one refusal of `rules.operationId`, then hand back the error that answers it. */
async function refused<E extends Error>(
  request: FastifyRequest,
  claims: JWTPayload,
  rules: AccountOperationRules,
  refusal: { reason: RefusalReason; requiredFactor?: AccountFactor; maxAge?: number },
  error: E
): Promise<E> {
  await emitUserEvent(
    request,
    REFUSED_EVENT,
    {
      operation: rules.operationId,
      reason: refusal.reason,
      ...(refusal.requiredFactor === undefined ? {} : { requiredFactor: refusal.requiredFactor }),
      ...(refusal.maxAge === undefined ? {} : { maxAge: refusal.maxAge }),
    },
    {
      userId: claims.sub,
      clientId: claims.clientId,
      actor: 'user',
      ...(isDelegated(claims) && claims.act ? { act: claims.act } : {}),
    }
  );
  return error;
}

/** The 503 of a read the guard could not make; the cause is logged, never sent. */
function lookupFailed(request: FastifyRequest, read: string, cause: unknown) {
  request.log.error({ err: cause, read }, 'the account operation guard could not read its input');
  return new TemporarilyUnavailableError(ACCOUNT_LOOKUP_RETRY_SECONDS, {
    reason: `account operation guard: ${read} unavailable`,
  });
}

/**
 * The browser session the token names (`sid`), when it is the recent sign-in
 * behind it: a live session of the token's user in the request's realm,
 * signed in at the token's `auth_time` (to the second the claim keeps).
 * `undefined` for a token that names none, or names another. Throws when the
 * session cannot be read.
 */
async function sessionOfToken(
  request: FastifyRequest,
  claims: JWTPayload,
  realmId: string,
  now: number
) {
  const sid = claims.sid;
  if (typeof sid !== 'string' || sid.length === 0 || claims.authTime === undefined) {
    return undefined;
  }
  const session = await request.server.repositories.sessions.findById(realmId, sid);
  if (
    session === undefined ||
    session.userId !== claims.sub ||
    (session.revokedAt !== null && session.revokedAt !== undefined) ||
    session.expiresAt <= now ||
    Math.floor(session.authTime / 1000) * 1000 !== claims.authTime
  ) {
    return undefined;
  }
  return session;
}

/**
 * The checks of steps 2 to 5 for a request whose token the family guard has
 * already accepted (`request.jwtPayload`). Throws the error that answers a
 * refusal, after recording it.
 *
 * @param removing - the credential a removal is for (step 5): while it is
 *   new, a recent sign-in that proved the password removes it
 */
export async function checkAccountOperation(
  request: FastifyRequest,
  rules: AccountOperationRules,
  removing?: CredentialTarget
): Promise<void> {
  const claims = request.jwtPayload as JWTPayload;
  const userId = subjectOf(claims);

  // ADR-019 Decision 7: no act-chain token where the operation refuses one,
  // and none counts as the person's fresh authentication.
  if (
    isDelegated(claims) &&
    (rules.actChain === 'refused' || rules.freshAuthentication !== 'none')
  ) {
    throw await refused(
      request,
      claims,
      rules,
      { reason: 'delegated_token' },
      new DelegatedTokenRefusedError()
    );
  }
  if (rules.freshAuthentication === 'none') return;

  const now = Date.now();
  if (!isFreshSignIn(claims.authTime, now)) {
    throw await refused(
      request,
      claims,
      rules,
      { reason: 'authentication_too_old', maxAge: FRESH_AUTHENTICATION_MAX_AGE_SECONDS },
      new InsufficientUserAuthenticationError(FRESH_AUTHENTICATION_MAX_AGE_SECONDS)
    );
  }

  const realmId = requestRealm(request).id;
  let credentials: readonly BoundCredential[];
  try {
    credentials = await request.server.repositories.userCredentials.findAllByUserId(userId);
  } catch (cause) {
    throw await refused(
      request,
      claims,
      rules,
      { reason: 'lookup_failed' },
      lookupFailed(request, 'credentials', cause)
    );
  }
  // Step 5: the password alone, after a fresh sign-in, removes a credential
  // while it is new (#1064; ADR-017 Decision 8, amended 2026-11-12).
  if (
    removing !== undefined &&
    (claims.amr ?? []).includes('pwd') &&
    credentials.some(
      (row) =>
        row.realmId === realmId && isTargetCredential(row, removing) && isNewCredential(row, now)
    )
  ) {
    return;
  }
  const requiredFactor = requiredFactorOf(credentials, realmId, now);
  // The session behind the token, read once and only when a rule needs it.
  let read: Promise<Awaited<ReturnType<typeof sessionOfToken>>> | undefined;
  const session = async () => {
    read ??= sessionOfToken(request, claims, realmId, now);
    try {
      return await read;
    } catch (cause) {
      throw await refused(
        request,
        claims,
        rules,
        { reason: 'lookup_failed' },
        lookupFailed(request, 'session', cause)
      );
    }
  };
  if ((claims.amr ?? []).includes(requiredFactor)) {
    // The account holds a new credential of that factor (#1064): the
    // token's sign-in counts only when its session shows it proved another.
    if (!holdsNewFactor(requiredFactor, credentials, realmId, now)) return;
    const own = await session();
    if (
      own !== undefined &&
      !provedOnlyThroughNew(requiredFactor, own.newCredentialIds ?? [], credentials, realmId, now)
    ) {
      return;
    }
  }

  if (rules.freshAuthentication === 'strongest-factor-or-recovery-code') {
    if ((await session())?.recoveryCodeUsed === true) return;
  }

  throw await refused(
    request,
    claims,
    rules,
    { reason: 'strongest_factor_missing', requiredFactor, maxAge: 0 },
    new InsufficientUserAuthenticationError(0)
  );
}

/** A route of the account API, as its guard and its schema see it. */
export interface AccountOperationGuard {
  /** The route's `preValidation`: the family's token guard, then the operation's rules. */
  readonly guard: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
  /** The members of the route's schema that state the rules, as the contract does. */
  readonly schema: {
    readonly operationId: string;
    readonly 'x-qauth-class': FamilyOperationClass;
    readonly 'x-qauth-permission': string;
    readonly 'x-qauth-fresh-authentication': FreshAuthenticationRule;
    readonly 'x-qauth-act-chain': ActChainRule;
  };
}

/** What a route adds to its operation's rules. */
export interface AccountOperationOptions {
  /**
   * The credential the request removes, read from the request before it is
   * validated (step 5): `undefined` when it names none. A value no credential
   * of the account has matches none, so the rule of the strongest factor
   * applies.
   */
  readonly removing?: (request: FastifyRequest) => CredentialTarget | undefined;
}

/**
 * The guard of one account operation, built once per route: its
 * `preValidation` hook, which runs before validation so a caller without a
 * fitting token learns nothing about what the route accepts, and the schema
 * members that publish its rules. A route spreads both, so what the guard
 * checks and what the OpenAPI document says are one value, and
 * `account-contract.test.ts` holds that value to the contract.
 *
 * @throws {Error} at build time for an id that is no account operation id or
 *   a rule the contract does not define
 */
export function accountOperation(
  rules: AccountOperationRules,
  options: AccountOperationOptions = {}
): AccountOperationGuard {
  if (!OPERATION_ID.test(rules.operationId)) {
    throw new Error(`accountOperation: ${rules.operationId} is not an account operation id`);
  }
  if (
    !FRESH_AUTHENTICATION_RULES.includes(rules.freshAuthentication) ||
    !ACT_CHAIN_RULES.includes(rules.actChain)
  ) {
    throw new Error(
      `accountOperation: ${rules.operationId} has a rule the contract does not define`
    );
  }
  const frozen: AccountOperationRules = Object.freeze({ ...rules });
  // The scope of the operation's class (#933); throws for another class.
  const access = familyOperation(
    'account',
    { operationClass: frozen.operationClass, permission: frozen.permission },
    { subjects: ['user'] }
  );
  return Object.freeze({
    guard: async function accountOperationGuard(request: FastifyRequest, reply: FastifyReply) {
      await access.guard(request, reply);
      await checkAccountOperation(request, frozen, options.removing?.(request));
    },
    schema: Object.freeze({
      operationId: frozen.operationId,
      ...access.schema,
      'x-qauth-fresh-authentication': frozen.freshAuthentication,
      'x-qauth-act-chain': frozen.actChain,
    }),
  });
}

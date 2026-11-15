import type { BrowserSession } from '@qauth-labs/fastify-plugin-sessions';
import { eventRequest } from '@qauth-labs/shared-events';
import type { FastifyRequest } from 'fastify';

import { env } from '../../config/env';
import { toStoredAssuranceLevel } from './acr-claims';
import type { AuthorizationCodeGrant } from './authorization-code';
import type { EnvironmentPolicy } from './environment-policy';
import type { RealmRow } from './request-realm';

/**
 * WHO AN AUTHORIZATION REQUEST IS DECIDED FOR: the browser session it comes
 * with, or the user an interaction just registered (#640). What the decision
 * and the code read of each: the authentication time the step-up gate
 * compares, whether the dangerous-scope step-up holds, and what the code
 * binds of the authentication.
 */

/**
 * A user an interaction just registered (#640; ADR-017 Decisions 8 and 10),
 * or whose password it just reset (#642): the account, with no browser
 * session and no authentication time. A request is decided for it as for a
 * session that authenticated at no known time: a dangerous scope,
 * `prompt=login`, `max_age` or a client that forces a fresh login needs a
 * sign-in first, and its code carries no `auth_time`, no `amr` and no `acr`.
 * Its code names a logout-only session (#1144), which the mint writes: no
 * cookie names it, and the account's session endings send the client a
 * logout token with its `sid`.
 */
export interface RegisteredSubject {
  readonly registered: true;
  readonly realmId: string;
  readonly userId: string;
  /**
   * What finished the interaction (#1144): a registration, or a password
   * reset, which advanced the account's session epoch past 0.
   */
  readonly finishedBy: 'registration' | 'reset';
}

/**
 * What {@link subjectGrant} needs for a {@link RegisteredSubject}'s
 * logout-only session (#1144): the realm's browser session lifetime, and the
 * request that finished it, whose address and `User-Agent` the account page
 * shows.
 */
export interface SubjectGrantContext {
  readonly realm: Pick<RealmRow, 'ssoMaxLifespan'>;
  readonly request: Pick<FastifyRequest, 'ip' | 'headers'>;
}

/** Who an authorization request is decided for: a browser session, or a user just registered. */
export type AuthorizationSubject = BrowserSession | RegisteredSubject;

/** Whether `subject` is a registration's ({@link RegisteredSubject}). */
export function isRegisteredSubject(subject: AuthorizationSubject): subject is RegisteredSubject {
  return 'registered' in subject && subject.registered === true;
}

/**
 * The authentication time the step-up gate compares, in epoch milliseconds:
 * none for a registration, which no sign-in authenticated, so every rule
 * that asks for a fresh sign-in asks for one.
 */
export function subjectAuthTimeMs(subject: AuthorizationSubject): number {
  return isRegisteredSubject(subject) ? Number.NEGATIVE_INFINITY : subject.authTime;
}

/**
 * Whether the dangerous-scope step-up holds for `subject`: as the client's
 * environment policy says for a session (ADR-008 §5), and always for a
 * registration, so a dangerous scope is never granted without a sign-in.
 */
export function subjectEnforcesDangerousStepUp(
  subject: AuthorizationSubject,
  policy: Pick<EnvironmentPolicy, 'agentStepUpEnforced'>
): boolean {
  return isRegisteredSubject(subject) ? true : policy.agentStepUpEnforced;
}

/** What a code binds of its subject's authentication. */
type SubjectGrant = Pick<
  AuthorizationCodeGrant,
  'authTime' | 'amr' | 'assuranceLevel' | 'sessionExpiresAt' | 'session'
>;

/**
 * What a code binds of its subject's authentication: the browser session's
 * `auth_time`, `amr`, assurance level, end and `sid`. For a registration or a
 * reset, none of the authentication (ADR-017 Decision 10: no `auth_time`, no
 * `amr`, no `acr`), and a logout-only session the mint writes (#1144), which
 * ends when a browser session the realm started now would: its `sid` goes to
 * the ID token, and its end caps the refresh family.
 *
 * @throws Error for a registered subject without `context`, which only a
 *   caller that cannot mint for one omits
 */
export function subjectGrant(subject: BrowserSession): SubjectGrant;
export function subjectGrant(
  subject: AuthorizationSubject,
  context: SubjectGrantContext
): SubjectGrant;
export function subjectGrant(
  subject: AuthorizationSubject,
  context?: SubjectGrantContext
): SubjectGrant {
  if (isRegisteredSubject(subject)) {
    if (context === undefined) {
      throw new Error('a registration or a reset needs its realm and request to name a session');
    }
    const expiresAt = Date.now() + (context.realm.ssoMaxLifespan ?? env.SESSION_COOKIE_TTL) * 1000;
    const userAgent = context.request.headers['user-agent'];
    // As a browser session stores them (`createBrowserSession`).
    const origin = eventRequest({
      ip: context.request.ip,
      userAgent: typeof userAgent === 'string' ? userAgent : undefined,
    });
    return {
      authTime: null,
      amr: null,
      assuranceLevel: null,
      sessionExpiresAt: expiresAt,
      session: {
        realmId: subject.realmId,
        logoutOnly: subject.finishedBy,
        expiresAt,
        ipAddress: origin?.ip ?? null,
        userAgent: origin?.userAgent ?? null,
      },
    };
  }
  return {
    // OIDC Core §2 `auth_time`: the REAL end-user authentication time (the
    // browser session's `auth_time`, epoch MS), never the code-mint time, so
    // /oauth/token can assert it in the ID token and a `max_age` check
    // evaluates the actual session age.
    authTime: subject.authTime,
    // RFC 8176 `amr` (#662): the methods the session's sign-in proved, for
    // the ID token and the access tokens. None for a session that proved no
    // method this server names (a wallet or upstream sign-in), and for one
    // created before sessions stored them: the tokens then carry no `amr`.
    amr: subject.amr.length > 0 ? [...subject.amr] : null,
    // #237 (ADR-004/ADR-010): the authentication's eIDAS LoA, for the ID
    // token's `acr`. NULL on the password path (`'low'`, no claim).
    assuranceLevel: toStoredAssuranceLevel(subject.assuranceLevel),
    // ADR-019 Decision 3 (#552): the session's absolute end, so the refresh
    // family this code starts never outlives the session.
    sessionExpiresAt: subject.expiresAt,
    // ADR-019 Decisions 3 and 4 (#549): the session whose `sid` the code
    // exchange puts in the ID token, and which records this client.
    session: { realmId: subject.realmId, sid: subject.sid },
  };
}

import type { BrowserSession } from '@qauth-labs/fastify-plugin-sessions';

import { toStoredAssuranceLevel } from './acr-claims';
import type { AuthorizationCodeGrant } from './authorization-code';
import type { EnvironmentPolicy } from './environment-policy';

/**
 * WHO AN AUTHORIZATION REQUEST IS DECIDED FOR: the browser session it comes
 * with, or the user an interaction just registered (#640). What the decision
 * and the code read of each: the authentication time the step-up gate
 * compares, whether the dangerous-scope step-up holds, and what the code
 * binds of the authentication.
 */

/**
 * A user an interaction just registered (#640; ADR-017 Decisions 8 and 10):
 * the new account, with no browser session and no authentication time. A
 * request is decided for it as for a session that authenticated at no known
 * time: a dangerous scope, `prompt=login`, `max_age` or a client that forces a
 * fresh login needs a sign-in first, and its code carries no `auth_time`, no
 * `acr` and no session.
 */
export interface RegisteredSubject {
  readonly registered: true;
  readonly realmId: string;
  readonly userId: string;
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

/**
 * What a code binds of its subject's authentication: the browser session's
 * `auth_time`, assurance level, end and `sid`, or, for a registration, none
 * of them (ADR-017 Decision 10: no `auth_time`, no `amr`, no session).
 */
export function subjectGrant(
  subject: AuthorizationSubject
): Pick<AuthorizationCodeGrant, 'authTime' | 'assuranceLevel' | 'sessionExpiresAt' | 'session'> {
  if (isRegisteredSubject(subject)) {
    return { authTime: null, assuranceLevel: null, sessionExpiresAt: null, session: null };
  }
  return {
    // OIDC Core §2 `auth_time`: the REAL end-user authentication time (the
    // browser session's `auth_time`, epoch MS), never the code-mint time, so
    // /oauth/token can assert it in the ID token and a `max_age` check
    // evaluates the actual session age.
    authTime: subject.authTime,
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

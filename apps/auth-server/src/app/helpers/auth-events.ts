import { createHash } from 'node:crypto';

import type { FastifyBaseLogger, FastifyRequest } from 'fastify';

/**
 * Auth event names emitted to the structured logger (#124, #125). Kept aligned
 * with the database `audit_logs` event vocabulary so log lines and audit rows
 * can be cross-referenced.
 */
export type AuthEventName =
  | 'user.login.success'
  | 'user.login.failure'
  | 'user.register.success'
  | 'user.register.failure'
  | 'user.logout.success'
  | 'user.logout.failure'
  | 'oauth.token.exchange.success'
  | 'oauth.token.exchange.failure';

/**
 * Structured fields attached to an auth event log line. No secrets, tokens,
 * passwords, or authorization codes are ever included — the redaction config in
 * `config/logger.ts` is a second line of defence, but callers must not pass
 * sensitive values here in the first place.
 */
export interface AuthEventDetails {
  /** Subject user id, when known. */
  userId?: string | null;
  /** OAuth client id (public identifier), when known. */
  clientId?: string | null;
  /** Plain email — only for success paths where enumeration is not a concern. */
  email?: string | null;
  /**
   * SHA-256 hash of the (normalised) email — preferred on failure paths so a
   * failed-login log cannot be used to enumerate which addresses exist (#125).
   */
  emailHash?: string | null;
  /** Failure reason / short error code. Never an exception with secrets. */
  reason?: string | null;
  /** OAuth grant type, for token events. */
  grantType?: string | null;
}

/**
 * Compute a stable, non-reversible hash of an email for failed-login logs.
 * Using a hash (rather than the raw address) avoids leaking which accounts
 * exist while still letting operators correlate repeated failures (#125).
 *
 * @param email - Normalised email address.
 * @returns Hex-encoded SHA-256 digest.
 */
export function hashEmail(email: string): string {
  return createHash('sha256').update(email).digest('hex');
}

/**
 * Log a structured auth event (#124, #125).
 *
 * Emits a single log line on the request-scoped logger (so it carries `reqId`)
 * with a stable shape: event name, outcome, client/user identifiers, source IP,
 * and an ISO timestamp. Failures are logged at `warn`, successes at `info`.
 *
 * @param request - The Fastify request (used for the scoped logger and IP).
 * @param event - The auth event name.
 * @param success - Whether the event represents a success or failure.
 * @param details - Additional non-sensitive structured fields.
 */
export function logAuthEvent(
  request: FastifyRequest,
  event: AuthEventName,
  success: boolean,
  details: AuthEventDetails = {}
): void {
  const logger: FastifyBaseLogger = request.log;
  const payload = {
    authEvent: event,
    success,
    userId: details.userId ?? undefined,
    clientId: details.clientId ?? undefined,
    email: details.email ?? undefined,
    emailHash: details.emailHash ?? undefined,
    reason: details.reason ?? undefined,
    grantType: details.grantType ?? undefined,
    ip: request.ip,
    timestamp: new Date().toISOString(),
  };

  if (success) {
    logger.info(payload, `auth event: ${event}`);
  } else {
    logger.warn(payload, `auth event: ${event}`);
  }
}

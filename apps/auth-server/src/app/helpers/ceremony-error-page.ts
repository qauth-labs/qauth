import { type ErrorPageCode, isTraceId } from '@qauth-labs/shared-interaction-contract';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

import { buildRealmUrl } from './realm-url';
import { type RealmRow, requestRealm } from './request-realm';

/**
 * THE CEREMONY APP'S ERROR PAGE (#1106; ADR-019 Decisions 5 and 6, ADR-020
 * §3): where the auth server sends the browser for an ending that leaves no
 * interaction for a ceremony page to read, when the realm names one in its
 * `ceremonyApp.errorPage` policy. The contract's `error-page.ts` defines the
 * codes and the query.
 */

/**
 * The path of the realm's error page, or `null` when the realm names none
 * and the auth server keeps its own pages. The policy takes nothing but a
 * path under `/ui/` (`CEREMONY_APP_PAGE_PATTERN`), so the URL built from it
 * is always on the realm's own origin.
 *
 * @throws PolicyValidationError when the realm's stored policies are not a
 *   valid document, as every reader of the policy store
 */
export function ceremonyErrorPageOf(
  fastify: Pick<FastifyInstance, 'policyStore'>,
  realm: RealmRow
): string | null {
  return fastify.policyStore.ofRealm(realm).policies.ceremonyApp.errorPage;
}

/**
 * What an ending adds to the query: a logout's, the facts its own page
 * showed (#1106); an admin enrolment's, whether it stored the passkey (#621).
 */
export interface ErrorPageFacts {
  /** Whether this browser holds no session of the realm now. */
  readonly signedOut?: boolean;
  /** The host of the app the person would go back to, as text. */
  readonly host?: string;
  /** Whether the admin enrolment stored the account's first passkey. */
  readonly enrolled?: boolean;
}

/**
 * The URL of the error page `path` for an ending with `code`, on the
 * request's realm: `code`, the request's id as `trace_id` when it is one a
 * `trace_id` can carry, and the ending's facts. Exported for its unit test.
 */
export function ceremonyErrorPageUrl(
  request: FastifyRequest,
  path: string,
  code: ErrorPageCode,
  facts: ErrorPageFacts = {}
): string {
  const query = new URLSearchParams({ code });
  if (isTraceId(request.id)) query.set('trace_id', request.id);
  if (facts.signedOut !== undefined) query.set('signed_out', String(facts.signedOut));
  if (facts.host !== undefined) query.set('host', facts.host);
  if (facts.enrolled !== undefined) query.set('enrolled', String(facts.enrolled));
  return buildRealmUrl(requestRealm(request), `${path}?${query.toString()}`);
}

/**
 * Answer `303 See Other` to the error page `path` for an ending with `code`,
 * with nothing to cache: the browser shows the ceremony app's page instead of
 * one of the auth server's.
 */
export function sendToCeremonyErrorPage(
  request: FastifyRequest,
  reply: FastifyReply,
  path: string,
  code: ErrorPageCode,
  facts: ErrorPageFacts = {}
): FastifyReply {
  reply.header('Cache-Control', 'no-store');
  return reply.redirect(ceremonyErrorPageUrl(request, path, code, facts), 303);
}

import type { FastifyRequest } from 'fastify';

import { realmIssuer } from './realm-url';
import type { RealmRow } from './request-realm';

/**
 * WHETHER A BROWSER REQUEST COMES FROM THE REALM ORIGIN (ADR-019 Decision 6):
 * the check the Interaction API's answer, cancel and personal read make
 * (#616), and the form post that starts an admin enrolment (#621).
 */

/** How strictly a request must show that it comes from the realm origin. */
export type OriginRule =
  /**
   * An answer or a cancel: `Sec-Fetch-Site: same-origin`; from a browser that
   * sends no `Sec-Fetch-Site`, an `Origin` of the realm. Neither: refused.
   */
  | 'required'
  /**
   * The personal-data read: refused when a header names another origin. A
   * request with neither header passes (the contract's rule for the read).
   */
  | 'unless_absent';

/**
 * Whether the request comes from the realm origin (ADR-019 Decision 6), by
 * the headers a browser sets and a page cannot.
 *
 * An answer or a cancel (`required`) follows the contract's rule: when the
 * browser sent `Sec-Fetch-Site`, it decides, and must be `same-origin`; only
 * when it did not, `Origin` must be the realm origin (`null` and any other
 * origin refused), and a request with neither is refused. `Sec-Fetch-Site`
 * decides alone because a form post from a page whose referrer policy is
 * `no-referrer`, as the ceremony pages' is, sends `Origin: null` (Fetch,
 * "append a request Origin header") with `Sec-Fetch-Site: same-origin`; and
 * an opaque-origin document, such as a sandboxed frame, sends
 * `Sec-Fetch-Site: cross-site`.
 *
 * The personal-data read (`unless_absent`) refuses a request either header
 * names another origin by, and lets one with neither through.
 */
export function comesFromRealmOrigin(
  headers: FastifyRequest['headers'],
  realm: Pick<RealmRow, 'issuer'>,
  rule: OriginRule
): boolean {
  const site = headers['sec-fetch-site'];
  const origin = headers.origin;
  const realmOrigin = new URL(realmIssuer(realm)).origin;
  if (rule === 'required') {
    if (site !== undefined) return site === 'same-origin';
    return origin === realmOrigin;
  }
  if (site !== undefined && site !== 'same-origin') return false;
  return origin === undefined || origin === realmOrigin;
}

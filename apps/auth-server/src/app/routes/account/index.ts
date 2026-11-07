import type { FastifyInstance } from 'fastify';

import { registerAccountConsentRoutes } from './consents';
import { registerAccountLinkedAccountRoutes } from './linked-accounts';

/**
 * THE ACCOUNT API, `/account/v1-rc.0` (ADR-019 Decision 7, #524).
 *
 * An end user manages their own account. Its first routes are the consents:
 * the active grants the user gave, and their revocation, which replace the
 * cookie-authenticated `/consents` (a deprecated alias until the account
 * console, v0.3, moves); then the linked upstream accounts and their
 * removal (#670).
 *
 * Every route is guarded by `requireFamilyToken('account')` (#509): a token
 * whose only audience is `urn:qauth:aud:account:v1-rc.0`, as the account
 * console's backend holds it, sent as a Bearer or a DPoP token, whose
 * subject is an enabled user of the request's realm (#869), and which
 * carries the account scope of the operation's class (#933):
 * `qauth:account:read` for a list or a read, `qauth:account:write` for a
 * change, or 403 `forbidden`. Each route's operation guard
 * (`accountOperation`) checks it with the operation's own rules. The account
 * family accepts a delegated token (RFC 8693 `act`); a route that changes a
 * credential, an identifier, the contact address or a linked account, or
 * deletes the account, will refuse one itself. Revoking a consent is none of
 * these. The routes follow the API conventions (`reference/api-conventions.md`).
 */
export const autoPrefix = '/account/v1-rc.0';

export default async function (fastify: FastifyInstance) {
  registerAccountConsentRoutes(fastify);
  registerAccountLinkedAccountRoutes(fastify);
}

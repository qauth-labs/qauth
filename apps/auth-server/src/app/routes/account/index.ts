import type { FastifyInstance } from 'fastify';

import { MERGE_PATCH_MEDIA_TYPE } from '../../api-conventions/conditional-requests';
import { createAccountFactors } from '../../helpers/account-factors';
import { createEngineMailer } from '../../helpers/engine-mail';
import { registerAccountConsentRoutes } from './consents';
import { registerAccountLinkedAccountRoutes } from './linked-accounts';
import { registerAccountPasskeyRoutes } from './passkeys';
import { registerAccountRecoveryCodeRoutes } from './recovery-codes';
import { registerAccountSessionRoutes } from './sessions';
import { registerAccountSignInMethodRoutes } from './sign-in-methods';
import { registerAccountTotpRoutes } from './totp';

/**
 * THE ACCOUNT API, `/account/v1-rc.0` (ADR-019 Decision 7, #524).
 *
 * An end user manages their own account. Its first routes are the consents:
 * the active grants the user gave, and their revocation, which replace the
 * cookie-authenticated `/consents` (a deprecated alias until the account
 * console, v0.4, moves); then the linked upstream accounts and their
 * removal (#670); then the sign-in methods' read and the password change
 * (#1107); then the passkeys, their rename and their removal (#1108); then
 * the authenticator app's enrolment and removal, and the recovery codes'
 * status and regeneration (#1109); then the sessions, ending one, and
 * signing out everywhere (#1110).
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
 * deletes the account, will refuse one itself. Revoking a consent and ending
 * a session are none of these. The routes follow the API conventions
 * (`reference/api-conventions.md`).
 *
 * Every answer carries `Cache-Control: no-store`, as the account contract
 * states: each is the user's own, errors included (#1107).
 */
export const autoPrefix = '/account/v1-rc.0';

export default async function (fastify: FastifyInstance) {
  fastify.addHook('onSend', async (_request, reply, payload) => {
    reply.header('Cache-Control', 'no-store');
    return payload;
  });
  // A PATCH body here is a JSON Merge Patch (RFC 7396), parsed as JSON is.
  // Registered in this module only, so no route outside the families starts
  // taking the media type.
  fastify.addContentTypeParser(
    MERGE_PATCH_MEDIA_TYPE,
    { parseAs: 'string' },
    fastify.getDefaultJsonParser('error', 'error')
  );
  registerAccountConsentRoutes(fastify);
  registerAccountLinkedAccountRoutes(fastify);
  registerAccountSignInMethodRoutes(fastify);
  registerAccountPasskeyRoutes(fastify);
  // The authenticator app and the recovery codes share the sign-in engine's
  // ports (#1109), built once here; their notices go out after the answer,
  // through the engine's mail, whose background tasks register a hook.
  const mailer = createEngineMailer(fastify);
  const factors = createAccountFactors(fastify, mailer);
  registerAccountTotpRoutes(fastify, factors, mailer);
  registerAccountRecoveryCodeRoutes(fastify, factors);
  registerAccountSessionRoutes(fastify);
}

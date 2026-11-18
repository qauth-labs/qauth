import { randomBytes } from 'node:crypto';

import {
  createPasskeyProvider,
  generateWebAuthnUserHandle,
  webauthnCredentialDataSchema,
  type WebAuthnEnrolment,
  type WebAuthnProvider,
  WebAuthnRejection,
} from '@qauth-labs/fastify-plugin-federation';
import {
  BadRequestError,
  extractConstraintName,
  pgErrorCodeOf,
  UniqueConstraintError,
} from '@qauth-labs/shared-errors';
import { stepUrn } from '@qauth-labs/shared-interaction-contract';
import { resolveRpId } from '@qauth-labs/shared-validation';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

import { ceremonyErrorPageOf, ceremonyErrorPageUrl } from './ceremony-error-page';
import { html, render } from './html';
import {
  type InteractionDecision,
  type InteractionState,
  startAdminEnrolmentInteraction,
} from './interaction';
import type {
  AdminEnrolmentRequest,
  InteractionPersonalData,
  InteractionStep,
} from './interaction-record';
import { passkeyAuthenticatorOf } from './new-factors';
import { storePasskeyEnrolment } from './passkey-enrolment';
import { createRedisWebAuthnChallenges, relyingPartyNameOf } from './passkey-sign-in';
import { buildRealmUrl } from './realm-url';
import { type RealmRow, requestRealm } from './request-realm';
import { uiStylesheetLink } from './ui-assets';
import { emitUserEvent } from './user-events';
import { passkeyCeremonyOrigins } from './webauthn-relying-party';

/**
 * THE ONE-TIME ADMIN ENROLMENT (#621; ADR-019 Decision 7).
 *
 * The break-glass command `enrol-admin` (#602) creates an admin account with
 * no password and no credential, its grant, and a one-time enrolment whose
 * token only the URL it prints holds (`/ui/admin-enrolment#token=…`; the
 * `admin_enrolments` row keeps its SHA-256). This module turns that URL into
 * the account's first passkey, over the Interaction API:
 *
 * 1. The start ({@link startAdminEnrolment}): the ceremony app's enrolment
 *    page posts the token from its fragment to `POST /auth/admin-enrolment`.
 *    A token that may still be redeemed (unused, unexpired, of this realm,
 *    for an enabled account) starts an interaction of purpose
 *    `admin_enrolment` in that browser, at the `admin_enrolment` step: a
 *    WebAuthn registration of a discoverable passkey that verifies the
 *    user, under the realm's RP ID. The token is read, not spent, so a link
 *    scanner or a ceremony the person abandons costs nothing. A token that
 *    is malformed, unknown, used, expired, another realm's or for an account
 *    that is gone or disabled gets one answer, the same for each
 *    ({@link sendAdminEnrolmentRefused}), and no interaction. So does every
 *    start while passkey sign-in is off (`WEBAUTHN_ENABLED`), without
 *    reading the token: the account could not sign in.
 * 2. The answer ({@link decideAdminEnrolment}): the registration is checked
 *    (user verification required), then one transaction stores the
 *    passkey, spends the enrolment by its id under the same conditions
 *    (`redeemEnrolment`: once, before it expires, by the database's clock
 *    too), and records `user.credential_added` and
 *    `admin.enrolment_completed`. The first moves the account's
 *    `admin_grants.last_security_change_at`, so it cannot approve another
 *    admin's request for 7 days (the two-admin rule's rule 3). A refused
 *    registration shows the step again with `invalid_credentials` and a new
 *    ceremony; an enrolment spent or expired meanwhile ends the interaction
 *    as refused, with nothing stored.
 * 3. The end: the realm's ceremony error page, when it names one
 *    (`admin_enrolment_finished` or `admin_enrolment_refused`), else the
 *    auth server's status page (`GET /auth/admin-enrolment/status`).
 *
 * No step of it writes or accepts a password, and nobody signs in: the
 * interaction's transaction stays empty, and the admin signs in with the
 * passkey afterwards, like any account.
 */

/** The step's URN. */
export const ADMIN_ENROLMENT_STEP = stepUrn('admin_enrolment');

/** The auth server's own page an enrolment ends on, when the realm names no error page. */
export const ADMIN_ENROLMENT_STATUS_PATH = '/auth/admin-enrolment/status';

/** How an admin enrolment ended, as its status page tells it. */
export const ADMIN_ENROLMENT_RESULTS = ['enrolled', 'cancelled', 'refused'] as const;

export type AdminEnrolmentResult = (typeof ADMIN_ENROLMENT_RESULTS)[number];

/** Why a start was refused: logged, never answered. */
type StartRefusal = 'passkeys_off' | 'malformed' | 'not_redeemable' | 'account' | 'realm';

/** What {@link startAdminEnrolment} did. */
export type AdminEnrolmentStart =
  | { readonly kind: 'started'; readonly id: string }
  | { readonly kind: 'refused' };

/**
 * The enrolment was spent or expired between the start and the stored
 * passkey, or its account was disabled or deleted meanwhile.
 */
class AdminEnrolmentSpentError extends Error {
  constructor() {
    super('the admin enrolment was spent or expired before the passkey was stored');
    this.name = 'AdminEnrolmentSpentError';
  }
}

/**
 * Why the passkey's transaction found nothing left to enrol, or `undefined`
 * for an error that says nothing of the enrolment. Besides the checks of
 * {@link AdminEnrolmentSpentError}, the database refuses two of these
 * itself: the trigger `admin_enrolments_use_once` when its own clock passed
 * the expiry before the request's did, and the credential's foreign key when
 * the account was deleted, as an operator does with an account whose URL
 * leaked. Each ends the enrolment as refused, as an expired or used token
 * does, rather than failing every answer until the interaction expires.
 */
function spentReasonOf(error: unknown): string | undefined {
  if (error instanceof AdminEnrolmentSpentError) return error.message;
  const code = pgErrorCodeOf(error);
  const constraint = extractConstraintName(error);
  if (code === '23514' && constraint === 'admin_enrolments_use_once') {
    return "the admin enrolment expired by the database's clock before the passkey was stored";
  }
  if (code === '23503' && constraint === 'user_credentials_user_id_users_id_fk') {
    return 'the admin enrolment’s account was deleted before the passkey was stored';
  }
  return undefined;
}

/** The name of an admin account in its passkey: `admin-` and 8 characters of its user handle. */
export function adminAccountNameOf(handle: string): string {
  return `admin-${handle.slice(0, 8)}`;
}

/** The WebAuthn provider's transaction of an enrolment's ceremony: the realm and the ceremony key. */
function transactionOf(realmId: string, request: AdminEnrolmentRequest): string {
  return `${realmId}:admin-enrolment:${request.ceremony}`;
}

/** The realm row, read now: the RP ID lock its first passkey took may be newer than the request's. */
async function currentRealm(fastify: FastifyInstance, realmId: string): Promise<RealmRow> {
  const realm = await fastify.repositories.realms.findById(realmId);
  if (realm === undefined) throw new Error('an admin enrolment for a realm that does not exist');
  return realm;
}

/** The ceremony state an enrolment's step carries: its step, and its personal data. */
interface Ceremony {
  readonly step: InteractionStep;
  readonly personal: InteractionPersonalData;
}

/**
 * Begin a registration ceremony for the account an enrolment is for: a
 * discoverable passkey that verifies the user, under the realm's RP ID and
 * origin, with the account's user handle and a name made from it, which
 * names nobody. `error` marks the step of a refused answer.
 */
async function beginCeremony(
  fastify: FastifyInstance,
  provider: WebAuthnProvider,
  realm: RealmRow,
  request: AdminEnrolmentRequest,
  error?: 'invalid_credentials'
): Promise<Ceremony> {
  const name = adminAccountNameOf(request.userHandle);
  const started = await provider.startRegistration({
    transactionId: transactionOf(realm.id, request),
    purpose: 'sign-in',
    rp: { id: resolveRpId(realm), name: relyingPartyNameOf(fastify, realm) },
    origins: passkeyCeremonyOrigins(realm, []),
    user: { handle: request.userHandle, name, displayName: name },
  });
  return {
    step: {
      name: ADMIN_ENROLMENT_STEP,
      params: {
        options: {
          challenge: started.challenge,
          rp: started.rp,
          pubKeyCredParams: started.pubKeyCredParams.map((param) => ({ ...param })),
          timeout: started.timeout,
          authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
          attestation: 'none',
        },
      },
      alternatives: [],
      ...(error === undefined ? {} : { error }),
    },
    personal: { user: { ...started.user } },
  };
}

/** The enrolment's WebAuthn provider, over Redis. */
export function adminEnrolmentProvider(fastify: FastifyInstance): WebAuthnProvider {
  return createPasskeyProvider(createRedisWebAuthnChallenges(fastify));
}

/**
 * Start an admin enrolment with the token the browser posted (step 1 of the
 * module): an interaction at the `admin_enrolment` step, bound to this
 * browser, expiring no later than the enrolment. The token is read and
 * never spent here, and never logged.
 */
export async function startAdminEnrolment(
  fastify: FastifyInstance,
  request: FastifyRequest,
  reply: FastifyReply,
  token: unknown,
  provider: WebAuthnProvider = adminEnrolmentProvider(fastify)
): Promise<AdminEnrolmentStart> {
  const refused = (reason: StartRefusal): AdminEnrolmentStart => {
    request.log.info({ adminEnrolmentRefused: reason }, 'an admin enrolment start was refused');
    return { kind: 'refused' };
  };
  // An account whose one credential is a passkey could not sign in while
  // passkeys are off (`WEBAUTHN_ENABLED`): the token is not read, and stays
  // usable once they are on. The operator's log says why.
  if (fastify.passkeySignIn !== true) {
    request.log.warn(
      { adminEnrolmentRefused: 'passkeys_off' satisfies StartRefusal },
      'an admin enrolment start was refused: passkey sign-in is off (WEBAUTHN_ENABLED)'
    );
    return { kind: 'refused' };
  }
  if (typeof token !== 'string') return refused('malformed');
  const realmId = requestRealm(request).id;
  const enrolment = await fastify.repositories.adminEnrolments.findRedeemable(
    realmId,
    token,
    Date.now()
  );
  if (enrolment === undefined) return refused('not_redeemable');
  const user = await fastify.repositories.users.findById(realmId, enrolment.userId);
  if (user === undefined || !user.enabled) return refused('account');
  const realm = await fastify.repositories.realms.findById(realmId);
  if (realm === undefined || !realm.enabled) return refused('realm');

  const held: AdminEnrolmentRequest = {
    enrolmentId: enrolment.id,
    userId: enrolment.userId,
    ceremony: randomBytes(32).toString('base64url'),
    // A new account with no passkey: a new handle.
    userHandle: generateWebAuthnUserHandle(),
  };
  const ceremony = await beginCeremony(fastify, provider, realm, held);
  const started = await startAdminEnrolmentInteraction(request, reply, {
    request: held,
    step: ceremony.step,
    personal: ceremony.personal,
    expiresAt: enrolment.expiresAt,
  });
  return { kind: 'started', id: started.id };
}

/** A browser's JSON registration response, or `undefined` when it is not JSON. */
function parseResponse(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
}

/**
 * Decide an answer to the `admin_enrolment` step (step 2 of the module):
 * check the registration, then store the passkey and spend the enrolment in
 * one transaction, with its events. `response` is the answer's
 * `webauthn_response`, read by the step grammar. `answered` learns how the
 * enrolment ended, for the page the browser goes to.
 *
 * - A registration the provider refuses (a wrong challenge, origin or RP
 *   ID, no user verification, a malformed response, a ceremony that timed
 *   out), a credential id the realm already holds, or a passkey created
 *   under another RP ID than the realm's: the step again, with
 *   `invalid_credentials` and a new ceremony. Nothing is stored and the
 *   enrolment stays unspent.
 * - An enrolment spent or expired since the start, or an account disabled
 *   or deleted since: the interaction finishes as `refused`, and the
 *   transaction that would have stored the passkey rolls back.
 * - Otherwise the interaction finishes as `enrolled`.
 */
export async function decideAdminEnrolment(
  fastify: FastifyInstance,
  request: FastifyRequest,
  state: Extract<InteractionState, { readonly purpose: 'admin_enrolment' }>,
  response: string,
  answered: (result: Exclude<AdminEnrolmentResult, 'cancelled'>) => void,
  provider: WebAuthnProvider = adminEnrolmentProvider(fastify)
): Promise<InteractionDecision> {
  const held = state.request;
  const realm = await currentRealm(fastify, requestRealm(request).id);
  const again = async (reason: string): Promise<InteractionDecision> => {
    request.log.info({ realmId: realm.id, reason }, 'an admin enrolment passkey was refused');
    const ceremony = await beginCeremony(fastify, provider, realm, held, 'invalid_credentials');
    return { kind: 'step', step: ceremony.step, personal: ceremony.personal };
  };

  let verified: WebAuthnEnrolment;
  try {
    verified = await provider.finishRegistration({
      transactionId: transactionOf(realm.id, held),
      response: parseResponse(response),
    });
  } catch (error) {
    if (!(error instanceof WebAuthnRejection)) throw error;
    return again(error.reason);
  }

  try {
    await storePasskeyEnrolment(
      {
        db: fastify.db,
        realms: fastify.repositories.realms,
        userCredentials: fastify.repositories.userCredentials,
      },
      {
        realmId: realm.id,
        userId: held.userId,
        enrolment: verified,
        // In the passkey's transaction: the enrolment is spent once, and its
        // records commit with the passkey, or nothing does.
        recorded: async (credential, tx) => {
          // The account may have been disabled since the start, as an
          // operator does with an account whose URL leaked: it gets no
          // passkey, and its enrolment stays as it is.
          const account = await fastify.repositories.users.findById(realm.id, held.userId, tx);
          if (account === undefined || !account.enabled) throw new AdminEnrolmentSpentError();
          const redeemed = await fastify.repositories.adminEnrolments.redeemEnrolment(
            realm.id,
            held.enrolmentId,
            held.userId,
            Date.now(),
            tx
          );
          if (redeemed === undefined) throw new AdminEnrolmentSpentError();
          const data = webauthnCredentialDataSchema.safeParse(credential.credentialData);
          // Also the two-admin rule's record of a changed credential (#521):
          // the account cannot approve for 7 days.
          await emitUserEvent(
            request,
            'urn:qauth:event:user.credential_added:v1-rc.0',
            {
              type: 'passkey',
              credentialId: credential.id,
              ...(data.success ? { authenticator: passkeyAuthenticatorOf(data.data) } : {}),
            },
            { tx, realmId: realm.id, userId: held.userId, actor: 'user' }
          );
          await emitUserEvent(
            request,
            'urn:qauth:event:admin.enrolment_completed:v1-rc.0',
            { credentialId: credential.id },
            { tx, realmId: realm.id, userId: held.userId, actor: 'user' }
          );
        },
      }
    );
  } catch (error) {
    const spent = spentReasonOf(error);
    if (spent !== undefined) {
      request.log.info({ realmId: realm.id }, spent);
      answered('refused');
      return { kind: 'finished' };
    }
    // The realm holds the credential id already, or its RP ID changed under
    // the ceremony: nothing was written, and another ceremony may succeed.
    if (error instanceof UniqueConstraintError) return again('credential-exists');
    if (error instanceof BadRequestError) return again('rp-id-changed');
    throw error;
  }
  answered('enrolled');
  return { kind: 'finished' };
}

/**
 * Where the browser goes once an enrolment has ended (step 3 of the
 * module): the realm's ceremony error page, when it names one, with
 * `admin_enrolment_refused`, or `admin_enrolment_finished` and whether the
 * passkey was stored; else the auth server's status page.
 */
export function adminEnrolmentEndUrl(
  fastify: FastifyInstance,
  request: FastifyRequest,
  result: AdminEnrolmentResult
): string {
  const realm = requestRealm(request);
  const errorPage = ceremonyErrorPageOf(fastify, realm);
  if (errorPage !== null) {
    return result === 'refused'
      ? ceremonyErrorPageUrl(request, errorPage, 'admin_enrolment_refused')
      : ceremonyErrorPageUrl(request, errorPage, 'admin_enrolment_finished', {
          enrolled: result === 'enrolled',
        });
  }
  return buildRealmUrl(realm, `${ADMIN_ENROLMENT_STATUS_PATH}?result=${result}`);
}

/** What the auth server's own page says, by how the enrolment ended. */
const PAGES: Readonly<Record<AdminEnrolmentResult, { title: string; text: string }>> = {
  enrolled: {
    title: 'Your passkey is registered',
    text: 'Your admin account signs in with this passkey from now on. It has no password. It can approve another admin’s request only after 7 days.',
  },
  cancelled: {
    title: 'The enrolment was cancelled',
    text: 'No passkey was registered. The enrolment link still works until it expires; open it again to register your passkey.',
  },
  refused: {
    title: 'This enrolment link is no longer valid',
    text: 'This link registered no passkey. It may have expired, been used already or be incomplete, or the server may not accept passkeys yet. Ask the operator who enrolled you.',
  },
};

/** Send the auth server's page for an enrolment that ended with `result`. */
function sendEnrolmentPage(
  reply: FastifyReply,
  result: AdminEnrolmentResult,
  status: number
): FastifyReply {
  const { title, text } = PAGES[result];
  const page = render(
    html`<!doctype html>
      <html lang="en">
        <head>
          <meta charset="utf-8" />
          <meta name="viewport" content="width=device-width,initial-scale=1" />
          <meta name="robots" content="noindex" />
          <title>${title} — QAuth</title>
          ${uiStylesheetLink()}
        </head>
        <body>
          <main class="card">
            <h1>${title}</h1>
            <p>${text}</p>
          </main>
        </body>
      </html>`
  );
  reply.header('Content-Type', 'text/html; charset=utf-8');
  reply.header('Cache-Control', 'no-store');
  reply.header('Referrer-Policy', 'no-referrer');
  return reply.code(status).send(page);
}

/**
 * Answer a refused start, the same for every reason: `303` to the realm's
 * ceremony error page with `admin_enrolment_refused` when it names one,
 * else the auth server's page with `400`. Nothing is cached, and no
 * `Referer` leaves it.
 */
export function sendAdminEnrolmentRefused(
  fastify: FastifyInstance,
  request: FastifyRequest,
  reply: FastifyReply
): FastifyReply {
  const errorPage = ceremonyErrorPageOf(fastify, requestRealm(request));
  if (errorPage !== null) {
    reply.header('Cache-Control', 'no-store');
    reply.header('Referrer-Policy', 'no-referrer');
    return reply.redirect(ceremonyErrorPageUrl(request, errorPage, 'admin_enrolment_refused'), 303);
  }
  return sendEnrolmentPage(reply, 'refused', 400);
}

/**
 * The status page an enrolment ends on (`GET /auth/admin-enrolment/status`):
 * what its `result` says, a value of {@link ADMIN_ENROLMENT_RESULTS}; any
 * other value, or none, reads as `refused`, the page that claims nothing was
 * stored. A realm that names its ceremony error page gets `303` to it with
 * the same ending.
 */
export function answerAdminEnrolmentStatus(
  fastify: FastifyInstance,
  request: FastifyRequest,
  reply: FastifyReply,
  result: unknown
): FastifyReply {
  const ending: AdminEnrolmentResult =
    typeof result === 'string' && (ADMIN_ENROLMENT_RESULTS as readonly string[]).includes(result)
      ? (result as AdminEnrolmentResult)
      : 'refused';
  if (ceremonyErrorPageOf(fastify, requestRealm(request)) !== null) {
    reply.header('Cache-Control', 'no-store');
    return reply.redirect(adminEnrolmentEndUrl(fastify, request, ending), 303);
  }
  return sendEnrolmentPage(reply, ending, 200);
}

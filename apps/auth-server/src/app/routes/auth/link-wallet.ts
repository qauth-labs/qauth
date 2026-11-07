import { InvalidCsrfTokenError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { env } from '../../../config/env';
import { WALLET_LOGIN_STATUS_RATE_LIMIT, WALLET_LOGIN_STATUS_RATE_WINDOW_S } from '../../constants';
import { resolveBrowserSession } from '../../helpers/browser-session';
import { realmRateLimitKey } from '../../helpers/realm-rate-limit';
import { csrfTokensEqual } from '../../helpers/session-cookie';
import { readSessionSideRecord } from '../../helpers/session-side-record';
import { emitUserEvent } from '../../helpers/user-events';
import {
  advanceWalletLinkFlow,
  startWalletLinkFlow,
  WALLET_LINK_CONFLICT,
  WALLET_LINK_EXPIRED,
  WALLET_LINK_REFUSAL,
  WALLET_LINK_UNAVAILABLE,
} from '../../helpers/wallet-link-flow';
import { isWalletLoginHandle } from '../../helpers/wallet-login-flow';

/**
 * `POST /auth/link/wallet` — attach a wallet credential to the SIGNED-IN
 * account (issue #238, ADR-004 "Account Linking", ADR-009 §5).
 *
 * ## Authenticated by construction
 *
 * Every endpoint here requires a valid `__Host-qauth_session` cookie and
 * refuses with 401 otherwise. That is not access control bolted onto a wallet
 * flow — it IS the flow: `session-binding` binds a presentation to the account
 * the caller is already authenticated as, and without a session there is no
 * account to bind to. ADR-009 §1's second bootstrap case is what makes that the
 * only correct shape: a presentation must never be able to attach itself to an
 * existing account, or *"any holder of any trusted credential [could] claim an
 * existing account by asserting its email"*.
 *
 * ## CSRF
 *
 * `POST` is state-changing (it writes an `oid4vp_request_states` row) and
 * cookie-authed, so it takes the same defence `DELETE /consents/:id` takes: the
 * caller echoes the per-session `apiCsrfToken` in an `X-CSRF-Token` header. The
 * custom header forces a CORS preflight for cross-origin attempts, and the
 * timing-safe comparison closes the same-origin gap `SameSite=Lax` does not.
 * `GET /auth/link/wallet/:handle` is deliberately exempt: it is the polling
 * surface, and while it does COMPLETE a link, reaching it requires the browser
 * binder cookie for that specific handle — a value a cross-site caller cannot
 * obtain and could not name a handle without.
 *
 * The token is not MINTED here. `GET /consents` is the one place a session's
 * `apiCsrfToken` is created, deliberately: one per-session token rather than one
 * per feature, so a first-party UI does not have to learn which endpoint mints
 * which. A session that has never obtained one therefore cannot start a link
 * through the JSON API — fail-closed, and the browser form at `/ui/wallet-link`
 * (which uses the signed double-submit login-CSRF cookie instead) is unaffected.
 *
 * ## Fail-closed registration
 *
 * The routes are not REGISTERED unless `WALLET_FEDERATION_ENABLED` is on, so a
 * default deployment answers 404 — the endpoints do not exist rather than
 * existing and refusing — and every handler re-resolves the capability, so a
 * deployment that ends up with no usable `VerifierProfile` refuses rather than
 * falling back to a permissive posture (#296, LOCKED).
 *
 * ## Statuses, and the ONE that is allowed to be specific
 *
 * `expired` and `rejected` are deliberately uniform: an unvalidatable
 * presentation, an untrusted issuer, a stale handle, a wrong binder and a
 * different session all render the same way, matching the login path. `conflict`
 * is the exception ADR-009 permits — the caller is authenticated and acting on
 * their own account, so "that credential belongs to another account" enumerates
 * nothing they could not already establish. It is only ever produced where a
 * stable per-wallet key exists (see `prepareWalletLink`).
 *
 * ## Same device only (#405, ADR-013 as amended 2026-11-07)
 *
 * A link is made only with a wallet on the device the browser runs on. The
 * start body accepts an optional `device`, and the one value it accepts is
 * `this`; `other`, the cross-device mode this endpoint offered before, is
 * refused by the body schema with `400` `validation_error`, whose `errors`
 * names `/device`, as any other value outside the schema is. An absent field,
 * or no body at all, is same-device. The flow completes on the browser's
 * return leg (`GET /ui/wallet-login/return`, reached through the
 * `redirect_uri` the Response Endpoint hands the wallet), and the poll here
 * reports `pending` until it does — OID4VP 1.0 §14.2, "MUST require the
 * frontend to pass the respective Response Code" — then `linked` once, from
 * the done-marker the return leg leaves.
 *
 * Why the other mode is gone: a cross-device link completed by this poll, and
 * nothing on that path ties the wallet that answers to the browser that
 * asked. Whoever scans a link code answers it, and the credential they present
 * says nothing about the account the code was made for. The Response Code is
 * what binds a presentation to the browser that requested it, and it exists
 * only on the same-device path.
 */

/** Header carrying the CSRF token on the state-changing POST. */
const CSRF_HEADER = 'x-csrf-token';

/**
 * The start body (#405). Nullish rather than merely optional: a `POST` with no
 * payload at all reaches the handler with a `null` body, and a caller built
 * before #405 sends exactly that. Anything else is validated — `device` is
 * `this` or absent, never free text, and never `other`: linking is
 * same-device only (ADR-013 as amended 2026-11-07), so the cross-device mode
 * is refused here with `400` `validation_error` before the handler runs.
 */
const startRequestSchema = z
  .object({
    /**
     * Where the wallet is: `this`, the device the browser runs on, is the one
     * value accepted. Absent — or an absent body — means the same.
     */
    device: z
      .literal('this', {
        error: 'Linking works only with a wallet on this device; "other" is not accepted.',
      })
      .optional(),
  })
  .nullish();

const startResponseSchema = z.object({
  /** Opaque handle addressing this linking flow. */
  handle: z.string(),
  /**
   * The wallet invocation URI to render as a QR code or deep link. OPAQUE — the
   * caller renders it and does not interpret it.
   */
  invocation_uri: z.string(),
  /** Absolute expiry of the presentation request, epoch ms. */
  expires_at: z.number(),
});

const statusResponseSchema = z.object({
  status: z.enum(['pending', 'linked', 'conflict', 'expired', 'rejected']),
  /** Fixed server copy. Present on every status except `pending`. */
  message: z.string().optional(),
});

/**
 * A refusal this route answers by its status alone (#513): the error handler
 * sends the problem document of that status, `unauthorized`, `not_found` or
 * `internal_error`, with the message as its `detail` below 500.
 */
class WalletLinkRefusal extends Error {
  constructor(
    readonly statusCode: 401 | 404 | 500,
    message: string
  ) {
    super(message);
    this.name = 'WalletLinkRefusal';
  }
}

/** The refusal of a request with no browser session. */
function signInFirst(): WalletLinkRefusal {
  return new WalletLinkRefusal(401, 'Sign in before linking a wallet credential.');
}

export default async function (fastify: FastifyInstance) {
  if (!env.WALLET_FEDERATION_ENABLED) {
    fastify.log.debug('wallet linking API not registered (WALLET_FEDERATION_ENABLED is off)');
    return;
  }

  fastify.withTypeProvider<ZodTypeProvider>().post(
    '/link/wallet',
    {
      schema: {
        description:
          "Start linking a wallet credential to the signed-in account. Requires a valid session cookie and an `X-CSRF-Token` header matching the per-session token returned by `GET /consents`. Issues an OID4VP 1.0 presentation request in LINKING mode: the validated response is bound to the caller's authenticated users.id and is never used to resolve or create an account (ADR-009 §5). Linking is same-device only (ADR-013, amended 2026-11-07): the wallet must be on the device the browser runs on, the link completes on the browser's return leg at `GET /ui/wallet-login/return`, and the poll answers `pending` until then (OID4VP 1.0 §14.2, HAIP 1.0 §5.1). The optional `device` field accepts only `this`, which is also what an absent field or body means; `other` (cross-device) is refused with `400` `validation_error`. Issues #238, #405.",
        tags: ['Auth'],
        'x-qauth-stability': 'experimental',
        'x-qauth-errors': [400, 401, 404],
        body: startRequestSchema,
        response: { 200: startResponseSchema },
      },
      config: {
        surface: 'browser',
        rateLimit: {
          max: env.LOGIN_RATE_LIMIT,
          timeWindow: env.LOGIN_RATE_WINDOW * 1000,
          keyGenerator: realmRateLimitKey,
        },
      },
    },
    async (request, reply) => {
      const session = await resolveBrowserSession(fastify, request, reply);
      if (!session) throw signInFirst();

      const provided = request.headers[CSRF_HEADER] as string | undefined;
      const { apiCsrfToken } = await readSessionSideRecord(fastify, session);
      if (!csrfTokensEqual(provided, apiCsrfToken)) {
        await emitUserEvent(
          request,
          'urn:qauth:event:request.csrf_rejected:v1-rc.0',
          { form: 'wallet_link' },
          { userId: session.userId, actor: 'user' }
        );
        throw new InvalidCsrfTokenError();
      }

      // The body carries nothing the handler reads: the schema has refused
      // every `device` but `this`, and the helper starts a same-device flow
      // whatever reaches it (ADR-013 as amended 2026-11-07).
      try {
        const started = await startWalletLinkFlow(fastify, request, reply, session.userId);
        if (started === undefined) {
          throw new WalletLinkRefusal(404, WALLET_LINK_UNAVAILABLE);
        }

        return reply.send({
          handle: started.handle,
          invocation_uri: started.invocationUri,
          expires_at: started.expiresAt,
        });
      } catch (error) {
        if (error instanceof WalletLinkRefusal) throw error;
        // A profile forbidding what the request needs, an unreachable store, a
        // failed insert: operator-visible, none of them the caller's business.
        fastify.log.error({ err: error }, 'failed to start a wallet-link flow');
        throw new WalletLinkRefusal(500, WALLET_LINK_REFUSAL);
      }
    }
  );

  fastify.withTypeProvider<ZodTypeProvider>().get(
    '/link/wallet/:handle',
    {
      schema: {
        description:
          'Poll a wallet-linking flow. A link is same-device only (ADR-013, amended 2026-11-07): it completes on the return leg, writing a second user_credentials row (provider_type=wallet) under the same users.id, and this poll answers `pending` until then, then `linked` once (#405). Issue #238.',
        tags: ['Auth'],
        'x-qauth-stability': 'experimental',
        'x-qauth-errors': [400, 401],
        params: z.object({ handle: z.string() }),
        response: { 200: statusResponseSchema },
      },
      config: {
        surface: 'browser',
        // Sized for polling, matching the wallet-login status endpoint.
        rateLimit: {
          max: WALLET_LOGIN_STATUS_RATE_LIMIT,
          timeWindow: WALLET_LOGIN_STATUS_RATE_WINDOW_S * 1000,
          keyGenerator: realmRateLimitKey,
        },
      },
    },
    async (request, reply) => {
      reply.header('Cache-Control', 'no-store');

      const session = await resolveBrowserSession(fastify, request, reply);
      if (!session) throw signInFirst();

      const { handle } = request.params as { handle: string };
      if (!isWalletLoginHandle(handle)) {
        return reply.send({ status: 'expired', message: WALLET_LINK_EXPIRED });
      }

      const outcome = await advanceWalletLinkFlow(fastify, request, reply, handle, session.userId, {
        via: 'poll',
      });

      switch (outcome.status) {
        case 'pending':
          return reply.send({ status: 'pending' });
        case 'linked':
          return reply.send({
            status: 'linked',
            message: outcome.rebound
              ? 'Your wallet credential was updated.'
              : 'Your wallet credential is now linked to this account.',
          });
        case 'conflict':
          return reply.send({ status: 'conflict', message: WALLET_LINK_CONFLICT });
        case 'rejected':
          return reply.send({ status: 'rejected', message: WALLET_LINK_REFUSAL });
        default:
          return reply.send({ status: 'expired', message: WALLET_LINK_EXPIRED });
      }
    }
  );
}

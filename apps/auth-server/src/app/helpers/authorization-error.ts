import type { FastifyReply } from 'fastify';

import { redirectHost } from './consent';
import { html, render, safe, safeUrl } from './html';
import { type AuthorizationResponseParams, buildRedirectUrl } from './oauth-redirect';

/** The provisioning-origin field of an `oauth_clients` row. */
export interface ClientOriginLike {
  /**
   * `oauth_clients.provisioned_by_operator`. Optional so a partially shaped
   * object type-checks; anything but a strict `true` reads as NOT
   * operator-provisioned.
   */
  provisionedByOperator?: boolean | null;
}

/** An RFC 6749 §4.1.2.1 error response, with the RFC 9207 `iss`. */
export type AuthorizationErrorParams = Extract<AuthorizationResponseParams, { error: string }>;

/**
 * True only for a client an operator provisioned (the system client, the
 * `db:seed-oauth-clients` manifest, the `db:seed` fixture), whose redirect
 * URIs the operator therefore vouches for.
 *
 * A POSITIVE marker (ANT-2026-O8U3P920). The earlier rule keyed on the markers
 * of the self-service paths that were known to be anonymous (open DCR and
 * CIMD) and trusted everything else, which left out the clients a
 * self-registered developer creates through `POST /api/clients`: an account
 * anyone can open, a redirect URI of their choosing, and no marker. Trusting
 * only what an operator wrote covers every self-service path, including ones
 * added later, and it never ages out.
 *
 * Fail-closed: `undefined`, `null` and `false` all read as untrusted. The
 * column is written `true` only by the operator paths; developer, DCR and
 * CIMD writes pin it to `false`, and no request body can reach it.
 */
export function isOperatorProvisionedClient(client: ClientOriginLike): boolean {
  return client.provisionedByOperator === true;
}

function untrustedRedirectPage(location: string, params: AuthorizationErrorParams): string {
  const host = redirectHost(location);
  // Only an http(s) target becomes a link: the URI is client-supplied, and
  // registration also accepts RFC 8252 private-use schemes for native apps,
  // and the bare schemes listed in REDIRECT_URI_CUSTOM_SCHEMES (#774).
  const href = safeUrl(location);
  const description = params.error_description ? html`: ${params.error_description}` : safe('');
  const continueLink = href
    ? html`<p><a href="${href}" rel="noopener noreferrer">Continue to ${host}</a></p>`
    : safe('');
  return render(
    html`<!doctype html>
      <html lang="en">
        <head>
          <meta charset="utf-8" />
          <meta name="viewport" content="width=device-width,initial-scale=1" />
          <meta name="robots" content="noindex" />
          <title>Sign-in not completed</title>
        </head>
        <body>
          <main>
            <h1>Sign-in not completed</h1>
            <p>
              The application's sign-in request ended with the error
              <code>${params.error}</code>${description}.
            </p>
            <p>
              This application was not set up by the operator of this server, so you are not sent
              back to it automatically. Continue only if you started this sign-in and expected to
              return to <code>${host}</code>.
            </p>
            ${continueLink}
          </main>
        </body>
      </html>`
  );
}

/**
 * Deliver an authorization error response (RFC 6749 §4.1.2.1) that would
 * otherwise leave the issuer before the user has seen any QAuth page.
 *
 * RFC 9700 §4.11.2 ("Authorization Server as Open Redirector"): the AS
 * redirects automatically only to a redirect URI it trusts. For an
 * operator-provisioned client ({@link isOperatorProvisionedClient}) that is
 * the registered URI, and the 302 is unchanged (OpenID Connect requires it,
 * e.g. `login_required` for `prompt=none`). For every other client (open DCR,
 * CIMD, `POST /api/clients`) whoever registered the URI may have done so to
 * bounce visitors off the issuer's origin, so the error is shown on the issuer
 * instead, with the destination host and a link carrying the full error
 * response: the user decides, and a legitimate client still receives the
 * error one click later.
 */
export function sendAuthorizationError(
  reply: FastifyReply,
  client: ClientOriginLike,
  redirectUri: string,
  params: AuthorizationErrorParams
): FastifyReply {
  const location = buildRedirectUrl(redirectUri, params);
  if (isOperatorProvisionedClient(client)) {
    return reply.redirect(location, 302);
  }
  reply.code(400);
  reply.header('Content-Type', 'text/html; charset=utf-8');
  reply.header('Cache-Control', 'no-store');
  return reply.send(untrustedRedirectPage(location, params));
}

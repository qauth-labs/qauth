import type { FastifyReply } from 'fastify';

import { redirectHost } from './consent';
import { html, render, safe, safeUrl } from './html';
import { type AuthorizationResponseParams, buildRedirectUrl } from './oauth-redirect';

/** The registration-origin fields of an `oauth_clients` row. */
export interface ClientOriginLike {
  dynamicRegisteredAt: number | null;
  metadata?: Record<string, unknown> | null;
}

/** An RFC 6749 §4.1.2.1 error response, with the RFC 9207 `iss`. */
export type AuthorizationErrorParams = Extract<AuthorizationResponseParams, { error: string }>;

/**
 * True for a client whose redirect URIs nobody vetted: one created through
 * open Dynamic Client Registration (RFC 7591, `POST /oauth/register`, no
 * credential required) or materialised from a Client ID Metadata Document
 * (any host that can serve one). The registering party chose the redirect
 * URIs, so matching a request against them exactly says nothing about where
 * they lead.
 *
 * Unlike `isDynamicClientWithinBadgeWindow` this does not age out: who
 * registered the redirect URI does not change after 30 days.
 *
 * `dynamicRegisteredAt` is written only by `POST /oauth/register` and
 * `registrationType` only by that route and by CIMD materialisation; neither
 * is editable through the developer API. An operator-provisioned client (seed
 * manifest, the system client) has neither.
 */
export function isSelfRegisteredClient(client: ClientOriginLike): boolean {
  if (client.dynamicRegisteredAt !== null && client.dynamicRegisteredAt !== undefined) return true;
  const registrationType = client.metadata?.registrationType;
  return registrationType === 'dynamic' || registrationType === 'cimd';
}

function untrustedRedirectPage(location: string, params: AuthorizationErrorParams): string {
  const host = redirectHost(location);
  // Only an http(s) target becomes a link: the URI is client-supplied, and DCR
  // also accepts custom schemes (RFC 8252 native apps).
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
              This application registered itself with this server, so you are not sent back to it
              automatically. Continue only if you started this sign-in and expected to return to
              <code>${host}</code>.
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
 * operator-provisioned client that is the registered URI, and the 302 is
 * unchanged (OpenID Connect requires it, e.g. `login_required` for
 * `prompt=none`). For a self-registered client ({@link isSelfRegisteredClient})
 * anyone could have registered the URI to bounce visitors off the issuer's
 * origin, so the error is shown on the issuer instead, with the destination
 * host and a link carrying the full error response: the user decides, and a
 * legitimate client still receives the error one click later.
 */
export function sendAuthorizationError(
  reply: FastifyReply,
  client: ClientOriginLike,
  redirectUri: string,
  params: AuthorizationErrorParams
): FastifyReply {
  const location = buildRedirectUrl(redirectUri, params);
  if (!isSelfRegisteredClient(client)) {
    return reply.redirect(location, 302);
  }
  reply.code(400);
  reply.header('Content-Type', 'text/html; charset=utf-8');
  reply.header('Cache-Control', 'no-store');
  return reply.send(untrustedRedirectPage(location, params));
}

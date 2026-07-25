import type { FastifyInstance } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { html, render } from '../../helpers/html';
import { consumePendingAuthorization } from '../../helpers/pending-authorization';

/**
 * Resume a pending authorization request (qauth-labs/qauth#316 follow-up).
 *
 * `/oauth/authorize` and `/ui/consent` park the pending authorize URL in Redis
 * and send the browser to `/ui/login?return_to=/ui/resume/<handle>` — a compact
 * path instead of the whole nested authorize query string, which used to blow
 * the `Location` header past a reverse proxy's header buffer. See
 * `helpers/pending-authorization.ts` for the size analysis and the
 * unguessable / single-use / no-browser-binding rationale.
 *
 * After a successful sign-in, `/ui/login`'s POST redirects here. This route is
 * the ONLY place a handle is exchanged back for a URL, so the open-redirector
 * surface is a single function: the destination comes out of Redis and is
 * re-checked to be this server's own `/oauth/authorize?…` — never a
 * client-supplied absolute URL, and never rebuilt from request input.
 *
 * The handle is burned on read, so a login URL recovered from browser history
 * or a screen recording cannot be replayed.
 */

/**
 * Rendered when a handle is missing, expired, or already used.
 *
 * All three degrade IDENTICALLY and deliberately: a distinguishable response
 * would let an attacker probe which handles ever existed. The page is a plain
 * 400 with no link and no redirect — we cannot reconstruct the authorize
 * request (that is the whole point of not carrying it in the URL), and bouncing
 * anywhere derived from request input would reintroduce the open-redirect risk
 * the handle exists to avoid. The user is told to restart from the application,
 * which is the only correct recovery for an OAuth request whose PKCE
 * `code_verifier` still lives in the client.
 */
function expiredPage(cspNonce: string): string {
  return render(
    html`<!doctype html>
      <html lang="en">
        <head>
          <meta charset="utf-8" />
          <meta name="viewport" content="width=device-width,initial-scale=1" />
          <meta name="robots" content="noindex" />
          <title>Sign-in request expired — QAuth</title>
          <style nonce="${cspNonce}">
            body {
              font-family:
                system-ui,
                -apple-system,
                Segoe UI,
                Roboto,
                sans-serif;
              background: #f6f7f9;
              color: #1a1a1a;
              margin: 0;
              min-height: 100vh;
              display: flex;
              align-items: center;
              justify-content: center;
            }
            .card {
              background: #fff;
              padding: 32px;
              border-radius: 12px;
              box-shadow: 0 4px 24px rgba(0, 0, 0, 0.06);
              width: 100%;
              max-width: 420px;
            }
            h1 {
              margin: 0 0 12px;
              font-size: 20px;
            }
            p {
              margin: 0 0 8px;
              font-size: 14px;
              line-height: 1.5;
              color: #374151;
            }
          </style>
        </head>
        <body>
          <div class="card">
            <h1>This sign-in request has expired</h1>
            <p>
              You are signed in, but the authorization request that sent you here is no longer
              valid. It may have timed out, or it may already have been completed in another tab.
            </p>
            <p>Return to the application you were signing in to and start again.</p>
          </div>
        </body>
      </html>`
  );
}

export default async function (fastify: FastifyInstance) {
  fastify.withTypeProvider<ZodTypeProvider>().get(
    '/resume/:handle',
    {
      schema: {
        description:
          'Resume a pending authorization request after login. The handle is single-use and resolves ONLY to an authorize URL this server minted. Issue #316.',
        tags: ['UI'],
        params: z.object({ handle: z.string() }),
      },
    },
    async (request, reply) => {
      const { handle } = request.params as { handle: string };

      const authorizeUrl = await consumePendingAuthorization(fastify, handle);

      reply.header('Cache-Control', 'no-store');
      if (!authorizeUrl) {
        // Missing / expired / replayed — all indistinguishable. Never a 500,
        // never a redirect to anything derived from the request.
        reply.header('Content-Type', 'text/html; charset=utf-8');
        reply.code(400);
        return reply.send(expiredPage(reply.cspNonce.style));
      }

      // `/oauth/authorize` re-validates client_id, redirect_uri, scope, PKCE
      // and step-up from scratch, exactly as on a first visit — resuming grants
      // nothing that a fresh authorize request would not.
      return reply.redirect(authorizeUrl, 302);
    }
  );
}

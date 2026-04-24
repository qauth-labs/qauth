import { randomBytes } from 'node:crypto';

import { BadRequestError, isUniqueConstraintError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { env } from '../../../config/env';
import { AUTHORIZATION_CODE_TTL_MS } from '../../constants';
import { resolveBrowserSession } from '../../helpers/browser-session';
import {
  canSkipConsent,
  describeScope,
  filterRequestedScopes,
  isDynamicClientWithinBadgeWindow,
} from '../../helpers/consent';
import { html, render, safe } from '../../helpers/html';
import { buildRedirectUrl } from '../../helpers/oauth-redirect';
import { getOrCreateDefaultRealm } from '../../helpers/realm';
import {
  type BrowserSessionData,
  csrfTokensEqual,
  generateCsrfToken,
} from '../../helpers/session-cookie';
import { authorizeQuerySchema } from '../../schemas/oauth';

/**
 * Consent screen & Allow/Deny POST handler (issue #150).
 *
 * GET  /ui/consent — server-renders the consent page given the same query
 *                    parameters as /oauth/authorize. Expects a signed
 *                    session cookie; otherwise redirects to the login
 *                    page with return_to=<original authorize url>.
 * POST /ui/consent — processes Allow / Deny; on Allow, issues an
 *                    authorization code and redirects to redirect_uri; on
 *                    Deny, redirects with error=access_denied (RFC 6749
 *                    §4.1.2.1). CSRF-protected via a form token bound to
 *                    the signed session cookie.
 */

const consentFormSchema = z.object({
  decision: z.enum(['allow', 'deny']),
  allow_forever: z.string().optional(),
  csrf_token: z.string().min(1),
  // Mirror of the original authorize params so we don't need to stash them
  // in the session (keeps the session payload small + stateless enough).
  client_id: z.string().min(1),
  redirect_uri: z.string().url(),
  state: z.string().max(255).optional(),
  scope: z.string().optional(),
  nonce: z.string().max(255).optional(),
  code_challenge: z.string().min(43).max(128),
  code_challenge_method: z.literal('S256'),
  response_type: z.literal('code'),
});

type ConsentForm = z.infer<typeof consentFormSchema>;

function buildAuthorizeUrl(query: Record<string, string | undefined>): string {
  const u = new URL('/oauth/authorize', 'http://placeholder');
  for (const [k, v] of Object.entries(query)) {
    if (v != null && v !== '') u.searchParams.set(k, v);
  }
  // Return only the path + query portion; login's return_to rejects absolute.
  return `${u.pathname}?${u.searchParams.toString()}`;
}

function consentPage(opts: {
  clientName: string;
  clientHomepage?: string;
  audience: string[];
  scopes: string[];
  badgeDynamic: boolean;
  csrfToken: string;
  authorizeParams: Record<string, string | undefined>;
  userEmail: string;
}): string {
  const scopeRows = opts.scopes.length
    ? opts.scopes.map((s) => html`<li><code>${s}</code> — ${describeScope(s)}</li>`)
    : [html`<li><em>No scopes requested.</em></li>`];

  const hidden = Object.entries(opts.authorizeParams)
    .filter(([, v]) => v != null && v !== '')
    .map(([k, v]) => html`<input type="hidden" name="${k}" value="${String(v)}" />`);

  const audienceBlock = opts.audience.length
    ? html`<p><strong>Tokens will be valid for:</strong> ${opts.audience.join(', ')}</p>`
    : safe('');

  const badge = opts.badgeDynamic
    ? html`<div class="badge">
        Newly registered application — double-check the name and URL before approving.
      </div>`
    : safe('');

  const homepage = opts.clientHomepage
    ? html`<p class="homepage">
        <a href="${opts.clientHomepage}" rel="noopener noreferrer" target="_blank"
          >${opts.clientHomepage}</a
        >
      </p>`
    : safe('');

  return render(
    html`<!doctype html>
      <html lang="en">
        <head>
          <meta charset="utf-8" />
          <meta name="viewport" content="width=device-width,initial-scale=1" />
          <meta name="robots" content="noindex" />
          <title>Authorize ${opts.clientName}</title>
          <style>
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
              max-width: 520px;
            }
            h1 {
              margin: 0 0 8px;
              font-size: 20px;
            }
            .homepage a {
              color: #2a5bd7;
              font-size: 13px;
            }
            ul.scopes {
              padding-left: 20px;
            }
            ul.scopes li {
              margin: 6px 0;
            }
            code {
              background: #f0f1f4;
              padding: 1px 6px;
              border-radius: 4px;
              font-size: 12px;
            }
            .badge {
              background: #fff4e5;
              color: #8a4b08;
              border: 1px solid #f5c16c;
              border-radius: 6px;
              padding: 10px 12px;
              margin: 16px 0;
              font-size: 13px;
            }
            .actions {
              display: flex;
              gap: 12px;
              margin-top: 24px;
            }
            button {
              flex: 1;
              padding: 10px;
              border-radius: 6px;
              border: 0;
              font-weight: 600;
              font-size: 14px;
              cursor: pointer;
            }
            button.allow {
              background: #2a5bd7;
              color: #fff;
            }
            button.deny {
              background: #e9ecf2;
              color: #1a1a1a;
            }
            .as-user {
              color: #6b7280;
              font-size: 13px;
              margin-top: 0;
            }
            .forever {
              font-size: 13px;
              margin-top: 16px;
              display: flex;
              align-items: center;
              gap: 8px;
            }
          </style>
        </head>
        <body>
          <form class="card" method="post" action="/ui/consent">
            <h1>${opts.clientName} wants to access your account</h1>
            ${homepage}
            <p class="as-user">Signed in as ${opts.userEmail}</p>
            ${badge}
            <p><strong>Requested access:</strong></p>
            <ul class="scopes">
              ${scopeRows}
            </ul>
            ${audienceBlock}
            <label class="forever">
              <input type="checkbox" name="allow_forever" value="1" checked />
              Remember this decision
            </label>
            <input type="hidden" name="csrf_token" value="${opts.csrfToken}" />
            ${hidden}
            <div class="actions">
              <button type="submit" name="decision" value="deny" class="deny">Deny</button>
              <button type="submit" name="decision" value="allow" class="allow">Allow</button>
            </div>
          </form>
        </body>
      </html>`
  );
}

export default async function (fastify: FastifyInstance) {
  /**
   * Render the consent page. Query parameters mirror /oauth/authorize so a
   * 302 from that endpoint to here carries enough state to both render and
   * re-issue the authorize call on Allow.
   */
  fastify.withTypeProvider<ZodTypeProvider>().get(
    '/ui/consent',
    {
      schema: {
        description:
          'Render the OAuth consent screen. Requires a valid __Host-qauth_session cookie; otherwise redirects to /ui/login.',
        tags: ['UI'],
        querystring: authorizeQuerySchema,
      },
    },
    async (request, reply) => {
      const query = request.query as z.infer<typeof authorizeQuerySchema>;

      const session = await resolveBrowserSession(fastify, request, reply);
      if (!session) {
        const returnTo = buildAuthorizeUrl(query);
        return reply.redirect(`/ui/login?return_to=${encodeURIComponent(returnTo)}`, 302);
      }

      const realm = await getOrCreateDefaultRealm(fastify);
      const client = await fastify.repositories.oauthClients.findByClientId(
        realm.id,
        query.client_id
      );
      if (!client || !client.enabled) {
        throw new BadRequestError('invalid_client');
      }
      if (!client.redirectUris.includes(query.redirect_uri)) {
        throw new BadRequestError('redirect_uri not registered');
      }

      const scopes = filterRequestedScopes(query.scope, client);

      // Rotate the CSRF token on every consent render so an old page cannot
      // be replayed. The same token is returned to the browser via the
      // hidden form field *and* stored in the server-side session; the
      // POST handler compares the two in a timing-safe way.
      const csrfToken = generateCsrfToken();
      await fastify.sessionUtils.setSession<BrowserSessionData>(
        session.sessionId,
        { ...session, csrfToken },
        env.SESSION_COOKIE_TTL
      );

      reply.header('Content-Type', 'text/html; charset=utf-8');
      reply.header('Cache-Control', 'no-store');
      // OWASP: tighten rendering context against clickjacking / MIME sniffing.
      reply.header('X-Frame-Options', 'DENY');
      reply.header('X-Content-Type-Options', 'nosniff');
      reply.header('Referrer-Policy', 'no-referrer');

      return reply.send(
        consentPage({
          clientName: client.name,
          clientHomepage: (client.metadata as Record<string, unknown> | null)?.homepage_uri as
            | string
            | undefined,
          audience: client.audience ?? [],
          scopes,
          badgeDynamic: isDynamicClientWithinBadgeWindow(client),
          csrfToken,
          authorizeParams: {
            client_id: query.client_id,
            redirect_uri: query.redirect_uri,
            state: query.state,
            scope: query.scope,
            nonce: query.nonce,
            code_challenge: query.code_challenge,
            code_challenge_method: query.code_challenge_method,
            response_type: query.response_type,
          },
          userEmail: session.email,
        })
      );
    }
  );

  /**
   * Process the Allow / Deny decision. Emits a final redirect to the
   * client's redirect_uri in both cases.
   */
  fastify.withTypeProvider<ZodTypeProvider>().post(
    '/ui/consent',
    {
      schema: {
        description:
          'Submit the consent decision. CSRF-protected; re-uses the authorize params to issue a code on Allow.',
        tags: ['UI'],
        body: consentFormSchema,
      },
      config: {
        rateLimit: {
          max: env.AUTHORIZE_RATE_LIMIT,
          timeWindow: env.AUTHORIZE_RATE_WINDOW * 1000,
          keyGenerator: (req) => req.ip || 'unknown',
        },
      },
    },
    async (request, reply) => {
      const body = request.body as ConsentForm;

      const session = await resolveBrowserSession(fastify, request, reply);
      if (!session) {
        // No session: re-route through login then come straight back to
        // authorize. We deliberately do NOT redirect into /ui/consent —
        // /oauth/authorize is the canonical entry point and will re-check
        // client validity.
        const returnTo = buildAuthorizeUrl({
          client_id: body.client_id,
          redirect_uri: body.redirect_uri,
          state: body.state,
          scope: body.scope,
          nonce: body.nonce,
          code_challenge: body.code_challenge,
          code_challenge_method: body.code_challenge_method,
          response_type: body.response_type,
        });
        return reply.redirect(`/ui/login?return_to=${encodeURIComponent(returnTo)}`, 302);
      }

      if (!csrfTokensEqual(session.csrfToken, body.csrf_token)) {
        await fastify.repositories.auditLogs.create({
          userId: session.userId,
          oauthClientId: null,
          event: 'oauth.consent.csrf_failure',
          eventType: 'auth',
          success: false,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'] || null,
          metadata: { client_id: body.client_id },
        });
        throw new BadRequestError('invalid_csrf_token');
      }

      // Burn the CSRF token so the form cannot be replayed. A fresh one is
      // minted on the next GET /ui/consent render.
      await fastify.sessionUtils.setSession<BrowserSessionData>(
        session.sessionId,
        { ...session, csrfToken: undefined },
        env.SESSION_COOKIE_TTL
      );

      const realm = await getOrCreateDefaultRealm(fastify);
      const client = await fastify.repositories.oauthClients.findByClientId(
        realm.id,
        body.client_id
      );
      if (!client || !client.enabled) {
        throw new BadRequestError('invalid_client');
      }
      if (!client.redirectUris.includes(body.redirect_uri)) {
        throw new BadRequestError('redirect_uri not registered');
      }

      // Deny path: redirect with error=access_denied, state preserved
      // (RFC 6749 §4.1.2.1).
      if (body.decision === 'deny') {
        await fastify.repositories.auditLogs.create({
          userId: session.userId,
          oauthClientId: client.id,
          event: 'oauth.consent.denied',
          eventType: 'auth',
          success: false,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'] || null,
          metadata: { client_id: body.client_id },
        });
        return reply.redirect(
          buildRedirectUrl(body.redirect_uri, {
            error: 'access_denied',
            error_description: 'User denied the authorization request.',
            state: body.state ?? undefined,
          }),
          302
        );
      }

      // Allow: persist the grant if the user checked the box, then issue a
      // code. The grant upsert merges with any prior record so subsequent
      // requests with a subset of these scopes skip the screen.
      const scopes = filterRequestedScopes(body.scope, client);
      if (body.allow_forever === '1') {
        await fastify.repositories.oauthConsents.upsertGrant(
          session.userId,
          client.id,
          realm.id,
          scopes
        );
      }

      const expiresAt = Date.now() + AUTHORIZATION_CODE_TTL_MS;
      const MAX_CREATE_ATTEMPTS = 3;
      let code: string | null = null;
      for (let attempt = 0; attempt < MAX_CREATE_ATTEMPTS; attempt++) {
        try {
          const candidate = randomBytes(32).toString('base64url');
          await fastify.repositories.authorizationCodes.create({
            code: candidate,
            oauthClientId: client.id,
            userId: session.userId,
            redirectUri: body.redirect_uri,
            codeChallenge: body.code_challenge,
            codeChallengeMethod: 'S256',
            nonce: body.nonce ?? null,
            scopes,
            state: body.state ?? null,
            expiresAt,
          });
          code = candidate;
          break;
        } catch (err) {
          if (!isUniqueConstraintError(err)) throw err;
          if (attempt === MAX_CREATE_ATTEMPTS - 1) throw err;
        }
      }
      if (!code) throw new Error('Unreachable');

      await fastify.repositories.auditLogs.create({
        userId: session.userId,
        oauthClientId: client.id,
        event: 'oauth.consent.granted',
        eventType: 'auth',
        success: true,
        ipAddress: request.ip,
        userAgent: request.headers['user-agent'] || null,
        metadata: {
          client_id: body.client_id,
          scopes,
          remembered: body.allow_forever === '1',
        },
      });

      return reply.redirect(
        buildRedirectUrl(body.redirect_uri, {
          code,
          state: body.state ?? undefined,
        }),
        302
      );
    }
  );
}

// Exported for the /oauth/authorize fast-path (skip-consent branch).
export { canSkipConsent };

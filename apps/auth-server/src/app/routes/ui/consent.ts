import { randomBytes } from 'node:crypto';

import { BadRequestError, isUniqueConstraintError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { env } from '../../../config/env';
import { AUTHORIZATION_CODE_TTL_MS, STEP_UP_FRESH_AUTH_WINDOW_MS } from '../../constants';
import { resolveBrowserSession } from '../../helpers/browser-session';
import { findExceedingAgentScopesForClient } from '../../helpers/client-auth';
import { isAgentClient, resolveClient } from '../../helpers/client-resolution';
import {
  canSkipConsent,
  describeScope,
  filterRequestedScopes,
  isDynamicClientWithinBadgeWindow,
  isLoopbackRedirect,
  redirectHost,
} from '../../helpers/consent';
import { resolveIssuerIdentifier } from '../../helpers/discovery';
import { resolveEnvironmentPolicy } from '../../helpers/environment-policy';
import { html, render, safe, safeUrl } from '../../helpers/html';
import { buildRedirectUrl, isRedirectUriAllowedForPolicy } from '../../helpers/oauth-redirect';
import { getOrCreateDefaultRealm } from '../../helpers/realm';
import { highestAgentModeInScopes } from '../../helpers/scope-modes';
import {
  type BrowserSessionData,
  csrfTokensEqual,
  generateCsrfToken,
} from '../../helpers/session-cookie';
import { evaluateStepUp, isDangerousScope, parsePromptMode } from '../../helpers/step-up';
import { markRelaxedCsp } from '../../plugins/security-headers';
import { authorizeQuerySchema, resourceParamSchema } from '../../schemas/oauth';

/**
 * RFC 8707: parse every `resource=` entry from a URL query string.
 * See authorize.ts's parseResourceFromUrl — fastify-type-provider-zod@6.1.0
 * drops the parsed `resource` from request.query for GET routes when the
 * schema is a union + transform. Reading request.url sidesteps that.
 */
function parseResourceFromUrl(url: string): string[] {
  const q = url.indexOf('?');
  if (q < 0) return [];
  return new URLSearchParams(url.slice(q + 1)).getAll('resource');
}

/**
 * Order-independent equality of two scope sets. Used by the consent POST to
 * confirm the POSTed (allowlist-filtered) scopes match exactly the set bound to
 * the session on the GET render — defence against a tampered hidden `scope`
 * field. Both inputs are already de-duplicated by `filterRequestedScopes`.
 */
function scopeSetsEqual(a: readonly string[], b: readonly string[]): boolean {
  if (a.length !== b.length) return false;
  const set = new Set(a);
  return b.every((s) => set.has(s));
}

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
  // ADR-007 §2 (#185): step-up params carried through so the POST mint path
  // re-evaluates them server-side (the hidden `scope` field is
  // attacker-controlled, so the dangerous-elevation re-auth gate must run HERE
  // too, not only pre-consent). Empty string ⇒ treated as absent.
  prompt: z.enum(['none', 'login', 'consent']).optional(),
  max_age: z.coerce.number().int().min(0).max(315360000).optional(),
  // RFC 8707: carried through as hidden form field(s). POST body transforms
  // work (unlike GET querystrings), so `resourceParamSchema` populates an
  // array on `body.resource`.
  resource: resourceParamSchema,
});

type ConsentForm = z.infer<typeof consentFormSchema>;

function buildAuthorizeUrl(query: Record<string, string | string[] | number | undefined>): string {
  const u = new URL('/oauth/authorize', 'http://placeholder');
  for (const [k, v] of Object.entries(query)) {
    if (v == null) continue;
    // RFC 8707: `resource` may be multi-valued — append one param per entry
    // so every requested resource survives the login round-trip.
    if (Array.isArray(v)) {
      for (const entry of v) {
        if (entry !== '') u.searchParams.append(k, entry);
      }
    } else {
      // `max_age` arrives as a number from the parsed query; stringify before
      // appending. Empty strings are dropped to keep the URL clean.
      const s = String(v);
      if (s !== '') u.searchParams.set(k, s);
    }
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
  /** Per-request CSP nonce (issue #113) stamped onto the inline <style> tag. */
  cspNonce: string;
  authorizeParams: Record<string, string | undefined>;
  /** RFC 8707 resource indicators — emitted as one hidden input per URI. */
  resources: string[];
  userEmail: string;
  /** Host portion of the redirect_uri, shown so the user can sanity-check the destination. */
  redirectHost: string;
  /** True when the redirect targets loopback/localhost (CIMD §6 impersonation warning). */
  redirectIsLoopback: boolean;
  /** True for CIMD-resolved clients (no operator pre-registration). */
  isCimd: boolean;
}): string {
  const scopeRows = opts.scopes.length
    ? opts.scopes.map((s) => html`<li><code>${s}</code> — ${describeScope(s)}</li>`)
    : [html`<li><em>No scopes requested.</em></li>`];

  const hidden = [
    ...Object.entries(opts.authorizeParams)
      .filter(([, v]) => v != null && v !== '')
      .map(([k, v]) => html`<input type="hidden" name="${k}" value="${String(v)}" />`),
    ...opts.resources.map((r) => html`<input type="hidden" name="resource" value="${r}" />`),
  ];

  const audienceBlock = opts.audience.length
    ? html`<p><strong>Tokens will be valid for:</strong> ${opts.audience.join(', ')}</p>`
    : safe('');

  // CIMD §6: always show where the authorization code will be sent, and warn
  // when that destination is the user's own machine (localhost) for a client
  // the operator never pre-registered.
  const redirectBlock = html`<p class="redirect">
    <strong>You will be redirected to:</strong> <code>${opts.redirectHost}</code>
  </p>`;

  const loopbackWarning =
    opts.redirectIsLoopback && opts.isCimd
      ? html`<div class="warn">
          This app will receive your authorization code on <code>${opts.redirectHost}</code>
          (your own device). Only continue if you started this sign-in yourself.
        </div>`
      : safe('');

  const badge = opts.badgeDynamic
    ? html`<div class="badge">
        Newly registered application — double-check the name and URL before approving.
      </div>`
    : safe('');

  // #112: an OAuth client's homepage_uri is attacker-controlled (especially for
  // CIMD/dynamically registered clients). HTML-escaping alone does not stop a
  // `javascript:` URL from executing on click, so the href is gated through
  // safeUrl(): only http(s)/mailto links are rendered clickable. The visible
  // text is still escaped by the `html` tag so a rejected URL shows harmlessly.
  const safeHomepage = safeUrl(opts.clientHomepage);
  const homepage = safeHomepage
    ? html`<p class="homepage">
        <a href="${safeHomepage}" rel="noopener noreferrer" target="_blank">${safeHomepage}</a>
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
          <style nonce="${opts.cspNonce}">
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
            .warn {
              background: #fdecea;
              color: #8a1c12;
              border: 1px solid #f1a59c;
              border-radius: 6px;
              padding: 10px 12px;
              margin: 16px 0;
              font-size: 13px;
            }
            .redirect {
              font-size: 13px;
              color: #374151;
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
            ${badge} ${loopbackWarning}
            <p><strong>Requested access:</strong></p>
            <ul class="scopes">
              ${scopeRows}
            </ul>
            ${audienceBlock} ${redirectBlock}
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
    '/consent',
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

      // RFC 9207 §2 (#282): same issuer identifier the discovery documents
      // advertise, echoed as `iss` on every authorization response this route
      // emits. The consent screen terminates the authorization request on both
      // Allow and Deny, so its redirects are authorization responses too and
      // carry the mix-up defence exactly like /oauth/authorize's.
      const iss = resolveIssuerIdentifier(fastify.jwtUtils.getIssuer());

      const session = await resolveBrowserSession(fastify, request, reply);
      if (!session) {
        const returnTo = buildAuthorizeUrl(query);
        return reply.redirect(`/ui/login?return_to=${encodeURIComponent(returnTo)}`, 302);
      }

      const realm = await getOrCreateDefaultRealm(fastify);
      // Pre-registered → CIMD resolution (a CIMD client reaching consent was
      // already materialised by /oauth/authorize, so findByClientId inside
      // resolveClient hits it; if its document cache expired it is re-fetched
      // and re-validated here).
      const { client } = await resolveClient(fastify, realm.id, query.client_id);
      if (!client || !client.enabled) {
        throw new BadRequestError('invalid_client');
      }
      if (!client.redirectUris.includes(query.redirect_uri)) {
        throw new BadRequestError('redirect_uri not registered');
      }

      // ADR-008 §5/§7 (#197): effective environment policy for this (client,
      // realm). The consent screen is one of the FEW browser surfaces that
      // unambiguously carries a `client_id`, so it is where a client-scoped T3
      // relaxation (below) is safe to apply. The localhost redirect gate also
      // applies on the render path so we never show a consent screen for a
      // redirect the POST handler will (correctly) refuse.
      const policy = resolveEnvironmentPolicy(client, realm);
      if (!isRedirectUriAllowedForPolicy(query.redirect_uri, policy)) {
        throw new BadRequestError('redirect_uri not permitted for this environment');
      }

      // ADR-007 §2 (#184): fail fast on the render path too — don't show a
      // consent screen for an over-cap agent scope that the POST handler will
      // (correctly) refuse to mint a code for. Same deny-by-default gate;
      // redirect_uri is already validated above so an `invalid_scope` redirect
      // is safe (RFC 6749 §4.1.2.1).
      if (findExceedingAgentScopesForClient(query.scope, client).length > 0) {
        return reply.redirect(
          buildRedirectUrl(query.redirect_uri, {
            error: 'invalid_scope',
            error_description: 'requested scope exceeds the agent scope mode for this client',
            state: query.state ?? undefined,
            iss,
          }),
          302
        );
      }

      const isCimd =
        (client.metadata as Record<string, unknown> | null)?.registrationType === 'cimd';

      const scopes = filterRequestedScopes(query.scope, client);

      // Reuse the session's existing CSRF token if present; only mint a
      // fresh one when none exists yet. Rotating on every GET would break
      // multi-tab flows: opening the consent page in a second tab would
      // invalidate the first tab's hidden form field, so the first tab's
      // submit would fail even though the user's intent is legitimate.
      // The token is still burned on successful POST, and a new session
      // (re-login) always mints a new one.
      const csrfToken = session.csrfToken ?? generateCsrfToken();

      // Scope-presentation integrity (#150 hardening): bind the EXACT scope set
      // the user is about to see to the session, keyed by client_id. The POST
      // handler grants only these scopes — the hidden `scope` form field is
      // attacker-controllable, so the persisted grant must match what was
      // rendered, not what is submitted. Always persisted (the scope set can
      // change between GETs for the same client), so this write also covers the
      // first-time CSRF-token mint above.
      const consentScopes = { ...(session.consentScopes ?? {}), [client.clientId]: scopes };
      await fastify.sessionUtils.setSession<BrowserSessionData>(
        session.sessionId,
        { ...session, csrfToken, consentScopes },
        env.SESSION_COOKIE_TTL
      );

      reply.header('Content-Type', 'text/html; charset=utf-8');
      reply.header('Cache-Control', 'no-store');
      // Clickjacking / MIME-sniffing / referrer hardening are applied globally
      // by the security-headers plugin (issue #113), including the strict
      // nonce-based CSP that this page's inline <style> relies on.
      //
      // ADR-008 §5 (#197) T3 relaxation, CLIENT-SCOPED. T3 security headers /
      // CSRF / secure cookies are largely GLOBAL controls with NO client in
      // scope, so they DEFAULT TO STRICT (production) everywhere — see the
      // security-headers plugin and session-cookie helper, which stay strict.
      // The consent screen is the rare browser surface that unambiguously
      // carries a `client_id`, so it is the one place we may safely relax the
      // CSP for a `development` client: it permits `'unsafe-inline'` styles so a
      // developer iterating on this page is not forced to nonce every style.
      // `t3SecurityEnforced` is true for staging/production (and fail-safe for
      // an unset client/realm), so this NEVER loosens a hardened deployment.
      //
      // The actual header swap is owned by the GLOBAL security-headers plugin's
      // onSend (the one place that already overrides helmet's CSP, for Swagger):
      // here we only MARK the reply. That keeps the CSP-override logic in a
      // single location and means this route needs no onSend of its own (so the
      // unit-test harness, which mocks a bare `fastify`, is unaffected).
      if (!policy.t3SecurityEnforced) {
        markRelaxedCsp(reply);
      }

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
          cspNonce: reply.cspNonce.style,
          authorizeParams: {
            client_id: query.client_id,
            redirect_uri: query.redirect_uri,
            state: query.state,
            scope: query.scope,
            nonce: query.nonce,
            code_challenge: query.code_challenge,
            code_challenge_method: query.code_challenge_method,
            response_type: query.response_type,
            // ADR-007 §2 (#185): preserve the step-up params so the POST mint
            // path re-evaluates them server-side.
            prompt: query.prompt,
            max_age: query.max_age !== undefined ? String(query.max_age) : undefined,
          },
          // RFC 8707: parsed directly from request.url (see
          // parseResourceFromUrl). Rendered as one hidden <input
          // name="resource" value="<uri>" /> per entry so the POST body
          // carries every requested resource URI back to the handler.
          resources: parseResourceFromUrl(request.url),
          // #230: session email is optional (future non-email credentials);
          // fall back to the stable subject id for display.
          userEmail: session.email ?? session.userId,
          redirectHost: redirectHost(query.redirect_uri),
          redirectIsLoopback: isLoopbackRedirect(query.redirect_uri),
          isCimd,
        })
      );
    }
  );

  /**
   * Process the Allow / Deny decision. Emits a final redirect to the
   * client's redirect_uri in both cases.
   */
  fastify.withTypeProvider<ZodTypeProvider>().post(
    '/consent',
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

      // RFC 9207 §2 (#282): same issuer identifier the discovery documents
      // advertise, echoed as `iss` on every authorization response this route
      // emits. The consent screen terminates the authorization request on both
      // Allow and Deny, so its redirects are authorization responses too and
      // carry the mix-up defence exactly like /oauth/authorize's.
      const iss = resolveIssuerIdentifier(fastify.jwtUtils.getIssuer());

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
          // ADR-007 §2 (#185): carry the step-up params back so /oauth/authorize
          // re-applies them after the login round-trip.
          prompt: body.prompt,
          max_age: body.max_age !== undefined ? String(body.max_age) : undefined,
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
      const { client } = await resolveClient(fastify, realm.id, body.client_id);
      if (!client || !client.enabled) {
        throw new BadRequestError('invalid_client');
      }
      if (!client.redirectUris.includes(body.redirect_uri)) {
        throw new BadRequestError('redirect_uri not registered');
      }

      // ADR-008 §5/§7 (#197): effective environment policy for this (client,
      // realm). Gates the localhost redirect and the automatic step-up below.
      const policy = resolveEnvironmentPolicy(client, realm);
      if (!isRedirectUriAllowedForPolicy(body.redirect_uri, policy)) {
        throw new BadRequestError('redirect_uri not permitted for this environment');
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
            iss,
          }),
          302
        );
      }

      // ADR-007 §2 (#184): enforce the agent scope-mode cap HERE, on the path
      // that actually mints the authorization code. The pre-consent cap check
      // in /oauth/authorize is bypassed for first-time consent (the common
      // case), because authorize redirects to this route before issuing the
      // code. Without this gate a `readonly`-capped agent whose allowlist
      // contains `agent:exec` could POST `scope=agent:exec` here and obtain an
      // exec code (the hidden `scope` field is attacker-controlled; the CSRF
      // token binds the session, not the scope). Deny-by-default, fail-closed:
      // a non-agent / un-capped client is rejected too. RFC 6749 §4.1.2.1
      // `invalid_scope`, state preserved.
      const exceedingAgentScopes = findExceedingAgentScopesForClient(body.scope, client);
      if (exceedingAgentScopes.length > 0) {
        await fastify.repositories.auditLogs.create({
          userId: session.userId,
          oauthClientId: client.id,
          event: 'oauth.consent.denied',
          eventType: 'auth',
          success: false,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'] || null,
          metadata: {
            error: 'invalid_scope',
            reason: 'agent_scope_mode_exceeded',
            client_id: body.client_id,
            exceeding: exceedingAgentScopes.join(' '),
          },
        });
        return reply.redirect(
          buildRedirectUrl(body.redirect_uri, {
            error: 'invalid_scope',
            error_description: 'requested scope exceeds the agent scope mode for this client',
            state: body.state ?? undefined,
            iss,
          }),
          302
        );
      }

      // Scope-presentation integrity (#150 hardening). The hidden `scope` field
      // is attacker-controllable, so we do NOT trust it to determine the granted
      // set. The GET render bound the EXACT scopes shown to the user into the
      // session, keyed by client_id. We grant those. As defence-in-depth we
      // still re-filter the POSTed scopes against the client allowlist and
      // require them to match the bound set: any divergence (a tampered hidden
      // field that survived the allowlist intersection) is refused rather than
      // silently granting a set the user never saw. A missing binding (a POST
      // with no preceding GET in this session) is likewise refused.
      const boundScopes = session.consentScopes?.[client.clientId];
      const postedScopes = filterRequestedScopes(body.scope, client);
      if (boundScopes === undefined || !scopeSetsEqual(boundScopes, postedScopes)) {
        await fastify.repositories.auditLogs.create({
          userId: session.userId,
          oauthClientId: client.id,
          event: 'oauth.consent.denied',
          eventType: 'auth',
          success: false,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'] || null,
          metadata: {
            error: 'invalid_scope',
            reason: 'consent_scope_mismatch',
            client_id: body.client_id,
            bound: boundScopes ?? null,
            posted: postedScopes,
          },
        });
        return reply.redirect(
          buildRedirectUrl(body.redirect_uri, {
            error: 'invalid_scope',
            error_description: 'consent scope does not match the rendered authorization request',
            state: body.state ?? undefined,
            iss,
          }),
          302
        );
      }
      // Grant the bound (user-visible) scopes — never the raw POST body.
      const scopes = boundScopes;

      // ADR-007 §2 (#185): step-up gate on the mint path. Re-authentication is
      // enforced HERE, not only pre-consent, because the hidden `scope`/`prompt`/
      // `max_age` fields are attacker-controllable and the CSRF token binds the
      // session, not the scope. A dangerous scope (write:* / agent:admin /
      // agent:exec), `prompt=login`, or an exceeded `max_age` must be backed by
      // a fresh authentication: if the session is stale we refuse to mint the
      // code and bounce through /ui/login (which re-mints the session,
      // resetting auth_time). Prior consent is intentionally NOT consulted here
      // — every scope about to be minted is treated as needing the gate, so the
      // dangerous-op re-auth cannot be skipped by a stale prior grant.
      // Only `requiresFreshLogin` is consulted on this mint path: the user is
      // actively consenting (this IS the consent screen submit), so
      // `requiresConsent` — always true here given `priorConsentScopes: []` —
      // is irrelevant. We just need to confirm the authentication is fresh
      // enough for whatever (incl. dangerous) scopes are about to be granted.
      const prompt = parsePromptMode(body.prompt);
      const stepUp = evaluateStepUp({
        requestedScopes: scopes,
        priorConsentScopes: [],
        prompt,
        maxAgeSeconds: body.max_age ?? null,
        authTimeMs: session.createdAt,
        nowMs: Date.now(),
        freshAuthWindowMs: STEP_UP_FRESH_AUTH_WINDOW_MS,
        // ADR-008 §5 (#197): relax the automatic dangerous-scope fresh-login on
        // the mint path for a development client; explicit prompt/max_age still
        // force step-up in every environment.
        enforceDangerousStepUp: policy.agentStepUpEnforced,
      });
      if (stepUp.requiresFreshLogin) {
        await fastify.repositories.auditLogs.create({
          userId: session.userId,
          oauthClientId: client.id,
          event: 'oauth.stepup.required',
          eventType: 'auth',
          success: false,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'] || null,
          metadata: {
            client_id: body.client_id,
            reason: 'fresh_authentication_required',
            dangerous: stepUp.dangerous,
            prompt: prompt ?? null,
            maxAge: body.max_age ?? null,
          },
        });
        const returnTo = buildAuthorizeUrl({
          client_id: body.client_id,
          redirect_uri: body.redirect_uri,
          state: body.state,
          scope: body.scope,
          nonce: body.nonce,
          code_challenge: body.code_challenge,
          code_challenge_method: body.code_challenge_method,
          response_type: body.response_type,
          prompt: body.prompt,
          max_age: body.max_age !== undefined ? String(body.max_age) : undefined,
          resource: body.resource,
        });
        return reply.redirect(`/ui/login?return_to=${encodeURIComponent(returnTo)}`, 302);
      }

      // Allow: persist the grant if the user checked the box, then issue a
      // code. The grant upsert merges with any prior record so subsequent
      // requests with a subset of these scopes skip the screen.
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
            // RFC 8707: bind the requested resource(s) to this code so
            // /oauth/token can set the issued access token's `aud` claim.
            resource: body.resource ?? [],
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

      // ADR-007 §2 (#185): every elevation that grants a dangerous scope is
      // audited as a distinct step-up event (in addition to the normal
      // consent.granted record), with the fresh `auth_time` so an operator can
      // see the dangerous grant was minted right after a re-authentication.
      const dangerousGranted = scopes.filter(isDangerousScope);
      if (dangerousGranted.length > 0) {
        // Per-agent action audit (ADR-007 §2, #186). When the elevating client
        // is an agent (fail-closed `isAgentClient`), attribute the elevation to
        // it and record the effective agent scope mode so the dangerous grant
        // is accountable in the agent-activity view. A non-agent client records
        // no agent fields (existing behavior unchanged). This is a user-driven
        // consent elevation, not on-behalf-of delegation, so there is no `act`
        // chain.
        const elevatingAgent = isAgentClient(client);
        await fastify.repositories.auditLogs.create({
          userId: session.userId,
          oauthClientId: client.id,
          actorClientId: elevatingAgent ? client.clientId : null,
          scopeMode: elevatingAgent ? highestAgentModeInScopes(scopes) : null,
          event: 'oauth.stepup.elevation',
          eventType: 'auth',
          success: true,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'] || null,
          metadata: {
            client_id: body.client_id,
            dangerousScopes: dangerousGranted,
            scopes,
            authTime: session.createdAt,
          },
        });
      }

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
          dangerousScopes: dangerousGranted,
        },
      });

      return reply.redirect(
        buildRedirectUrl(body.redirect_uri, {
          code,
          state: body.state ?? undefined,
          iss,
        }),
        302
      );
    }
  );
}

// Exported for the /oauth/authorize fast-path (skip-consent branch).
export { canSkipConsent };

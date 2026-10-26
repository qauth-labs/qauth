import { InvalidCsrfTokenError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { env } from '../../../config/env';
import { STEP_UP_FRESH_AUTH_WINDOW_MS } from '../../constants';
import { toStoredAssuranceLevel } from '../../helpers/acr-claims';
import { mintAuthorizationCode } from '../../helpers/authorization-code';
import { sendAuthorizationError } from '../../helpers/authorization-error';
import { resolveBrowserSession } from '../../helpers/browser-session';
import {
  findExceedingAgentScopesForClient,
  unlistedReservedAudiences,
} from '../../helpers/client-auth';
import {
  isAgentClient,
  resolveClient,
  unresolvedClientError,
} from '../../helpers/client-resolution';
import { isClientUsable, unusableClientError } from '../../helpers/client-status';
import {
  canSkipConsent,
  describeScope,
  filterRequestedScopes,
  isDynamicClientWithinBadgeWindow,
  isLoopbackRedirect,
  redirectHost,
} from '../../helpers/consent';
import { malformedDpopJktError, readAuthorizationDpopJkt } from '../../helpers/dpop';
import { resolveEnvironmentPolicy } from '../../helpers/environment-policy';
import { html, render, safe, safeUrl } from '../../helpers/html';
import {
  buildRedirectUrl,
  isRedirectUriAllowedForPolicy,
  redirectUriMatchesRegistered,
  redirectUriNotPermittedError,
  unregisteredRedirectUriError,
} from '../../helpers/oauth-redirect';
import { redirectToLoginWithPendingAuthorization } from '../../helpers/pending-authorization';
import { realmRateLimitKey } from '../../helpers/realm-rate-limit';
import { realmIssuer } from '../../helpers/realm-url';
import { requestRealm } from '../../helpers/request-realm';
import { highestAgentModeInScopes } from '../../helpers/scope-modes';
import { csrfTokensEqual, generateCsrfToken } from '../../helpers/session-cookie';
import {
  burnConsentCsrfToken,
  readSessionSideRecord,
  writeSessionSideRecord,
} from '../../helpers/session-side-record';
import { evaluateStepUp, isDangerousScope, parsePromptMode } from '../../helpers/step-up';
import { emitUserEvent } from '../../helpers/user-events';
import { markRelaxedCsp } from '../../plugins/security-headers';
import { type ConsentForm, consentFormSchema } from '../../schemas/consent';
import { authorizeQuerySchema } from '../../schemas/oauth';

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
 * Order- and duplicate-independent equality of two RFC 8707 resource lists.
 * Unlike scopes, `resource` values are not de-duplicated by the schema.
 */
function resourceSetsEqual(a: readonly string[], b: readonly string[]): boolean {
  const left = new Set(a);
  const right = new Set(b);
  return left.size === right.size && [...right].every((r) => left.has(r));
}

/**
 * Consent screen & Allow/Deny POST handler (issue #150).
 *
 * GET  /ui/consent — server-renders the consent page given the same query
 *                    parameters as /oauth/authorize. Expects a signed
 *                    session cookie; otherwise redirects to the login page
 *                    with `return_to=/ui/resume/<handle>`, the authorize URL
 *                    itself being parked server-side (#316 follow-up).
 * POST /ui/consent — processes Allow / Deny; on Allow, issues an
 *                    authorization code and redirects to redirect_uri; on
 *                    Deny, redirects with error=access_denied (RFC 6749
 *                    §4.1.2.1). CSRF-protected via a form token bound to
 *                    the signed session cookie.
 */

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
  userIdentifier: string;
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
            <p class="as-user">Signed in as ${opts.userIdentifier}</p>
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
        'x-qauth-stability': 'stable',
        'x-qauth-errors': [400],
        querystring: authorizeQuerySchema,
      },
      config: { surface: 'browser' },
    },
    async (request, reply) => {
      const query = request.query as z.infer<typeof authorizeQuerySchema>;

      // RFC 9207 §2 (#282): same issuer identifier the discovery documents
      // advertise, echoed as `iss` on every authorization response this route
      // emits. The consent screen terminates the authorization request on both
      // Allow and Deny, so its redirects are authorization responses too and
      // carry the mix-up defence exactly like /oauth/authorize's. The issuer
      // is the request realm's, from its row (ADR-019 Decision 1, #490).
      const iss = realmIssuer(requestRealm(request));

      const session = await resolveBrowserSession(fastify, request, reply);
      if (!session) {
        // #316 follow-up: the rebuilt authorize URL is parked server-side and
        // the browser only carries a short handle, so a 2048-char `state` can
        // no longer inflate this Location header past a proxy's header buffer.
        return redirectToLoginWithPendingAuthorization(
          fastify,
          reply,
          // `dpop_jkt` is taken in any shape (`dpopJktParamSchema`); only a
          // single value goes back to /oauth/authorize, which checks it again.
          buildAuthorizeUrl({
            ...query,
            dpop_jkt: typeof query.dpop_jkt === 'string' ? query.dpop_jkt : undefined,
          })
        );
      }

      const realm = requestRealm(request);
      // Pre-registered → CIMD resolution (a CIMD client reaching consent was
      // already materialised by /oauth/authorize, so findByClientId inside
      // resolveClient hits it; if its document cache expired it is re-fetched
      // and re-validated here).
      const { client } = await resolveClient(fastify, realm.id, query.client_id);
      if (!client) throw unresolvedClientError();
      // A disabled or operator-suspended client (ANT-2026-DR5XI3LV).
      if (!isClientUsable(client)) throw unusableClientError();
      if (!redirectUriMatchesRegistered(query.redirect_uri, client.redirectUris)) {
        throw unregisteredRedirectUriError();
      }

      // ADR-008 §5/§7 (#197): effective environment policy for this (client,
      // realm). The consent screen is one of the FEW browser surfaces that
      // unambiguously carries a `client_id`, so it is where a client-scoped T3
      // relaxation (below) is safe to apply. The localhost redirect gate also
      // applies on the render path so we never show a consent screen for a
      // redirect the POST handler will (correctly) refuse.
      const policy = resolveEnvironmentPolicy(client, realm);
      if (
        !isRedirectUriAllowedForPolicy(query.redirect_uri, policy, env.REDIRECT_URI_CUSTOM_SCHEMES)
      ) {
        throw redirectUriNotPermittedError();
      }

      // RFC 9449 §10 (#480): the DPoP key the code will be bound to, carried
      // to the POST as a hidden field while DPoP is on. /oauth/authorize
      // refused a malformed value before redirecting here.
      const dpopJkt = readAuthorizationDpopJkt(fastify, query.dpop_jkt);
      if (dpopJkt.kind === 'malformed') {
        throw malformedDpopJktError();
      }

      // ADR-007 §2 (#184): fail fast on the render path too — don't show a
      // consent screen for an over-cap agent scope that the POST handler will
      // (correctly) refuse to mint a code for. Same deny-by-default gate;
      // redirect_uri is already validated above. This fires before the user
      // has seen the screen (and the destination host on it), so the error of
      // a client no operator provisioned is shown rather than redirected, as
      // on /oauth/authorize (RFC 9700 §4.11.2).
      if (findExceedingAgentScopesForClient(query.scope, client).length > 0) {
        return sendAuthorizationError(reply, client, query.redirect_uri, {
          error: 'invalid_scope',
          error_description: 'requested scope exceeds the agent scope mode for this client',
          state: query.state ?? undefined,
          iss,
        });
      }

      const isCimd =
        (client.metadata as Record<string, unknown> | null)?.registrationType === 'cimd';

      const scopes = filterRequestedScopes(query.scope, client);

      // RFC 8707: the validated, array-normalized `resource` (never a
      // re-parse of request.url — see the note in oauth/authorize.ts). Shown
      // as the audience, bound to the session below and recorded on the
      // grant, so what the user approves is what the token is issued for.
      const resources = query.resource ?? [];

      // #509: a QAuth API audience (`urn:qauth:aud:`) is issued only to a
      // client that lists it. /oauth/authorize refuses such a request before
      // it redirects here; a request that comes straight to this screen is
      // refused the same way, so no consent is shown, bound or stored for an
      // audience the token endpoint would refuse.
      if (unlistedReservedAudiences(client, resources).length > 0) {
        return sendAuthorizationError(reply, client, query.redirect_uri, {
          error: 'invalid_target',
          error_description: 'a QAuth API audience is issued only to a client that lists it',
          state: query.state ?? undefined,
          iss,
        });
      }

      // The CSRF token, the bound scopes and resources, and the identifier
      // shown below live in the session's side record (#488), not in the
      // session: rendering this screen writes Redis only.
      const side = await readSessionSideRecord(fastify, session);

      // Reuse the session's existing CSRF token if present; only mint a
      // fresh one when none exists yet. Rotating on every GET would break
      // multi-tab flows: opening the consent page in a second tab would
      // invalidate the first tab's hidden form field, so the first tab's
      // submit would fail even though the user's intent is legitimate.
      // The token is still burned on successful POST, and a new session
      // (re-login) always mints a new one.
      const csrfToken = side.csrfToken ?? generateCsrfToken();

      // Scope-presentation integrity (#150 hardening): bind the EXACT scope set
      // the user is about to see to the session, keyed by client_id. The POST
      // handler grants only these scopes — the hidden `scope` form field is
      // attacker-controllable, so the persisted grant must match what was
      // rendered, not what is submitted. Always persisted (the scope set can
      // change between GETs for the same client), so this write also covers the
      // first-time CSRF-token mint above. The RFC 8707 resources shown as the
      // audience are bound the same way: they become the token's `aud`.
      // The side record expires with the session: rendering the screen never
      // extends it.
      await writeSessionSideRecord(fastify, session, {
        csrfToken,
        consent: { clientId: client.clientId, scopes, resources },
      });

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
          // The precedence `resolveAudience` applies to the token's `aud`: the
          // requested `resource` overrides the client's configured audience,
          // so the screen names the resource server the token will be for.
          audience: resources.length > 0 ? resources : (client.audience ?? []),
          scopes,
          badgeDynamic: isDynamicClientWithinBadgeWindow(client),
          csrfToken,
          cspNonce: reply.cspNonce.style,
          authorizeParams: {
            client_id: query.client_id,
            redirect_uri: query.redirect_uri,
            state: query.state,
            // The form submits the scopes this page LISTS (the
            // allowlist-filtered set bound to the session above), never the
            // raw request. The POST re-filters the submitted value against the
            // allowlist as it is THEN, so a raw value would pick up scopes the
            // client's owner added after this render, and match a binding a
            // later render rewrote: a grant of scopes this page never showed.
            scope: scopes.join(' '),
            nonce: query.nonce,
            code_challenge: query.code_challenge,
            code_challenge_method: query.code_challenge_method,
            response_type: query.response_type,
            // ADR-007 §2 (#185): preserve the step-up params so the POST mint
            // path re-evaluates them server-side.
            prompt: query.prompt,
            max_age: query.max_age !== undefined ? String(query.max_age) : undefined,
            // RFC 9449 §10 (#480): absent, so no hidden field, while DPoP is
            // off or the request bound no key.
            dpop_jkt: dpopJkt.kind === 'bound' ? dpopJkt.jkt : undefined,
          },
          // Rendered as one hidden <input name="resource" value="<uri>" />
          // per entry so the POST body carries every requested resource URI
          // back to the handler, which compares them with the binding above.
          resources,
          // #230: the identifier of the credential the user signed in with.
          // A sign-in without one, or a lost side record, shows the stable
          // subject id instead.
          userIdentifier: side.identifier ?? session.userId,
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
        'x-qauth-stability': 'stable',
        'x-qauth-errors': [400],
        body: consentFormSchema,
      },
      config: {
        surface: 'browser',
        rateLimit: {
          max: env.AUTHORIZE_RATE_LIMIT,
          timeWindow: env.AUTHORIZE_RATE_WINDOW * 1000,
          keyGenerator: realmRateLimitKey,
        },
      },
    },
    async (request, reply) => {
      const body = request.body as ConsentForm;

      // RFC 9207 §2 (#282): same issuer identifier the discovery documents
      // advertise, echoed as `iss` on every authorization response this route
      // emits. The consent screen terminates the authorization request on both
      // Allow and Deny, so its redirects are authorization responses too and
      // carry the mix-up defence exactly like /oauth/authorize's. The issuer
      // is the request realm's, from its row (ADR-019 Decision 1, #490).
      const iss = realmIssuer(requestRealm(request));

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
          // RFC 9449 §10 (#480): /oauth/authorize reads and checks it again.
          dpop_jkt: typeof body.dpop_jkt === 'string' ? body.dpop_jkt : undefined,
        });
        // #316 follow-up: short handle in the URL, full authorize URL in Redis.
        return redirectToLoginWithPendingAuthorization(fastify, reply, returnTo);
      }

      const side = await readSessionSideRecord(fastify, session);
      if (!csrfTokensEqual(side.csrfToken, body.csrf_token)) {
        // No client: the posted `client_id` is not resolved before this check.
        await emitUserEvent(
          request,
          'urn:qauth:event:request.csrf_rejected:v1-rc.0',
          { form: 'consent' },
          { userId: session.userId, actor: 'user' }
        );
        throw new InvalidCsrfTokenError();
      }

      // Burn the CSRF token so the form cannot be replayed. A fresh one is
      // minted on the next GET /ui/consent render.
      await burnConsentCsrfToken(fastify, session);

      const realm = requestRealm(request);
      const { client } = await resolveClient(fastify, realm.id, body.client_id);
      if (!client) throw unresolvedClientError();
      // A disabled or operator-suspended client (ANT-2026-DR5XI3LV).
      if (!isClientUsable(client)) throw unusableClientError();
      if (!redirectUriMatchesRegistered(body.redirect_uri, client.redirectUris)) {
        throw unregisteredRedirectUriError();
      }

      // ADR-008 §5/§7 (#197): effective environment policy for this (client,
      // realm). Gates the localhost redirect and the automatic step-up below.
      const policy = resolveEnvironmentPolicy(client, realm);
      if (
        !isRedirectUriAllowedForPolicy(body.redirect_uri, policy, env.REDIRECT_URI_CUSTOM_SCHEMES)
      ) {
        throw redirectUriNotPermittedError();
      }

      // RFC 9449 §10 (#480): the DPoP key the code is bound to, from the
      // rendered form. A malformed value was never rendered, so it is refused.
      const dpopJkt = readAuthorizationDpopJkt(fastify, body.dpop_jkt);
      if (dpopJkt.kind === 'malformed') {
        throw malformedDpopJktError();
      }

      // Deny path: redirect with error=access_denied, state preserved
      // (RFC 6749 §4.1.2.1).
      if (body.decision === 'deny') {
        await emitUserEvent(
          request,
          'urn:qauth:event:consent.denied:v1-rc.0',
          { error: 'access_denied' },
          { realmId: realm.id, userId: session.userId, clientId: client.clientId, actor: 'user' }
        );
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
        await emitUserEvent(
          request,
          'urn:qauth:event:consent.denied:v1-rc.0',
          { error: 'invalid_scope', reason: 'agent_scope_mode_exceeded' },
          { realmId: realm.id, userId: session.userId, clientId: client.clientId, actor: 'user' }
        );
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
      const boundScopes = side.consentScopes[client.clientId];
      const postedScopes = filterRequestedScopes(body.scope, client);
      if (boundScopes === undefined || !scopeSetsEqual(boundScopes, postedScopes)) {
        await emitUserEvent(
          request,
          'urn:qauth:event:consent.denied:v1-rc.0',
          { error: 'invalid_scope', reason: 'consent_scope_mismatch' },
          { realmId: realm.id, userId: session.userId, clientId: client.clientId, actor: 'user' }
        );
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

      // RFC 8707: the same integrity rule for the resources, which become the
      // token's `aud`. The GET bound the resources it named as the audience;
      // the hidden `resource` fields must name exactly those, or this is a
      // page the session no longer describes (a later render rebound it) or
      // a tampered form. A session rendered before resources were bound
      // carries no entry, which reads as "named none".
      const boundResources = side.consentResources[client.clientId] ?? [];
      const postedResources = body.resource ?? [];
      if (!resourceSetsEqual(boundResources, postedResources)) {
        await emitUserEvent(
          request,
          'urn:qauth:event:consent.denied:v1-rc.0',
          { error: 'invalid_target', reason: 'consent_resource_mismatch' },
          { realmId: realm.id, userId: session.userId, clientId: client.clientId, actor: 'user' }
        );
        return reply.redirect(
          buildRedirectUrl(body.redirect_uri, {
            error: 'invalid_target',
            error_description: 'consent resource does not match the rendered authorization request',
            state: body.state ?? undefined,
            iss,
          }),
          302
        );
      }
      // Record and bind the resources the screen named — never the raw POST.
      const resources = boundResources;

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
        authTimeMs: session.authTime,
        nowMs: Date.now(),
        freshAuthWindowMs: STEP_UP_FRESH_AUTH_WINDOW_MS,
        // ADR-008 §5 (#197): relax the automatic dangerous-scope fresh-login on
        // the mint path for a development client; explicit prompt/max_age still
        // force step-up in every environment.
        enforceDangerousStepUp: policy.agentStepUpEnforced,
      });
      if (stepUp.requiresFreshLogin) {
        await emitUserEvent(
          request,
          'urn:qauth:event:step_up.required:v1-rc.0',
          {
            reason: 'fresh_authentication_required',
            ...(stepUp.dangerous.length > 0 ? { dangerousScopes: stepUp.dangerous } : {}),
            ...(prompt === null ? {} : { prompt }),
            ...(body.max_age === undefined ? {} : { maxAge: body.max_age }),
          },
          { realmId: realm.id, userId: session.userId, clientId: client.clientId, actor: 'user' }
        );
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
          resource: resources,
          dpop_jkt: dpopJkt.kind === 'bound' ? dpopJkt.jkt : undefined,
        });
        // #316 follow-up: short handle in the URL, full authorize URL in Redis.
        return redirectToLoginWithPendingAuthorization(fastify, reply, returnTo);
      }

      // Allow: persist the grant if the user checked the box, then issue a
      // code. The grant upsert merges with any prior record so subsequent
      // requests with a subset of these scopes, for the resource(s) this
      // screen named as the audience, skip the screen. An approval that is
      // not persisted is one-time: /oauth/token mints a refresh token only
      // under a stored consent, the row the user can list and revoke.
      if (body.allow_forever === '1') {
        await fastify.repositories.oauthConsents.upsertGrant(
          session.userId,
          client.id,
          realm.id,
          scopes,
          resources
        );
      }

      const code = await mintAuthorizationCode(fastify, {
        oauthClientId: client.id,
        userId: session.userId,
        redirectUri: body.redirect_uri,
        codeChallenge: body.code_challenge,
        codeChallengeMethod: body.code_challenge_method,
        nonce: body.nonce ?? null,
        // OIDC Core §2 `auth_time`: the REAL end-user authentication time
        // (browser-session establishment, epoch MS), so /oauth/token can
        // assert `auth_time` in the ID token and `max_age` evaluates the
        // actual session age rather than this code's mint time.
        authTime: session.authTime,
        // #237 (ADR-004/ADR-010): the authentication's eIDAS LoA, bound to
        // the code so /oauth/token can assert `acr`. NULL for a password
        // login (`'low'`), which is the "omit the claim" outcome.
        assuranceLevel: toStoredAssuranceLevel(session.assuranceLevel),
        // ADR-019 Decision 3 (#552): the session's absolute end, so the
        // refresh family this code starts never outlives the session.
        sessionExpiresAt: session.expiresAt,
        scopes,
        // RFC 8707: bind the resource(s) the screen named to this code so
        // /oauth/token can set the issued access token's `aud` claim.
        resource: resources,
        state: body.state ?? null,
        // RFC 9449 §10 (#480): the DPoP key the token request must prove.
        dpopJkt: dpopJkt.kind === 'bound' ? dpopJkt.jkt : null,
      });

      // ADR-007 §2 (#185): every elevation that grants a dangerous scope is
      // recorded as a distinct step-up event (in addition to the normal
      // consent.granted event), with the fresh `auth_time` so an operator can
      // see the dangerous grant was minted right after a re-authentication.
      const dangerousGranted = scopes.filter(isDangerousScope);
      if (dangerousGranted.length > 0) {
        // Per-agent action record (ADR-007 §2, #186). When the elevating
        // client is an agent (fail-closed `isAgentClient`), the event records
        // the effective agent scope mode so the dangerous grant is accountable
        // in the agent-activity view; a non-agent client records none. The
        // actor is the user, who granted the elevation, and the agent is the
        // event's client: this is a user-driven consent elevation, not
        // on-behalf-of delegation, so there is no `act` chain.
        const scopeMode = isAgentClient(client) ? highestAgentModeInScopes(scopes) : null;
        await emitUserEvent(
          request,
          'urn:qauth:event:step_up.elevated:v1-rc.0',
          {
            scopes,
            dangerousScopes: dangerousGranted,
            ...(scopeMode === null ? {} : { scopeMode }),
            authenticatedAt: new Date(session.authTime).toISOString(),
          },
          { realmId: realm.id, userId: session.userId, clientId: client.clientId, actor: 'user' }
        );
      }

      await emitUserEvent(
        request,
        'urn:qauth:event:consent.granted:v1-rc.0',
        {
          scopes,
          remembered: body.allow_forever === '1',
          ...(dangerousGranted.length > 0 ? { dangerousScopes: dangerousGranted } : {}),
        },
        { realmId: realm.id, userId: session.userId, clientId: client.clientId, actor: 'user' }
      );

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

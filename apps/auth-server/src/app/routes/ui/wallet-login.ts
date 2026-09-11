import { randomUUID } from 'node:crypto';

import {
  hashOid4vpResponseCode,
  isOid4vpResponseCode,
  MAX_OID4VP_RESPONSE_CODE_LENGTH,
} from '@qauth-labs/fastify-plugin-federation';
import { normalizeEmail } from '@qauth-labs/shared-validation';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { env } from '../../../config/env';
import {
  ASSERTED_IDENTIFIER_MAX_LENGTH,
  WALLET_LOGIN_POLL_INTERVAL_MS,
  WALLET_LOGIN_STATUS_RATE_LIMIT,
  WALLET_LOGIN_STATUS_RATE_WINDOW_S,
} from '../../constants';
import { resolveBrowserSession } from '../../helpers/browser-session';
import { html, render, safe, safeCustomSchemeUrl } from '../../helpers/html';
import { encodeQrCode, renderQrCodeSvg } from '../../helpers/qr-code';
import { getOrCreateDefaultRealm } from '../../helpers/realm';
import { resolveReturnTo } from '../../helpers/return-to';
import {
  clearLoginCsrfCookie,
  csrfTokensEqual,
  dropWalletFlowBinding,
  findWalletFlowBinder,
  generateCsrfToken,
  LOGIN_CSRF_COOKIE_NAME,
  readCookie,
  readWalletFlowBindings,
  setLoginCsrfCookie,
  setSessionCookie,
  setWalletFlowCookie,
  verifyLoginCsrfCookie,
  WALLET_FLOW_COOKIE_NAME,
} from '../../helpers/session-cookie';
import {
  advanceWalletLinkFlow,
  WALLET_LINK_CONFLICT,
  WALLET_LINK_REFUSAL,
} from '../../helpers/wallet-link-flow';
import {
  createWalletLoginFlow,
  decideSignalGate,
  deleteWalletFlowDoneMarker,
  deleteWalletLoginFlow,
  deleteWalletPresentationSignal,
  deleteWalletPresentationStash,
  discardWalletPresentation,
  generateWalletFlowSecret,
  isWalletLoginHandle,
  readWalletFlowDoneMarker,
  readWalletLoginFlow,
  readWalletPresentationSignalRecord,
  type WalletFlowDoneMarker,
  type WalletFlowSurface,
  type WalletLoginFlow,
  writeWalletFlowDoneMarker,
} from '../../helpers/wallet-login-flow';
import {
  buildWalletLoginInvocation,
  resolveWalletLoginCapability,
  WALLET_LOGIN_RETURN_PATH,
} from '../../helpers/wallet-login-request';
import { resolveWalletPresentation } from '../../helpers/wallet-presentation';
import {
  WALLET_LINK_CONFLICT_TITLE,
  WALLET_LINK_REJECTED_TITLE,
  walletLinkedPage,
  walletLinkTerminalPage,
  walletPageStyles,
  walletReturnRefusalPage,
  walletSignedInPage,
  walletTerminalPage,
} from '../../helpers/wallet-ui';
import { runWithCredentialStatusAuditContext } from '../../helpers/wallet-verification';

/**
 * Server-rendered WALLET LOGIN screens (issue #239, ADR-004 / ADR-009).
 *
 * Mounted under `/ui/*` alongside the password login it extends, and built on
 * the same primitives: the same `html` escaping helper, the same signed
 * double-submit login-CSRF cookie, the same `__Host-` session cookie, the same
 * `return_to` guard. It is an additional way to arrive at a browser session, not
 * a parallel UI.
 *
 * ## The identifier field is not polish
 *
 * ADR-009 Decision §1: `asserted-lookup` is the universal default because **no
 * protocol-guaranteed stable wallet subject identifier exists**. The user
 * asserts which account they mean; the presentation proves entitlement to it.
 * There is therefore **no usernameless wallet login**, and the field is
 * REQUIRED. The ADR calls this out as counter-intuitive enough that a future
 * implementer will try to remove it — removing it does not simplify the flow, it
 * makes the flow unimplementable.
 *
 * Note what the field does NOT do: it is never looked up before the presentation
 * arrives. Submitting it always renders a QR code, whether or not an account
 * exists, so the screen is not an account oracle.
 *
 * ## Targeting surface — QR / deep link only (SCOPE DECISION, #239)
 *
 * OID4VP 1.0 offers two ways to reach a wallet: the cross-device QR / same-device
 * deep link handled here, and the browser-native Digital Credentials API, whose
 * `origin:` Client Identifier Prefix is reserved for it. **This issue ships
 * QR/deep-link only.** The DC API path requires that prefix, which
 * `client-identifier.ts` does not implement, and its request must be signed —
 * which needs #298. Shipping half of it would mean an entry point that works in
 * one browser build and fails everywhere else. The invocation URI is treated as
 * opaque throughout, so adding the DC API later changes what the backend
 * produces, not this screen's structure.
 *
 * ## Fail-closed, twice
 *
 * The routes are not REGISTERED unless `WALLET_FEDERATION_ENABLED` is on (a
 * default deployment answers 404 — the screens do not exist rather than existing
 * and refusing), and every handler re-resolves the capability per request, so a
 * deployment that ends up with no usable `VerifierProfile` refuses instead of
 * falling back to a permissive posture (#296, LOCKED).
 *
 * ## One refusal, always
 *
 * Expired request, wallet-reported error, unvalidatable presentation, untrusted
 * issuer, unknown account, disabled account: ALL render
 * {@link WALLET_LOGIN_REFUSAL}. #236's rule is that an untrusted issuer must not
 * be distinguishable from a malformed presentation, and on a login screen the
 * difference between "no such account" and "credential rejected" would be an
 * account oracle available to anyone. The reason is logged server-side; the
 * browser gets one sentence.
 *
 * ## Same device or another device — the user says which (#405, ADR-013)
 *
 * The identifier form ends in TWO submit buttons, `device=this` ("Use a wallet
 * on this device") and `device=other` ("Scan with a wallet on another device").
 * The choice is the user's own form submission — the login-CSRF cookie already
 * gates that POST — and it is recorded at flow start, in both records at once:
 * `same_device` on the `oid4vp_request_states` row (what the wallet's POST
 * redeems) and `sameDevice` on the flow record (what the browser's poll reads).
 * An absent field is cross-device, so every existing client and harness keeps
 * the QR path it had.
 *
 * The server needs to know because the two flows END differently, and OID4VP
 * 1.0 §14.2 says why. With `direct_post` the wallet sends the response
 * out-of-band, so an attacker who relayed the Authorization Request to a
 * victim's wallet could conclude the flow on a device that never saw the
 * victim; the fix — "the Verifier's Response URI MUST include a fresh secret
 * (Response Code) into the redirect URI returned to the Wallet and […] MUST
 * require the frontend to pass the respective Response Code" — only works when
 * the wallet's browser IS the browser that started the flow, which §14.2
 * concedes "is not applicable to cross-device scenarios". §13.3 draws the two
 * models: a same-device flow ends with step 7, the wallet redirecting the user
 * agent to the Verifier's frontend with the code; a cross-device flow ends at
 * step 6 with no `redirect_uri`, and the frontend fetches the result on its
 * own — this file's poll. HAIP 1.0 §5.1 makes the same-device leg a MUST:
 * "Verifiers MUST include redirect_uri", "Wallets MUST follow the redirect",
 * and "Verifiers MUST reject presentations if Wallets do not follow the
 * redirect back or the redirect back arrives in a different user session to
 * the one the request was initiated in".
 *
 * So the pending page renders exactly ONE affordance per flow — the deep link
 * for `this`, the QR for `other` — and the state machine below treats a
 * same-device flow's `received` signal as "wait for the return leg", never as
 * "complete by polling". The return leg is `GET /ui/wallet-login/return`, whose
 * JSDoc holds the order of operations; the deadline that turns a never-followed
 * redirect into an active rejection is `WALLET_RETURN_CODE_TTL_MS`; and the
 * done-marker that lets the ORIGINAL tab continue after the wallet completed
 * the flow in a new one is `helpers/wallet-login-flow.ts`'s
 * `WalletFlowDoneMarker`. The status JSON the poller reads is unchanged in
 * shape.
 */

/** The ONE sentence any wallet-login failure renders. */
export const WALLET_LOGIN_REFUSAL = 'We could not complete that sign-in. Please try again.';

/** Copy for a flow whose presentation request timed out. */
export const WALLET_LOGIN_EXPIRED = 'This sign-in request has expired. Please start again.';

/**
 * Shared page chrome, so the wallet screens cannot drift apart visually.
 *
 * Moved to `helpers/wallet-ui.ts` when account linking (#238) added a second
 * wallet surface; re-exported through this local alias so the three screens
 * below read exactly as they did.
 */
const pageStyles = walletPageStyles;

/**
 * Screen 1 — assert an account, then start the presentation request.
 *
 * Two submit buttons on the one form, named `device` (#405): the button the
 * user taps IS the same-device choice, so there is no separate control to
 * forget and no state to carry between screens. Both are plain submits — a
 * browser with scripts off makes the same choice the same way. The first
 * button in source order is the one an Enter key in the field triggers, and it
 * is the cross-device one on purpose: that is the path every deployment served
 * before #405, and the one that cannot strand a user on a device with no
 * wallet.
 */
function identifierPage(opts: {
  returnTo: string;
  cspNonce: string;
  csrfToken: string;
  error?: string;
  identifier?: string;
}): string {
  const { returnTo, cspNonce, csrfToken, error, identifier } = opts;
  return render(
    html`<!doctype html>
      <html lang="en">
        <head>
          <meta charset="utf-8" />
          <meta name="viewport" content="width=device-width,initial-scale=1" />
          <meta name="robots" content="noindex" />
          <title>Sign in with your wallet — QAuth</title>
          ${pageStyles(cspNonce)}
        </head>
        <body>
          <form class="card" method="post" action="/ui/wallet-login">
            <h1>Sign in with your wallet</h1>
            ${error ? html`<div class="error" role="alert">${error}</div>` : ''}
            <p>
              Tell us which account you are signing in to, then present a credential from your
              wallet to prove it is yours.
            </p>
            <input type="hidden" name="return_to" value="${returnTo}" />
            <input type="hidden" name="csrf_token" value="${csrfToken}" />
            <label>
              Email or username
              <input
                type="text"
                name="identifier"
                autocomplete="username"
                autocapitalize="none"
                spellcheck="false"
                required
                maxlength="${ASSERTED_IDENTIFIER_MAX_LENGTH}"
                aria-describedby="identifier-hint"
                value="${identifier ?? ''}"
              />
            </label>
            <p class="hint" id="identifier-hint">
              Your wallet does not tell us who you are, so we need you to say which account you
              mean.
            </p>
            <button type="submit" name="device" value="other">
              Scan with a wallet on another device
            </button>
            <button type="submit" name="device" value="this" class="secondary">
              Use a wallet on this device
            </button>
            <p class="hint" id="device-hint">
              Choose where your wallet is: scanning shows a code for a wallet on your phone; using
              this device opens a wallet installed here and brings you back when you're done.
            </p>
            <a class="footer-link" href="/ui/login?return_to=${encodeURIComponent(returnTo)}"
              >Sign in with a password instead</a
            >
          </form>
        </body>
      </html>`
  );
}

/**
 * Screen 2 — the wallet invocation, plus the wait.
 *
 * The deep link is a plain anchor rather than a script-driven navigation: the
 * invocation URI is a custom scheme or a universal link, and letting the browser
 * decide what to do with it is what makes both work. `safeUrl()` from `html.ts`
 * cannot guard it — that helper allowlists http/https/mailto, and this href is
 * `openid4vp://…` by design — so it goes through that file's denylist
 * counterpart, `safeCustomSchemeUrl()`, instead: any scheme a wallet might
 * register is fine, `javascript:`/`data:`/`vbscript:` and their encoded
 * spellings are not. HTML-escaping alone would not help here, because
 * `javascript:alert(1)` contains nothing `esc()` touches.
 *
 * `federationEnvSchema` already refuses to boot on such a value (#239), so this
 * branch is unreachable through configuration. That is deliberate: neither check
 * is load-bearing on its own, and the render path stays safe if a future caller
 * feeds this screen a URI from somewhere other than `OID4VP_WALLET_INVOCATION_
 * ENDPOINT`. When the link is refused the page still renders, with an
 * explanation where the anchor would be — unusable, but it must not emit an
 * executable href.
 *
 * ## Exactly one affordance (#405)
 *
 * A same-device flow renders the anchor and NO QR; a cross-device flow renders
 * the QR and NO anchor. The two are not interchangeable once the flow has
 * started: the Response Endpoint hands a wallet a `redirect_uri` only for a
 * same-device row, and the state machine completes a same-device flow only on
 * the return leg. Offering both on one page would let a user scan a same-device
 * request with a phone — whose wallet would then be sent to a browser that does
 * not hold the flow, and refused — or tap a cross-device request's link and
 * have the wallet complete a flow that is waiting on a poll. Each variant gets
 * a "Start again" footer link instead, which begins a FRESH flow with the other
 * choice available; the old one expires harmlessly.
 *
 * The anchor is a plain user-gesture `href`, exactly as before #405: a
 * server-side redirect to the invocation URI would be refused by the page's
 * `form-action 'self'` CSP in Chromium and WebKit, and iOS does not open an app
 * for a universal link reached through a 3xx. No script handler, no form.
 *
 * The QR code degrades rather than throws: a payload past the encoder's maximum
 * (`QR_MAX_BYTES`) renders an explanation and the "Start again" link, because
 * an over-long invocation URI is a configuration outcome and this screen must
 * not 500 on it. It no longer falls back to the deep link — a device that was
 * asked to scan cannot use one.
 */
function pendingPage(opts: {
  handle: string;
  invocationUri: string;
  sameDevice: boolean;
  cspNonce: string;
  scriptNonce: string;
  returnTo: string;
}): string {
  const { handle, invocationUri, sameDevice, cspNonce, scriptNonce, returnTo } = opts;
  const statusPath = `/ui/wallet-login/${handle}/status`;
  const startAgainHref = `/ui/wallet-login?return_to=${encodeURIComponent(returnTo)}`;

  return render(
    html`<!doctype html>
      <html lang="en">
        <head>
          <meta charset="utf-8" />
          <meta name="viewport" content="width=device-width,initial-scale=1" />
          <meta name="robots" content="noindex" />
          <title>Waiting for your wallet — QAuth</title>
          ${pageStyles(cspNonce)}
        </head>
        <body>
          <div class="card">
            <h1>Present a credential</h1>
            ${
              sameDevice
                ? sameDeviceInvocation(invocationUri)
                : crossDeviceInvocation(invocationUri, startAgainHref)
            }
            <div class="status" id="wallet-status" role="status" aria-live="polite">
              ${
                sameDevice
                  ? "Opening your wallet on this device… When you're done, your wallet will bring you back here."
                  : 'Waiting for your wallet…'
              }
            </div>
            <noscript>
              <p class="hint">
                This page updates itself when JavaScript is enabled.
                <a href="/ui/wallet-login/${handle}">Check whether your wallet has responded</a>.
              </p>
            </noscript>
            <a class="footer-link" href="${startAgainHref}">Start again</a>
            <a class="footer-link" href="/ui/login?return_to=${encodeURIComponent(returnTo)}"
              >Cancel and sign in with a password</a
            >
          </div>
          <script nonce="${scriptNonce}">
            (function () {
              var statusUrl = ${safe(JSON.stringify(statusPath))};
              var interval = ${WALLET_LOGIN_POLL_INTERVAL_MS};
              var region = document.getElementById('wallet-status');
              function poll() {
                fetch(statusUrl, {
                  credentials: 'same-origin',
                  headers: { Accept: 'application/json' },
                })
                  .then(function (response) {
                    return response.ok ? response.json() : null;
                  })
                  .then(function (body) {
                    if (!body || body.status === 'pending') {
                      window.setTimeout(poll, interval);
                      return;
                    }
                    if (body.status === 'complete' && body.redirect_to) {
                      window.location.assign(body.redirect_to);
                      return;
                    }
                    region.textContent = body.message || '';
                  })
                  .catch(function () {
                    window.setTimeout(poll, interval);
                  });
              }
              window.setTimeout(poll, interval);
            })();
          </script>
        </body>
      </html>`
  );
}

/**
 * The same-device half of the pending page: the "Open my wallet" anchor.
 *
 * `safeCustomSchemeUrl()` rather than `safeUrl()`, for the reason the
 * `pendingPage` JSDoc gives: the href is `openid4vp://…` by design, so the
 * denylist is the right guard. When it refuses, the page renders an explanation
 * and no href at all — it must not emit an executable one — and stays a page
 * rather than a 500.
 */
function sameDeviceInvocation(invocationUri: string) {
  const deepLink = safeCustomSchemeUrl(invocationUri);
  return html`<p>Open your wallet on this device to present a credential.</p>
    ${
      deepLink === undefined
        ? html`<p class="hint">
            This deployment cannot offer an open-my-wallet link. Contact your administrator.
          </p>`
        : html`<a class="alt-action" href="${deepLink}">Open my wallet</a>`
    }`;
}

/**
 * The cross-device half of the pending page: the QR code.
 *
 * Over-long payloads (`QR_MAX_BYTES`) get an explanation and a way to start
 * over rather than a deep link — see the `pendingPage` JSDoc.
 */
function crossDeviceInvocation(invocationUri: string, startAgainHref: string) {
  const qr = encodeQrCode(invocationUri);
  return html`<p>Scan this code with the wallet on your other device.</p>
    ${
      qr === undefined
        ? html`<p class="hint">
            This request is too large to show as a code, so it cannot be scanned. Contact your
            administrator, or <a href="${startAgainHref}">start again</a> and use a wallet on this
            device instead.
          </p>`
        : html`<div class="qr">
            ${safe(renderQrCodeSvg(qr, 'QR code containing the wallet sign-in request'))}
          </div>`
    }`;
}

/** Screen 3 — a terminal state: expired, refused, or not available. */
const terminalPage = walletTerminalPage;

const walletLoginFormSchema = z.object({
  /**
   * The account the user ASSERTS (ADR-009 §1). Bounded like every other
   * pre-authentication string in this codebase — it reaches Redis and, later, an
   * `external_sub` lookup.
   */
  identifier: z.string().min(1).max(ASSERTED_IDENTIFIER_MAX_LENGTH),
  return_to: z.string().optional(),
  csrf_token: z.string().min(1),
  /**
   * Which submit button was pressed (#405): `this` opens a wallet on this
   * device and completes on the return leg; `other` renders a QR and completes
   * by polling. Defaults to `other` so a body without the field — the E2E
   * harness, a client built before #405 — keeps the cross-device path it had.
   * The handler ALSO treats anything but `'this'` as `other`, so the default
   * holds even for a caller that bypasses schema validation.
   */
  device: z.enum(['this', 'other']).default('other'),
});

type WalletLoginForm = z.infer<typeof walletLoginFormSchema>;

const walletLoginStatusSchema = z.object({
  status: z.enum(['pending', 'complete', 'expired', 'rejected']),
  /** Present on every terminal status except `complete`. Fixed server copy. */
  message: z.string().optional(),
  /** Present only on `complete`: the relative path to continue to. */
  redirect_to: z.string().optional(),
});

/**
 * Normalize the asserted identifier.
 *
 * ADR-009 §1 stores it in `user_credentials.external_sub`, the same column
 * `PasswordProvider` fills with a normalized email — so it must be normalized
 * the SAME way or the two providers would disagree about what "the same account"
 * means. Email and username normalize identically today (trim + lowercase);
 * this function is the single place that changes if they ever stop doing so.
 */
function normalizeAssertedIdentifier(value: string): string {
  return normalizeEmail(value);
}

/** How this flow ended, as far as the browser is concerned. */
type FlowOutcome =
  | { status: 'pending'; flow: WalletLoginFlow }
  | { status: 'complete'; redirectTo: string }
  | { status: 'expired' }
  | { status: 'rejected' };

/**
 * Which surface is asking the state machine to advance (#405); see
 * `WalletFlowSurface`. Optional with `poll` as the default so a caller that
 * predates #405 keeps its meaning.
 */
interface AdvanceOptions {
  via?: WalletFlowSurface;
}

/**
 * Read a flow, apply the browser binder, and advance it as far as it can go.
 *
 * The ONE place a wallet-login flow changes state, shared by the page handler
 * (which redirects or re-renders), the status handler (which answers JSON) and
 * the return handler (#405, which renders a terminal page). Two surfaces
 * observing the same flow through two implementations is how one of them ends
 * up skipping the binder check; three would make it certain.
 *
 * Missing flow, wrong binder and expired flow all return `expired`: they are
 * indistinguishable to the caller by design, so a handle harvested from a screen
 * share or a log cannot be probed for whether it was ever real.
 *
 * ## The same-device gate (#405, ADR-013 D7)
 *
 * After the binder, expiry and mode gates, the signal record decides — in
 * `decideSignalGate`, the ONE function both this machine and the link
 * machine call, documented there: a wallet error or a foreign landing is
 * `rejected` on every flow via either surface; `received` on a same-device
 * flow is `pending` by poll until the Response Code deadline and `rejected`
 * after it; `received` via the return leg, or on a cross-device flow by
 * poll, proceeds to resolution. This machine does what the verdict says —
 * logs the reason, terminates, answers — so the flow still changes state in
 * one place while the rule lives in one place.
 *
 * ## Completion differs by surface (D6, D8)
 *
 * Both surfaces mint the session identically. The poll then burns this flow's
 * cookie binding and answers `complete`. The return leg does NOT burn the
 * binding — the wallet opened it in a NEW tab, and the original tab's next poll
 * must still be able to prove it holds the flow — and instead leaves a
 * done-marker under the handle, and it leaves one for EVERY terminal outcome
 * it reaches, refusals included, so the original tab reports the same word
 * the return tab showed rather than "expired". The marker is written BEFORE
 * the flow is terminated (`concludeReturnLeg`; the poll never completes a
 * same-device flow, so a poll that lands mid-completion is `pending`, never
 * a second completion). When the original tab's poll finds the flow gone, it
 * consults the marker: binder matches → marker deleted, binding burned, and
 * `complete` with `redirectTo` (re-issuing the session cookie the marker
 * names) or `rejected`, exactly once, and no second session. Anything else
 * about a missing flow is `expired`, as it always was.
 */
async function advanceWalletLoginFlow(
  fastify: FastifyInstance,
  request: FastifyRequest,
  reply: FastifyReply,
  handle: string,
  options: AdvanceOptions = {}
): Promise<FlowOutcome> {
  const via = options.via ?? 'poll';

  // Browser binding. Without it, an attacker could start a flow, present their
  // own credential and hand the victim the URL — the victim's browser would
  // finish the flow and be signed in as the attacker. Looked up BY HANDLE, so a
  // second flow started in the same browser does not unbind this one. See
  // `WALLET_FLOW_COOKIE_NAME`. Read before the flow because the done-marker
  // path below needs it too.
  const binder = findWalletFlowBinder(readCookie(request, WALLET_FLOW_COOKIE_NAME), handle);

  const flow = await readWalletLoginFlow(fastify, handle);
  if (flow === null) return resolveDoneMarker(fastify, request, reply, handle, binder);

  if (!binder || !csrfTokensEqual(flow.binder, binder)) {
    fastify.log.warn(
      { ip: request.ip },
      'wallet-login flow accessed without its browser binder cookie'
    );
    return { status: 'expired' };
  }

  if (Date.now() >= flow.expiresAt) {
    await terminate(fastify, handle, flow);
    return { status: 'expired' };
  }

  // A LINK flow may never be completed here (#238). Doing so would sign this
  // browser in as the linking user without any credential of that account's
  // having been checked — the flow was started by an already-authenticated
  // session, so its handle is not a login proof. Refused rather than ignored.
  if ((flow.mode ?? 'login') !== 'login') {
    fastify.log.warn({ ip: request.ip }, 'a wallet LINK flow was submitted to the login path');
    await terminate(fastify, handle, flow);
    return { status: 'rejected' };
  }

  const record = await readWalletPresentationSignalRecord(fastify, flow.stateHash);
  if (record === null) return { status: 'pending', flow };

  // The one marker a refused return leg leaves for the original tab (D8):
  // the word, and the binder that gates it. Nothing to navigate to.
  const rejectedMarker: WalletFlowDoneMarker = {
    binder: flow.binder,
    mode: 'login',
    outcome: 'rejected',
  };

  // The same-device gate, shared with the link machine (D7). A same-device
  // presentation completes ONLY on the return leg (OID4VP 1.0 §14.2); by
  // polling it is pending while the wallet could still bring the browser
  // back, and rejected once the code it was handed can no longer be redeemed
  // (HAIP 1.0 §5.1, "do not follow the redirect back").
  const gate = decideSignalGate(record, flow, via);
  if (gate.verdict === 'pending') return { status: 'pending', flow };
  if (gate.verdict === 'rejected') {
    if (gate.warn !== undefined) fastify.log.warn({ ip: request.ip }, gate.warn);
    if (via === 'return') {
      await concludeReturnLeg(fastify, handle, flow, rejectedMarker);
    } else {
      await terminate(fastify, handle, flow);
    }
    return { status: 'rejected' };
  }

  // A presentation arrived. Everything from here is the seam that turns it into
  // a session: validate (#234), trust the issuer (#236), resolve the subject
  // (#300), enrol on a first presentation (#235). Note where each input comes
  // from — the presented bytes are the wallet's, everything they are checked
  // against is this flow record's.
  // Correlate credential-status audit events with THIS request (#378). Status
  // refusals bypass `onRefusal` by design — the checker's fine-grained reason
  // must not reach the wire — so `onAudit` is the only server-side channel that
  // carries it, and `request.log` is what gives those lines a `reqId`.
  const resolution = await runWithCredentialStatusAuditContext(
    { log: request.log, realmId: flow.realmId },
    () =>
      resolveWalletPresentation(fastify, {
        realmId: flow.realmId,
        stateHash: flow.stateHash,
        assertedIdentifier: flow.assertedIdentifier,
        nonce: flow.nonce ?? '',
        clientId: flow.clientId ?? '',
        dcqlQuery: flow.dcqlQuery ?? {},
      })
  );

  // By POLL the flow ends here, before anything is minted, as it always has:
  // a cross-device flow CAN be completed by a concurrent poll, so the window
  // in which two of them read the same presentation stays as narrow as it
  // was. By RETURN it ends in `concludeReturnLeg`, AFTER the marker for the
  // original tab is written — no concurrent caller can complete a same-device
  // flow (the poll is gated and the code is spent), so keeping it addressable
  // for the few round trips below costs nothing and closes the window in
  // which that tab would have found neither flow nor marker.
  if (via === 'poll') await terminate(fastify, handle, flow);

  if (resolution.status !== 'authenticated') {
    await auditWalletLogin(fastify, request, {
      userId: null,
      success: false,
      metadata: { assertedIdentifier: flow.assertedIdentifier, reason: 'not_resolved' },
    });
    if (via === 'return') await concludeReturnLeg(fastify, handle, flow, rejectedMarker);
    return { status: 'rejected' };
  }

  // The `enabled` gate, exactly as the password login applies it: a valid
  // credential for a disabled account is still a refused sign-in, and it must
  // look like every other refusal.
  const user = await fastify.repositories.users.findById(resolution.userId);
  if (!user || !user.enabled) {
    fastify.log.warn(
      { userId: resolution.userId },
      'wallet presentation resolved to a missing or disabled user'
    );
    await auditWalletLogin(fastify, request, {
      userId: null,
      success: false,
      metadata: { assertedIdentifier: flow.assertedIdentifier, reason: 'user_unavailable' },
    });
    if (via === 'return') await concludeReturnLeg(fastify, handle, flow, rejectedMarker);
    return { status: 'rejected' };
  }

  // Session-fixation defence: a fresh session id on every successful
  // authentication, even if the browser already had one.
  const sessionId = randomUUID();
  await fastify.sessionUtils.setSession(
    sessionId,
    {
      userId: user.id,
      // The value stored as this credential's `external_sub` — the asserted,
      // normalized identifier (ADR-009 §1), mirroring what the password login
      // puts here.
      email: resolution.externalSub,
      sessionId,
      createdAt: Date.now(),
      // #237: the eIDAS LoA the presented credential and its issuer established,
      // carried on the session so `/oauth/authorize` can bind it to the
      // authorization code and `/oauth/token` can assert `acr` in the ID token.
      // Spread conditionally so a resolution that established nothing leaves the
      // field ABSENT rather than storing `'low'` — the password login stores
      // nothing here either, and "no assurance" must have one representation.
      ...(resolution.assuranceLevel !== undefined && resolution.assuranceLevel !== 'low'
        ? { assuranceLevel: resolution.assuranceLevel }
        : {}),
    },
    env.SESSION_COOKIE_TTL
  );

  await fastify.repositories.users.updateLastLogin(user.id);
  await auditWalletLogin(fastify, request, {
    userId: user.id,
    success: true,
    metadata: { sessionId, returnTo: flow.returnTo, verifierProfile: flow.verifierProfile },
  });

  setSessionCookie(reply, sessionId);

  if (via === 'return') {
    // The wallet opened this leg in a NEW tab. The binding stays in the shared
    // cookie jar so the ORIGINAL tab's next poll can still prove it holds the
    // flow, and the marker is what that poll will find where the flow was. It
    // is written AFTER the session and the audit row, so a marker without a
    // word exists only for a sign-in that happened, and BEFORE the flow is
    // deleted, so that poll never finds neither. It carries the session id
    // so consuming it can re-issue the cookie this response is about to set
    // — see `WalletFlowDoneMarker.sessionId` for why that is safe.
    await concludeReturnLeg(fastify, handle, flow, {
      binder: flow.binder,
      mode: 'login',
      redirectTo: flow.returnTo,
      sessionId,
    });
    return { status: 'complete', redirectTo: flow.returnTo };
  }

  // Burn only THIS flow's binding: another flow may still be pending in the
  // same browser, and clearing the whole cookie would strand it.
  dropWalletFlowBinding(request, reply, handle);

  return { status: 'complete', redirectTo: flow.returnTo };
}

/**
 * What a poll finds where a flow used to be (#405, ADR-013 D8).
 *
 * A same-device flow that ended on the return leg — in the tab the wallet
 * opened — has been terminated like any other, and the tab that started it is
 * still polling. Before answering `expired` for a missing flow, look for the
 * done-marker the return leg left under this handle. It is honoured only when
 * this browser presents the flow's binder (timing-safe, as the flow itself was
 * gated), only for a marker of THIS state machine's mode (a login poll must
 * not eat a link flow's marker, whose page is waiting for a different word),
 * and only once: the marker is deleted and the cookie binding burned in the
 * same breath, so a second poll is `expired` again.
 *
 * The answer is the word the marker carries. A refused return leg left
 * `outcome: 'rejected'`, and that is what the original tab is told — the
 * same sentence the return tab showed, rather than an "expired" that would
 * depend on whether this poll or the redirect got there first. A completed
 * one left no word and a `redirectTo` (the flow's validated `returnTo`), and
 * a `sessionId`: nothing is minted — the session exists since the return leg
 * — but its cookie is re-issued on this response, so the original tab's
 * navigation does not depend on another tab's `Set-Cookie` having landed
 * first. The binder that unlocked the marker is what makes that safe; see
 * `WalletFlowDoneMarker.sessionId`. A marker of this mode that carries any
 * other word is a refusal too: the one completed outcome is recorded by the
 * absence of a word, so nothing that carries one may read as complete.
 *
 * A poll WITHOUT the binder learns nothing and burns nothing: the read and
 * the delete are separate on purpose (see `readWalletFlowDoneMarker`), so a
 * handle harvested from a screen share cannot strand the rightful tab.
 */
async function resolveDoneMarker(
  fastify: FastifyInstance,
  request: FastifyRequest,
  reply: FastifyReply,
  handle: string,
  binder: string | null
): Promise<FlowOutcome> {
  const marker = await readWalletFlowDoneMarker(fastify, handle);
  if (marker === null || !binder || !csrfTokensEqual(marker.binder, binder)) {
    return { status: 'expired' };
  }
  if (marker.mode !== 'login') return { status: 'expired' };

  await deleteWalletFlowDoneMarker(fastify, handle);
  dropWalletFlowBinding(request, reply, handle);

  if (marker.outcome !== undefined) return { status: 'rejected' };

  if (typeof marker.sessionId === 'string' && marker.sessionId.length > 0) {
    setSessionCookie(reply, marker.sessionId);
  }
  return { status: 'complete', redirectTo: marker.redirectTo ?? '/' };
}

/**
 * End a flow on the RETURN leg (#405, ADR-013 D8): the done-marker first, the
 * flow second.
 *
 * The order is the point, and `WalletFlowDoneMarker` says why at length: the
 * original tab is answered from the flow record while one exists and from
 * the marker once there is not, so the marker must exist before the flow
 * stops existing or a poll in between finds neither. Safe on this leg
 * specifically, because nothing can complete a same-device flow while it
 * stays addressable for these two writes — the poll is gated and the code is
 * spent.
 */
async function concludeReturnLeg(
  fastify: FastifyInstance,
  handle: string,
  flow: WalletLoginFlow,
  marker: WalletFlowDoneMarker
): Promise<void> {
  await writeWalletFlowDoneMarker(fastify, handle, marker);
  await terminate(fastify, handle, flow);
}

/** Drop every trace of a finished flow so nothing can be polled or replayed. */
async function terminate(
  fastify: FastifyInstance,
  handle: string,
  flow: WalletLoginFlow
): Promise<void> {
  await deleteWalletLoginFlow(fastify, handle);
  await deleteWalletPresentationSignal(fastify, flow.stateHash);
  // The presented bytes go too. They are single-use by construction — the
  // `state` behind them is already redeemed — but leaving them addressable would
  // keep attacker-supplied text alive for the rest of the TTL for no purpose.
  await deleteWalletPresentationStash(fastify, flow.stateHash);
}

async function auditWalletLogin(
  fastify: FastifyInstance,
  request: FastifyRequest,
  entry: { userId: string | null; success: boolean; metadata: Record<string, unknown> }
): Promise<void> {
  await fastify.repositories.auditLogs.create({
    userId: entry.userId,
    oauthClientId: null,
    event: entry.success ? 'ui.wallet_login.success' : 'ui.wallet_login.failure',
    eventType: 'auth',
    success: entry.success,
    ipAddress: request.ip,
    userAgent: request.headers['user-agent'] || null,
    metadata: entry.metadata,
  });
}

function sendHtml(reply: FastifyReply, body: string, statusCode?: number): FastifyReply {
  reply.header('Content-Type', 'text/html; charset=utf-8');
  reply.header('Cache-Control', 'no-store');
  if (statusCode !== undefined) reply.code(statusCode);
  return reply.send(body);
}

export default async function (fastify: FastifyInstance) {
  // Registration gate (#232 / #299), identical in shape to the `direct_post`
  // endpoint's: a deployment that never opted into wallet federation answers
  // 404 for these paths. An entry point that does not exist cannot be probed.
  if (!env.WALLET_FEDERATION_ENABLED) {
    fastify.log.debug('wallet-login UI not registered (WALLET_FEDERATION_ENABLED is off)');
    return;
  }

  fastify.withTypeProvider<ZodTypeProvider>().get(
    '/wallet-login',
    {
      schema: {
        description:
          'Renders the wallet sign-in screen, which collects the account identifier the user asserts (ADR-009). Issue #239.',
        tags: ['UI'],
        querystring: z.object({
          return_to: z.string().optional(),
          error: z.string().optional(),
        }),
      },
    },
    async (request, reply) => {
      const q = request.query as { return_to?: string; error?: string };
      const returnTo = resolveReturnTo(q.return_to);

      if (resolveWalletLoginCapability(fastify) === undefined) {
        return sendHtml(
          reply,
          terminalPage({
            cspNonce: reply.cspNonce.style,
            title: 'Wallet sign-in is not available',
            message: 'This server is not currently accepting wallet credentials.',
            returnTo,
            retry: false,
          }),
          404
        );
      }

      // Same signed double-submit login-CSRF cookie the password form uses, and
      // reused rather than re-minted so a user who opens both screens keeps one
      // consistent token.
      const existing = verifyLoginCsrfCookie(readCookie(request, LOGIN_CSRF_COOKIE_NAME));
      const csrfToken = existing ?? generateCsrfToken();
      if (!existing) setLoginCsrfCookie(reply, csrfToken);

      return sendHtml(
        reply,
        identifierPage({
          returnTo,
          cspNonce: reply.cspNonce.style,
          csrfToken,
          error: q.error,
        })
      );
    }
  );

  fastify.withTypeProvider<ZodTypeProvider>().post(
    '/wallet-login',
    {
      schema: {
        description:
          'Starts a wallet sign-in: records the asserted account identifier and issues an OID4VP presentation request. Issue #239.',
        tags: ['UI'],
        body: walletLoginFormSchema,
      },
      config: {
        rateLimit: {
          max: env.LOGIN_RATE_LIMIT,
          timeWindow: env.LOGIN_RATE_WINDOW * 1000,
          keyGenerator: (request) => request.ip || 'unknown',
        },
      },
    },
    async (request, reply) => {
      const body = request.body as WalletLoginForm;
      const returnTo = resolveReturnTo(body.return_to);

      const capability = resolveWalletLoginCapability(fastify);
      if (capability === undefined) {
        return sendHtml(
          reply,
          terminalPage({
            cspNonce: reply.cspNonce.style,
            title: 'Wallet sign-in is not available',
            message: 'This server is not currently accepting wallet credentials.',
            returnTo,
            retry: false,
          }),
          404
        );
      }

      // Login CSRF, checked BEFORE anything else so a forged cross-site POST
      // cannot mint presentation requests (each of which is a DB row).
      const cookieCsrf = verifyLoginCsrfCookie(readCookie(request, LOGIN_CSRF_COOKIE_NAME));
      if (!cookieCsrf || !csrfTokensEqual(cookieCsrf, body.csrf_token)) {
        await fastify.repositories.auditLogs.create({
          userId: null,
          oauthClientId: null,
          event: 'ui.wallet_login.csrf_failure',
          eventType: 'auth',
          success: false,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'] || null,
          metadata: {},
        });
        const freshCsrf = generateCsrfToken();
        setLoginCsrfCookie(reply, freshCsrf);
        return sendHtml(
          reply,
          identifierPage({
            returnTo,
            cspNonce: reply.cspNonce.style,
            csrfToken: freshCsrf,
            error: 'Your session expired. Please try again.',
            identifier: body.identifier,
          }),
          403
        );
      }

      // NOT looked up. The identifier is an assertion, and checking whether it
      // exists here would turn this screen into an account oracle — every
      // submission must produce the same page.
      const assertedIdentifier = normalizeAssertedIdentifier(body.identifier);

      // The user's device choice (#405). Compared against the one value that
      // means same-device rather than trusting the schema default, so a body
      // that reached this handler without validation is still cross-device.
      const sameDevice = body.device === 'this';

      let handle: string;
      let invocationUri: string;
      try {
        const realm = await getOrCreateDefaultRealm(fastify);
        const invocation = await buildWalletLoginInvocation(fastify, capability);

        await fastify.repositories.oid4vpRequestStates.create({
          realmId: realm.id,
          stateHash: invocation.stateHash,
          nonce: invocation.nonce,
          verifierProfile: capability.profile.id,
          // Written on the ROW because the Response Endpoint decides from the
          // row alone whether to hand the wallet a `redirect_uri` (#405); it
          // cannot read the flow record and must not be able to. A boolean
          // names no browser. See `WalletLoginFlow.sameDevice`.
          sameDevice,
          // The mode the request actually asked for, read off the built request
          // rather than restated (#377 Phase C): the intake refuses a submission
          // that arrives in the other mode, so this column has to be the truth.
          responseMode: invocation.request.response_mode,
          // Spread into a fresh object literal: the column is typed
          // `Record<string, unknown>` and an interface has no implicit index
          // signature. Nothing is reshaped — this is the query that was sent.
          dcqlQuery: { ...invocation.request.dcql_query },
          expiresAt: invocation.expiresAt,
          // The per-request decryption key, when the request is direct_post.jwt
          // (#377 Phase C). All three columns or none — the schema's CHECK says
          // so, and the helper hands them over as one value so a caller cannot
          // copy two of them. It lands HERE and not on the flow record below:
          // the row is what the wallet's response redeems, and the browser's
          // record has no business carrying a private key.
          ...(invocation.responseEncryption === undefined
            ? {}
            : {
                responseEncryptionKid: invocation.responseEncryption.kid,
                responseEncryptionPrivateJwk: invocation.responseEncryption.privateJwk,
                responseEncryptionKeyProtection: invocation.responseEncryption.protection,
              }),
        });

        const binder = generateWalletFlowSecret();
        handle = await createWalletLoginFlow(fastify, {
          stateHash: invocation.stateHash,
          assertedIdentifier,
          mode: 'login',
          invocationUri: invocation.invocationUri,
          // Carried so the terminal outcome that ends this flow also removes
          // the parked request object (#377). Absent when unsigned.
          ...(invocation.requestObjectHandle === undefined
            ? {}
            : { requestObjectHandle: invocation.requestObjectHandle }),
          // Recorded on the BROWSER's record so the presentation is checked
          // against values the wallet cannot choose (#234). See `WalletLoginFlow`.
          nonce: invocation.nonce,
          clientId: invocation.request.client_id,
          dcqlQuery: { ...invocation.request.dcql_query },
          // The same choice, on the record the poll reads (#405): this is what
          // makes the state machine refuse to complete the flow by polling and
          // wait for the return leg instead. Written only when true so a
          // cross-device record looks exactly as it did before #405.
          ...(sameDevice ? { sameDevice } : {}),
          returnTo,
          binder,
          realmId: realm.id,
          verifierProfile: capability.profile.id,
          expiresAt: invocation.expiresAt,
          createdAt: Date.now(),
        });
        invocationUri = invocation.invocationUri;

        // ADDED to whatever this browser already holds rather than replacing
        // it: a user who starts a second sign-in while the first QR is still on
        // screen must keep both usable. See `WALLET_FLOW_COOKIE_NAME`.
        setWalletFlowCookie(reply, [
          ...readWalletFlowBindings(readCookie(request, WALLET_FLOW_COOKIE_NAME)),
          { handle, binder, expiresAt: invocation.expiresAt },
        ]);
      } catch (error) {
        // A profile that forbids what the request needs, an unreachable store, a
        // failed insert: all operator-visible, none of them the user's business.
        fastify.log.error({ err: error }, 'failed to start a wallet-login flow');
        return sendHtml(
          reply,
          terminalPage({
            cspNonce: reply.cspNonce.style,
            title: 'Sign-in could not be started',
            message: WALLET_LOGIN_REFUSAL,
            returnTo,
            retry: true,
          }),
          500
        );
      }

      // The login-CSRF cookie has done its job for this flow; the browser binder
      // takes over from here.
      clearLoginCsrfCookie(reply);

      // Rendered directly rather than redirected to: the invocation is already
      // in hand, and a redirect would cost the user a round trip before the QR
      // appears. The price is that this page is a POST RESPONSE BODY — reloading
      // it re-POSTs and starts a NEW flow. `GET /ui/wallet-login/:handle` is the
      // URL that re-renders THIS flow from its record, which is why the noscript
      // block links there.
      return sendHtml(
        reply,
        pendingPage({
          handle,
          invocationUri,
          sameDevice,
          cspNonce: reply.cspNonce.style,
          scriptNonce: reply.cspNonce.script,
          returnTo,
        })
      );
    }
  );

  fastify.withTypeProvider<ZodTypeProvider>().get(
    '/wallet-login/:handle',
    {
      schema: {
        description:
          'Re-renders a wallet sign-in in progress, advancing it if the wallet has responded. Also the no-JavaScript refresh path. Issue #239.',
        tags: ['UI'],
        params: z.object({ handle: z.string() }),
      },
      config: {
        rateLimit: {
          max: WALLET_LOGIN_STATUS_RATE_LIMIT,
          timeWindow: WALLET_LOGIN_STATUS_RATE_WINDOW_S * 1000,
          keyGenerator: (request) => request.ip || 'unknown',
        },
      },
    },
    async (request, reply) => {
      const { handle } = request.params as { handle: string };
      if (!isWalletLoginHandle(handle)) {
        return sendHtml(
          reply,
          terminalPage({
            cspNonce: reply.cspNonce.style,
            title: 'Sign-in request expired',
            message: WALLET_LOGIN_EXPIRED,
            returnTo: '/',
            retry: true,
          }),
          404
        );
      }

      const outcome = await advanceWalletLoginFlow(fastify, request, reply, handle, {
        via: 'poll',
      });

      switch (outcome.status) {
        case 'complete':
          reply.header('Cache-Control', 'no-store');
          return reply.redirect(outcome.redirectTo, 302);
        case 'pending':
          return sendHtml(
            reply,
            pendingPage({
              handle,
              invocationUri: outcome.flow.invocationUri,
              sameDevice: outcome.flow.sameDevice === true,
              cspNonce: reply.cspNonce.style,
              scriptNonce: reply.cspNonce.script,
              returnTo: outcome.flow.returnTo,
            })
          );
        case 'rejected':
          return sendHtml(
            reply,
            terminalPage({
              cspNonce: reply.cspNonce.style,
              title: 'Sign-in was not completed',
              message: WALLET_LOGIN_REFUSAL,
              returnTo: '/',
              retry: true,
            }),
            401
          );
        default:
          return sendHtml(
            reply,
            terminalPage({
              cspNonce: reply.cspNonce.style,
              title: 'Sign-in request expired',
              message: WALLET_LOGIN_EXPIRED,
              returnTo: '/',
              retry: true,
            }),
            410
          );
      }
    }
  );

  fastify.withTypeProvider<ZodTypeProvider>().get(
    '/wallet-login/:handle/status',
    {
      schema: {
        description:
          'Polled by the wallet sign-in screen. Reports whether the direct_post presentation response has arrived, and completes the sign-in when it has. Issue #239.',
        tags: ['UI'],
        params: z.object({ handle: z.string() }),
        response: { 200: walletLoginStatusSchema },
      },
      config: {
        // Sized for polling; see WALLET_LOGIN_STATUS_RATE_LIMIT for why the
        // global default is the wrong shape here.
        rateLimit: {
          max: WALLET_LOGIN_STATUS_RATE_LIMIT,
          timeWindow: WALLET_LOGIN_STATUS_RATE_WINDOW_S * 1000,
          keyGenerator: (request) => request.ip || 'unknown',
        },
      },
    },
    async (request, reply) => {
      const { handle } = request.params as { handle: string };
      reply.header('Cache-Control', 'no-store');

      if (!isWalletLoginHandle(handle)) {
        return reply.send({ status: 'expired', message: WALLET_LOGIN_EXPIRED });
      }

      const outcome = await advanceWalletLoginFlow(fastify, request, reply, handle, {
        via: 'poll',
      });

      switch (outcome.status) {
        case 'complete':
          return reply.send({ status: 'complete', redirect_to: outcome.redirectTo });
        case 'pending':
          return reply.send({ status: 'pending' });
        case 'rejected':
          return reply.send({ status: 'rejected', message: WALLET_LOGIN_REFUSAL });
        default:
          return reply.send({ status: 'expired', message: WALLET_LOGIN_EXPIRED });
      }
    }
  );

  /**
   * The same-device RETURN LEG (#405, ADR-013 D5) — where a wallet on this
   * device brings the browser back, carrying the Response Code the Response
   * Endpoint handed it (OID4VP 1.0 §8.2, §13.3 step 7; HAIP 1.0 §5.1 "Wallets
   * MUST follow the redirect to redirect_uri").
   *
   * Registered as the literal `'/wallet-login/return'` (the docs-site
   * endpoint-coverage invariant reads route literals); static, so find-my-way
   * prefers it over `/wallet-login/:handle`. Same registration gate and the
   * same polling-shaped per-IP rate limit as the sibling GET routes. Every
   * response it sends is `Cache-Control: no-store` and `Referrer-Policy:
   * no-referrer`, set before any branch: the request URL carries a bearer
   * secret, and neither a cache nor a `Referer` on an outbound link may keep
   * it.
   *
   * ## Order: shape, BURN, then bind
   *
   * 1. Shape-check the code (`isOid4vpResponseCode`, exactly 43 base64url
   *    characters). Anything else → the refusal page, nothing touched. The
   *    querystring schema is `z.string().optional()` rather than a `.max()`
   *    at the edge, deliberately: a Zod 400 for an over-long or missing value
   *    would be a SECOND refusal shape, and this route has exactly one. A 400
   *    would leak nothing about the code's validity, but a route that answers
   *    one way to "too long" and another to "unknown" is a route whose
   *    refusals can be told apart, and the point of the shape guard is that
   *    they cannot. The regex is anchored and linear, so an over-long value
   *    costs one pass and no database round trip.
   * 2. `redeemResponseCode(sha256(code))` — ONE guarded `UPDATE` in the
   *    repository that SPENDS the code whatever happens next (its five
   *    predicates: digest, unspent, unexpired, row redeemed, `same_device`).
   *    `undefined` — unknown, expired, replayed, cross-device — → the refusal
   *    page. This runs BEFORE the browser is asked anything, and that order is
   *    the security property: a code that lands anywhere is dead everywhere.
   * 3. Read this browser's bindings from the binder cookie (at most three),
   *    read each flow, and select the one whose `stateHash` is the one the
   *    code named AND whose stored binder matches the cookie's, timing-safely.
   *    None → a FOREIGN LANDING: the wallet opened a different browser than
   *    the flow started in, an in-app browser with its own cookie jar, a
   *    private window, or an attacker replaying a code from a log. OID4VP
   *    §14.2 concedes the technique cannot serve that case ("the original
   *    session will also not be available there") and HAIP §5.1 says what to
   *    do: "reject presentations if […] the redirect back arrives in a
   *    different user session". So: `discardWalletPresentation` (the parked
   *    bytes go, the signal becomes `return_rejected`), a warning in the log,
   *    the refusal page. The burned code is the hard guarantee — the
   *    initiating flow is same-device, a same-device flow never completes by
   *    polling, and the one code that could have completed it is spent — and
   *    the discard is what lets that flow's poll say `rejected` promptly
   *    rather than at the deadline.
   * 4. Dispatch on `flow.mode`. `login` → the ONE state machine,
   *    `advanceWalletLoginFlow(…, { via: 'return' })`, which re-applies the
   *    binder, expiry and mode gates and completes the flow — session minted
   *    exactly as by polling, done-marker written, binding KEPT (D6/D8).
   *    `link` → {@link completeLinkModeReturn}: the browser session is
   *    re-resolved and compared with the user the flow was started by (a
   *    link flow was initiated in a USER session, so a return without one,
   *    or in another user's, is a foreign landing in HAIP §5.1's sense),
   *    then the link state machine, `advanceWalletLinkFlow(…, { via:
   *    'return' })`, applies its own mode, binder, same-user and expiry
   *    gates and links the credential — done-marker written, binding KEPT,
   *    as for login.
   *
   * ## Outcomes
   *
   * `complete` → 200, {@link walletSignedInPage}: "You're signed in", go back
   * to the tab where you started; `redirectTo` offered only as a secondary
   * link. NOT a redirect — the wallet opened this leg in a new tab, and the
   * original tab holds the OAuth client's `state` and PKCE verifier; it will
   * continue on its own once its poll consumes the marker. `rejected` (a
   * wallet-reported error on a same-device row — the Response Endpoint hands
   * out a `redirect_uri` on that path too, §8.2 "or for Error Responses" — or
   * an unresolvable presentation, or an unavailable user) → the EXISTING
   * refusal terminal page, `WALLET_LOGIN_REFUSAL`, 401, byte-for-byte what
   * the page GET renders for the same outcome — which is why it carries no
   * address-bar scrub: the code in the URL is spent, and the bytes stay
   * comparable (ADR-013 records the trade). The state machine left a
   * `rejected` marker for the original tab on that path, so both tabs say
   * the same thing. `expired` / `pending` (a flow that died between step 3
   * and the state machine; a signal write that had failed) → the refusal
   * page. The link arm's outcome table is on {@link completeLinkModeReturn}.
   *
   * ## One refusal page
   *
   * Steps 1–3 and the `expired`/`pending` arm of step 4 render ONE
   * byte-identical page ({@link walletReturnRefusalPage}): HTTP 200 (in-app
   * browsers decorate non-2xx navigations), no "Try again" (a new flow in the
   * wrong cookie jar is a trap), the password footer kept. The reason is
   * logged server-side only; NOTHING is audited on refusal — the Response
   * Endpoint audits nothing on its refusals either, and an audit row per
   * junk landing would be a write primitive for anyone with a URL; and no
   * request-supplied text is echoed — there is nothing to echo. The refusal
   * page and the completed pages carry a nonced `history.replaceState` that
   * scrubs the (already spent) code from the address bar; a browser without
   * scripts loses only that hygiene, and the 401/409 pages above forgo it
   * for byte-identity with their page-GET twins.
   */
  fastify.withTypeProvider<ZodTypeProvider>().get(
    '/wallet-login/return',
    {
      schema: {
        description: `Same-device return leg of a wallet sign-in (OID4VP 1.0 §8.2 / §14.2, HAIP 1.0 §5.1). The wallet redirects the browser here with the single-use Response Code (${MAX_OID4VP_RESPONSE_CODE_LENGTH} base64url characters) it received from the direct_post Response Endpoint; the code is spent first, then matched against the flows this browser holds, and the sign-in completes only in the browser that started it. Every refusal renders one identical page. Issue #405.`,
        tags: ['UI'],
        querystring: z.object({
          response_code: z.string().optional(),
        }),
      },
      config: {
        rateLimit: {
          max: WALLET_LOGIN_STATUS_RATE_LIMIT,
          timeWindow: WALLET_LOGIN_STATUS_RATE_WINDOW_S * 1000,
          keyGenerator: (request) => request.ip || 'unknown',
        },
      },
    },
    async (request, reply) => {
      reply.header('Cache-Control', 'no-store');
      reply.header('Referrer-Policy', 'no-referrer');

      const refusalPage = () =>
        walletReturnRefusalPage({
          cspNonce: reply.cspNonce.style,
          scriptNonce: reply.cspNonce.script,
          returnPath: WALLET_LOGIN_RETURN_PATH,
        });

      const { response_code: code } = request.query as { response_code?: string };

      // (1) Shape. Nothing has been looked up yet, and for a value that was not
      // minted here nothing will be.
      if (!isOid4vpResponseCode(code)) {
        fastify.log.warn({ ip: request.ip }, 'same-device return carried no well-formed code');
        return sendHtml(reply, refusalPage(), 200);
      }

      // (2) Burn. The code is spent by this statement whatever follows.
      const redeemed = await fastify.repositories.oid4vpRequestStates.redeemResponseCode(
        hashOid4vpResponseCode(code)
      );
      if (redeemed === undefined) {
        fastify.log.warn({ ip: request.ip }, 'same-device return code was not redeemable');
        return sendHtml(reply, refusalPage(), 200);
      }

      // (3) Bind. Among the flows THIS browser can prove it holds, the one the
      // code named — or nobody's.
      const candidate = await findReturningFlow(fastify, request, redeemed.stateHash);
      if (candidate === null) {
        await discardWalletPresentation(fastify, redeemed.stateHash);
        fastify.log.warn({ ip: request.ip }, 'same-device return arrived in a foreign session');
        return sendHtml(reply, refusalPage(), 200);
      }

      // (4) Dispatch on what the flow is FOR.
      if ((candidate.flow.mode ?? 'login') !== 'login') {
        return completeLinkModeReturn(fastify, request, reply, candidate, refusalPage());
      }

      const outcome = await advanceWalletLoginFlow(fastify, request, reply, candidate.handle, {
        via: 'return',
      });

      switch (outcome.status) {
        case 'complete':
          return sendHtml(
            reply,
            walletSignedInPage({
              cspNonce: reply.cspNonce.style,
              scriptNonce: reply.cspNonce.script,
              redirectTo: outcome.redirectTo,
              returnPath: WALLET_LOGIN_RETURN_PATH,
            }),
            200
          );
        case 'rejected':
          return sendHtml(
            reply,
            terminalPage({
              cspNonce: reply.cspNonce.style,
              title: 'Sign-in was not completed',
              message: WALLET_LOGIN_REFUSAL,
              returnTo: '/',
              retry: true,
            }),
            401
          );
        default:
          return sendHtml(reply, refusalPage(), 200);
      }
    }
  );
}

/**
 * Among the flows this browser holds a binding for, the one a spent Response
 * Code named — or null (#405, step 3 of the return route).
 *
 * The join runs from the browser's side: the binder cookie names at most three
 * handles, each flow is read, and a flow is the candidate only if its
 * `stateHash` is the one the code resolved to AND its stored binder matches the
 * cookie's copy. Both comparisons are timing-safe. The state hash is a public
 * digest and the row already proved it, but the two checks sit on one line and
 * a reader should not have to work out which of them is the secret; the binder
 * IS the secret, and it is compared the way the state machine compares it.
 *
 * Nothing here is written, and nothing here trusts the code beyond the one
 * value the repository returned for it. A browser holding several bindings can
 * only ever advance the flow that owns the code — consuming a code for a
 * sibling flow the same browser also started is exactly right.
 */
async function findReturningFlow(
  fastify: FastifyInstance,
  request: FastifyRequest,
  stateHash: string
): Promise<{ handle: string; flow: WalletLoginFlow } | null> {
  const bindings = readWalletFlowBindings(readCookie(request, WALLET_FLOW_COOKIE_NAME));

  for (const binding of bindings) {
    const flow = await readWalletLoginFlow(fastify, binding.handle);
    if (flow === null) continue;
    if (!csrfTokensEqual(flow.stateHash, stateHash)) continue;
    if (!csrfTokensEqual(flow.binder, binding.binder)) continue;
    return { handle: binding.handle, flow };
  }

  return null;
}

/**
 * The return leg for an account-LINKING flow (#405, ADR-013 D5 step 4, link
 * arm).
 *
 * Reached only after steps 1–3 of the return route: the code is spent, and
 * the flow it named is one THIS browser holds the binder for. What is left
 * is what the linking poll checks on every tick — a live session, and the
 * same user the flow was started by — and the link state machine applies
 * both, exactly as `routes/auth/link-wallet.ts` does, so the return leg is
 * not the one surface that skips them.
 *
 * ## The session gate is a foreign-landing gate
 *
 * A link flow is initiated in a USER session (`linkUserId`, from a verified
 * cookie), so a return that arrives with no session at all, or with a
 * session for a DIFFERENT user (the jar's session was replaced — a logout
 * and a login in another tab — while the wallet was open), is "a different
 * user session to the one the request was initiated in" — the case HAIP 1.0
 * §5.1 says the Verifier MUST reject — even though the browser holds the
 * binder. Both are treated as step 3 treats a foreign landing:
 * `discardWalletPresentation` (parked bytes gone, signal `return_rejected`),
 * a warning that says which, the refusal page. Nothing is audited, and the
 * state machine is not entered: it would refuse the mismatch too, but its
 * same-user gate answers `expired` without discarding anything —
 * indistinguishable from its other gates by design, the right answer for a
 * poll — and this leg's job is the active rejection: the parked bytes must
 * not stay addressable for the rest of their TTL, and the original tab (once
 * it is the right user again) must be told `rejected` on its next poll, not
 * left to the deadline. The user comparison is timing-safe, as the machine's
 * is. The spent code guarantees the presentation can never be linked either
 * way.
 *
 * ## Outcomes
 *
 * `linked` → 200, {@link walletLinkedPage} with the address-bar scrub: the
 * same sentence `/ui/wallet-link/:handle` renders, from the same builder,
 * plus the one script every page under this URL carries. A terminal page and
 * not a redirect, and per-tab safe by construction — a link flow's
 * `returnTo` is `/`, nothing in the original tab is waiting to continue, and
 * that tab's own poll renders the same page from the done-marker the state
 * machine left. `conflict` → 409, `rejected` → 401: the linking surface's
 * existing terminal pages, byte for byte what `/ui/wallet-link/:handle`
 * renders for the same outcomes — the browser DOES hold this flow, so their
 * "Try again" / "Back" affordances are safe here, and like the login arm's
 * 401 they carry no scrub so the bytes can be compared (the code in the
 * address bar is spent; ADR-013 records the trade). The state machine left
 * a marker for those two as well, so the original tab shows the same word.
 * `expired` / `pending` → the route's one refusal page, as for login.
 */
async function completeLinkModeReturn(
  fastify: FastifyInstance,
  request: FastifyRequest,
  reply: FastifyReply,
  candidate: { handle: string; flow: WalletLoginFlow },
  refusalPage: string
): Promise<FastifyReply> {
  const session = await resolveBrowserSession(fastify, request, reply);
  if (!session) {
    await discardWalletPresentation(fastify, candidate.flow.stateHash);
    fastify.log.warn(
      { ip: request.ip },
      'same-device return for a wallet LINK flow arrived without a session'
    );
    return sendHtml(reply, refusalPage, 200);
  }
  if (
    typeof candidate.flow.linkUserId !== 'string' ||
    !csrfTokensEqual(candidate.flow.linkUserId, session.userId)
  ) {
    await discardWalletPresentation(fastify, candidate.flow.stateHash);
    fastify.log.warn(
      { ip: request.ip },
      'same-device return for a wallet LINK flow arrived in a different user session'
    );
    return sendHtml(reply, refusalPage, 200);
  }

  const outcome = await advanceWalletLinkFlow(
    fastify,
    request,
    reply,
    candidate.handle,
    session.userId,
    { via: 'return' }
  );

  switch (outcome.status) {
    case 'linked':
      return sendHtml(
        reply,
        walletLinkedPage({
          cspNonce: reply.cspNonce.style,
          rebound: outcome.rebound,
          scrub: { scriptNonce: reply.cspNonce.script, returnPath: WALLET_LOGIN_RETURN_PATH },
        }),
        200
      );
    case 'conflict':
      return sendHtml(
        reply,
        walletLinkTerminalPage({
          cspNonce: reply.cspNonce.style,
          title: WALLET_LINK_CONFLICT_TITLE,
          message: WALLET_LINK_CONFLICT,
          retry: false,
        }),
        409
      );
    case 'rejected':
      return sendHtml(
        reply,
        walletLinkTerminalPage({
          cspNonce: reply.cspNonce.style,
          title: WALLET_LINK_REJECTED_TITLE,
          message: WALLET_LINK_REFUSAL,
          retry: true,
        }),
        401
      );
    default:
      return sendHtml(reply, refusalPage, 200);
  }
}

import { html, render, safe, type SafeHtml } from './html';

/**
 * Chrome shared by the wallet screens (issues #239, #238, #405).
 *
 * Extracted when account linking (#238) added a second wallet surface. Two
 * copies of a page style block drift within one release; two copies of a
 * terminal page drift in what they say a failure MEANS, which is worse — the
 * whole point of `WALLET_LOGIN_REFUSAL` and `WALLET_LINK_REFUSAL` is that a user
 * sees one sentence for every failure, and that guarantee is per-surface only if
 * both surfaces render it the same way.
 *
 * The same-device return leg (#405) adds two pages with the same discipline:
 * {@link walletReturnRefusalPage}, the ONE page every refusal on
 * `/ui/wallet-login/return` renders, and {@link walletSignedInPage}. They live
 * here rather than in the login route because the return route serves BOTH
 * wallet surfaces — a link flow's redirect lands on the same path — and a
 * refusal that differed by a byte between the two modes would tell a landing
 * which kind of flow its spent code had named.
 *
 * The same leg is why the LINKING terminal pages moved here too
 * ({@link walletLinkTerminalPage}, {@link walletLinkedPage}): a link flow
 * started on this device ends on the return route, and the outcome it renders
 * there must be the outcome `/ui/wallet-link/:handle` renders — one copy, one
 * markup, so the user reads the same sentence whichever tab the wallet
 * happened to open.
 *
 * This module imports nothing that reads `env`, on purpose: it is loaded by
 * every wallet route and by tests that stub the environment, and a page builder
 * has no business depending on configuration. Anything a page needs from the
 * deployment is passed in.
 *
 * The markup is unchanged from the wallet-login screens it came out of.
 */

/** Shared page chrome, so the wallet screens cannot drift apart visually. */
export function walletPageStyles(cspNonce: string): SafeHtml {
  return html`<style nonce="${cspNonce}">
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
      margin: 0 0 12px;
      font-size: 14px;
      line-height: 1.5;
      color: #374151;
    }
    label {
      display: block;
      margin-top: 16px;
      font-size: 13px;
      font-weight: 600;
    }
    input[type='text'] {
      display: block;
      width: 100%;
      padding: 10px 12px;
      margin-top: 6px;
      border: 1px solid #d8dbe0;
      border-radius: 6px;
      font-size: 14px;
      box-sizing: border-box;
    }
    .hint {
      margin-top: 6px;
      font-size: 12px;
      color: #6b7280;
    }
    button {
      margin-top: 24px;
      width: 100%;
      padding: 10px;
      border: 0;
      border-radius: 6px;
      background: #2a5bd7;
      color: #fff;
      font-weight: 600;
      font-size: 14px;
      cursor: pointer;
    }
    button.secondary {
      margin-top: 12px;
      border: 1px solid #2a5bd7;
      background: #fff;
      color: #2a5bd7;
    }
    .error {
      background: #fdecea;
      color: #a1261b;
      padding: 10px 12px;
      border-radius: 6px;
      font-size: 13px;
      margin-bottom: 16px;
    }
    .status {
      background: #eef2ff;
      color: #27337a;
      padding: 10px 12px;
      border-radius: 6px;
      font-size: 13px;
      margin-top: 16px;
    }
    .qr {
      width: 240px;
      max-width: 100%;
      margin: 20px auto;
      border: 1px solid #e5e7eb;
      border-radius: 8px;
      padding: 8px;
      background: #fff;
    }
    .alt-action {
      display: block;
      width: 100%;
      padding: 10px;
      border: 1px solid #2a5bd7;
      border-radius: 6px;
      background: #fff;
      color: #2a5bd7;
      font-weight: 600;
      font-size: 14px;
      text-align: center;
      text-decoration: none;
      box-sizing: border-box;
      margin-top: 16px;
    }
    .footer-link {
      display: block;
      margin-top: 20px;
      font-size: 13px;
      text-align: center;
    }
  </style>`;
}

/**
 * Where a page rendered under the return route's URL asks for the Response
 * Code to be scrubbed from the address bar (#405). See
 * {@link scrubResponseCodeScript} for what the script does and why it is
 * hygiene rather than a control. Optional on the builders that serve both a
 * plain surface and the return leg: when absent, not a byte of the page
 * changes, which is what lets the two surfaces be compared byte for byte.
 */
export interface ResponseCodeScrub {
  scriptNonce: string;
  /** The return route's own path, for the address-bar rewrite. */
  returnPath: string;
}

/** A terminal state: expired, refused, linked, or not available. */
export function walletTerminalPage(opts: {
  cspNonce: string;
  title: string;
  message: string;
  returnTo: string;
  retry: boolean;
  /** Where "Try again" goes. Defaults to the wallet LOGIN entry point. */
  retryHref?: string;
  /** The bottom link. Defaults to the password sign-in entry point. */
  footer?: { href: string; label: string };
  /** Present only when rendered under the return route's URL (#405). */
  scrub?: ResponseCodeScrub;
}): string {
  const { cspNonce, title, message, returnTo, retry, retryHref, footer, scrub } = opts;
  const retryTarget = retryHref ?? `/ui/wallet-login?return_to=${encodeURIComponent(returnTo)}`;
  const footerHref = footer?.href ?? `/ui/login?return_to=${encodeURIComponent(returnTo)}`;
  const footerLabel = footer?.label ?? 'Sign in with a password';

  return render(
    html`<!doctype html>
      <html lang="en">
        <head>
          <meta charset="utf-8" />
          <meta name="viewport" content="width=device-width,initial-scale=1" />
          <meta name="robots" content="noindex" />
          <title>${title} — QAuth</title>
          ${walletPageStyles(cspNonce)}
        </head>
        <body>
          <div class="card">
            <h1>${title}</h1>
            <p role="alert">${message}</p>
            ${retry ? html`<a class="alt-action" href="${retryTarget}">Try again</a>` : ''}
            <a class="footer-link" href="${footerHref}">${footerLabel}</a>
          </div>
          ${scrub === undefined ? '' : scrubResponseCodeScript(scrub.scriptNonce, scrub.returnPath)}
        </body>
      </html>`
  );
}

/**
 * The terminal screen every account-LINKING outcome renders (#238), with the
 * linking surface's own chrome: "Try again" starts a new link rather than a
 * new login, and the footer goes back rather than to the password form —
 * the user is signed in already.
 *
 * Moved out of `routes/ui/wallet-link.ts` for #405 so the return route can
 * render the same outcomes; see the module JSDoc. `returnTo` is fixed at `/`
 * because a link flow has no OAuth continuation to carry.
 */
export function walletLinkTerminalPage(opts: {
  cspNonce: string;
  title: string;
  message: string;
  retry: boolean;
  /** Present only when rendered under the return route's URL (#405). */
  scrub?: ResponseCodeScrub;
}): string {
  return walletTerminalPage({
    cspNonce: opts.cspNonce,
    title: opts.title,
    message: opts.message,
    returnTo: '/',
    retry: opts.retry,
    retryHref: '/ui/wallet-link',
    footer: { href: '/', label: 'Back' },
    ...(opts.scrub === undefined ? {} : { scrub: opts.scrub }),
  });
}

/**
 * Copy of the linking outcomes the two linking surfaces share (#238, #405).
 *
 * Exported so the route tests can pin the bytes rather than a phrase, and so
 * `/ui/wallet-link/:handle` and the return route render the SAME sentence for
 * the same outcome. The refusal and conflict sentences stay with the flow
 * helper (`WALLET_LINK_REFUSAL`, `WALLET_LINK_CONFLICT`) because the JSON API
 * sends them too; only the titles the HTML surfaces put over them live here.
 */
export const WALLET_LINKED_TITLE = 'Wallet credential linked';
export const WALLET_LINKED =
  'Your wallet credential is now linked to this account. You can sign in with either.';
export const WALLET_LINK_REBOUND =
  'Your wallet credential was updated. You can sign in with it or with your password.';
export const WALLET_LINK_CONFLICT_TITLE = 'Already linked elsewhere';
export const WALLET_LINK_REJECTED_TITLE = 'Linking was not completed';
export const WALLET_LINK_EXPIRED_TITLE = 'Linking request expired';

/**
 * The page a completed link renders — on the link page's own poll and, for a
 * same-device link, on the return leg (#405).
 *
 * `rebound` picks the sentence: a credential that was already linked to THIS
 * account and has been re-keyed reads differently from a first link. No
 * "Try again": there is nothing to retry. A terminal page rather than a
 * redirect on both surfaces, and that is per-tab safe by construction — a
 * link flow's `returnTo` is `/`, so nothing in the original tab is waiting to
 * continue; that tab's own poll will render this same page from the
 * done-marker.
 */
export function walletLinkedPage(opts: {
  cspNonce: string;
  rebound: boolean;
  /** Present only when rendered under the return route's URL (#405). */
  scrub?: ResponseCodeScrub;
}): string {
  return walletLinkTerminalPage({
    cspNonce: opts.cspNonce,
    title: WALLET_LINKED_TITLE,
    message: opts.rebound ? WALLET_LINK_REBOUND : WALLET_LINKED,
    retry: false,
    ...(opts.scrub === undefined ? {} : { scrub: opts.scrub }),
  });
}

/**
 * Copy of the one refusal the same-device return leg renders (#405).
 *
 * Exported so a test can pin the bytes rather than a phrase, and so the two
 * modes that share the route render it from one string. Written for the
 * cases it must serve at once, with nothing that distinguishes them: a
 * cross-device phone that a conformant wallet sent here anyway (benign — the
 * other device is finishing), a garbage or replayed code, and a same-device
 * return the wallet opened in a different browser than the flow started in
 * (SFSafariViewController, a Custom Tab, a non-default browser). The last is
 * the case HAIP 1.0 §5.1 says the Verifier MUST reject, and OID4VP 1.0 §14.2
 * concedes the technique cannot serve; the copy says so plainly and sends the
 * user back to where they started, because a new flow begun in the wrong
 * cookie jar is a trap — which is also why the page offers no "Try again".
 */
export const WALLET_RETURN_REFUSAL_TITLE = 'Finish signing in where you started';
export const WALLET_RETURN_REFUSAL =
  "This browser doesn't hold the sign-in you began, so it can't finish it here. If your wallet opened a different browser than the one you started in, that sign-in can't be completed — go back to where you started and try again, making sure your wallet returns you to the same browser.";

/** Copy of the return leg's completed page (#405). See {@link walletSignedInPage}. */
export const WALLET_SIGNED_IN_TITLE = "You're signed in";
export const WALLET_SIGNED_IN =
  "Go back to the tab or window where you started — it's continuing there on its own.";

/**
 * The inline script both return-leg pages carry: scrub the Response Code from
 * the address bar (#405).
 *
 * The code rides in the query string (OID4VP 1.0 §8.2 permits it; a fragment
 * would make the landing JS-only, and every wallet page here has a noscript
 * twin), so once the page has rendered it is sitting in the URL bar and in
 * this tab's history entry. `history.replaceState` rewrites the entry to the
 * bare path without a navigation. By the time this runs the code has already
 * been SPENT — every path that renders either page consumed it first — so the
 * scrub is hygiene against shoulder-surfing and a "copy link" reflex, not a
 * control, and a browser with scripts disabled loses nothing that matters.
 * Nonced like the poller on the pending page, so it runs under the page's CSP.
 *
 * `returnPath` is passed in rather than imported: the constant that names the
 * path (`WALLET_LOGIN_RETURN_PATH`) lives beside the other wallet-facing URLs in
 * a module that reads `env`, and this one must not.
 */
function scrubResponseCodeScript(scriptNonce: string, returnPath: string): SafeHtml {
  return html`<script nonce="${scriptNonce}">
    history.replaceState(null, '', ${safe(JSON.stringify(returnPath))});
  </script>`;
}

/**
 * The ONE page every refusal on `/ui/wallet-login/return` renders (#405).
 *
 * Byte-identical for a malformed code, an unknown one, an expired one, a
 * replayed one, a code whose flow this browser does not hold, a link-mode
 * flow whose browser has no session (or another user's), and a return the
 * state machine could not advance: the reason is logged server-side and
 * nothing about it reaches the page. (A link-mode code in a browser that
 * holds the flow AND the same user's session completes, on the linking
 * surface's own page.) HTTP
 * 200, decided by the caller rather than here, because in-app browsers
 * decorate non-2xx navigations with their own chrome; the status carries no
 * information the body does not. No "Try again" (`walletTerminalPage`'s
 * `retry`), since a new flow started in the wrong cookie jar is exactly the
 * mistake the copy is steering the user away from; the password sign-in
 * footer is kept, as every wallet terminal page keeps it. Nothing supplied by
 * the request is rendered — there is no parameter to echo.
 *
 * @param opts.returnPath - the route's own path, for the address-bar scrub.
 */
export function walletReturnRefusalPage(opts: {
  cspNonce: string;
  scriptNonce: string;
  returnPath: string;
}): string {
  const { cspNonce, scriptNonce, returnPath } = opts;

  return render(
    html`<!doctype html>
      <html lang="en">
        <head>
          <meta charset="utf-8" />
          <meta name="viewport" content="width=device-width,initial-scale=1" />
          <meta name="robots" content="noindex" />
          <title>${WALLET_RETURN_REFUSAL_TITLE} — QAuth</title>
          ${walletPageStyles(cspNonce)}
        </head>
        <body>
          <div class="card">
            <h1>${WALLET_RETURN_REFUSAL_TITLE}</h1>
            <p role="alert">${WALLET_RETURN_REFUSAL}</p>
            <a class="footer-link" href="/ui/login?return_to=%2F">Sign in with a password</a>
          </div>
          ${scrubResponseCodeScript(scriptNonce, returnPath)}
        </body>
      </html>`
  );
}

/**
 * The page a completed same-device return leg renders (#405, ADR-013 D6).
 *
 * A terminal page, deliberately NOT a redirect to `redirectTo`. Wallets open
 * the `redirect_uri` in a new tab; the tab that started the flow is the one
 * whose `sessionStorage` holds the OAuth client's `state` and PKCE verifier,
 * and it is polling. So the leg that completes the sign-in tells the user to
 * go back — the original tab continues on its own once its poll consumes the
 * done-marker — and offers `redirectTo` only as a secondary link for the case
 * where that tab is gone. Redirecting here would land a server-side client on
 * two authorization codes for one login and an SPA client on a "state
 * mismatch" error in the tab the user is looking at.
 *
 * `redirectTo` is the flow's `returnTo`, validated by `isSafeReturnTo` when the
 * flow was created and read back from the flow record — never from the
 * request. It is rendered from memory: the flow is already terminated.
 *
 * @param opts.redirectTo - the flow's validated `returnTo`.
 * @param opts.returnPath - the route's own path, for the address-bar scrub.
 */
export function walletSignedInPage(opts: {
  cspNonce: string;
  scriptNonce: string;
  redirectTo: string;
  returnPath: string;
}): string {
  const { cspNonce, scriptNonce, redirectTo, returnPath } = opts;

  return render(
    html`<!doctype html>
      <html lang="en">
        <head>
          <meta charset="utf-8" />
          <meta name="viewport" content="width=device-width,initial-scale=1" />
          <meta name="robots" content="noindex" />
          <title>${WALLET_SIGNED_IN_TITLE} — QAuth</title>
          ${walletPageStyles(cspNonce)}
        </head>
        <body>
          <div class="card">
            <h1>${WALLET_SIGNED_IN_TITLE}</h1>
            <p role="status">${WALLET_SIGNED_IN}</p>
            <a class="alt-action" href="${redirectTo}">Continue here instead</a>
          </div>
          ${scrubResponseCodeScript(scriptNonce, returnPath)}
        </body>
      </html>`
  );
}

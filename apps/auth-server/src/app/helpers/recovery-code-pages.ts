import { html, render, type SafeHtml } from './html';
import { walletPageStyles } from './wallet-ui';

/**
 * THE RECOVERY CODES' PAGES (#649; ADR-017 Decision 8), server-rendered in
 * the current `/ui` style, as `/ui/login` is: each works without JavaScript.
 * The design-system screens of #650 replace them.
 *
 * - "Save your recovery codes" (the `recovery_codes` step): the ten codes,
 *   shown once, and a confirmation that they are saved, which the step
 *   needs before it ends.
 * - "Use a recovery code" (the `recovery_code` step): one field, with the
 *   wrong-code error when the last answer was refused.
 *
 * Both post to the Interaction API's answer endpoint as a plain form: the
 * step's URN, its CSRF value and the answer. Neither puts a code in a URL;
 * the route sends both with `Cache-Control: no-store`.
 */

/**
 * The page's chrome: the shared `/ui` stylesheet (#472), and the page's own
 * rules under the request's CSP nonce.
 */
function page(opts: {
  readonly cspNonce: string;
  readonly title: string;
  readonly body: SafeHtml;
}): string {
  return render(
    html`<!doctype html>
      <html lang="en">
        <head>
          <meta charset="utf-8" />
          <meta name="viewport" content="width=device-width,initial-scale=1" />
          <meta name="robots" content="noindex" />
          <meta name="referrer" content="no-referrer" />
          <title>${opts.title} — QAuth</title>
          ${walletPageStyles(opts.cspNonce)}
          <style nonce="${opts.cspNonce}">
            .codes {
              columns: 2;
              column-gap: 1.5rem;
              padding-left: 2rem;
              font-family: var(--font-mono);
            }
            .codes li {
              padding: 0.125rem 0;
              break-inside: avoid;
            }
            .codes code {
              padding: 0;
              background-color: transparent;
              white-space: nowrap;
            }
            @media (max-width: 30rem) {
              .codes {
                columns: 1;
              }
            }
            .confirm {
              display: flex;
              gap: 0.5rem;
              align-items: flex-start;
              margin: 1rem 0;
              font-weight: var(--font-weight-regular);
            }
            .confirm input {
              margin-top: 0.125rem;
            }
          </style>
        </head>
        <body>
          <main class="card">${opts.body}</main>
        </body>
      </html>`
  );
}

/** What every form of these pages posts beside its answer. */
interface StepForm {
  /** The Interaction API's answer endpoint of the interaction, on the realm's origin. */
  readonly action: string;
  /** The step's URN, the answer's `type`. */
  readonly type: string;
  /** The step view's CSRF value. */
  readonly csrf: string;
}

function hiddenFields(form: StepForm): SafeHtml {
  return html`<input type="hidden" name="type" value="${form.type}" />
    <input type="hidden" name="csrf" value="${form.csrf}" />`;
}

/** The "save your recovery codes" page's title. */
export const RECOVERY_CODES_TITLE = 'Save your recovery codes';

/**
 * "Save your recovery codes": the set, shown once, and the confirmation the
 * step needs (`acknowledged=true`).
 */
export function recoveryCodesPage(
  opts: StepForm & { readonly cspNonce: string; readonly codes: readonly string[] }
): string {
  const { cspNonce, codes } = opts;
  return page({
    cspNonce,
    title: RECOVERY_CODES_TITLE,
    body: html`<h1>${RECOVERY_CODES_TITLE}</h1>
      <p>
        If you lose your second factor, one of these codes signs you in in its place, after your
        password. Each code works once. Keep them somewhere safe, apart from your devices: they are
        not shown again.
      </p>
      <ol class="codes">
        ${codes.map((code) => html`<li><code>${code}</code></li>`)}
      </ol>
      <form method="post" action="${opts.action}">
        ${hiddenFields(opts)}
        <label class="confirm">
          <input type="checkbox" name="acknowledged" value="true" required />
          <span>I have saved these codes</span>
        </label>
        <button type="submit">Continue</button>
      </form>`,
  });
}

/** The "use a recovery code" page's title. */
export const RECOVERY_CODE_TITLE = 'Use a recovery code';

/** The wrong-code error: the same for a wrong code, a used one and one of another set. */
export const RECOVERY_CODE_REFUSED =
  'That code did not work. Check it, or try another of your codes.';

/** "Use a recovery code": one field, and the error of a refused answer. */
export function recoveryCodePage(
  opts: StepForm & { readonly cspNonce: string; readonly refused: boolean }
): string {
  const { cspNonce, refused } = opts;
  return page({
    cspNonce,
    title: RECOVERY_CODE_TITLE,
    body: html`<h1>${RECOVERY_CODE_TITLE}</h1>
      <p>
        Enter one of the recovery codes you saved, in place of your second factor. It looks like
        <code>abcd-efgh-ijkl-mnop</code>; case, spaces and dashes do not matter. Each code works
        once.
      </p>
      ${refused ? html`<p class="error" role="alert">${RECOVERY_CODE_REFUSED}</p>` : ''}
      <form method="post" action="${opts.action}">
        ${hiddenFields(opts)}
        <label for="recovery_code">Recovery code</label>
        <input
          id="recovery_code"
          name="recovery_code"
          type="text"
          required
          minlength="16"
          maxlength="39"
          autocomplete="one-time-code"
          autocapitalize="none"
          spellcheck="false"
          ${refused ? html`aria-invalid="true"` : ''}
        />
        <button type="submit">Continue</button>
      </form>`,
  });
}

/** The page of an interaction that is unknown, expired or finished. */
export const RECOVERY_PAGE_EXPIRED_TITLE = 'This sign-in has ended';

/** The page of an interaction that is unknown, expired or finished: start again at the app. */
export function recoveryPageExpired(opts: { readonly cspNonce: string }): string {
  return page({
    cspNonce: opts.cspNonce,
    title: RECOVERY_PAGE_EXPIRED_TITLE,
    body: html`<h1>${RECOVERY_PAGE_EXPIRED_TITLE}</h1>
      <p role="alert">
        This sign-in expired or is already finished. Go back to the application and sign in again.
      </p>`,
  });
}

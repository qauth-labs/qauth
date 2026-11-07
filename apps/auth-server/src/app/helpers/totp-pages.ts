import { html, render, safe, type SafeHtml } from './html';
import { encodeQrCode, renderQrCodeSvg } from './qr-code';
import { walletPageStyles } from './wallet-ui';

/**
 * THE AUTHENTICATOR APP'S PAGES (#653; ADR-017 Decisions 7 and 8, ADR-020
 * §3), server-rendered in the current `/ui` style, as `/ui/login` is: each
 * works without JavaScript. The design-system screens of #654 replace them.
 *
 * - "Enter the code from your authenticator app" (the `totp` step): one
 *   six-digit field, the wrong-code error when the last answer was refused,
 *   and, when the step offers it, a recovery code in its place.
 * - "Set up an authenticator app" (the `totp_setup` step): the secret as a
 *   QR code of its `otpauth://` URI and as text, and the field for the first
 *   code, which binds the secret.
 *
 * Both post to the Interaction API's answer endpoint as a plain form: the
 * step's URN, its CSRF value and the answer. Neither puts the secret or a
 * code in a URL; the route sends both with `Cache-Control: no-store`.
 */

/** The page's chrome: the shared `/ui` styles under the request's CSP nonce. */
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
            .secret {
              font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
              font-size: 1.05rem;
              letter-spacing: 0.05em;
              word-break: break-all;
            }
            details {
              margin-top: 1.5rem;
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

/** The six-digit field both steps answer with. */
function codeField(refused: boolean): SafeHtml {
  return html`<label for="otp">Code</label>
    <input
      id="otp"
      name="otp"
      type="text"
      required
      inputmode="numeric"
      pattern="[0-9]{6}"
      minlength="6"
      maxlength="6"
      autocomplete="one-time-code"
      ${refused ? html`aria-invalid="true"` : ''}
    />`;
}

/** The wrong-code error of both steps: the same for a wrong code, a used one and a late one. */
export const TOTP_REFUSED =
  'That code did not work. Enter the code your authenticator app shows now.';

/** The "enter the code" page's title. */
export const TOTP_TITLE = 'Enter the code from your authenticator app';

/**
 * "Enter the code from your authenticator app": one field, the error of a
 * refused answer and, when the step offers it, a recovery code in its place
 * (the step's `recovery_code` alternative, answered at the same endpoint).
 */
export function totpPage(
  opts: StepForm & {
    readonly cspNonce: string;
    readonly refused: boolean;
    /** The recovery-code alternative's form, when the step offers one. */
    readonly recoveryCode?: StepForm;
  }
): string {
  const { cspNonce, refused, recoveryCode } = opts;
  return page({
    cspNonce,
    title: TOTP_TITLE,
    body: html`<h1>${TOTP_TITLE}</h1>
      <p>
        Open the authenticator app you set up for this account and enter the six-digit code it
        shows.
      </p>
      ${refused ? html`<p class="error" role="alert">${TOTP_REFUSED}</p>` : ''}
      <form method="post" action="${opts.action}">
        ${hiddenFields(opts)} ${codeField(refused)}
        <button type="submit">Continue</button>
      </form>
      ${
        recoveryCode === undefined
          ? ''
          : html`<details>
              <summary>Use a recovery code instead</summary>
              <form method="post" action="${recoveryCode.action}">
                ${hiddenFields(recoveryCode)}
                <label for="recovery_code">Recovery code</label>
                <input
                  id="recovery_code"
                  name="recovery_code"
                  type="text"
                  required
                  minlength="16"
                  maxlength="39"
                  autocomplete="off"
                  autocapitalize="none"
                  spellcheck="false"
                />
                <button type="submit">Continue</button>
              </form>
            </details>`
      }`,
  });
}

/** The set-up page's title. */
export const TOTP_SETUP_TITLE = 'Set up an authenticator app';

/** The secret in groups of four, as an authenticator app's manual entry reads it. */
export function groupedSecret(secret: string): string {
  return secret.replace(/(.{4})(?=.)/g, '$1 ');
}

/**
 * "Set up an authenticator app": the secret as a QR code and as text, and the
 * field for the first code. The secret is bound only once that code is valid.
 */
export function totpSetupPage(
  opts: StepForm & {
    readonly cspNonce: string;
    readonly refused: boolean;
    /** The secret, unpadded base32. */
    readonly secret: string;
    /** The same secret as an `otpauth://totp/` URI, which the QR code holds. */
    readonly otpauthUri: string;
  }
): string {
  const { cspNonce, refused } = opts;
  const qr = encodeQrCode(opts.otpauthUri);
  return page({
    cspNonce,
    title: TOTP_SETUP_TITLE,
    body: html`<h1>${TOTP_SETUP_TITLE}</h1>
      <p>
        This account needs a second factor. Scan this code with an authenticator app on your phone,
        or enter the key below in it by hand, then enter the six-digit code the app shows.
      </p>
      ${
        qr === undefined
          ? ''
          : html`<div class="qr">
              ${safe(renderQrCodeSvg(qr, 'QR code containing the authenticator app key'))}
            </div>`
      }
      <p>Key: <code class="secret">${groupedSecret(opts.secret)}</code></p>
      <p class="hint">Time-based, six digits, every 30 seconds. Do not share this key.</p>
      ${refused ? html`<p class="error" role="alert">${TOTP_REFUSED}</p>` : ''}
      <form method="post" action="${opts.action}">
        ${hiddenFields(opts)} ${codeField(refused)}
        <button type="submit">Continue</button>
      </form>`,
  });
}

import { html, render, type SafeHtml } from './html';
import { walletPageStyles } from './wallet-ui';

/**
 * THE PASSKEY PAGES (#651; ADR-017 Decisions 4 and 10), server-rendered in
 * the current `/ui` style, as `/ui/login` and the recovery codes' pages are.
 * The design-system screens of #652 replace them.
 *
 * - "Sign in with a passkey" (the `webauthn_get` step, current or offered
 *   beside the password): one button that runs the browser's passkey
 *   ceremony with the step's request options, which name no account.
 * - "Add a passkey" (the `webauthn_create` step, offered after a sign-in):
 *   one button that runs the registration ceremony with the step's creation
 *   options and the account's user entity, and "Not now", which declines.
 *
 * The ceremony needs JavaScript: one inline script, under the request's CSP
 * script nonce, reads the options from the form's `data-options` attribute
 * (escaped like every value of these pages), calls
 * `navigator.credentials.get()` or `.create()` and posts the result,
 * `PublicKeyCredential.toJSON()` as a JSON string, to the Interaction API's
 * answer endpoint as a plain form: the step's URN, its CSRF value and
 * `webauthn_response`. Nothing goes in a URL; the routes send every page with
 * `Cache-Control: no-store`.
 */

/** The page's chrome: the shared `/ui` stylesheet (#472). */
function page(opts: {
  readonly cspNonce: string;
  readonly scriptNonce: string;
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
        </head>
        <body>
          <main class="card">${opts.body}</main>
          ${ceremonyScript(opts.scriptNonce)}
        </body>
      </html>`
  );
}

/**
 * The ceremony: run on the button, post the credential's JSON. The button is
 * disabled until the script finds the WebAuthn JSON helpers, so a browser
 * without them, or without JavaScript, never posts an empty answer.
 */
function ceremonyScript(scriptNonce: string): SafeHtml {
  return html`<script nonce="${scriptNonce}">
    (function () {
      var form = document.getElementById('passkey-form');
      var start = document.getElementById('passkey-start');
      var status = document.getElementById('passkey-status');
      if (!form || !start || !status) return;
      var create = form.getAttribute('data-mode') === 'create';
      var parse =
        window.PublicKeyCredential &&
        PublicKeyCredential[
          create ? 'parseCreationOptionsFromJSON' : 'parseRequestOptionsFromJSON'
        ];
      if (typeof parse !== 'function' || !navigator.credentials) {
        status.textContent = 'This browser cannot use a passkey here.';
        return;
      }
      start.disabled = false;
      start.addEventListener('click', function () {
        start.disabled = true;
        status.textContent = '';
        var publicKey = parse.call(
          PublicKeyCredential,
          JSON.parse(form.getAttribute('data-options'))
        );
        var ceremony = create
          ? navigator.credentials.create({ publicKey: publicKey })
          : navigator.credentials.get({ publicKey: publicKey });
        ceremony
          .then(function (credential) {
            if (!credential) throw new Error('no credential');
            form.elements.namedItem('webauthn_response').value = JSON.stringify(
              credential.toJSON()
            );
            form.submit();
          })
          .catch(function () {
            start.disabled = false;
            status.textContent = 'The passkey was not used. You can try again.';
          });
      });
    })();
  </script>`;
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

/** What both pages render with. */
interface PasskeyPageOptions extends StepForm {
  readonly cspNonce: string;
  readonly scriptNonce: string;
  /** Whether the last answer to the step was refused. */
  readonly refused: boolean;
  /** The WebAuthn options the ceremony runs with, in their JSON form (§5.1). */
  readonly options: Readonly<Record<string, unknown>>;
}

function hiddenFields(form: StepForm): SafeHtml {
  return html`<input type="hidden" name="type" value="${form.type}" />
    <input type="hidden" name="csrf" value="${form.csrf}" />`;
}

/** The form that runs the ceremony and posts its result. */
function ceremonyForm(
  opts: PasskeyPageOptions & { readonly mode: 'get' | 'create'; readonly label: string }
): SafeHtml {
  return html`<form
      id="passkey-form"
      method="post"
      action="${opts.action}"
      data-mode="${opts.mode}"
      data-options="${JSON.stringify(opts.options)}"
    >
      ${hiddenFields(opts)}
      <input type="hidden" name="webauthn_response" value="" />
      <button id="passkey-start" type="button" disabled>${opts.label}</button>
    </form>
    <p id="passkey-status" role="status" aria-live="polite"></p>
    <noscript><p class="error">A passkey needs JavaScript in this browser.</p></noscript>`;
}

/** The "sign in with a passkey" page's title. */
export const PASSKEY_SIGN_IN_TITLE = 'Sign in with a passkey';

/** The refused-passkey error: the same whatever was wrong, and whoever's passkey it was. */
export const PASSKEY_REFUSED = 'That passkey did not work. Try again, or use another passkey.';

/** The link back to the interaction's other ways in. */
export const PASSKEY_OTHER_WAY = 'Sign in another way';

/**
 * "Sign in with a passkey": the ceremony, the error of a refused answer, and
 * a link back to the interaction's ceremony page, where the password and the
 * identifier the engine offers beside the passkey are, for a person with no
 * usable passkey or a browser that cannot run the ceremony.
 */
export function passkeySignInPage(
  opts: PasskeyPageOptions & {
    /** The interaction's ceremony page, on the realm's origin. */
    readonly otherWay: string;
  }
): string {
  return page({
    cspNonce: opts.cspNonce,
    scriptNonce: opts.scriptNonce,
    title: PASSKEY_SIGN_IN_TITLE,
    body: html`<h1>${PASSKEY_SIGN_IN_TITLE}</h1>
      <p>
        Use the passkey saved on this device, a phone or a security key. Your device asks you to
        unlock it with your fingerprint, face, PIN or screen lock.
      </p>
      ${opts.refused ? html`<p class="error" role="alert">${PASSKEY_REFUSED}</p>` : ''}
      ${ceremonyForm({ ...opts, mode: 'get', label: 'Use a passkey' })}
      <p><a href="${opts.otherWay}">${PASSKEY_OTHER_WAY}</a></p>`,
  });
}

/** The "add a passkey" page's title. */
export const PASSKEY_ENROLMENT_TITLE = 'Add a passkey';

/** The refused-registration error. */
export const PASSKEY_ENROLMENT_REFUSED =
  'The passkey could not be added. Try again, or choose "Not now".';

/** The "create your account with a passkey" page's title (#655). */
export const PASSKEY_REGISTRATION_TITLE = 'Create your account with a passkey';

/** The refused-registration error of a registration by passkey (#655). */
export const PASSKEY_REGISTRATION_REFUSED =
  'The passkey could not be created. Try again, or use an email address instead.';

/** The link from a registration by passkey to the address step (#655). */
export const PASSKEY_REGISTRATION_OTHER_WAY = 'Use an email address instead';

/** The "add a new passkey" page's title, after a recovery code (#655). */
export const PASSKEY_REBIND_TITLE = 'Add a new passkey';

/** The refused error of the new passkey after a recovery code (#655). */
export const PASSKEY_REBIND_REFUSED = 'The passkey could not be added. Try again.';

/**
 * "Add a passkey": the ceremony, and "Not now", which declines the offer.
 * With `purpose` `register`, the registration of an account by passkey alone
 * (#655), with a link to the address step; with `rebind`, the new passkey a
 * recovery code binds in place of a lost one, which cannot be declined.
 */
export function passkeyEnrolmentPage(
  opts: PasskeyPageOptions & {
    /** Whether the person may decline: the step's `optional`. */
    readonly optional: boolean;
    /** What the passkey is for: the offer after a sign-in by default. */
    readonly purpose?: 'enrol' | 'register' | 'rebind';
    /** The interaction's ceremony page, for a registration's other way. */
    readonly otherWay?: string;
  }
): string {
  if (opts.purpose === 'register') {
    return page({
      cspNonce: opts.cspNonce,
      scriptNonce: opts.scriptNonce,
      title: PASSKEY_REGISTRATION_TITLE,
      body: html`<h1>${PASSKEY_REGISTRATION_TITLE}</h1>
        <p>
          Your device saves a passkey for this account and asks for your fingerprint, face, PIN or
          screen lock. You sign in with it, with no email address and no password. You then get
          recovery codes to keep: they are the only way back in if you lose the passkey.
        </p>
        ${
          opts.refused
            ? html`<p class="error" role="alert">${PASSKEY_REGISTRATION_REFUSED}</p>`
            : ''
        }
        ${ceremonyForm({ ...opts, mode: 'create', label: 'Create a passkey' })}
        ${
          opts.otherWay === undefined
            ? ''
            : html`<p><a href="${opts.otherWay}">${PASSKEY_REGISTRATION_OTHER_WAY}</a></p>`
        }`,
    });
  }
  if (opts.purpose === 'rebind') {
    return page({
      cspNonce: opts.cspNonce,
      scriptNonce: opts.scriptNonce,
      title: PASSKEY_REBIND_TITLE,
      body: html`<h1>${PASSKEY_REBIND_TITLE}</h1>
        <p>
          Your recovery code worked. Add a new passkey on this device in place of the one you lost:
          you sign in with it next. Keep your other recovery codes.
        </p>
        ${opts.refused ? html`<p class="error" role="alert">${PASSKEY_REBIND_REFUSED}</p>` : ''}
        ${ceremonyForm({ ...opts, mode: 'create', label: 'Add a passkey' })}`,
    });
  }
  return page({
    cspNonce: opts.cspNonce,
    scriptNonce: opts.scriptNonce,
    title: PASSKEY_ENROLMENT_TITLE,
    body: html`<h1>${PASSKEY_ENROLMENT_TITLE}</h1>
      <p>
        Sign in next time with your fingerprint, face, PIN or screen lock instead of your password.
        Once the passkey is added, signing in to this account takes it: your password alone no
        longer does. You also get recovery codes to keep, for when you lose the passkey.
      </p>
      ${opts.refused ? html`<p class="error" role="alert">${PASSKEY_ENROLMENT_REFUSED}</p>` : ''}
      ${ceremonyForm({ ...opts, mode: 'create', label: 'Add a passkey' })}
      ${
        opts.optional
          ? html`<form method="post" action="${opts.action}">
              ${hiddenFields(opts)}
              <button class="secondary" type="submit">Not now</button>
            </form>`
          : ''
      }`,
  });
}

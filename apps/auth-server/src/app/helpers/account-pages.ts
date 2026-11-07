import type { AccountOverview, AccountPasskey, AccountSession } from './account-changes';
import type { AccountFactor } from './account-operation-guard';
import { html, render, type SafeHtml } from './html';
import { walletPageStyles } from './wallet-ui';

/**
 * THE HOSTED ACCOUNT PAGES (#844; ADR-017 Decision 8, ADR-020 §3),
 * server-rendered in the current `/ui` style, as `/ui/login` is: every form
 * is a plain HTML form that posts to its own route with the session's CSRF
 * value, so each page works without JavaScript. The design-system account
 * console replaces them, page by page:
 *
 * - the sign-in methods overview and the password change: #685;
 * - passkeys: #686;
 * - the authenticator app and the recovery codes: #687;
 * - sessions and "sign out everywhere": #688.
 *
 * Linked upstream accounts sit with the sign-in methods. Every page is sent
 * with `Cache-Control: no-store`; none puts a secret or a code in a URL.
 */

/** The path of the overview, and of every form's route, on the realm's origin. */
export const ACCOUNT_PAGE_PATH = '/ui/account';

/** The notices a change leaves for the overview, by its `notice` query value. */
export const ACCOUNT_NOTICES = {
  confirmed: 'You confirmed it’s you. You can make your change now.',
  passkey: 'Passkey set-up finished. Your passkeys are listed below.',
  totp: 'Authenticator app set-up finished.',
  linked: 'The account is linked. You can sign in with it from now on.',
  password_changed:
    'Your password is changed. Your other sessions were signed out; this one stays.',
  passkey_renamed: 'The passkey’s name is changed.',
  passkey_removed: 'The passkey is removed. It no longer signs you in.',
  totp_removed: 'The authenticator app is turned off.',
  recovery_codes_saved: 'Your new recovery codes are saved.',
  recovery_codes_replaced:
    'Those recovery codes were replaced by a newer set. Get a new set if you did not save the newest one.',
  unlinked: 'The account is unlinked. It no longer signs you in.',
  session_ended: 'The session is signed out.',
} as const;

export type AccountNotice = keyof typeof ACCOUNT_NOTICES;

/** The names of a factor, as the "confirm it's you" page asks for it. */
const FACTOR_NAMES: Record<AccountFactor, string> = {
  pop: 'a passkey',
  otp: 'your authenticator app',
  pwd: 'your password',
};

/** A time in epoch milliseconds, as the pages show it. */
export function shownTime(at: number): string {
  return `${new Date(at).toISOString().slice(0, 16).replace('T', ' ')} UTC`;
}

/** The page's chrome: the shared `/ui` styles, and the account pages' own, under the CSP nonce. */
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
            .card.wide {
              max-width: 560px;
              margin: 32px 0;
            }
            h2 {
              margin: 28px 0 8px;
              font-size: 16px;
            }
            .item {
              border-top: 1px solid #e5e7eb;
              padding: 12px 0;
              font-size: 14px;
            }
            .item .meta {
              color: #6b7280;
              font-size: 12px;
              margin: 2px 0 0;
            }
            .actions {
              display: flex;
              flex-wrap: wrap;
              gap: 8px;
              align-items: flex-end;
              margin-top: 8px;
            }
            .actions form {
              margin: 0;
            }
            .actions button,
            .actions input[type='text'] {
              width: auto;
              margin-top: 0;
              padding: 6px 12px;
              font-size: 13px;
            }
            input[type='password'] {
              display: block;
              width: 100%;
              padding: 10px 12px;
              margin-top: 6px;
              border: 1px solid #d8dbe0;
              border-radius: 6px;
              font-size: 14px;
              box-sizing: border-box;
            }
            .codes code {
              font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
              font-size: 15px;
            }
          </style>
        </head>
        <body>
          <main class="card wide">${opts.body}</main>
        </body>
      </html>`
  );
}

/** The CSRF value every form posts. */
function csrfField(csrf: string): SafeHtml {
  return html`<input type="hidden" name="csrf" value="${csrf}" />`;
}

/** A form of one button. */
function buttonForm(opts: {
  readonly action: string;
  readonly csrf: string;
  readonly label: string;
  readonly secondary?: boolean;
  readonly fields?: SafeHtml;
}): SafeHtml {
  return html`<form method="post" action="${opts.action}">
    ${csrfField(opts.csrf)} ${opts.fields ?? ''}
    <button type="submit" ${opts.secondary === true ? html`class="secondary"` : ''}>
      ${opts.label}
    </button>
  </form>`;
}

/** The overview's title. */
export const ACCOUNT_TITLE = 'Your account';

/** What the overview is drawn with. */
export interface AccountPageInput {
  readonly cspNonce: string;
  readonly csrf: string;
  readonly overview: AccountOverview;
  readonly notice?: AccountNotice;
  /** Whether passkeys are on in this deployment (`WEBAUTHN_ENABLED`). */
  readonly passkeysOn: boolean;
}

function passkeyItem(passkey: AccountPasskey, csrf: string): SafeHtml {
  const base = `${ACCOUNT_PAGE_PATH}/passkeys/${encodeURIComponent(passkey.id)}`;
  return html`<div class="item">
    <strong>${passkey.nickname ?? 'Passkey'}</strong>${passkey.disabled ? ' (turned off)' : ''}
    <p class="meta">
      Added ${shownTime(passkey.createdAt)} ·
      ${passkey.lastUsedAt === null ? 'never used' : `last used ${shownTime(passkey.lastUsedAt)}`} ·
      ${passkey.backedUp ? 'synced' : 'on one device'}
    </p>
    <div class="actions">
      <form method="post" action="${base}/rename">
        ${csrfField(csrf)}
        <input
          type="text"
          name="nickname"
          maxlength="64"
          aria-label="New name"
          placeholder="New name"
          value="${passkey.nickname ?? ''}"
        />
        <button type="submit" class="secondary">Rename</button>
      </form>
      ${buttonForm({ action: `${base}/remove`, csrf, label: 'Remove', secondary: true })}
    </div>
  </div>`;
}

function sessionItem(session: AccountSession, csrf: string): SafeHtml {
  return html`<div class="item">
    <strong>${session.current ? 'This browser' : (session.userAgent ?? 'A browser')}</strong>
    <p class="meta">
      Signed in ${shownTime(session.createdAt)} · last active ${shownTime(session.lastSeenAt)}
      ${session.ipAddress === null ? '' : html` · from ${session.ipAddress}`}
    </p>
    ${
      session.clients.length === 0
        ? ''
        : html`<p class="meta">Signed in to: ${session.clients.join(', ')}</p>`
    }
    <div class="actions">
      ${buttonForm({
        action: `${ACCOUNT_PAGE_PATH}/sessions/${encodeURIComponent(session.sid)}/end`,
        csrf,
        label: session.current ? 'Sign out of this browser' : 'Sign out this session',
        secondary: true,
      })}
    </div>
  </div>`;
}

/**
 * The overview: every sign-in method with its state and its actions, the
 * linked upstream accounts, and the live sessions. A change that asks for a
 * fresh sign-in sends the person through one when it is refused.
 */
export function accountPage(input: AccountPageInput): string {
  const { csrf, overview, notice } = input;
  const passkeysTitle = `Passkeys (${overview.passkeys.length})`;
  return page({
    cspNonce: input.cspNonce,
    title: ACCOUNT_TITLE,
    body: html`<h1>${ACCOUNT_TITLE}</h1>
      ${
        overview.password.address === undefined
          ? ''
          : html`<p>Signed in as <strong>${overview.password.address}</strong>.</p>`
      }
      ${
        notice === undefined
          ? ''
          : html`<p class="status" role="status">${ACCOUNT_NOTICES[notice]}</p>`
      }
      <p class="hint">
        Changes to how you sign in ask you to confirm it’s you first, with
        ${FACTOR_NAMES[overview.requiredFactor]}.
      </p>

      <h2>Password</h2>
      <div class="item">
        ${
          overview.password.set
            ? html`A password is set.
                <div class="actions">
                  <a class="alt-action" href="${ACCOUNT_PAGE_PATH}/password">Change password</a>
                </div>`
            : 'No password is set: you sign in another way.'
        }
      </div>

      <h2>${passkeysTitle}</h2>
      ${
        overview.passkeys.length === 0
          ? html`<div class="item">No passkeys yet.</div>`
          : overview.passkeys.map((passkey) => passkeyItem(passkey, csrf))
      }
      ${
        input.passkeysOn
          ? html`<div class="actions">
              ${buttonForm({ action: `${ACCOUNT_PAGE_PATH}/passkeys/add`, csrf, label: 'Add a passkey' })}
            </div>`
          : ''
      }

      <h2>Authenticator app</h2>
      <div class="item">
        ${
          overview.totp.set
            ? html`An authenticator app is set up.
                <div class="actions">
                  ${buttonForm({
                    action: `${ACCOUNT_PAGE_PATH}/totp/remove`,
                    csrf,
                    label: 'Turn off',
                    secondary: true,
                  })}
                </div>`
            : html`No authenticator app is set up.
                <div class="actions">
                  ${buttonForm({
                    action: `${ACCOUNT_PAGE_PATH}/totp/setup`,
                    csrf,
                    label: 'Set up an authenticator app',
                  })}
                </div>`
        }
      </div>

      <h2>Recovery codes</h2>
      <div class="item">
        ${
          overview.recoveryCodes.issued
            ? `${overview.recoveryCodes.unused} of 10 codes left.`
            : 'No recovery codes yet.'
        }
        <div class="actions">
          ${buttonForm({
            action: `${ACCOUNT_PAGE_PATH}/recovery-codes/regenerate`,
            csrf,
            label: 'Get new recovery codes',
            secondary: true,
          })}
        </div>
      </div>

      <h2>Linked accounts</h2>
      ${
        overview.linkedAccounts.length === 0
          ? html`<div class="item">No linked accounts.</div>`
          : overview.linkedAccounts.map(
              (linked) =>
                html`<div class="item">
                  <strong>${linked.providerName ?? linked.provider}</strong>
                  <p class="meta">Linked ${shownTime(linked.createdAt)}</p>
                  <div class="actions">
                    ${buttonForm({
                      action: `${ACCOUNT_PAGE_PATH}/linked-accounts/${encodeURIComponent(linked.id)}/unlink`,
                      csrf,
                      label: 'Unlink',
                      secondary: true,
                    })}
                  </div>
                </div>`
            )
      }
      ${
        overview.linkable.length === 0
          ? ''
          : html`<div class="actions">
              ${overview.linkable.map((provider) =>
                buttonForm({
                  action: `${ACCOUNT_PAGE_PATH}/linked-accounts/link`,
                  csrf,
                  label: `Link ${provider.name}`,
                  fields: html`<input
                    type="hidden"
                    name="provider"
                    value="${provider.provider}"
                  />`,
                })
              )}
            </div>`
      }

      <h2>Sessions</h2>
      ${overview.sessions.map((session) => sessionItem(session, csrf))}
      ${buttonForm({
        action: `${ACCOUNT_PAGE_PATH}/sessions/end-all`,
        csrf,
        label: 'Sign out everywhere',
      })}`,
  });
}

/** The password page's title. */
export const PASSWORD_CHANGE_TITLE = 'Change your password';

/** The wrong-current-password error. */
export const CURRENT_PASSWORD_REFUSED = 'That is not your current password.';

/** "Change your password": the current one, the new one, and why the last try was refused. */
export function passwordChangePage(opts: {
  readonly cspNonce: string;
  readonly csrf: string;
  readonly address?: string;
  /** The messages of a refused try: the policy's, or the wrong current password's. */
  readonly errors?: readonly string[];
}): string {
  const errors = opts.errors ?? [];
  return page({
    cspNonce: opts.cspNonce,
    title: PASSWORD_CHANGE_TITLE,
    body: html`<h1>${PASSWORD_CHANGE_TITLE}</h1>
      <p>Your other sessions are signed out once it is changed; this one stays.</p>
      ${
        errors.length === 0
          ? ''
          : html`<div class="error" role="alert">
              ${errors.map((message) => html`<p>${message}</p>`)}
            </div>`
      }
      <form method="post" action="${ACCOUNT_PAGE_PATH}/password">
        ${csrfField(opts.csrf)}
        ${
          opts.address === undefined
            ? ''
            : html`<input
                type="hidden"
                name="username"
                autocomplete="username"
                value="${opts.address}"
              />`
        }
        <label for="current_password">Current password</label>
        <input
          id="current_password"
          name="current_password"
          type="password"
          required
          maxlength="1024"
          autocomplete="current-password"
        />
        <label for="new_password">New password</label>
        <input
          id="new_password"
          name="new_password"
          type="password"
          required
          maxlength="1024"
          autocomplete="new-password"
        />
        <button type="submit">Change password</button>
      </form>
      <a class="footer-link" href="${ACCOUNT_PAGE_PATH}">Back to your account</a>`,
  });
}

/** The new recovery codes page's title. */
export const NEW_RECOVERY_CODES_TITLE = 'Your new recovery codes';

/** The new set, shown once, and the confirmation that it was saved. */
export function newRecoveryCodesPage(opts: {
  readonly cspNonce: string;
  readonly csrf: string;
  readonly codes: readonly string[];
  readonly setId: string;
}): string {
  return page({
    cspNonce: opts.cspNonce,
    title: NEW_RECOVERY_CODES_TITLE,
    body: html`<h1>${NEW_RECOVERY_CODES_TITLE}</h1>
      <p>
        Your old recovery codes no longer work. Each of these works once, in place of a lost second
        factor. Keep them somewhere safe, apart from your devices: they are not shown again.
      </p>
      <ol class="codes">
        ${opts.codes.map((code) => html`<li><code>${code}</code></li>`)}
      </ol>
      <form method="post" action="${ACCOUNT_PAGE_PATH}/recovery-codes/confirm">
        ${csrfField(opts.csrf)}
        <input type="hidden" name="set_id" value="${opts.setId}" />
        <label class="confirm">
          <input type="checkbox" name="acknowledged" value="true" required />
          <span>I have saved these codes</span>
        </label>
        <button type="submit">Done</button>
      </form>`,
  });
}

/** The "confirm it's you" page's title. */
export const REAUTHENTICATE_TITLE = 'Confirm it’s you';

/**
 * A change refused for want of a fresh sign-in: the factor it needs, and the
 * form that starts one. The change is made again afterwards; nothing is kept.
 */
export function reauthenticatePage(opts: {
  readonly cspNonce: string;
  readonly csrf: string;
  readonly requiredFactor: AccountFactor;
  readonly returnTo: string;
}): string {
  return page({
    cspNonce: opts.cspNonce,
    title: REAUTHENTICATE_TITLE,
    body: html`<h1>${REAUTHENTICATE_TITLE}</h1>
      <p>
        This change needs a sign-in from the last five minutes, with
        ${FACTOR_NAMES[opts.requiredFactor]}. Sign in again, then make the change.
      </p>
      ${buttonForm({
        action: `${ACCOUNT_PAGE_PATH}/reauthenticate`,
        csrf: opts.csrf,
        label: 'Sign in again',
        fields: html`<input type="hidden" name="return_to" value="${opts.returnTo}" />`,
      })}
      <a class="footer-link" href="${ACCOUNT_PAGE_PATH}">Back to your account</a>`,
  });
}

/** A refusal or an ending: its title, its message and the way back. */
export function accountMessagePage(opts: {
  readonly cspNonce: string;
  readonly title: string;
  readonly message: string;
  /** The link back: the overview by default. */
  readonly back?: { readonly href: string; readonly label: string };
}): string {
  const back = opts.back ?? { href: ACCOUNT_PAGE_PATH, label: 'Back to your account' };
  return page({
    cspNonce: opts.cspNonce,
    title: opts.title,
    body: html`<h1>${opts.title}</h1>
      <p>${opts.message}</p>
      <a class="footer-link" href="${back.href}">${back.label}</a>`,
  });
}

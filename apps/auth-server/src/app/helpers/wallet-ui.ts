import { html, render, type SafeHtml } from './html';

/**
 * Chrome shared by the wallet screens (issues #239, #238).
 *
 * Extracted when account linking (#238) added a second wallet surface. Two
 * copies of a page style block drift within one release; two copies of a
 * terminal page drift in what they say a failure MEANS, which is worse — the
 * whole point of `WALLET_LOGIN_REFUSAL` and `WALLET_LINK_REFUSAL` is that a user
 * sees one sentence for every failure, and that guarantee is per-surface only if
 * both surfaces render it the same way.
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
}): string {
  const { cspNonce, title, message, returnTo, retry, retryHref, footer } = opts;
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
        </body>
      </html>`
  );
}

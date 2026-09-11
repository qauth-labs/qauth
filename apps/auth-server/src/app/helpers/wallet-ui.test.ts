import { describe, expect, it } from 'vitest';

import {
  WALLET_LINK_REBOUND,
  WALLET_LINKED,
  WALLET_LINKED_TITLE,
  WALLET_RETURN_REFUSAL,
  WALLET_RETURN_REFUSAL_TITLE,
  WALLET_SIGNED_IN,
  WALLET_SIGNED_IN_TITLE,
  walletLinkedPage,
  walletLinkTerminalPage,
  walletReturnRefusalPage,
  walletSignedInPage,
} from './wallet-ui';

/**
 * The two pages the same-device return leg renders (#405). The route suite
 * proves WHEN each is rendered and that every refusal is the same bytes; this
 * pins WHAT each page is made of, so a copy or markup change is a deliberate
 * edit here and not a surprise in a byte-compare elsewhere.
 */

const nonces = { cspNonce: 'style-nonce', scriptNonce: 'script-nonce' };
const returnPath = '/ui/wallet-login/return';

describe('walletReturnRefusalPage (#405)', () => {
  const page = walletReturnRefusalPage({ ...nonces, returnPath });

  it('renders the one refusal, with no way to start a flow in this browser', () => {
    expect(page).toContain(`<h1>${WALLET_RETURN_REFUSAL_TITLE}</h1>`);
    expect(page).toContain(WALLET_RETURN_REFUSAL.replace(/'/g, '&#39;'));
    expect(page).not.toContain('Try again');
    expect(page).not.toContain('/ui/wallet-login?');
    expect(page).toContain('href="/ui/login?return_to=%2F">Sign in with a password</a>');
  });

  it('is a pure function of the nonces: nothing from the request can reach it', () => {
    expect(walletReturnRefusalPage({ ...nonces, returnPath })).toBe(page);
  });

  it('scrubs the Response Code from the address bar with a nonced inline script', () => {
    expect(page).toContain('<script nonce="script-nonce">');
    expect(page).toContain(`history.replaceState(null, '', "${returnPath}")`);
    expect(page).toContain('<style nonce="style-nonce">');
    expect(page).toContain('<meta name="robots" content="noindex" />');
  });
});

describe('walletSignedInPage (#405)', () => {
  it('tells the user to go back, and offers the continuation only as a secondary link', () => {
    const page = walletSignedInPage({
      ...nonces,
      returnPath,
      redirectTo: '/oauth/authorize?client_id=abc&scope=openid',
    });

    expect(page).toContain(`<h1>${WALLET_SIGNED_IN_TITLE.replace(/'/g, '&#39;')}</h1>`);
    expect(page).toContain(WALLET_SIGNED_IN.replace(/'/g, '&#39;'));
    // Escaped into the attribute; it is a link, not a redirect.
    expect(page).toContain(
      '<a class="alt-action" href="/oauth/authorize?client_id=abc&amp;scope=openid">Continue here instead</a>'
    );
    expect(page).not.toContain('http-equiv="refresh"');
    expect(page).toContain(`history.replaceState(null, '', "${returnPath}")`);
  });

  it('escapes a hostile redirectTo rather than trusting it', () => {
    // The route passes a value `isSafeReturnTo` already accepted; the builder
    // still escapes, so a future caller cannot make it emit markup.
    const page = walletSignedInPage({ ...nonces, returnPath, redirectTo: '/"><script>' });
    expect(page).toContain('href="/&quot;&gt;&lt;script&gt;"');
    expect(page).not.toContain('href="/"><script>');
  });
});

describe('the linking terminal pages (#238, moved for #405)', () => {
  it('renders the linked and rebound sentences with the linking chrome and no "Try again"', () => {
    const linked = walletLinkedPage({ cspNonce: 'style-nonce', rebound: false });
    const rebound = walletLinkedPage({ cspNonce: 'style-nonce', rebound: true });

    expect(linked).toContain(`<h1>${WALLET_LINKED_TITLE}</h1>`);
    expect(linked).toContain(WALLET_LINKED);
    expect(rebound).toContain(WALLET_LINK_REBOUND);
    expect(linked).not.toContain(WALLET_LINK_REBOUND);
    for (const page of [linked, rebound]) {
      expect(page).not.toContain('Try again');
      expect(page).toContain('href="/">Back</a>');
      expect(page).not.toContain('history.replaceState');
    }
  });

  it('adds only the address-bar scrub when rendered under the return route (#405)', () => {
    const plain = walletLinkedPage({ cspNonce: 'style-nonce', rebound: false });
    const scrubbed = walletLinkedPage({
      cspNonce: 'style-nonce',
      rebound: false,
      scrub: { scriptNonce: 'script-nonce', returnPath },
    });

    expect(scrubbed).toContain(`history.replaceState(null, '', "${returnPath}")`);
    expect(scrubbed).toContain('<script nonce="script-nonce">');
    // The scrub is the ONLY difference, so the two surfaces can be compared
    // byte for byte once it is stripped.
    expect(scrubbed.replace(/<script nonce="script-nonce">[\s\S]*?<\/script>/, '')).toBe(plain);
    expect(scrubbed.length).toBeGreaterThan(plain.length);
  });

  it('the generic linking terminal page keeps its own retry target and footer', () => {
    const page = walletLinkTerminalPage({
      cspNonce: 'style-nonce',
      title: 'Linking was not completed',
      message: 'nope',
      retry: true,
    });

    expect(page).toContain('<a class="alt-action" href="/ui/wallet-link">Try again</a>');
    expect(page).toContain('href="/">Back</a>');
    expect(page).not.toContain('/ui/wallet-login');
  });
});

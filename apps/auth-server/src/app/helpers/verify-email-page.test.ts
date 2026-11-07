import { describe, expect, it } from 'vitest';

import { UI_STYLESHEET_URL } from './ui-assets';
import { VERIFY_FORM_ACTION, verifyEmailPage } from './verify-email-page';

describe('verifyEmailPage', () => {
  it('escapes every value it puts in the page: the token, the CSRF token and the address', () => {
    // The routes only ever pass a 64-hex token and the server's own values;
    // the renderer escapes them anyway, as every page of the hosted UI does.
    const hostile = '"><script>alert(1)</script>';
    const form = verifyEmailPage({
      kind: 'form',
      token: hostile,
      csrfToken: hostile,
      error: hostile,
    });
    const verified = verifyEmailPage({ kind: 'verified', email: hostile });

    for (const page of [form, verified]) {
      expect(page).not.toContain('<script>');
      expect(page).toContain('&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;');
    }
    expect(form).toContain('name="token" value="&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;"');
  });

  it('posts the form to /ui/verify, links the /ui stylesheet, and loads nothing from elsewhere', () => {
    const page = verifyEmailPage({ kind: 'form', token: 'a'.repeat(64), csrfToken: 'csrf' });

    expect(VERIFY_FORM_ACTION).toBe('/ui/verify');
    expect(page).toContain('<form method="post" action="/ui/verify">');
    // The one file the page loads, from its own origin (#472): no inline style
    // or script, so it needs no CSP nonce.
    expect([...page.matchAll(/<link [^>]*>/g)].map(([tag]) => tag)).toEqual([
      `<link rel="stylesheet" href="${UI_STYLESHEET_URL}" />`,
    ]);
    expect(page).not.toMatch(/<script|<style|<img|https?:\/\//);
  });

  it.each([
    ['incomplete-link', 'This link is incomplete'],
    ['invalid-link', 'This link is no longer valid'],
    ['already-verified', 'Email address already verified'],
  ] as const)('renders the %s page with no form', (kind, heading) => {
    const page = verifyEmailPage({ kind });

    expect(page).toContain(`<h1>${heading}</h1>`);
    expect(page).not.toContain('<form');
  });
});

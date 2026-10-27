import { describe, expect, it } from 'vitest';

import { VERIFY_FORM_ACTION, verifyEmailPage } from './verify-email-page';

describe('verifyEmailPage', () => {
  it('escapes every value it puts in the page: the token, the CSRF token and the address', () => {
    // The routes only ever pass a 64-hex token and the server's own values;
    // the renderer escapes them anyway, as every page of the hosted UI does.
    const hostile = '"><script>alert(1)</script>';
    const form = verifyEmailPage(
      { kind: 'form', token: hostile, csrfToken: hostile, error: hostile },
      'nonce-1'
    );
    const verified = verifyEmailPage({ kind: 'verified', email: hostile }, 'nonce-1');

    for (const page of [form, verified]) {
      expect(page).not.toContain('<script>');
      expect(page).toContain('&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;');
    }
    expect(form).toContain('name="token" value="&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;"');
  });

  it('posts the form to /ui/verify, carries the nonce, and loads nothing from elsewhere', () => {
    const page = verifyEmailPage(
      { kind: 'form', token: 'a'.repeat(64), csrfToken: 'csrf' },
      'the-nonce'
    );

    expect(VERIFY_FORM_ACTION).toBe('/ui/verify');
    expect(page).toContain('<form method="post" action="/ui/verify">');
    expect(page).toContain('<style nonce="the-nonce">');
    expect(page).not.toMatch(/<script|<link|<img|https?:\/\//);
  });

  it.each([
    ['incomplete-link', 'This link is incomplete'],
    ['invalid-link', 'This link is no longer valid'],
    ['already-verified', 'Email address already verified'],
  ] as const)('renders the %s page with no form', (kind, heading) => {
    const page = verifyEmailPage({ kind }, 'n');

    expect(page).toContain(`<h1>${heading}</h1>`);
    expect(page).not.toContain('<form');
  });
});

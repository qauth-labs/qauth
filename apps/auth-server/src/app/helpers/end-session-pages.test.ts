import type { ClientDisplay } from '@qauth-labs/shared-interaction-client';
import { stepUrn } from '@qauth-labs/shared-interaction-contract';
import { describe, expect, it } from 'vitest';

import { endSessionPage, formActionSourceOf } from './end-session-pages';
import { UI_STYLESHEET_URL } from './ui-assets';

/**
 * The pages of RP-initiated logout (#675): what they show, what they escape,
 * and the `form-action` source the confirm page's CSP widens to. The route
 * suite (`routes/oauth/end-session.test.ts`) covers when each page answers.
 */

const NONCE = 'n0nce';
const LOGOUT_CONFIRM = stepUrn('logout_confirm');

/** Every `href` of a page, in order: what it links or loads. */
function hrefsOf(page: string): string[] {
  return [...page.matchAll(/href="([^"]*)"/g)].map(([, href]) => href);
}

function confirmPage(identifier: string, client?: ClientDisplay): string {
  return endSessionPage(
    {
      kind: 'confirm',
      action: '/interaction/v1-rc.0/abc/answer',
      step: LOGOUT_CONFIRM,
      csrf: 'c'.repeat(43),
      identifier,
      ...(client === undefined ? {} : { client }),
    },
    NONCE
  );
}

describe('the confirm page (#675)', () => {
  it('escapes the identifier and the declared client name', () => {
    const page = confirmPage('<img src=x onerror=alert(1)>@example.com', {
      kind: 'unverified',
      declaredName: '<script>alert("x")</script>',
      newClient: false,
    });
    expect(page).not.toContain('<img src=x');
    expect(page).not.toContain('<script>');
    expect(page).toContain('&lt;img src=x onerror=alert(1)&gt;@example.com');
    expect(page).toContain('&lt;script&gt;');
    expect(page).toContain('(a name the app gave itself)');
  });

  it('names the app by its verified domain first, then its declared name', () => {
    const page = confirmPage('alice@example.com', {
      kind: 'admin_registered',
      verifiedDomain: {
        host: 'notes.example.com',
        registrableDomain: 'example.com',
        sharedHosting: false,
      },
      declaredName: 'Notes',
      newClient: false,
    });
    expect(page).toContain('<strong>Notes</strong> (notes.example.com) asks to sign you out.');
  });

  it('says only that a sign-out was requested when the request named no client', () => {
    const page = confirmPage('alice@example.com');
    expect(page).toContain('A sign-out was requested for this browser.');
  });

  it('posts the step, its CSRF value and one of three decisions to the action, with the style nonce', () => {
    const page = confirmPage('alice@example.com');
    expect(page).toContain('<form method="post" action="/interaction/v1-rc.0/abc/answer">');
    expect(page).toContain(`name="type" value="${LOGOUT_CONFIRM}"`);
    expect(page).toContain(`name="csrf" value="${'c'.repeat(43)}"`);
    for (const decision of ['logout', 'logout_all', 'stay']) {
      expect(page).toContain(`name="decision" value="${decision}"`);
    }
    expect(page).toContain(`<style nonce="${NONCE}">`);
    expect(page).not.toContain('<script');
  });
});

describe('the refusal page (#675)', () => {
  it('shows the trace id and no request parameter', () => {
    const page = endSessionPage({ kind: 'refused', traceId: 'req-<1>' }, NONCE);
    expect(page).toContain('This sign-out request is not valid');
    expect(page).toContain('Reference: req-&lt;1&gt;');
    expect(page).not.toContain('<form');
    // Nothing links or loads anything but the /ui stylesheet, and nothing redirects.
    expect(hrefsOf(page)).toEqual([UI_STYLESHEET_URL]);
    expect(page).not.toMatch(/http-equiv/i);
  });
});

describe('the status pages (#675)', () => {
  it('says signed out, or still signed in', () => {
    expect(endSessionPage({ kind: 'signed_out' }, NONCE)).toContain('You are signed out');
    expect(endSessionPage({ kind: 'signed_in' }, NONCE)).toContain('You are still signed in');
  });
});

describe('the signed-out page of a client the operator did not set up (#675)', () => {
  it('names the host and links to the return URI, escaped', () => {
    const page = endSessionPage(
      {
        kind: 'leaving',
        host: 'app.example<b>',
        href: 'https://app.example/out?state="x"&a=1',
      },
      NONCE
    );
    expect(page).toContain('You are signed out');
    expect(page).toContain('<strong>app.example&lt;b&gt;</strong>');
    expect(page).toContain(
      '<a href="https://app.example/out?state=&quot;x&quot;&amp;a=1" rel="noopener noreferrer">'
    );
    expect(page).not.toContain('<form');
  });

  it('shows no link for a return URI that is not http(s)', () => {
    const page = endSessionPage(
      { kind: 'leaving', host: 'com.example.app', href: undefined },
      NONCE
    );
    expect(page).toContain('com.example.app');
    expect(hrefsOf(page)).toEqual([UI_STYLESHEET_URL]);
    expect(page).not.toMatch(/http-equiv/i);
  });
});

describe('formActionSourceOf (#675)', () => {
  it.each([
    [
      'an https URI',
      'https://notes.example.com:8443/signed-out?x=1#f',
      'https://notes.example.com:8443',
    ],
    ['an http loopback URI', 'http://127.0.0.1:4000/out', 'http://127.0.0.1:4000'],
    ['an IPv6 loopback URI', 'http://[::1]:4000/out', 'http://[::1]:4000'],
    ['a native app scheme', 'com.example.notes:/signed-out', 'com.example.notes:'],
  ])('gives the source of %s', (_label, uri, source) => {
    expect(formActionSourceOf(uri)).toBe(source);
  });

  it.each([
    ['no URI', 'not a uri'],
    ['an empty string', ''],
    ['a scheme with a quote', "a'b:/x"],
  ])('gives nothing for %s', (_label, uri) => {
    expect(formActionSourceOf(uri)).toBeUndefined();
  });
});

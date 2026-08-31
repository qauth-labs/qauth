import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { renderToString } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

/**
 * The consent screen (#150 AC 6), and the regression guard for #366.
 *
 * This page was the only route in `routes/` without a test, and the only one
 * calling the auth-server directly from the browser. Those two facts were the
 * same fact: nothing rendered it, so nothing noticed that the cookie it asked
 * the browser to send (`__Host-qauth_session`) is set only by the auth-server's
 * own hosted UI, is `SameSite=Lax` so would not travel on a cross-origin
 * `fetch()` anyway, and would be refused by a default production CORS policy
 * before any of that mattered.
 *
 * The last case below is the one that must not be deleted: it asserts the page
 * contains no browser-side `fetch()` at all, which is the property that broke.
 */

// A never-resolving promise keeps the component in its initial "loading" state
// for SSR rendering (effects do not run under renderToString anyway).
const pending = new Promise(() => undefined);

vi.mock('../../server/actions/consents', () => ({
  listConsentsFn: vi.fn(() => pending),
  revokeConsentFn: vi.fn(() => Promise.resolve({ ok: true, data: null })),
}));

vi.mock('@tanstack/react-router', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@tanstack/react-router')>();
  return {
    ...actual,
    useRouter: vi.fn(() => ({ navigate: vi.fn() })),
    Link: ({ children }: { children: React.ReactNode }) => <span>{children}</span>,
  };
});

import { Route } from './consents';

const PageComponent = Route.options.component as NonNullable<typeof Route.options.component>;
const ROUTE_DIR = dirname(fileURLToPath(import.meta.url));

describe('ConsentsPage', () => {
  it('renders the heading and its explanation', () => {
    const html = renderToString(<PageComponent />);
    expect(html).toContain('Authorized applications');
    expect(html).toContain('Revoking a grant forces the app to ask for');
  });

  it('shows a loading state on first render (before the effect resolves)', () => {
    const html = renderToString(<PageComponent />);
    expect(html).toContain('Loading');
  });

  it('REGRESSION (#366): the page never calls the auth-server from the browser', () => {
    // A source-level assertion on purpose. The defect was not a wrong value
    // this component could return under test — it was the presence of a
    // browser-side `fetch()` carrying ambient cookie credentials to another
    // origin. Only reading the source can catch that coming back, and the
    // component-level tests above would keep passing if it did.
    //
    // Comments are stripped first: this file's own prose, and the page's,
    // necessarily NAME the thing being banned.
    const code = readFileSync(join(ROUTE_DIR, 'consents.tsx'), 'utf8')
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/^\s*\/\/.*$/gm, '');

    expect(code).not.toMatch(/\bfetch\s*\(/);
    expect(code).not.toContain('credentials:');
    expect(code).not.toContain('__Host-qauth_session');
    expect(code).not.toContain('AUTH_SERVER_URL');
    // Positive half: it must be reaching the server functions instead. A page
    // that called nothing at all would satisfy the negatives above.
    expect(code).toContain('listConsentsFn(');
    expect(code).toContain('revokeConsentFn(');
  });

  it('lives under the _authed layout rather than beside it', () => {
    // Previously `routes/consents.tsx` — outside `_authed`, so it rendered for
    // anyone who typed the URL and then failed with a 401 from the network.
    // `Route.id` is only populated once the generated route tree is loaded, so
    // assert on the file layout the generator reads instead.
    expect(existsSync(join(ROUTE_DIR, 'consents.tsx'))).toBe(true);
    expect(existsSync(join(ROUTE_DIR, '..', 'consents.tsx'))).toBe(false);
  });

  it('is reachable by navigation, not only by typing the URL', () => {
    // The other half of why this page went unnoticed: nothing linked to it.
    const layout = readFileSync(join(ROUTE_DIR, '..', '_authed.tsx'), 'utf8');
    expect(layout).toContain('to="/consents"');
  });
});

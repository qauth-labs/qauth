import { RouterContextProvider } from '@tanstack/react-router';
import { renderToString } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

vi.mock('../server/actions/verify', () => ({
  verifyFn: vi.fn(),
}));

vi.mock('../server/actions/resend-verification', () => ({
  resendVerificationFn: vi.fn(),
}));

vi.mock('@tanstack/react-router', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@tanstack/react-router')>();
  return {
    ...actual,
    Link: ({ children }: { children: React.ReactNode }) => <span>{children}</span>,
  };
});

import { Route } from './verify';

const PageComponent = Route.options.component as NonNullable<typeof Route.options.component>;

const VALID_TOKEN = 'a'.repeat(64);

// Route.id is a getter backed by Route._id, which is normally populated by the
// route tree generator via Route.init(). Set _id directly so that
// Route.useSearch() passes from: '/verify' to useMatch in tests.
(Route as unknown as { _id: string })._id = '/verify';

// Minimal fake router for SSR-mode rendering.
// useRouterState reads router.state.matches when router.isServer === true.
const fakeRouter = {
  isServer: true,
  options: {},
  state: {
    matches: [{ id: '/verify', routeId: '/verify', search: { token: VALID_TOKEN }, context: {} }],
  },
} as unknown as Parameters<typeof RouterContextProvider>[0]['router'];

describe('verify validateSearch', () => {
  const validateSearch = Route.options.validateSearch as (raw: Record<string, unknown>) => {
    token: string;
  };

  it('accepts a valid 64-char lowercase hex token', () => {
    expect(validateSearch({ token: VALID_TOKEN })).toEqual({ token: VALID_TOKEN });
  });

  it('throws when token is missing', () => {
    expect(() => validateSearch({})).toThrow();
  });

  it('throws when token is too short', () => {
    expect(() => validateSearch({ token: 'abc123' })).toThrow();
  });

  it('throws when token contains non-hex characters (uppercase)', () => {
    // Auth-server issues lowercase hex only — uppercase is invalid.
    expect(() => validateSearch({ token: 'A'.repeat(64) })).toThrow();
  });

  it('throws when token is not a string', () => {
    expect(() => validateSearch({ token: 12345 })).toThrow();
  });
});

describe('VerifyPage component', () => {
  it('renders the pending state on initial render (useEffect not called in SSR)', () => {
    // useEffect is not invoked by renderToString, so the component always
    // starts in the "pending" stage.
    const html = renderToString(
      <RouterContextProvider router={fakeRouter}>
        <PageComponent />
      </RouterContextProvider>
    );
    expect(html).toContain('Verifying your email');
  });
});

import { RouterContextProvider } from '@tanstack/react-router';
import { renderToString } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

const { mockRedirect } = vi.hoisted(() => ({
  mockRedirect: vi.fn((opts: { to: string }) => {
    const err = new Error(`Redirect to ${opts.to}`) as Error & { to: string };
    err.to = opts.to;
    throw err;
  }),
}));

vi.mock('../server/actions/current-user', () => ({
  currentUserFn: vi.fn(),
}));

vi.mock('../server/actions/logout', () => ({
  logoutFn: vi.fn(),
}));

vi.mock('@tanstack/react-router', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@tanstack/react-router')>();
  return {
    ...actual,
    redirect: mockRedirect,
    // useRouter is mocked for the component's direct useRouter() call (navigate).
    // Route.useRouteContext() goes through the internal ./useRouter.js which reads React context
    // — that is provided by RouterContextProvider below.
    useRouter: vi.fn(() => ({ navigate: vi.fn() })),
    Outlet: () => null,
  };
});

import { currentUserFn } from '../server/actions/current-user';
import { Route } from './_authed';

const PageComponent = Route.options.component as NonNullable<typeof Route.options.component>;

// Route.id is a getter backed by Route._id, which is normally populated by the
// route tree generator via Route.init(). Set _id directly so that
// Route.useRouteContext() passes from: '/_authed' to useMatch in tests.
(Route as unknown as { _id: string })._id = '/_authed';

const testUser = { sub: 'u1', email: 'dev@example.com', email_verified: true };

// Minimal fake router for SSR-mode rendering via RouterContextProvider.
// Route.useRouteContext() → useMatch({ from: '/_authed' }) →
// router.stores.getRouteMatchStore(from).get() when router.isServer === true (1.170+).
const authedMatch = {
  id: '/_authed',
  routeId: '/_authed',
  search: {},
  context: { user: testUser },
};
const fakeRouter = {
  isServer: true,
  options: {},
  stores: {
    getRouteMatchStore: () => ({ get: () => authedMatch }),
    matchStores: new Map(),
  },
} as unknown as Parameters<typeof RouterContextProvider>[0]['router'];

describe('_authed beforeLoad guard', () => {
  it('throws a redirect to /login when currentUserFn returns null', async () => {
    vi.mocked(currentUserFn).mockResolvedValue(null);

    const beforeLoad = Route.options.beforeLoad as (ctx: unknown) => Promise<unknown>;
    await expect(beforeLoad({})).rejects.toMatchObject({ to: '/login' });
    expect(mockRedirect).toHaveBeenCalledWith({ to: '/login' });
  });

  it('returns the user context when currentUserFn returns a user', async () => {
    vi.mocked(currentUserFn).mockResolvedValue({ user: testUser });

    const beforeLoad = Route.options.beforeLoad as (ctx: unknown) => Promise<unknown>;
    const result = (await beforeLoad({})) as { user: typeof testUser };

    expect(result).toEqual({ user: testUser });
  });
});

describe('AuthedLayout component', () => {
  it('renders the portal header with user email and logout button', () => {
    const html = renderToString(
      <RouterContextProvider router={fakeRouter}>
        <PageComponent />
      </RouterContextProvider>
    );
    expect(html).toContain('QAuth Developer Portal');
    expect(html).toContain('dev@example.com');
    expect(html).toContain('Log out');
  });
});

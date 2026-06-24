import { RouterContextProvider } from '@tanstack/react-router';
import { renderToString } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { Route } from './dashboard';

const PageComponent = Route.options.component as NonNullable<typeof Route.options.component>;

// Route.id is a getter backed by Route._id, which is normally populated by the
// route tree generator via Route.init(). Set _id directly so that
// Route.useRouteContext() passes from: '/_authed/dashboard' to useMatch in tests.
(Route as unknown as { _id: string })._id = '/_authed/dashboard';

const testUser = { sub: 'u1', email: 'dev@example.com', email_verified: true };

// Minimal fake router for SSR-mode rendering via RouterContextProvider.
// Route.useRouteContext() → useMatch({ from: '/_authed/dashboard' }) → useRouterState() →
// reads router.state.matches when router.isServer === true.
const fakeRouter = {
  isServer: true,
  options: {},
  state: {
    matches: [
      {
        id: '/_authed/dashboard',
        routeId: '/_authed/dashboard',
        search: {},
        context: { user: testUser },
      },
    ],
  },
} as unknown as Parameters<typeof RouterContextProvider>[0]['router'];

describe('DashboardPage component', () => {
  it('greets the user by email', () => {
    const html = renderToString(
      <RouterContextProvider router={fakeRouter}>
        <PageComponent />
      </RouterContextProvider>
    );
    expect(html).toContain('dev@example.com');
    expect(html).toContain('Welcome');
  });

  it('renders the OAuth Clients placeholder card', () => {
    const html = renderToString(
      <RouterContextProvider router={fakeRouter}>
        <PageComponent />
      </RouterContextProvider>
    );
    expect(html).toContain('OAuth Clients');
    expect(html).toContain('Coming soon');
  });

  it('renders the API Keys placeholder card', () => {
    const html = renderToString(
      <RouterContextProvider router={fakeRouter}>
        <PageComponent />
      </RouterContextProvider>
    );
    expect(html).toContain('API Keys');
    expect(html).toContain('Coming soon');
  });
});

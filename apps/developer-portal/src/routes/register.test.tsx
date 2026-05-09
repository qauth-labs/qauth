import { renderToString } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

vi.mock('../server/actions/current-user', () => ({
  currentUserFn: vi.fn(),
}));

vi.mock('../server/actions/register', () => ({
  registerFn: vi.fn(),
}));

vi.mock('../server/actions/resend-verification', () => ({
  resendVerificationFn: vi.fn(),
}));

const { mockRedirect } = vi.hoisted(() => ({
  mockRedirect: vi.fn((opts: { to: string }) => {
    const err = new Error(`Redirect to ${opts.to}`) as Error & { to: string };
    err.to = opts.to;
    throw err;
  }),
}));

vi.mock('@tanstack/react-router', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@tanstack/react-router')>();
  return {
    ...actual,
    redirect: mockRedirect,
    Link: ({ children }: { children: React.ReactNode }) => <span>{children}</span>,
  };
});

import { currentUserFn } from '../server/actions/current-user';
import { Route } from './register';

describe('register beforeLoad guard', () => {
  it('throws a redirect to /dashboard when user is already authenticated', async () => {
    vi.mocked(currentUserFn).mockResolvedValue({
      user: { sub: 'u1', email: 'dev@example.com', email_verified: true },
    });

    const beforeLoad = Route.options.beforeLoad as (ctx: unknown) => Promise<unknown>;
    await expect(beforeLoad({})).rejects.toMatchObject({ to: '/dashboard' });
    expect(mockRedirect).toHaveBeenCalledWith({ to: '/dashboard' });
  });

  it('does not redirect when user is not authenticated', async () => {
    vi.mocked(currentUserFn).mockResolvedValue(null);

    const beforeLoad = Route.options.beforeLoad as (ctx: unknown) => Promise<unknown>;
    await expect(beforeLoad({})).resolves.toBeUndefined();
  });
});

describe('RegisterPage component', () => {
  it('renders email and password fields in idle state', () => {
    const html = renderToString(<Route.options.component />);
    expect(html).toContain('type="email"');
    expect(html).toContain('type="password"');
  });

  it('renders the submit button', () => {
    const html = renderToString(<Route.options.component />);
    expect(html).toContain('Create account');
  });

  it('renders a link to the login page', () => {
    const html = renderToString(<Route.options.component />);
    expect(html).toContain('Log in');
  });

  it('renders the email field with autocomplete attribute', () => {
    // React 19 preserves camelCase attribute names in renderToString output.
    const html = renderToString(<Route.options.component />);
    expect(html).toContain('autoComplete="email"');
  });
});

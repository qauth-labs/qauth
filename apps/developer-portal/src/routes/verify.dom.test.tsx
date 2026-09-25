// @vitest-environment jsdom
import { RouterContextProvider } from '@tanstack/react-router';
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

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

import { verifyFn } from '../server/actions/verify';
import { Route } from './verify';

// Opt into React's act() environment so effects flush synchronously.
(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const PageComponent = Route.options.component as NonNullable<typeof Route.options.component>;
const VALID_TOKEN = 'b'.repeat(64);

// Same minimal router stand-in as verify.test.tsx: Route.useSearch() reads the
// match from router.stores when router.isServer is true.
(Route as unknown as { _id: string })._id = '/verify';
const fakeRouter = {
  isServer: true,
  options: {},
  stores: {
    getRouteMatchStore: () => ({
      get: () => ({
        id: '/verify',
        routeId: '/verify',
        search: { token: VALID_TOKEN },
        context: {},
      }),
    }),
    matchStores: new Map(),
  },
} as unknown as Parameters<typeof RouterContextProvider>[0]['router'];

let container: HTMLDivElement;
let root: Root;

beforeEach(() => {
  vi.mocked(verifyFn).mockReset();
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
});

afterEach(() => {
  act(() => root.unmount());
  container.remove();
});

function renderPage() {
  act(() => {
    root.render(
      <RouterContextProvider router={fakeRouter}>
        <PageComponent />
      </RouterContextProvider>
    );
  });
}

describe('VerifyPage — verification needs an explicit confirmation', () => {
  it('does not verify when the page loads (a link fetch or prefetch must not verify)', () => {
    renderPage();

    expect(verifyFn).not.toHaveBeenCalled();
    expect(container.textContent).toContain('Confirm your email address');
  });

  it('verifies only when the reader presses the confirm button', async () => {
    vi.mocked(verifyFn).mockResolvedValue({
      ok: true,
      data: { message: 'Email verified successfully', email: 'dev@example.com' },
    } as never);
    renderPage();

    const button = Array.from(container.querySelectorAll('button')).find(
      (b) => b.textContent === 'Confirm email address'
    );
    expect(button).toBeDefined();

    await act(async () => {
      button?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    });

    expect(verifyFn).toHaveBeenCalledOnce();
    expect(verifyFn).toHaveBeenCalledWith({ data: { token: VALID_TOKEN } });
    expect(container.textContent).toContain('dev@example.com');
  });
});

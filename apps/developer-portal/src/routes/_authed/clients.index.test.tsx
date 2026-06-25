import { renderToString } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

// A never-resolving promise keeps the component in its initial "loading"
// state for SSR rendering (effects do not run under renderToString anyway).
const pending = new Promise(() => undefined);
vi.mock('../../server/actions/clients', () => ({
  listClientsFn: vi.fn(() => pending),
}));

vi.mock('@tanstack/react-router', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@tanstack/react-router')>();
  return {
    ...actual,
    useRouter: vi.fn(() => ({ navigate: vi.fn() })),
    Link: ({ children }: { children: React.ReactNode }) => <span>{children}</span>,
  };
});

import { Route } from './clients.index';

const PageComponent = Route.options.component as NonNullable<typeof Route.options.component>;

describe('ClientListPage', () => {
  it('renders the heading and a New client action', () => {
    const html = renderToString(<PageComponent />);
    expect(html).toContain('OAuth Clients');
    expect(html).toContain('New client');
  });

  it('shows a loading state on first render (before the effect resolves)', () => {
    const html = renderToString(<PageComponent />);
    expect(html).toContain('Loading');
  });
});

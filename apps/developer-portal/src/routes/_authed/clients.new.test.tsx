import { renderToString } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

vi.mock('../../server/actions/clients', () => ({
  createClientFn: vi.fn(),
}));

vi.mock('@tanstack/react-router', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@tanstack/react-router')>();
  return {
    ...actual,
    useRouter: vi.fn(() => ({ navigate: vi.fn() })),
    Link: ({ children }: { children: React.ReactNode }) => <span>{children}</span>,
  };
});

import { Route } from './clients.new';

const PageComponent = Route.options.component as NonNullable<typeof Route.options.component>;

describe('NewClientPage', () => {
  it('renders the create form inside the page', () => {
    const html = renderToString(<PageComponent />);
    expect(html).toContain('New OAuth client');
    expect(html).toContain('Create client');
    expect(html).toContain('Back to clients');
  });
});

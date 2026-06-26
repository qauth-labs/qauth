import { renderToString } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

// Never-resolving promise keeps the page in its initial loading state.
const pending = new Promise(() => undefined);
vi.mock('../../server/actions/clients', () => ({
  getClientFn: vi.fn(() => pending),
  updateClientFn: vi.fn(),
  deleteClientFn: vi.fn(),
  regenerateSecretFn: vi.fn(),
}));

// The detail page now renders ApiKeysSection, which imports the API-key server
// actions; mock them so the import graph never reaches the real env-validated
// config (and so no real fetch is attempted from this SSR test).
vi.mock('../../server/actions/api-keys', () => ({
  listApiKeysFn: vi.fn(() => pending),
  createApiKeyFn: vi.fn(),
  revokeApiKeyFn: vi.fn(),
}));

vi.mock('@tanstack/react-router', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@tanstack/react-router')>();
  return {
    ...actual,
    useRouter: vi.fn(() => ({ navigate: vi.fn() })),
    Link: ({ children }: { children: React.ReactNode }) => <span>{children}</span>,
  };
});

import { Route } from './clients.$clientId';

// Route.useParams() reads the route id; stub it to return our test param.
vi.spyOn(Route, 'useParams').mockReturnValue({ clientId: 'row-1' } as never);

const PageComponent = Route.options.component as NonNullable<typeof Route.options.component>;

describe('ClientDetailsPage', () => {
  it('renders a loading state and a back link before data resolves', () => {
    const html = renderToString(<PageComponent />);
    expect(html).toContain('Back to clients');
    expect(html).toContain('Loading');
  });
});

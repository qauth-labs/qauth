// @vitest-environment jsdom
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { ClientWithSecret, OAuthClient } from '../../server/auth-server-client';

vi.mock('../../server/actions/clients', () => ({
  getClientFn: vi.fn(),
  updateClientFn: vi.fn(),
  deleteClientFn: vi.fn(),
  regenerateSecretFn: vi.fn(),
}));

// The page renders ApiKeysSection; its server actions never answer here.
vi.mock('../../server/actions/api-keys', () => ({
  listApiKeysFn: vi.fn(() => new Promise(() => undefined)),
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

import { getClientFn, regenerateSecretFn, updateClientFn } from '../../server/actions/clients';
import { Route } from './clients.$clientId';

(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

vi.spyOn(Route, 'useParams').mockReturnValue({ clientId: 'row-1' } as never);
const PageComponent = Route.options.component as NonNullable<typeof Route.options.component>;

const CLIENT: OAuthClient = {
  id: 'row-1',
  clientId: 'app-1',
  name: 'My app',
  description: null,
  redirectUris: ['https://app.example.com/cb'],
  scopes: ['openid'],
  grantTypes: ['authorization_code'],
  responseTypes: ['code'],
  tokenEndpointAuthMethod: 'client_secret_basic',
  enabled: true,
  suspended: false,
  requirePkce: true,
  environment: 'production',
  staticApiKeysAllowed: false,
  createdAt: 1_700_000_000_000,
  updatedAt: 1_700_000_000_000,
  lastUsedAt: null,
  etag: '"before-regeneration"',
};

let container: HTMLDivElement;
let root: Root;

beforeEach(() => {
  vi.mocked(getClientFn).mockReset();
  vi.mocked(regenerateSecretFn).mockReset();
  vi.mocked(updateClientFn).mockReset();
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
});

afterEach(() => {
  act(() => root.unmount());
  container.remove();
});

function button(label: string): HTMLButtonElement {
  const found = [...document.querySelectorAll('button')].find(
    (candidate) => candidate.textContent?.trim() === label
  );
  if (found === undefined) throw new Error(`no button "${label}" in ${document.body.textContent}`);
  return found;
}

async function click(label: string) {
  await act(async () => {
    button(label).click();
  });
}

describe('ClientDetailsPage — regenerating the secret', () => {
  it("saves the next edit against the version the regeneration answered with, and keeps the secret out of the page's state", async () => {
    vi.mocked(getClientFn).mockResolvedValue({ ok: true, data: CLIENT } as never);
    const regenerated: ClientWithSecret = {
      ...CLIENT,
      updatedAt: 1_700_000_100_000,
      etag: '"after-regeneration"',
      clientSecret: 'the-new-secret',
    };
    vi.mocked(regenerateSecretFn).mockResolvedValue({ ok: true, data: regenerated } as never);
    vi.mocked(updateClientFn).mockResolvedValue({
      ok: true,
      data: { ...CLIENT, etag: '"after-save"' },
    } as never);
    await act(async () => {
      root.render(<PageComponent />);
    });

    await click('Regenerate');
    await click('Regenerate secret');
    expect(regenerateSecretFn).toHaveBeenCalledOnce();
    // Edit straight away, without a reload in between.
    await click('Edit');
    const form = container.querySelector('form') as HTMLFormElement;
    await act(async () => {
      form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
    });

    expect(updateClientFn).toHaveBeenCalledOnce();
    const sent = vi.mocked(updateClientFn).mock.calls[0][0] as unknown as {
      data: Record<string, unknown>;
    };
    expect(sent.data['ifMatch']).toBe('"after-regeneration"');
    expect(JSON.stringify(sent)).not.toContain('the-new-secret');
  });
});

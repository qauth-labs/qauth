// @vitest-environment jsdom
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { OAuthClient } from '../server/auth-server-client';

// Server-function mocks. Each test sets the resolved value it needs.
const { listApiKeysFn, createApiKeyFn, revokeApiKeyFn } = vi.hoisted(() => ({
  listApiKeysFn: vi.fn(),
  createApiKeyFn: vi.fn(),
  revokeApiKeyFn: vi.fn(),
}));

vi.mock('../server/actions/api-keys', () => ({
  listApiKeysFn,
  createApiKeyFn,
  revokeApiKeyFn,
}));

import { ApiKeysSection } from './api-keys-section';

(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let container: HTMLDivElement;
let root: Root;

beforeEach(() => {
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
  vi.clearAllMocks();
  // Default: an empty key list resolves immediately.
  listApiKeysFn.mockResolvedValue({ ok: true, data: { apiKeys: [] } });
});

afterEach(() => {
  act(() => root.unmount());
  container.remove();
  vi.restoreAllMocks();
});

function makeClient(overrides: Partial<OAuthClient> = {}): OAuthClient {
  return {
    id: 'client-uuid',
    clientId: 'app-123',
    name: 'My App',
    description: null,
    redirectUris: [],
    scopes: [],
    grantTypes: ['authorization_code'],
    responseTypes: ['code'],
    tokenEndpointAuthMethod: 'client_secret_post',
    enabled: true,
    requirePkce: true,
    environment: 'development',
    staticApiKeysAllowed: true,
    createdAt: 1700,
    updatedAt: null,
    lastUsedAt: null,
    ...overrides,
  };
}

/** Render and flush the initial list-load effect. */
async function render(client: OAuthClient) {
  await act(async () => {
    root.render(<ApiKeysSection client={client} onUnauthenticated={vi.fn()} />);
  });
  // Flush the pending list promise + its setState.
  await act(async () => {
    await Promise.resolve();
  });
}

function queryByText(text: string): boolean {
  return (container.textContent ?? '').includes(text);
}

describe('ApiKeysSection environment gating', () => {
  it('shows the create form for a development client', async () => {
    await render(makeClient({ environment: 'development', staticApiKeysAllowed: true }));
    expect(container.querySelector('#api-key-name')).not.toBeNull();
    expect(queryByText('Create API key')).toBe(true);
  });

  it('shows client_credentials guidance (no form) for a production client', async () => {
    await render(makeClient({ environment: 'production', staticApiKeysAllowed: false }));
    expect(container.querySelector('#api-key-name')).toBeNull();
    expect(queryByText('client_credentials')).toBe(true);
    expect(queryByText('production')).toBe(true);
  });
});

describe('ApiKeysSection create flow', () => {
  it('reveals the one-time plaintext key after creation, with a warning', async () => {
    createApiKeyFn.mockResolvedValue({
      ok: true,
      data: {
        id: 'key-1',
        clientId: 'client-uuid',
        name: 'Local dev',
        prefix: 'qauth_abcd',
        last4: 'wxyz',
        createdAt: 1700,
        lastUsedAt: null,
        revokedAt: null,
        key: 'qauth_abcd_thefullplaintextsecret',
      },
    });

    await render(makeClient());

    const input = container.querySelector('#api-key-name') as HTMLInputElement;
    const setValue = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!;
    act(() => {
      setValue.call(input, 'Local dev');
      input.dispatchEvent(new Event('input', { bubbles: true }));
    });

    const form = container.querySelector('form') as HTMLFormElement;
    await act(async () => {
      form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
      await Promise.resolve();
    });
    // Flush the post-create setState.
    await act(async () => {
      await Promise.resolve();
    });

    expect(createApiKeyFn).toHaveBeenCalledWith({
      data: { clientId: 'client-uuid', name: 'Local dev' },
    });
    expect(queryByText('qauth_abcd_thefullplaintextsecret')).toBe(true);
    expect(queryByText('not')).toBe(true);
    expect(queryByText('shown again')).toBe(true);
  });

  it('shows client_credentials guidance when the mint endpoint returns 403 (defense-in-depth)', async () => {
    // A stale gate flag: the UI believed keys were allowed, but the backend
    // refuses with FORBIDDEN. The error must still steer to client_credentials.
    createApiKeyFn.mockResolvedValue({
      ok: false,
      error: { code: 'FORBIDDEN', message: 'forbidden', status: 403 },
    });

    await render(makeClient());

    const input = container.querySelector('#api-key-name') as HTMLInputElement;
    const setValue = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!;
    act(() => {
      setValue.call(input, 'Local dev');
      input.dispatchEvent(new Event('input', { bubbles: true }));
    });

    const form = container.querySelector('form') as HTMLFormElement;
    await act(async () => {
      form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
      await Promise.resolve();
    });

    expect(queryByText('client_credentials')).toBe(true);
    // No reveal modal — nothing was created.
    expect(queryByText('shown again')).toBe(false);
  });
});

describe('ApiKeysSection revoke flow', () => {
  it('confirms and calls revokeApiKeyFn for an active key', async () => {
    listApiKeysFn.mockResolvedValue({
      ok: true,
      data: {
        apiKeys: [
          {
            id: 'key-1',
            clientId: 'client-uuid',
            name: 'Local dev',
            prefix: 'qauth_abcd',
            last4: 'wxyz',
            createdAt: 1700,
            lastUsedAt: null,
            revokedAt: null,
          },
        ],
      },
    });
    revokeApiKeyFn.mockResolvedValue({
      ok: true,
      data: {
        id: 'key-1',
        clientId: 'client-uuid',
        name: 'Local dev',
        prefix: 'qauth_abcd',
        last4: 'wxyz',
        createdAt: 1700,
        lastUsedAt: null,
        revokedAt: 1800,
      },
    });

    await render(makeClient());

    // The masked list renders prefix…last4.
    expect(queryByText('qauth_abcd')).toBe(true);

    // Open the confirm modal.
    const revokeBtn = Array.from(container.querySelectorAll('button')).find(
      (b) => b.textContent === 'Revoke'
    ) as HTMLButtonElement;
    expect(revokeBtn).toBeDefined();
    act(() => revokeBtn.click());

    expect(queryByText('Revoke this API key?')).toBe(true);

    // Confirm.
    const confirmBtn = Array.from(container.querySelectorAll('button')).find(
      (b) => b.textContent === 'Revoke key'
    ) as HTMLButtonElement;
    await act(async () => {
      confirmBtn.click();
      await Promise.resolve();
    });

    expect(revokeApiKeyFn).toHaveBeenCalledWith({
      data: { clientId: 'client-uuid', keyId: 'key-1' },
    });
  });

  it('marks revoked keys and offers no revoke button for them', async () => {
    listApiKeysFn.mockResolvedValue({
      ok: true,
      data: {
        apiKeys: [
          {
            id: 'key-2',
            clientId: 'client-uuid',
            name: 'Old key',
            prefix: 'qauth_dead',
            last4: 'beef',
            createdAt: 1600,
            lastUsedAt: null,
            revokedAt: 1700,
          },
        ],
      },
    });

    await render(makeClient());

    expect(queryByText('Revoked')).toBe(true);
    const revokeBtn = Array.from(container.querySelectorAll('button')).find(
      (b) => b.textContent === 'Revoke'
    );
    expect(revokeBtn).toBeUndefined();
  });
});

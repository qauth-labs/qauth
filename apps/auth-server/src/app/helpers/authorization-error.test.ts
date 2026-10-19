import type { FastifyReply } from 'fastify';
import { describe, expect, it, vi } from 'vitest';

vi.mock('../../config/env', () => ({
  env: {
    DYNAMIC_CLIENT_BADGE_DAYS: 30,
  },
}));

import { isOperatorProvisionedClient, sendAuthorizationError } from './authorization-error';

const DAY = 24 * 60 * 60 * 1000;

function createReply() {
  const state: {
    statusCode?: number;
    headers: Record<string, string>;
    redirected?: string;
    body?: unknown;
  } = { headers: {} };
  const reply = {
    code(n: number) {
      state.statusCode = n;
      return this;
    },
    header(k: string, v: string) {
      state.headers[k] = v;
      return this;
    },
    redirect(url: string, code: number) {
      state.redirected = url;
      state.statusCode = code;
      return this;
    },
    send(body: unknown) {
      state.body = body;
      return this;
    },
  };
  return { reply: reply as unknown as FastifyReply, state };
}

const OPERATOR_CLIENT = {
  provisionedByOperator: true,
  dynamicRegisteredAt: null,
  metadata: null,
  developerId: null,
};
const DCR_CLIENT = {
  provisionedByOperator: false,
  dynamicRegisteredAt: Date.now() - 400 * DAY,
  metadata: { registrationType: 'dynamic' },
  developerId: null,
};
const CIMD_CLIENT = {
  provisionedByOperator: false,
  dynamicRegisteredAt: null,
  metadata: { registrationType: 'cimd' },
  developerId: null,
};
// ANT-2026-O8U3P920: what `POST /api/clients` writes for a self-registered
// developer account. It carries neither DCR nor CIMD marker, which is what the
// earlier negative rule missed.
const DEVELOPER_CLIENT = {
  provisionedByOperator: false,
  dynamicRegisteredAt: null,
  metadata: null,
  developerId: '0190a000-0000-7000-8000-00000000000a',
};

const ERROR = {
  error: 'login_required',
  error_description: 'authentication is required but prompt=none was requested',
  state: 'st-1',
  iss: 'https://auth.example.com',
};

describe('isOperatorProvisionedClient', () => {
  it('is true only for a client an operator provisioned', () => {
    expect(isOperatorProvisionedClient(OPERATOR_CLIENT)).toBe(true);
  });

  it.each([
    ['an open-DCR client', DCR_CLIENT],
    ['a CIMD client', CIMD_CLIENT],
    ['a client a developer created through POST /api/clients', DEVELOPER_CLIENT],
  ])('is false for %s', (_label, client) => {
    expect(isOperatorProvisionedClient(client)).toBe(false);
  });

  it('fails closed when the marker is missing or not a strict true', () => {
    // A row with no marker (no DCR/CIMD field either) used to read as trusted.
    expect(isOperatorProvisionedClient({})).toBe(false);
    expect(isOperatorProvisionedClient({ provisionedByOperator: null })).toBe(false);
    expect(
      isOperatorProvisionedClient({ provisionedByOperator: 'true' as unknown as boolean })
    ).toBe(false);
  });
});

describe('sendAuthorizationError', () => {
  it('redirects an operator-provisioned client automatically (RFC 6749 §4.1.2.1)', () => {
    const { reply, state } = createReply();
    sendAuthorizationError(reply, OPERATOR_CLIENT, 'https://app.example.com/cb', ERROR);
    expect(state.statusCode).toBe(302);
    const location = new URL(state.redirected as string);
    expect(location.origin + location.pathname).toBe('https://app.example.com/cb');
    expect(location.searchParams.get('error')).toBe('login_required');
    expect(location.searchParams.get('iss')).toBe('https://auth.example.com');
  });

  it.each([
    ['a dynamically registered client', DCR_CLIENT],
    ['a CIMD client', CIMD_CLIENT],
    ['a client a developer created through POST /api/clients', DEVELOPER_CLIENT],
    ['a client with no provisioning marker at all', {}],
  ])('never redirects %s automatically: the user is told where they would go', (_l, client) => {
    // RFC 9700 §4.11.2: redirect automatically only to a URI the AS trusts.
    const { reply, state } = createReply();
    sendAuthorizationError(reply, client, 'https://login-qauth.attacker.example/sign-in', ERROR);

    expect(state.redirected).toBeUndefined();
    expect(state.statusCode).toBe(400);
    expect(state.headers['Content-Type']).toContain('text/html');
    expect(state.headers['Cache-Control']).toBe('no-store');
    const body = state.body as string;
    expect(body).toContain('login-qauth.attacker.example');
    expect(body).toContain('<code>login_required</code>');
    // The full error response is one deliberate click away, so a legitimate
    // client still receives it.
    const href = /<a href="([^"]+)"/.exec(body)?.[1]?.replace(/&amp;/g, '&');
    const target = new URL(href as string);
    expect(target.host).toBe('login-qauth.attacker.example');
    expect(target.searchParams.get('error')).toBe('login_required');
    expect(target.searchParams.get('state')).toBe('st-1');
    expect(target.searchParams.get('iss')).toBe('https://auth.example.com');
  });

  it('escapes what the client controls', () => {
    const { reply, state } = createReply();
    sendAuthorizationError(reply, DCR_CLIENT, 'https://app.example.com/cb', {
      ...ERROR,
      state: '"><script>alert(1)</script>',
    });
    const body = state.body as string;
    expect(body).not.toContain('<script>');
  });

  it('offers no link to a redirect URI whose scheme is not http(s)', () => {
    // DCR accepts custom-scheme (native app) redirect URIs; one is never
    // rendered as a clickable link built from client-supplied data.
    const { reply, state } = createReply();
    sendAuthorizationError(reply, DCR_CLIENT, 'com.example.app:/cb', ERROR);
    const body = state.body as string;
    expect(state.statusCode).toBe(400);
    expect(body).not.toContain('<a ');
  });
});

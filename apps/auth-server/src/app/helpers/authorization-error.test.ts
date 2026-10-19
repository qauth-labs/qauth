import type { FastifyReply } from 'fastify';
import { describe, expect, it, vi } from 'vitest';

vi.mock('../../config/env', () => ({
  env: {
    DYNAMIC_CLIENT_BADGE_DAYS: 30,
  },
}));

import { isSelfRegisteredClient, sendAuthorizationError } from './authorization-error';

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

const OPERATOR_CLIENT = { dynamicRegisteredAt: null, metadata: null };
const DCR_CLIENT = { dynamicRegisteredAt: Date.now() - 400 * DAY, metadata: null };
const CIMD_CLIENT = { dynamicRegisteredAt: null, metadata: { registrationType: 'cimd' } };

const ERROR = {
  error: 'login_required',
  error_description: 'authentication is required but prompt=none was requested',
  state: 'st-1',
  iss: 'https://auth.example.com',
};

describe('isSelfRegisteredClient', () => {
  it('an operator-provisioned or developer-portal client is not self-registered', () => {
    expect(isSelfRegisteredClient(OPERATOR_CLIENT)).toBe(false);
    expect(isSelfRegisteredClient({ dynamicRegisteredAt: null })).toBe(false);
  });

  it('a dynamically registered client is self-registered at any age', () => {
    expect(isSelfRegisteredClient({ ...DCR_CLIENT, dynamicRegisteredAt: Date.now() })).toBe(true);
    // Long past DYNAMIC_CLIENT_BADGE_DAYS: who registered it has not changed.
    expect(isSelfRegisteredClient(DCR_CLIENT)).toBe(true);
    expect(
      isSelfRegisteredClient({
        dynamicRegisteredAt: null,
        metadata: { registrationType: 'dynamic' },
      })
    ).toBe(true);
  });

  it('a CIMD client is self-registered (its document is the registration)', () => {
    expect(isSelfRegisteredClient(CIMD_CLIENT)).toBe(true);
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

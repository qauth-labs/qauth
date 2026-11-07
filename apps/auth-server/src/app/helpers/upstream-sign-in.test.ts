import { createHash } from 'node:crypto';

import { FLOW_COOKIE_NAME } from '@qauth-labs/shared-interaction-contract';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { fixturePluginMethod } from '../../testing/auth-method-plugins';
import { testRealm } from '../../testing/request-realm';
import { flowBindingOf, mintFlowSecret } from './flow-cookie';
import type { UpstreamProviderCatalog } from './upstream-providers';
import { lookUpAccount, upstreamRouteHost } from './upstream-sign-in';
import { emitUserEvent } from './user-events';

vi.mock('../../config/env', () => ({
  env: {
    NODE_ENV: 'test',
    LOGIN_RATE_LIMIT: 5,
    LOGIN_RATE_WINDOW: 900,
    REGISTRATION_RATE_LIMIT: 3,
    REGISTRATION_RATE_WINDOW: 3600,
  },
}));

vi.mock('./user-events', () => ({ emitUserEvent: vi.fn(async () => undefined) }));

/**
 * The callback host of the upstream sign-in flow (#639): what a provider's
 * start left pending is handed only to the browser whose flow cookie the
 * start bound, once. A callback replayed in another browser, or forged,
 * spends nothing; a callback with nothing pending, a cancel and a provider
 * error never reach the client.
 */
describe('upstreamRouteHost (#639)', () => {
  const REALM = testRealm({ id: 'realm-1' });
  const BINDING = 'b'.repeat(43);
  const WAY_BACK = '/oauth/authorize?client_id=app&response_type=code';
  const method = fixturePluginMethod({ type: 'oidc_corp' });
  const store = new Map<string, string>();
  const redis = {
    get: vi.fn(async (key: string) => store.get(key) ?? null),
    getdel: vi.fn(async (key: string) => {
      const value = store.get(key) ?? null;
      store.delete(key);
      return value;
    }),
    set: vi.fn(async (key: string, value: string) => {
      store.set(key, value);
      return 'OK';
    }),
  };
  const catalog: UpstreamProviderCatalog = {
    offered: vi.fn(async () => []),
    find: vi.fn(async (_realmId: string, type: string) =>
      type === method.type
        ? {
            entry: { provider: method.type, name: 'Example Corp' },
            method,
            hidden: false,
            marksVerified: true,
            context: async () => {
              throw new Error('no context in this test');
            },
          }
        : undefined
    ),
  };
  const host = upstreamRouteHost({ redis, log: { error: vi.fn(), warn: vi.fn() } } as never, {
    catalog,
    engines: () => {
      throw new Error('no engine in this test');
    },
  });

  /** What a start of `type` left pending, bound to the flow cookie `secret`. */
  function park(secret: string, type = method.type): string {
    const key = `upstream-sign-in:${REALM.id}:${createHash('sha256').update(BINDING).digest('hex')}`;
    store.set(
      key,
      JSON.stringify({
        v: 1,
        realmId: REALM.id,
        type,
        binding: BINDING,
        transaction: { state: 'state-1', nonce: 'nonce-1', codeVerifier: 'verifier-1' },
        interactionId: 'i'.repeat(43),
        revision: 1,
        flowBinding: flowBindingOf(secret),
        mode: 'pages',
        wayBack: WAY_BACK,
      })
    );
    return key;
  }

  /** A callback request in a browser holding the flow cookie `secret`, or none. */
  function callback(secret?: string): FastifyRequest {
    return {
      headers: secret === undefined ? {} : { cookie: `${FLOW_COOKIE_NAME}=${secret}` },
      realm: REALM,
      id: 'req-639',
      log: { error: vi.fn(), warn: vi.fn(), info: vi.fn() },
    } as unknown as FastifyRequest;
  }

  function reply() {
    const sent: { status?: number; body?: string; headers: Record<string, string> } = {
      headers: {},
    };
    const value = {
      cspNonce: { script: 'script-nonce', style: 'style-nonce' },
      header: vi.fn((name: string, header: string) => {
        sent.headers[name.toLowerCase()] = header;
        return value;
      }),
      code: vi.fn((status: number) => {
        sent.status = status;
        return value;
      }),
      send: vi.fn((body: string) => {
        sent.body = body;
        return value;
      }),
      redirect: vi.fn(),
    };
    return { reply: value as unknown as FastifyReply, sent, redirect: value.redirect };
  }

  beforeEach(() => {
    store.clear();
    redis.getdel.mockClear();
    vi.mocked(emitUserEvent).mockClear();
  });

  it('hands the pending sign-in once, to the browser whose flow cookie its start bound', async () => {
    const secret = mintFlowSecret();
    park(secret);

    expect(await host.peekTransaction(method, callback(secret), BINDING)).toEqual({
      binding: BINDING,
      transaction: { state: 'state-1', nonce: 'nonce-1', codeVerifier: 'verifier-1' },
    });
    expect(await host.takeTransaction(method, callback(secret), BINDING)).toMatchObject({
      binding: BINDING,
    });
    // Taken: a second callback with the same state finds nothing.
    expect(await host.takeTransaction(method, callback(secret), BINDING)).toBeUndefined();
  });

  it('leaves it alone for a callback replayed in another browser', async () => {
    const secret = mintFlowSecret();
    const key = park(secret);

    for (const other of [mintFlowSecret(), undefined]) {
      expect(await host.peekTransaction(method, callback(other), BINDING)).toBeUndefined();
      expect(await host.takeTransaction(method, callback(other), BINDING)).toBeUndefined();
    }
    expect(store.has(key)).toBe(true);
    expect(redis.getdel).not.toHaveBeenCalledWith(key);
    // The browser that started it still completes it.
    expect(await host.takeTransaction(method, callback(secret), BINDING)).toBeDefined();
  });

  it('never hands one to another provider, or for another binding', async () => {
    const secret = mintFlowSecret();
    park(secret, 'oidc_other');

    expect(await host.takeTransaction(method, callback(secret), BINDING)).toBeUndefined();
    expect(await host.takeTransaction(method, callback(secret), 'c'.repeat(43))).toBeUndefined();
    expect(await host.takeTransaction(method, callback(secret), undefined)).toBeUndefined();
  });

  it('answers a callback with nothing pending with the error page and its trace id, audited', async () => {
    const { reply: answer, sent, redirect } = reply();
    await host.complete(
      method,
      { kind: 'failed', reason: 'transaction_mismatch' },
      callback(mintFlowSecret()),
      answer
    );

    expect(sent.status).toBe(400);
    expect(sent.body).toContain('We could not sign you in');
    expect(sent.body).toContain('<code>req-639</code>');
    expect(redirect).not.toHaveBeenCalled();
    expect(vi.mocked(emitUserEvent)).toHaveBeenCalledWith(
      expect.anything(),
      'urn:qauth:event:user.sign_in_failed:v1-rc.0',
      { method: 'upstream', reason: 'transaction_mismatch' },
      expect.objectContaining({ realmId: REALM.id, userId: null, actor: 'user' })
    );
  });

  it.each([
    ['a cancel at the provider (access_denied)', { kind: 'declined' }, 'declined'],
    [
      'an error the provider answered',
      { kind: 'failed', reason: 'provider_error' },
      'provider_error',
    ],
  ])(
    'shows the provider-error page for %s, with the way back, and sends nothing to the client',
    async (_label, outcome, reason) => {
      const secret = mintFlowSecret();
      park(secret);
      const request = callback(secret);
      await host.takeTransaction(method, request, BINDING);
      const { reply: answer, sent, redirect } = reply();

      await host.complete(method, outcome, request, answer);

      expect(sent.status).toBe(200);
      expect(sent.body).toContain('Sign-in was not completed');
      expect(sent.body).toContain('Example Corp did not sign you in');
      expect(sent.body).toContain(`href="${WAY_BACK.replace(/&/g, '&amp;')}"`);
      expect(sent.headers['cache-control']).toBe('no-store');
      expect(redirect).not.toHaveBeenCalled();
      expect(vi.mocked(emitUserEvent)).toHaveBeenCalledWith(
        expect.anything(),
        'urn:qauth:event:user.sign_in_failed:v1-rc.0',
        { method: 'upstream', reason },
        expect.objectContaining({ realmId: REALM.id })
      );
    }
  );

  it("finds the realm's provider for a copy of its method, as a plugin's routes are mounted from", async () => {
    // The provider registry mounts a plugin's routes from a frozen snapshot of
    // its method, another object than the one the catalog holds.
    const snapshot = Object.freeze({ ...method });
    const secret = mintFlowSecret();
    park(secret);
    const request = callback(secret);
    await host.takeTransaction(snapshot, request, BINDING);
    const { reply: answer, sent } = reply();

    await host.complete(snapshot, { kind: 'declined' }, request, answer);

    expect(sent.status).toBe(200);
    expect(sent.body).toContain('Example Corp did not sign you in');
  });
});

/**
 * The callback's account lookup (#639, #670): the identity's account is found
 * by the realm, the provider's type and its subject alone. The repositories
 * here hold only those two reads, so a read of an address, an attribute or a
 * password credential fails the test: nothing finds an account to sign in to,
 * or to link to, by an email address.
 */
describe('lookUpAccount (#639, #670)', () => {
  const REALM = testRealm({ id: 'realm-1' });
  const SUBJECT = { externalSub: 'corp-user-1', iss: 'https://idp.example' };
  const request = { log: { error: vi.fn() } } as unknown as FastifyRequest;

  function server(credential: Record<string, unknown> | undefined) {
    const findByRealmProviderSub = vi.fn(async () => credential);
    const findById = vi.fn(async (_realmId: string, id: string) => ({ id, enabled: true }));
    const fastify = {
      repositories: { userCredentials: { findByRealmProviderSub }, users: { findById } },
    } as unknown as FastifyInstance;
    return { fastify, findByRealmProviderSub, findById };
  }

  it('reads the credential of the provider type and subject, and no other, for an unknown identity', async () => {
    const { fastify, findByRealmProviderSub, findById } = server(undefined);

    expect(await lookUpAccount(fastify, request, REALM, 'oidc_corp', SUBJECT)).toBeNull();

    expect(findByRealmProviderSub.mock.calls).toEqual([[REALM.id, 'oidc_corp', 'corp-user-1']]);
    expect(findById).not.toHaveBeenCalled();
  });

  it('answers the account that holds the identity under its issuer', async () => {
    const { fastify, findByRealmProviderSub, findById } = server({
      id: 'cred-1',
      userId: 'user-1',
      disabledAt: null,
      credentialData: { kind: 'upstream', iss: SUBJECT.iss, verified: true },
    });

    expect(await lookUpAccount(fastify, request, REALM, 'oidc_corp', SUBJECT)).toEqual({
      kind: 'account',
      userId: 'user-1',
      enabled: true,
      verified: true,
      created: false,
    });
    expect(findByRealmProviderSub.mock.calls).toEqual([[REALM.id, 'oidc_corp', 'corp-user-1']]);
    expect(findById.mock.calls).toEqual([[REALM.id, 'user-1']]);
  });
});

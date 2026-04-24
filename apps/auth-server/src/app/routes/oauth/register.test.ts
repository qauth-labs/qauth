import { BadRequestError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { describe, expect, it, type Mock, vi } from 'vitest';

vi.mock('../../../config/env', () => ({
  env: {
    DATABASE_URL: 'postgresql://test:test@localhost:5432/test',
    EMAIL_FROM_ADDRESS: 'noreply@example.com',
    EMAIL_BASE_URL: 'http://localhost:3000',
    DEFAULT_REALM_NAME: 'master',
    REGISTER_CLIENT_RATE_LIMIT: 30,
    REGISTER_CLIENT_RATE_WINDOW: 60,
    DEFAULT_DYNAMIC_REGISTRATION_SCOPES: ['openid', 'profile', 'email', 'offline_access'],
  },
}));

import registerRoute from './register';

interface TestContext {
  handler?: (request: any, reply: any) => Promise<unknown>;
}

function createReply() {
  const state: { statusCode: number; body: unknown; headers: Record<string, string> } = {
    statusCode: 200,
    body: undefined,
    headers: {},
  };
  const reply = {
    code(n: number) {
      state.statusCode = n;
      return reply;
    },
    header(k: string, v: string) {
      state.headers[k] = v;
      return reply;
    },
    send(body: unknown) {
      state.body = body;
      return body;
    },
  } as const;
  return { reply, state };
}

function createFastifyStub(
  realmOverrides: Partial<{
    dynamicRegistrationAllowedScopes: string[];
  }> = {}
) {
  const ctx: TestContext = {};

  const realm = {
    id: 'realm-1',
    name: 'master',
    enabled: true,
    dynamicRegistrationAllowedScopes: realmOverrides.dynamicRegistrationAllowedScopes ?? [
      'openid',
      'profile',
      'email',
      'offline_access',
    ],
  };

  const createdClients: any[] = [];
  const auditLogs: any[] = [];

  const fastify: any = {
    withTypeProvider: () => ({
      post: (
        _url: string,
        _opts: unknown,
        handler: (request: any, reply: any) => Promise<unknown>
      ) => {
        ctx.handler = handler;
        return fastify;
      },
    }),
    repositories: {
      realms: {
        findByName: vi.fn().mockResolvedValue(realm),
        update: vi.fn().mockResolvedValue({ ...realm }),
        create: vi.fn(),
      },
      oauthClients: {
        create: vi.fn(async (row: any) => {
          const persisted = {
            ...row,
            id: `client-row-${createdClients.length + 1}`,
            createdAt: 1_700_000_000_000,
            updatedAt: 1_700_000_000_000,
          };
          createdClients.push(persisted);
          return persisted;
        }),
      },
      auditLogs: {
        create: vi.fn(async (row: any) => {
          auditLogs.push(row);
          return row;
        }),
      },
    },
    passwordHasher: {
      hashPassword: vi.fn(async (v: string) => `argon2id$${v.slice(0, 8)}`),
    },
    log: {
      debug: vi.fn(),
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
    },
  };

  return {
    fastify: fastify as FastifyInstance,
    ctx,
    state: { createdClients, auditLogs, realm },
  };
}

describe('POST /oauth/register — Dynamic Client Registration (RFC 7591)', () => {
  it('creates a public client for the happy-path authorization_code flow', async () => {
    const { fastify, ctx, state } = createFastifyStub();
    await registerRoute(fastify);
    const handler = ctx.handler;
    expect(handler).toBeDefined();

    const { reply, state: replyState } = createReply();

    const result = await handler!(
      {
        body: {
          client_name: 'My MCP Client',
          redirect_uris: ['https://client.example/callback'],
          grant_types: ['authorization_code', 'refresh_token'],
          response_types: ['code'],
          scope: 'openid email',
        },
        ip: '127.0.0.1',
        headers: { 'user-agent': 'vitest' },
      },
      reply
    );

    expect(replyState.statusCode).toBe(201);
    expect(replyState.headers['Cache-Control']).toBe('no-store');
    expect(result).toMatchObject({
      client_id: expect.stringMatching(/[0-9a-f-]{36}/),
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      scope: 'openid email',
      client_name: 'My MCP Client',
      redirect_uris: ['https://client.example/callback'],
      client_id_issued_at: Math.floor(1_700_000_000_000 / 1000),
    });
    // Public client → no secret in response
    expect(result).not.toHaveProperty('client_secret');
    expect(result).not.toHaveProperty('client_secret_expires_at');

    // Persisted row reflects public-client posture
    const persisted = state.createdClients[0];
    expect(persisted.tokenEndpointAuthMethod).toBe('none');
    expect(persisted.requirePkce).toBe(true);
    expect(persisted.realmId).toBe('realm-1');

    // Audit log written
    expect(state.auditLogs[0]).toMatchObject({
      event: 'oauth.client.registered',
      eventType: 'client',
      success: true,
    });
  });

  it('returns a plaintext client_secret exactly once for confidential clients', async () => {
    const { fastify, ctx } = createFastifyStub();
    await registerRoute(fastify);

    const { reply } = createReply();
    const result = (await ctx.handler!(
      {
        body: {
          client_name: 'Confidential Service',
          redirect_uris: ['https://svc.example/cb'],
          grant_types: ['authorization_code', 'refresh_token'],
          response_types: ['code'],
          token_endpoint_auth_method: 'client_secret_basic',
        },
        ip: '127.0.0.1',
        headers: {},
      },
      reply
    )) as Record<string, unknown>;

    expect(result.token_endpoint_auth_method).toBe('client_secret_basic');
    expect(typeof result.client_secret).toBe('string');
    expect((result.client_secret as string).length).toBeGreaterThanOrEqual(32);
    expect(result.client_secret_expires_at).toBe(0);
  });

  it('rejects scopes outside the realm allowlist (scope cap)', async () => {
    const { fastify, ctx } = createFastifyStub();
    await registerRoute(fastify);

    const { reply } = createReply();

    await expect(
      ctx.handler!(
        {
          body: {
            redirect_uris: ['https://app.example/cb'],
            grant_types: ['authorization_code'],
            response_types: ['code'],
            scope: 'openid memory:admin',
          },
          ip: '127.0.0.1',
          headers: {},
        },
        reply
      )
    ).rejects.toBeInstanceOf(BadRequestError);
  });

  it('rejects http:// redirect_uris for non-loopback hosts (OAuth 2.1 §10.3)', async () => {
    const { fastify, ctx } = createFastifyStub();
    await registerRoute(fastify);

    const { reply } = createReply();

    await expect(
      ctx.handler!(
        {
          body: {
            redirect_uris: ['http://app.example/cb'],
            grant_types: ['authorization_code'],
            response_types: ['code'],
          },
          ip: '127.0.0.1',
          headers: {},
        },
        reply
      )
    ).rejects.toThrow(/invalid_redirect_uri/);
  });

  it('rejects client_credentials with token_endpoint_auth_method=none', async () => {
    const { fastify, ctx } = createFastifyStub();
    await registerRoute(fastify);

    const { reply } = createReply();

    await expect(
      ctx.handler!(
        {
          body: {
            grant_types: ['client_credentials'],
            response_types: [],
            token_endpoint_auth_method: 'none',
          },
          ip: '127.0.0.1',
          headers: {},
        },
        reply
      )
    ).rejects.toThrow(/invalid_client_metadata/);
  });

  it('strips unrecognized fields (application_type, custom_ext) without error (RFC 7591 §3.2)', async () => {
    const { fastify, ctx } = createFastifyStub();
    await registerRoute(fastify);

    const { reply } = createReply();
    const result = (await ctx.handler!(
      {
        body: {
          client_name: 'test-native-client',
          redirect_uris: ['http://localhost:54545/callback'],
          grant_types: ['authorization_code', 'refresh_token'],
          response_types: ['code'],
          token_endpoint_auth_method: 'none',
          scope: 'openid',
          application_type: 'native',
          'x-custom-extension': 'value',
        },
        ip: '127.0.0.1',
        headers: {},
      },
      reply
    )) as Record<string, unknown>;

    expect(result.client_id).toBeDefined();
    expect('client_secret' in result).toBe(false);
    expect('application_type' in result).toBe(false);
  });

  it('seeds the realm default allowlist on first use when empty', async () => {
    const { fastify, ctx, state } = createFastifyStub({
      dynamicRegistrationAllowedScopes: [],
    });
    await registerRoute(fastify);

    const { reply } = createReply();
    const result = (await ctx.handler!(
      {
        body: {
          redirect_uris: ['https://app.example/cb'],
          scope: 'openid profile',
        },
        ip: '127.0.0.1',
        headers: {},
      },
      reply
    )) as Record<string, unknown>;

    // Scope accepted → default allowlist must have been seeded
    expect(result.scope).toBe('openid profile');
    expect((fastify.repositories.realms.update as unknown as Mock).mock.calls[0][1]).toMatchObject({
      dynamicRegistrationAllowedScopes: ['openid', 'profile', 'email', 'offline_access'],
    });
    expect(state.realm.id).toBe('realm-1');
  });
});

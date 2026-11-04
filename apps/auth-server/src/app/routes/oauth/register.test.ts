import { EgressError } from '@qauth-labs/fastify-plugin-egress';
import {
  ForbiddenError,
  InvalidClientMetadataError,
  InvalidRedirectUriError,
  MisdirectedRequestError,
} from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { afterEach, beforeEach, describe, expect, it, type Mock, vi } from 'vitest';

import { testRealm } from '../../../testing/request-realm';
import { emitUserEvent } from '../../helpers/user-events';

vi.mock('../../helpers/user-events', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../helpers/user-events')>();
  const { checkedEmitUserEvent } = await import('../../../testing/user-events');
  return { ...actual, emitUserEvent: vi.fn(checkedEmitUserEvent(actual.userEventFor)) };
});

const emitUserEventMock = vi.mocked(emitUserEvent);

beforeEach(() => {
  emitUserEventMock.mockClear();
});

vi.mock('../../../config/env', () => ({
  env: {
    DATABASE_URL: 'postgresql://test:test@localhost:5432/test',
    EMAIL_FROM_ADDRESS: 'noreply@example.com',
    EMAIL_BASE_URL: 'http://localhost:3000',
    DEFAULT_REALM_NAME: 'master',
    REGISTER_CLIENT_RATE_LIMIT: 30,
    REGISTER_CLIENT_RATE_WINDOW: 60,
    DEFAULT_DYNAMIC_REGISTRATION_SCOPES: ['openid', 'profile', 'email', 'offline_access'],
    MAX_CLIENTS_PER_DEVELOPER: 3,
    REDIRECT_URI_CUSTOM_SCHEMES: [] as string[],
  },
}));

// Attribution has its own tests (helpers/registration-attribution.test.ts).
// Here it is a seam: anonymous by default, a developer when a test says so.
const { resolveDeveloperId } = vi.hoisted(() => ({
  resolveDeveloperId: vi.fn(async (): Promise<string | null> => null),
}));
vi.mock('../../helpers/registration-attribution', () => ({
  resolveRegistrationDeveloperId: resolveDeveloperId,
}));

import { env } from '../../../config/env';
import { dynamicClientRegistrationRequestSchema } from '../../schemas/oauth';
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

/** What the egress client throws for a host whose address it refuses. */
function egressRefusal(): EgressError {
  return new EgressError({
    reason: 'address',
    outcome: 'blocked',
    purpose: 'backchannel-logout',
    host: 'app.example',
    message: 'blocked: address',
  });
}

function createFastifyStub(
  realmOverrides: Partial<{
    dynamicRegistrationAllowedScopes: string[];
  }> = {}
) {
  const ctx: TestContext = {};

  const realm = testRealm({
    id: 'realm-1',
    dynamicRegistrationAllowedScopes: realmOverrides.dynamicRegistrationAllowedScopes ?? [
      'openid',
      'profile',
      'email',
      'offline_access',
    ],
  });

  const createdClients: any[] = [];

  const fastify: any = {
    withTypeProvider: () => ({
      post: (
        _url: string,
        _opts: unknown,
        handler: (request: any, reply: any) => Promise<unknown>
      ) => {
        ctx.handler = (request, reply) => {
          // The realm resolver's decoration (#486): a request reaches its
          // handler with the realm of its host.
          request.realm ??= realm;
          return handler(request, reply);
        };
        return fastify;
      },
    }),
    repositories: {
      realms: {
        // The allowlist is read from the database row (#487).
        findById: vi.fn().mockResolvedValue(realm),
        update: vi.fn().mockResolvedValue({ ...realm }),
      },
      oauthClients: {
        countByDeveloper: vi.fn(async () => 0),
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
    },
    passwordHasher: {
      hashPassword: vi.fn(async (v: string) => `argon2id$${v.slice(0, 8)}`),
    },
    // The egress client's address check (#624): every host public unless a
    // test refuses it.
    egress: {
      validateDestination: vi.fn(async (url: string) => ({
        url,
        host: new URL(url).hostname,
        port: 443,
        addresses: ['203.0.113.10'],
      })),
    },
    // A realm with no policies yet is capped with its fill's list (#516).
    policyStore: {
      ofRealm: vi.fn(() => ({
        policies: { registration: { dynamicRegistrationAllowedScopes: ['openid', 'profile'] } },
      })),
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
    state: { createdClients, realm },
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

    // Registration event recorded: the new client is its subject and actor.
    const clientId = (result as { client_id: string }).client_id;
    expect(emitUserEventMock).toHaveBeenCalledTimes(1);
    expect(emitUserEventMock).toHaveBeenCalledWith(
      expect.anything(),
      'urn:qauth:event:client.created:v1-rc.0',
      {
        registration: 'dynamic',
        isPublic: true,
        isAgent: false,
        grantTypes: ['authorization_code', 'refresh_token'],
        scopes: ['openid', 'email'],
        authMethod: 'none',
      },
      {
        realmId: 'realm-1',
        subject: { type: 'client', id: clientId },
        clientId,
        actor: 'client',
      }
    );
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

  it('caps scopes outside the realm allowlist instead of rejecting (RFC 7591 §2)', async () => {
    const { fastify, ctx } = createFastifyStub();
    await registerRoute(fastify);

    const { reply } = createReply();

    // A discover-then-register MCP client echoes back the resource's full
    // advertised `scopes_supported`, which can include privileged scopes a
    // public dynamic client may not hold (here `example:admin`). Rather than
    // failing the whole registration, we register the permitted subset.
    const result = (await ctx.handler!(
      {
        body: {
          redirect_uris: ['https://app.example/cb'],
          grant_types: ['authorization_code'],
          response_types: ['code'],
          scope: 'openid example:admin',
        },
        ip: '127.0.0.1',
        headers: {},
      },
      reply
    )) as Record<string, unknown>;

    expect(result.client_id).toBeDefined();
    expect(result.scope).toBe('openid');
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
    ).rejects.toBeInstanceOf(InvalidRedirectUriError);
  });

  // Found while fixing the findings of scan qauth-20261015-005.
  it.each(['javascript:alert(document.domain)', 'data:text/html,hi', 'myapp:/callback'])(
    'rejects the redirect_uri %s: only https, loopback http and private-use schemes',
    async (uri) => {
      const { fastify, ctx, state } = createFastifyStub();
      await registerRoute(fastify);

      await expect(
        ctx.handler!(
          {
            body: { redirect_uris: ['https://app.example/cb', uri] },
            ip: '127.0.0.1',
            headers: {},
          },
          createReply().reply
        )
      ).rejects.toBeInstanceOf(InvalidRedirectUriError);
      expect(state.createdClients).toHaveLength(0);
    }
  );

  describe('REDIRECT_URI_CUSTOM_SCHEMES (#774)', () => {
    const cursorCallback = 'cursor://anysphere.cursor-mcp/oauth/callback';

    afterEach(() => {
      env.REDIRECT_URI_CUSTOM_SCHEMES = [];
    });

    async function registerWith(redirectUri: string) {
      const { fastify, ctx, state } = createFastifyStub();
      await registerRoute(fastify);
      const { reply, state: replyState } = createReply();
      const run = () =>
        ctx.handler!(
          {
            body: { client_name: 'Native MCP Client', redirect_uris: [redirectUri] },
            ip: '127.0.0.1',
            headers: {},
          },
          reply
        );
      return { run, state, replyState };
    }

    it('refuses a bare scheme when the setting is empty', async () => {
      const { run, state } = await registerWith(cursorCallback);
      await expect(run()).rejects.toBeInstanceOf(InvalidRedirectUriError);
      expect(state.createdClients).toHaveLength(0);
    });

    it('registers a client whose redirect URI uses a listed bare scheme', async () => {
      env.REDIRECT_URI_CUSTOM_SCHEMES = ['cursor'];
      const { run, state, replyState } = await registerWith(cursorCallback);
      await expect(run()).resolves.toMatchObject({ redirect_uris: [cursorCallback] });
      expect(replyState.statusCode).toBe(201);
      expect(state.createdClients).toHaveLength(1);
      expect(state.createdClients[0].redirectUris).toEqual([cursorCallback]);
    });

    it('still refuses a bare scheme that is not listed', async () => {
      env.REDIRECT_URI_CUSTOM_SCHEMES = ['cursor'];
      const { run, state } = await registerWith('myapp:/callback');
      await expect(run()).rejects.toBeInstanceOf(InvalidRedirectUriError);
      expect(state.createdClients).toHaveLength(0);
    });
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
    ).rejects.toBeInstanceOf(InvalidClientMetadataError);
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

  it('registers an agent client and round-trips the is_agent flag (ADR-007 §2)', async () => {
    const { fastify, ctx, state } = createFastifyStub();
    await registerRoute(fastify);

    const { reply } = createReply();
    const result = (await ctx.handler!(
      {
        body: {
          client_name: 'Autonomous Agent',
          redirect_uris: ['https://agent.example/callback'],
          grant_types: ['authorization_code', 'refresh_token'],
          response_types: ['code'],
          scope: 'openid',
          is_agent: true,
        },
        ip: '127.0.0.1',
        headers: { 'user-agent': 'vitest' },
      },
      reply
    )) as Record<string, unknown>;

    // Echoed back in the registration response.
    expect(result.is_agent).toBe(true);
    // Persisted on the client row.
    expect(state.createdClients[0].isAgent).toBe(true);
    // Captured in the registration event.
    expect(emitUserEventMock).toHaveBeenCalledWith(
      expect.anything(),
      'urn:qauth:event:client.created:v1-rc.0',
      expect.objectContaining({ isAgent: true }),
      expect.anything()
    );
  });

  describe('post_logout_redirect_uris (OpenID Connect RP-Initiated Logout 1.0 §3.1, #675)', () => {
    const registerWith = async (body: Record<string, unknown>) => {
      const { fastify, ctx, state } = createFastifyStub();
      await registerRoute(fastify);
      const result = (await ctx.handler!(
        {
          body: dynamicClientRegistrationRequestSchema.parse({
            redirect_uris: ['https://app.example/cb'],
            ...body,
          }),
          ip: '127.0.0.1',
          headers: {},
        },
        createReply().reply
      )) as Record<string, unknown>;
      return { result, state };
    };

    it('stores the list and echoes it in the response (RFC 7591 §3.2.1)', async () => {
      const uris = ['https://app.example/signed-out', 'com.example.app:/signed-out'];
      const { result, state } = await registerWith({ post_logout_redirect_uris: uris });
      expect(state.createdClients[0].postLogoutRedirectUris).toEqual(uris);
      expect(result.post_logout_redirect_uris).toEqual(uris);
    });

    it('stores [] and echoes nothing when the request names none', async () => {
      const { result, state } = await registerWith({});
      expect(state.createdClients[0].postLogoutRedirectUris).toEqual([]);
      expect(result).not.toHaveProperty('post_logout_redirect_uris');
    });

    it('refuses an entry the redirect URI rule refuses, as invalid_client_metadata, and stores nothing', async () => {
      const { fastify, ctx, state } = createFastifyStub();
      await registerRoute(fastify);
      await expect(
        ctx.handler!(
          {
            body: {
              redirect_uris: ['https://app.example/cb'],
              post_logout_redirect_uris: ['https://app.example/bye', 'http://app.example/bye'],
            },
            ip: '127.0.0.1',
            headers: {},
          },
          createReply().reply
        )
      ).rejects.toBeInstanceOf(InvalidClientMetadataError);
      expect(state.createdClients).toHaveLength(0);
    });

    it('bounds the list like redirect_uris at the schema boundary', () => {
      const uris = (count: number) =>
        Array.from({ length: count }, (_, i) => `https://app.example/bye/${i}`);
      expect(
        dynamicClientRegistrationRequestSchema.safeParse({ post_logout_redirect_uris: uris(20) })
          .success
      ).toBe(true);
      expect(
        dynamicClientRegistrationRequestSchema.safeParse({ post_logout_redirect_uris: uris(21) })
          .success
      ).toBe(false);
    });
  });

  describe('backchannel_logout_uri (OpenID Connect Back-Channel Logout 1.0 §2.2, #624)', () => {
    const registerWith = async (
      body: Record<string, unknown>,
      refuse?: (url: string) => Error | undefined
    ) => {
      const { fastify, ctx, state } = createFastifyStub();
      const validateDestination = (fastify as unknown as { egress: { validateDestination: Mock } })
        .egress.validateDestination;
      if (refuse) {
        validateDestination.mockImplementation(async (url: string) => {
          const error = refuse(url);
          if (error) throw error;
          return { url, host: new URL(url).hostname, port: 443, addresses: ['203.0.113.10'] };
        });
      }
      await registerRoute(fastify);
      const run = () =>
        ctx.handler!(
          {
            body: dynamicClientRegistrationRequestSchema.parse({
              redirect_uris: ['https://app.example/cb'],
              ...body,
            }),
            ip: '127.0.0.1',
            headers: {},
          },
          createReply().reply
        ) as Promise<Record<string, unknown>>;
      return { run, state, validateDestination };
    };

    it('stores the URI with the client as its source, and echoes it with the sid flag (RFC 7591 §3.2.1)', async () => {
      const { run, state, validateDestination } = await registerWith({
        backchannel_logout_uri: 'https://app.example/backchannel',
        backchannel_logout_session_required: true,
      });
      const result = await run();
      expect(state.createdClients[0]).toMatchObject({
        backchannelLogoutUri: 'https://app.example/backchannel',
        backchannelLogoutUriSource: 'client',
        backchannelLogoutSessionRequired: true,
      });
      expect(result.backchannel_logout_uri).toBe('https://app.example/backchannel');
      expect(result.backchannel_logout_session_required).toBe(true);
      // A client-registered destination: never the allowlist (ADR-019 Decision 8).
      expect(validateDestination).toHaveBeenCalledWith('https://app.example/backchannel', {
        purpose: 'backchannel-logout',
        source: 'client',
        realm: expect.any(String),
      });
    });

    it('stores none and echoes nothing when the request names none', async () => {
      const { run, state, validateDestination } = await registerWith({
        backchannel_logout_session_required: true,
      });
      const result = await run();
      expect(state.createdClients[0]).toMatchObject({
        backchannelLogoutUri: null,
        backchannelLogoutUriSource: null,
      });
      expect(result).not.toHaveProperty('backchannel_logout_uri');
      expect(validateDestination).not.toHaveBeenCalled();
    });

    it.each([
      ['http://app.example/backchannel', 'must use https'],
      ['https://app.example/backchannel#x', 'must not include a fragment'],
      ['https://user:pw@app.example/backchannel', 'must not carry a user name or password'],
      ['/backchannel', 'is not an absolute URI'],
    ])('refuses %s as invalid_client_metadata and stores nothing', async (uri, problem) => {
      const { run, state, validateDestination } = await registerWith({
        backchannel_logout_uri: uri,
      });
      const error = await run().catch((caught: unknown) => caught);
      expect(error).toBeInstanceOf(InvalidClientMetadataError);
      expect((error as { errorDescription?: string }).errorDescription).toBe(
        `backchannel_logout_uri ${problem}`
      );
      expect(state.createdClients).toHaveLength(0);
      expect(validateDestination).not.toHaveBeenCalled();
    });

    it.each([
      'https://127.0.0.1/backchannel',
      'https://10.0.0.5/backchannel',
      'https://[::1]/backchannel',
      'https://internal.example/backchannel',
    ])(
      'refuses %s, whose address the egress client refuses, even for a development client',
      async (uri) => {
        const { run, state } = await registerWith({ backchannel_logout_uri: uri }, () =>
          egressRefusal()
        );
        const error = await run().catch((caught: unknown) => caught);
        expect(error).toBeInstanceOf(InvalidClientMetadataError);
        expect((error as { errorDescription?: string }).errorDescription).toBe(
          'backchannel_logout_uri must name a host that resolves, and only to public addresses'
        );
        expect(state.createdClients).toHaveLength(0);
      }
    );
  });

  it('defaults to a standard (non-agent) client when is_agent is omitted', async () => {
    const { fastify, ctx, state } = createFastifyStub();
    await registerRoute(fastify);

    const { reply } = createReply();
    const result = (await ctx.handler!(
      {
        body: {
          client_name: 'Standard Client',
          redirect_uris: ['https://app.example/cb'],
          grant_types: ['authorization_code'],
          response_types: ['code'],
        },
        ip: '127.0.0.1',
        headers: {},
      },
      reply
    )) as Record<string, unknown>;

    // Omitted from the response (matches the optional-field echo convention).
    expect('is_agent' in result).toBe(false);
    // Stored as the backward-compatible default.
    expect(state.createdClients[0].isAgent).toBe(false);
  });

  it('ignores a self-asserted environment in the DCR body (ADR-008 §4 — operator-set only)', async () => {
    const { fastify, ctx, state } = createFastifyStub();
    await registerRoute(fastify);

    const { reply } = createReply();
    const result = (await ctx.handler!(
      {
        body: {
          client_name: 'Sneaky Client',
          redirect_uris: ['https://app.example/cb'],
          grant_types: ['authorization_code', 'refresh_token'],
          response_types: ['code'],
          // A client cannot relax itself by self-declaring development:
          // the field is stripped by the schema AND the route forces
          // production. The client must NOT escape production gates.
          environment: 'development',
        },
        ip: '127.0.0.1',
        headers: {},
      },
      reply
    )) as Record<string, unknown>;

    // Never echoed back, and never persisted as the self-asserted value.
    expect('environment' in result).toBe(false);
    expect(state.createdClients[0].environment).toBe('production');
  });

  it('never marks a registration operator-provisioned, whatever the body says (ANT-2026-O8U3P920)', async () => {
    // Only an operator-provisioned client receives authorization errors by
    // automatic redirect; a DCR client registered its redirect URI itself.
    const { fastify, ctx, state } = createFastifyStub();
    await registerRoute(fastify);

    const { reply } = createReply();
    await ctx.handler!(
      {
        body: {
          client_name: 'Sneaky Client',
          redirect_uris: ['https://login-qauth.attacker.example/sign-in'],
          provisioned_by_operator: true,
          provisionedByOperator: true,
        },
        ip: '127.0.0.1',
        headers: {},
      },
      reply
    );

    expect(state.createdClients[0].provisionedByOperator).toBe(false);
  });

  it('never stores a first-party profile, whatever the body says (ADR-017 Decision 2, #631)', async () => {
    // First-partyness is operator-set: dynamic registration writes NULL, and
    // the database refuses a profile on a dynamically registered row.
    const { fastify, ctx, state } = createFastifyStub();
    await registerRoute(fastify);

    const { reply } = createReply();
    await ctx.handler!(
      {
        body: {
          client_name: 'Claims to be ours',
          redirect_uris: ['https://app.example.com/cb'],
          first_party_profile: 'native_backend',
          first_party_policy: { flows: ['login', 'register'], pkce_required: false },
          first_party_reason: 'trust me',
          firstPartyProfile: 'web_redirect',
        },
        ip: '127.0.0.1',
        headers: {},
      },
      reply
    );

    expect(state.createdClients[0]).toMatchObject({
      firstPartyProfile: null,
      firstPartyPolicy: null,
      firstPartyReason: null,
    });
  });

  it('never stores ID-JAG targets from the body (ADR-011, #434 — seed manifest only)', async () => {
    // The targets name foreign authorization servers and MCP servers a client
    // may mint or redeem an ID-JAG for: an operator decision, never the
    // registrant's.
    const { fastify, ctx, state } = createFastifyStub();
    await registerRoute(fastify);

    const { reply } = createReply();
    const result = (await ctx.handler!(
      {
        body: {
          client_name: 'Sneaky Client',
          redirect_uris: ['https://app.example/cb'],
          grant_types: ['authorization_code', 'refresh_token'],
          response_types: ['code'],
          id_jag_targets: ['https://as.partner.example'],
          idJagTargets: ['https://as.partner.example'],
        },
        ip: '127.0.0.1',
        headers: {},
      },
      reply
    )) as Record<string, unknown>;

    expect('id_jag_targets' in result).toBe(false);
    expect(state.createdClients[0].idJagTargets).toEqual([]);
  });

  it('never stores dpop_bound_access_tokens from the body (RFC 9449 §5.2, #480 — seed manifest only)', async () => {
    // RFC 9449 §5.2 registers `dpop_bound_access_tokens` as client metadata;
    // QAuth takes it from the operator alone, so a registration neither sets
    // it nor echoes it.
    const { fastify, ctx, state } = createFastifyStub();
    await registerRoute(fastify);

    const { reply } = createReply();
    const result = (await ctx.handler!(
      {
        body: {
          client_name: 'DPoP Client',
          redirect_uris: ['https://app.example/cb'],
          grant_types: ['authorization_code', 'refresh_token'],
          response_types: ['code'],
          dpop_bound_access_tokens: true,
          dpopBoundAccessTokens: true,
        },
        ip: '127.0.0.1',
        headers: {},
      },
      reply
    )) as Record<string, unknown>;

    expect('dpop_bound_access_tokens' in result).toBe(false);
    expect(state.createdClients[0].dpopBoundAccessTokens).toBe(false);
  });

  it('caps a realm with no policies yet with the list of its fill, and writes nothing (#516)', async () => {
    // The boot step stores the fill, the first node to boot winning: a
    // request that wrote this node's list could overwrite it.
    const { fastify, ctx } = createFastifyStub();
    const current = testRealm({
      id: 'realm-1',
      dynamicRegistrationAllowedScopes: [],
      policiesVersion: 0,
    });
    (fastify.repositories.realms.findById as unknown as Mock).mockResolvedValue(current);
    await registerRoute(fastify);

    const { reply } = createReply();
    const result = (await ctx.handler!(
      {
        body: {
          redirect_uris: ['https://app.example/cb'],
          scope: 'openid profile email',
        },
        ip: '127.0.0.1',
        headers: {},
      },
      reply
    )) as Record<string, unknown>;

    expect(fastify.policyStore.ofRealm).toHaveBeenCalledWith(current);
    expect(result.scope).toBe('openid profile');
    expect(fastify.repositories.realms.update).not.toHaveBeenCalled();
  });

  it('keeps the empty allowlist of a realm that has its policies: the environment only seeds (#516)', async () => {
    const { fastify, ctx } = createFastifyStub({ dynamicRegistrationAllowedScopes: [] });
    (fastify.repositories.realms.findById as unknown as Mock).mockResolvedValue(
      testRealm({ id: 'realm-1', dynamicRegistrationAllowedScopes: [], policiesVersion: 3 })
    );
    await registerRoute(fastify);

    const { reply } = createReply();
    const result = (await ctx.handler!(
      {
        body: { redirect_uris: ['https://app.example/cb'], scope: 'openid profile' },
        ip: '127.0.0.1',
        headers: {},
      },
      reply
    )) as Record<string, unknown>;

    // No scope is allowed, and the list is not rewritten from the environment.
    expect(result.scope ?? '').toBe('');
    expect(fastify.repositories.realms.update).not.toHaveBeenCalled();
  });

  it("reads the request realm's allowlist from the database, not the resolver's row (#487)", async () => {
    // The resolver's row can be up to its cache time old: an allowlist an
    // operator set since must not be overwritten by the first-use seed.
    const { fastify, ctx, state } = createFastifyStub();
    (fastify.repositories.realms.findById as unknown as Mock).mockResolvedValue(
      testRealm({ id: 'realm-tenant', dynamicRegistrationAllowedScopes: ['openid'] })
    );
    await registerRoute(fastify);

    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');
    const { reply } = createReply();
    const result = (await handler(
      {
        body: {
          redirect_uris: ['https://app.example/cb'],
          scope: 'openid profile',
        },
        ip: '127.0.0.1',
        headers: {},
        realm: testRealm({ id: 'realm-tenant', dynamicRegistrationAllowedScopes: [] }),
      },
      reply
    )) as Record<string, unknown>;

    expect(fastify.repositories.realms.findById).toHaveBeenCalledWith('realm-tenant');
    expect(fastify.repositories.realms.update).not.toHaveBeenCalled();
    expect(result.scope).toBe('openid');
    expect(state.createdClients[0].realmId).toBe('realm-tenant');
  });

  it('refuses a realm deleted within the resolver cache time, before the hash (#487)', async () => {
    // The resolver can still hand out the row of a realm deleted since it
    // cached it; the database no longer has it, so no client may be made.
    const { fastify, ctx, state } = createFastifyStub();
    (fastify.repositories.realms.findById as unknown as Mock).mockResolvedValue(undefined);
    await registerRoute(fastify);

    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');
    const { reply } = createReply();
    await expect(
      handler(
        {
          body: {
            redirect_uris: ['https://app.example/cb'],
            scope: 'openid profile',
            token_endpoint_auth_method: 'client_secret_basic',
          },
          ip: '127.0.0.1',
          headers: {},
        },
        reply
      )
    ).rejects.toThrow(MisdirectedRequestError);
    expect(fastify.repositories.realms.update).not.toHaveBeenCalled();
    expect(fastify.passwordHasher.hashPassword).not.toHaveBeenCalled();
    expect(state.createdClients).toHaveLength(0);
  });

  describe('client JWKS is never self-registered (RFC 7591 §2 / #384)', () => {
    it('strips jwks / jwks_uri / private_key_jwt at the schema boundary', () => {
      // The primary control: the request schema does not define these fields,
      // so they never reach the handler on a real request.
      const parsed = dynamicClientRegistrationRequestSchema.parse({
        client_name: 'Sneaky Client',
        redirect_uris: ['https://client.example/cb'],
        jwks: { keys: [{ kty: 'EC', crv: 'P-256', x: 'a', y: 'b' }] },
        jwks_uri: 'https://client.example/jwks.json',
      });
      expect(parsed).not.toHaveProperty('jwks');
      expect(parsed).not.toHaveProperty('jwks_uri');
      expect(
        dynamicClientRegistrationRequestSchema.safeParse({
          token_endpoint_auth_method: 'private_key_jwt',
        }).success
      ).toBe(false);
    });

    it('persists NULL key columns even when the fields reach the handler', async () => {
      // Defence in depth: stripping is a side effect of the schema, not a
      // control. A client must not be able to register, through an
      // unauthenticated endpoint, the keys that authenticate it or a URL the
      // authorization server will dereference — so the columns are pinned.
      const { fastify, ctx, state } = createFastifyStub();
      await registerRoute(fastify);

      const { reply } = createReply();
      await ctx.handler!(
        {
          body: {
            client_name: 'Sneaky Client',
            redirect_uris: ['https://client.example/cb'],
            jwks: { keys: [{ kty: 'EC', crv: 'P-256', x: 'a', y: 'b' }] },
            jwks_uri: 'https://client.example/jwks.json',
          },
          ip: '127.0.0.1',
          headers: {},
        },
        reply
      );

      const persisted = state.createdClients[0];
      expect(persisted.jwks).toBeNull();
      expect(persisted.jwksUri).toBeNull();
      expect(persisted.tokenEndpointAuthMethod).toBe('none');
    });
  });

  describe('clients per developer (MAX_CLIENTS_PER_DEVELOPER)', () => {
    // A registration that carries the developer's token adds a row to the same
    // list `POST /api/clients` does, so it counts against the same maximum.
    const DEVELOPER = '0190a000-0000-7000-8000-00000000000a';
    const registration = {
      body: { client_name: 'One more', redirect_uris: ['https://client.example/cb'] },
      ip: '127.0.0.1',
      headers: {},
    };

    async function register(fastify: FastifyInstance, ctx: TestContext) {
      await registerRoute(fastify);
      const handler = ctx.handler;
      if (!handler) throw new Error('Handler missing');
      // A fresh request per call: the realm decoration is set on it.
      return handler({ ...registration }, createReply().reply);
    }

    it('refuses an attributed registration once the developer owns the maximum', async () => {
      const { fastify, ctx, state } = createFastifyStub();
      (fastify.repositories.oauthClients.countByDeveloper as unknown as Mock).mockResolvedValue(3);
      resolveDeveloperId.mockResolvedValueOnce(DEVELOPER);

      await expect(register(fastify, ctx)).rejects.toThrow(ForbiddenError);
      // Counted in the request's realm (#489): the developer's clients of
      // another realm are not this realm's maximum.
      expect(fastify.repositories.oauthClients.countByDeveloper).toHaveBeenCalledWith(
        'realm-1',
        DEVELOPER
      );
      expect(fastify.passwordHasher.hashPassword).not.toHaveBeenCalled();
      expect(state.createdClients).toHaveLength(0);
    });

    it('does not count an anonymous registration, which belongs to no developer', async () => {
      const { fastify, ctx, state } = createFastifyStub();
      (fastify.repositories.oauthClients.countByDeveloper as unknown as Mock).mockResolvedValue(3);

      await register(fastify, ctx);
      expect(fastify.repositories.oauthClients.countByDeveloper).not.toHaveBeenCalled();
      expect(state.createdClients).toHaveLength(1);
    });
  });
});

/**
 * The RFC 8693 token-exchange grant, from provisioning through to a completed
 * exchange (#381).
 *
 * WHY THIS FILE EXISTS, AND WHY IT MUST NOT BE FOLDED INTO `token.test.ts`.
 *
 * `token.test.ts`'s `setupExchangeStub` takes a `grantTypes?: string[]` and
 * writes it straight onto a stub client object. Every delegation test therefore
 * asserts what the token endpoint does GIVEN a client that already carries the
 * grant — and none of them can observe whether any shipped path is able to put
 * it there. That is exactly how #381 survived: the grant was advertised in
 * `grant_types_supported`, enforced at `POST /oauth/token`, and rejected by DCR,
 * CIMD and the seed manifest alike, so the whole ADR-007 §2 delegation surface
 * was reachable only by writing the `oauth_clients.grant_types` JSONB column out
 * of band.
 *
 * The tests below close that loop. The client used for the exchange is NEVER
 * written as a literal: its `grantTypes` and `isAgent` are read back off the row
 * the REAL `POST /oauth/register` handler passed to `oauthClients.create`. If a
 * provisioning path stops admitting the URN, the exchange test fails with it —
 * which is the property that was missing.
 */
import {
  BadRequestError,
  InvalidClientError,
  UnauthorizedClientError,
} from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { describe, expect, it, vi } from 'vitest';

vi.mock('../../helpers/timing', () => ({
  ensureMinimumResponseTime: vi.fn().mockResolvedValue(undefined),
}));

vi.mock('../../../config/env', () => ({
  env: {
    DATABASE_URL: 'postgresql://test:test@localhost:5432/test',
    EMAIL_FROM_ADDRESS: 'noreply@example.com',
    EMAIL_BASE_URL: 'http://localhost:3000',
    DEFAULT_REALM_NAME: 'master',
    REGISTER_CLIENT_RATE_LIMIT: 30,
    REGISTER_CLIENT_RATE_WINDOW: 60,
    TOKEN_RATE_LIMIT: 60,
    TOKEN_RATE_WINDOW: 60,
    DEFAULT_DYNAMIC_REGISTRATION_SCOPES: ['openid', 'profile', 'email', 'offline_access'],
    // No signing keys here on purpose: `token.ts` reads none at module scope,
    // and the ADR-011 ID-JAG mint/consume paths — the only ones that would need
    // them — stay off. Signing itself is stubbed on `fastify.jwtUtils` below.
    ID_JAG_ENABLED: false,
    ID_JAG_TRUSTED_ISSUERS: {},
  },
}));

import { cimdDocumentSchema, toCimdClientInsert } from '../../helpers/cimd';
import { validateAndNormalize } from '../../helpers/dynamic-client-registration';
import { grantTypeSchema } from '../../schemas/clients';
import {
  dynamicClientRegistrationRequestSchema,
  TOKEN_EXCHANGE_GRANT_TYPE,
} from '../../schemas/oauth';
import registerRoute from './register';
import tokenRoute from './token';

const ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';
const CIMD_CLIENT_ID = 'https://agent.example.com/.well-known/oauth-client';
const SENTINEL_HASH = '$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$ZGlnZXN0';
const AGENT_CLIENT_ID = 'agent-client';
const ISSUER = 'https://auth.example.com';

interface TestContext {
  handler?: (request: any, reply: any) => Promise<unknown>;
  /**
   * The route's own declared options. Captured so the body schema under test is
   * the one `register.ts` actually wires into Fastify, not a second copy
   * imported here that could drift from it.
   */
  opts?: {
    schema?: { body?: { safeParse: (v: unknown) => { success: boolean; data?: unknown } } };
  };
}

function createReply() {
  const reply: any = {
    code: () => reply,
    header: () => reply,
    send: (body: unknown) => body,
  };
  return reply;
}

/* -------------------------------------------------------------------------- */
/*                     Stage 1 — the REAL registration path                    */
/* -------------------------------------------------------------------------- */

function createRegisterStub() {
  const ctx: TestContext = {};
  const createdClients: any[] = [];

  const realm = {
    id: 'realm-1',
    name: 'master',
    enabled: true,
    dynamicRegistrationAllowedScopes: ['openid', 'profile', 'email', 'offline_access'],
  };

  const fastify: any = {
    withTypeProvider: () => ({
      post: (_url: string, opts: any, handler: TestContext['handler']) => {
        ctx.opts = opts;
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
          const persisted = { ...row, id: `client-row-${createdClients.length + 1}` };
          createdClients.push(persisted);
          return persisted;
        }),
      },
      auditLogs: { create: vi.fn(async (row: any) => row) },
    },
    passwordHasher: { hashPassword: vi.fn(async (v: string) => `argon2id$${v.slice(0, 8)}`) },
    log: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  };

  return { fastify: fastify as FastifyInstance, ctx, createdClients };
}

/**
 * Register an agent client through the real DCR handler and hand back the row
 * the handler actually persisted. The returned row — not a literal — is what
 * stage 2 authenticates as.
 */
async function registerAgentThroughDcr(body: Record<string, unknown>) {
  const { fastify, ctx, createdClients } = createRegisterStub();
  await registerRoute(fastify);
  if (!ctx.handler) throw new Error('register handler missing');

  // Fastify validates `schema.body` through the Zod type provider BEFORE the
  // handler ever runs, so calling the handler with a raw object would skip the
  // very allowlist this issue is about — and did, in the first draft of this
  // file: reverting the DCR enum left the headline test green. Run the body
  // through the route's OWN declared schema first, exactly as the type provider
  // does, and fail the way a 400 would.
  const bodySchema = ctx.opts?.schema?.body;
  if (!bodySchema) throw new Error('register route declared no body schema');
  const parsed = bodySchema.safeParse(body);
  if (!parsed.success) {
    throw new BadRequestError('invalid_client_metadata: request body failed schema validation');
  }

  const response = (await ctx.handler(
    { body: parsed.data, ip: '127.0.0.1', headers: {} },
    createReply()
  )) as any;
  return { response, persisted: createdClients[0] };
}

/* -------------------------------------------------------------------------- */
/*                    Stage 2 — the REAL token-exchange path                   */
/* -------------------------------------------------------------------------- */

/**
 * A token-endpoint stub whose client row is supplied by the caller — in the
 * headline test, straight out of stage 1.
 */
function createTokenStub(persistedClient: {
  grantTypes: string[];
  isAgent?: boolean;
  maxAgentMode?: string | null;
}) {
  const ctx: TestContext = {};

  const client = {
    id: 'client-row-1',
    clientId: AGENT_CLIENT_ID,
    clientSecretHash: 'hash',
    enabled: true,
    scopes: [] as string[],
    audience: null,
    tokenEndpointAuthMethod: 'client_secret_post',
    // The two fields under test, taken VERBATIM from what registration
    // persisted. Writing either as a literal here would reintroduce the blind
    // spot this file exists to remove.
    grantTypes: persistedClient.grantTypes,
    isAgent: persistedClient.isAgent,
    maxAgentMode: persistedClient.maxAgentMode ?? null,
  };

  const user = {
    id: 'user-uuid-subject',
    email: 'subject@example.com',
    emailVerified: true,
    enabled: true,
  };

  const subjectPayload = {
    sub: user.id,
    clientId: 'original-app-client',
    scope: 'read:docs',
    aud: ['https://api.example.com', AGENT_CLIENT_ID],
    iss: ISSUER,
    token_use: 'access',
    exp: Math.floor(Date.now() / 1000) + 600,
  };

  const fastify: any = {
    withTypeProvider: () => ({
      post: (_url: string, _opts: unknown, handler: TestContext['handler']) => {
        ctx.handler = handler;
        return fastify;
      },
    }),
    repositories: {
      realms: {
        findByName: vi.fn().mockResolvedValue({ id: 'realm-1', name: 'default', enabled: true }),
        create: vi.fn(),
      },
      oauthClients: { findByClientId: vi.fn().mockResolvedValue(client) },
      authorizationCodes: { findByCode: vi.fn(), markUsed: vi.fn() },
      users: { findById: vi.fn().mockResolvedValue(user) },
      userCredentials: {
        findByUserIdAndType: vi.fn().mockResolvedValue(undefined),
        findByRealmProviderSub: vi.fn().mockResolvedValue(undefined),
      },
      userAttributes: { findVerifiedByUserIdAndKey: vi.fn().mockResolvedValue([]) },
      refreshTokens: {
        create: vi.fn(),
        findByTokenHashIncludingRevoked: vi.fn(),
        revoke: vi.fn(),
        revokeFamily: vi.fn(),
      },
      auditLogs: { create: vi.fn() },
    },
    passwordHasher: { verifyPassword: vi.fn().mockResolvedValue(true) },
    jwtUtils: {
      signAccessToken: vi.fn().mockResolvedValue('delegated.jwt.token'),
      isHybridSigningEnabled: () => false,
      signIdToken: vi.fn(),
      verifyAccessToken: vi.fn().mockResolvedValue(subjectPayload),
      generateRefreshToken: vi.fn(),
      hashRefreshToken: vi.fn((t: string) => `hash:${t}`),
      getAccessTokenLifespan: vi.fn().mockReturnValue(900),
      getRefreshTokenLifespan: vi.fn().mockReturnValue(604800),
      getIssuer: vi.fn().mockReturnValue(ISSUER),
    },
    pkceUtils: { verifyCodeChallenge: vi.fn() },
    sessionUtils: { setSession: vi.fn() },
    redis: { get: vi.fn().mockResolvedValue(null), set: vi.fn().mockResolvedValue('OK') },
    db: { transaction: vi.fn(async (cb: (tx: unknown) => Promise<unknown>) => cb({})) },
    log: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
    metrics: { loginAttempts: { inc: vi.fn() }, tokensIssued: { inc: vi.fn() } },
  };

  return { fastify: fastify as FastifyInstance, ctx, client, user };
}

async function exchange(fastify: FastifyInstance, ctx: TestContext) {
  await tokenRoute(fastify);
  if (!ctx.handler) throw new Error('token handler missing');
  return ctx.handler(
    {
      body: {
        grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
        client_id: AGENT_CLIENT_ID,
        client_secret: 'secret',
        subject_token: 'subject.jwt.token',
        subject_token_type: ACCESS_TOKEN_TYPE,
      },
      ip: '127.0.0.1',
      headers: { 'user-agent': 'vitest' },
    },
    createReply()
  );
}

/* -------------------------------------------------------------------------- */

describe('the token-exchange grant is reachable through a shipped provisioning path (#381)', () => {
  /** The registration body an MCP agent would actually send. */
  const AGENT_REGISTRATION = {
    client_name: 'My Agent',
    grant_types: ['client_credentials', TOKEN_EXCHANGE_GRANT_TYPE],
    // Token-endpoint-only grants take no authorization-endpoint response type;
    // the normalizer rejects `response_types` without `authorization_code`.
    response_types: [],
    token_endpoint_auth_method: 'client_secret_basic',
    is_agent: true,
  };

  it('HEADLINE: a client registered through POST /oauth/register completes an exchange', async () => {
    const { response, persisted } = await registerAgentThroughDcr(AGENT_REGISTRATION);

    // The grant survived validation, normalization and persistence...
    expect(persisted.grantTypes).toContain(TOKEN_EXCHANGE_GRANT_TYPE);
    expect(persisted.isAgent).toBe(true);
    // ...and RFC 7591 §3.2.1 echoes it back, so the client can see it holds it.
    expect(response.grant_types).toContain(TOKEN_EXCHANGE_GRANT_TYPE);

    // Now authenticate as exactly that row. Before #381 this line could not be
    // written at all: no provisioning path produced a row reaching this point.
    const { fastify, ctx, user } = createTokenStub(persisted);
    const result = (await exchange(fastify, ctx)) as any;

    expect(result.access_token).toBe('delegated.jwt.token');
    // RFC 8693 §4.1: sub is the end user, act identifies the acting agent.
    expect(fastify.jwtUtils.signAccessToken).toHaveBeenCalledWith(
      expect.objectContaining({
        sub: user.id,
        act: expect.objectContaining({ sub: AGENT_CLIENT_ID }),
      })
    );
    // No refresh token on a delegated grant.
    expect(result.refresh_token).toBeUndefined();
  });

  it('MUTATION: the same exchange is refused when the persisted row lacks the grant', async () => {
    // Same agent, registered WITHOUT the URN — proving the headline test passes
    // because of the grant and not because every exchange happens to succeed.
    const { persisted } = await registerAgentThroughDcr({
      ...AGENT_REGISTRATION,
      grant_types: ['client_credentials'],
    });
    expect(persisted.grantTypes).not.toContain(TOKEN_EXCHANGE_GRANT_TYPE);

    const { fastify, ctx } = createTokenStub(persisted);
    await expect(exchange(fastify, ctx)).rejects.toThrow(UnauthorizedClientError);
    expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
  });

  it('rejects the grant on a PUBLIC client at registration, not at every exchange', async () => {
    // `POST /oauth/token` authenticates the agent through the confidential
    // client-auth path, so a public client can never complete an exchange.
    // Registering the grant anyway would hand back an unreachable capability —
    // the same failure the `jwt-bearer` exclusion avoids. Mirrors the existing
    // client_credentials + `none` rule.
    expect(() =>
      validateAndNormalize(
        {
          grant_types: [TOKEN_EXCHANGE_GRANT_TYPE],
          response_types: [],
          token_endpoint_auth_method: 'none',
        },
        ['openid']
      )
    ).toThrow(/invalid_client_metadata/);
  });

  it('rejects the grant on a public client through the route, with RFC 7591 shape', async () => {
    await expect(
      registerAgentThroughDcr({
        ...AGENT_REGISTRATION,
        token_endpoint_auth_method: 'none',
      })
    ).rejects.toThrow(BadRequestError);
  });
});

describe('every provisioning path admits the token-exchange grant (#381)', () => {
  it('DCR: the request schema accepts the URN rather than 400-ing on it', () => {
    // RFC 7591 §3.2's ignore-unrecognized-fields behaviour applies to unknown
    // KEYS. `grant_types` is a known key with a constrained enum, so before
    // #381 an out-of-enum member was a hard validation error, not a strip.
    const parsed = dynamicClientRegistrationRequestSchema.safeParse({
      grant_types: ['client_credentials', TOKEN_EXCHANGE_GRANT_TYPE],
      response_types: [],
      token_endpoint_auth_method: 'client_secret_basic',
    });
    expect(parsed.success).toBe(true);
    expect(parsed.success && parsed.data.grant_types).toContain(TOKEN_EXCHANGE_GRANT_TYPE);
  });

  // The seed-manifest path is asserted from the other side of the Nx boundary,
  // in `libs/infra/db/src/lib/schema/grant-type-enum.test.ts`: `apps/auth-server`
  // is deliberately decoupled from `@qauth-labs/infra-db` (see the depConstraints
  // in eslint.config.mjs), so importing the pg enum here to check it would break
  // the layering this project enforces.

  it('developer API: POST /api/clients accepts the URN', () => {
    // This path is strictly more trusted than DCR (it requires an authenticated
    // developer), so refusing here while accepting on DCR would be incoherent.
    expect(grantTypeSchema.safeParse(TOKEN_EXCHANGE_GRANT_TYPE).success).toBe(true);
  });

  it('CIMD: a confidential (private_key_jwt) document keeps the grant', () => {
    const doc = cimdDocumentSchema.parse({
      client_id: CIMD_CLIENT_ID,
      client_name: 'MCP Agent',
      redirect_uris: ['https://agent.example.com/cb'],
      grant_types: ['authorization_code', TOKEN_EXCHANGE_GRANT_TYPE],
      response_types: ['code'],
      token_endpoint_auth_method: 'private_key_jwt',
      jwks: { keys: [{ kty: 'OKP', crv: 'Ed25519', x: 'abc', kid: 'k1' }] },
      is_agent: true,
    });
    const insert = toCimdClientInsert('realm-1', CIMD_CLIENT_ID, doc, SENTINEL_HASH);
    expect(insert.tokenEndpointAuthMethod).toBe('private_key_jwt');
    expect(insert.grantTypes).toContain(TOKEN_EXCHANGE_GRANT_TYPE);
  });

  it('CIMD: a PUBLIC document has the grant dropped, not rejected', () => {
    // CIMD documents describe a client across every AS it talks to, so a grant
    // that is unusable HERE is dropped the way an unimplemented one already is
    // — never a hard rejection of an otherwise fine document.
    const doc = cimdDocumentSchema.parse({
      client_id: CIMD_CLIENT_ID,
      client_name: 'MCP Agent',
      redirect_uris: ['https://agent.example.com/cb'],
      grant_types: ['authorization_code', TOKEN_EXCHANGE_GRANT_TYPE],
      response_types: ['code'],
      token_endpoint_auth_method: 'none',
    });
    const insert = toCimdClientInsert('realm-1', CIMD_CLIENT_ID, doc, SENTINEL_HASH);
    expect(insert.tokenEndpointAuthMethod).toBe('none');
    expect(insert.grantTypes).toEqual(['authorization_code']);
  });

  it('CIMD: a PUBLIC document declaring ONLY the grant is unusable, and says so', () => {
    const doc = cimdDocumentSchema.parse({
      client_id: CIMD_CLIENT_ID,
      client_name: 'MCP Agent',
      redirect_uris: ['https://agent.example.com/cb'],
      grant_types: [TOKEN_EXCHANGE_GRANT_TYPE],
      response_types: ['code'],
      token_endpoint_auth_method: 'none',
    });
    expect(() => toCimdClientInsert('realm-1', CIMD_CLIENT_ID, doc, SENTINEL_HASH)).toThrow(
      InvalidClientError
    );
  });

  it('ID-JAG stays operator-only on the self-service paths', () => {
    // The asymmetry is deliberate and must not be "tidied up": `jwt-bearer`
    // depends on the operator-set ID_JAG_TRUSTED_ISSUERS allowlist, so a
    // self-registered client could never reach it.
    const urn = 'urn:ietf:params:oauth:grant-type:jwt-bearer';
    expect(grantTypeSchema.safeParse(urn).success).toBe(false);
    expect(
      dynamicClientRegistrationRequestSchema.safeParse({
        grant_types: [urn],
        response_types: [],
        token_endpoint_auth_method: 'client_secret_basic',
      }).success
    ).toBe(false);
  });
});

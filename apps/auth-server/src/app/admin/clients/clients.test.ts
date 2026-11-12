import { NotFoundError } from '@qauth-labs/shared-errors';
import { getEventType } from '@qauth-labs/shared-events';
import type { FastifyRequest } from 'fastify';
import { describe, expect, it, vi } from 'vitest';
import type { z } from 'zod';

import { ClientManagedByDocumentError } from '../../helpers/admin-client-errors';
import { classifyRequest, OPERATION_REGISTRY } from '../../helpers/admin-operations';
import { RESERVED_OPERATIONS } from '../../helpers/admin-operations-reserved';
import type { AdminRateLimitCheck } from '../pipeline';
import { CLIENT_HEADER_LINES, clientChangeLines, shownValue } from './approval-lines';
import {
  applyClientPatch,
  classifyClientPatch,
  CLIENT_FIELD_DEFAULTS,
  CLIENT_FIELDS,
  listDirection,
  mergePatch,
  PATCHABLE_CLIENT_FIELDS,
} from './fields';
import {
  assertShownInFull,
  classifyClientDisable,
  CLIENT_OPERATION_IDS,
  type ClientCheckContext,
  clientSettingsProblems,
  refuseDocumentClient,
} from './operations';
import { previewClientPatch } from './preview';
import {
  type AdminClient,
  adminClientOf,
  adminClientSchema,
  adminClientVersion,
  type OAuthClientRecord,
  storedFirstPartyPolicy,
} from './representation';
import { clientCreateBodySchema, clientPatchBodySchema } from './routes';

/**
 * The client operations of the admin API (#632), without a listener: the
 * field table and the classification it gives an update, the patch and the
 * checks of a client's settings, the representation, what an approver is
 * shown, and the routes in the admin document. The routes behind the
 * pipeline, their approvals and their writes are exercised against real
 * containers in `admin-clients.integration.test.ts`.
 */

const REALM = '018f2d6e-8a8b-7c3d-9e0f-1a2b3c4d5e6f';
const CLIENT = '018f2d6e-8a8b-7c3d-9e0f-1a2b3c4d5e71';
const DEVELOPER = '018f2d6e-8a8b-7c3d-9e0f-1a2b3c4d5e72';
const SECRET_HASH = '$argon2id$v=19$m=19456,t=2,p=1$c2VjcmV0LXNhbHQ$aGFzaC1vZi10aGUtc2VjcmV0';

/** A stored client, as the repository returns it. */
function clientRow(overrides: Record<string, unknown> = {}): OAuthClientRecord {
  return {
    id: CLIENT,
    realmId: REALM,
    clientId: 'reports',
    clientSecretHash: SECRET_HASH,
    name: 'Reports',
    description: null,
    developerId: null,
    provisionedByOperator: true,
    dynamicRegisteredAt: null,
    metadata: null,
    enabled: true,
    suspended: false,
    suspendedAt: null,
    redirectUris: ['https://reports.example.com/callback'],
    postLogoutRedirectUris: [],
    backchannelLogoutUri: null,
    backchannelLogoutUriSource: null,
    backchannelLogoutSessionRequired: false,
    scopes: ['openid', 'reports:read'],
    clientCredentialsScopes: null,
    grantTypes: ['authorization_code', 'refresh_token'],
    responseTypes: ['code'],
    tokenEndpointAuthMethod: 'client_secret_basic',
    jwks: null,
    jwksUri: null,
    requirePkce: true,
    dpopBoundAccessTokens: false,
    environment: 'production',
    isAgent: false,
    maxAgentMode: null,
    verifiedDomain: null,
    firstPartyProfile: null,
    firstPartyPolicy: null,
    firstPartyReason: null,
    accessTokenLifespanSeconds: null,
    refreshTokenLifespanSeconds: null,
    createdAt: Date.UTC(2026, 10, 1),
    updatedAt: Date.UTC(2026, 10, 2),
    lastUsedAt: null,
    ...overrides,
  } as unknown as OAuthClientRecord;
}

const client = (overrides: Record<string, unknown> = {}): AdminClient =>
  adminClientOf(clientRow(overrides));

/** A first-party client as the operator provisions one (#631). */
const firstParty = (): AdminClient =>
  client({
    tokenEndpointAuthMethod: 'private_key_jwt',
    jwksUri: 'https://reports.example.com/jwks.json',
    firstPartyProfile: 'web_redirect',
    firstPartyReason: 'The operator runs the reports app.',
  });

const patch = (body: Record<string, unknown>) => ({
  method: 'PATCH',
  params: { realmId: REALM, clientId: CLIENT },
  query: {},
  body,
});

const context: ClientCheckContext = {
  customSchemes: [],
  realmAccessLifetime: (environment) => (environment === 'development' ? 3600 : 900),
  realmRefreshLifetime: 2_592_000,
};

const operation = (id: string) => {
  const found = OPERATION_REGISTRY.get(id);
  if (found === undefined) throw new Error(`${id} is not registered`);
  return found;
};

describe('the client field table (#632)', () => {
  it('holds every member of the representation, in its order, and nothing else', () => {
    expect(Object.keys(CLIENT_FIELDS)).toEqual(Object.keys(adminClientSchema.shape));
  });

  it('lists each field with its class', () => {
    const classes = Object.fromEntries(
      Object.entries(CLIENT_FIELDS).map(([name, field]) => [name, field.class])
    );
    expect(classes).toEqual({
      id: 'read-only',
      client_id: 'read-only',
      name: 'write',
      description: 'write',
      developerId: 'read-only',
      provisionedByOperator: 'read-only',
      dynamicallyRegistered: 'read-only',
      metadataDocument: 'read-only',
      enabled: 'read-only',
      suspended: 'read-only',
      suspendedAt: 'read-only',
      redirectUris: 'security',
      postLogoutRedirectUris: 'security',
      backchannelLogoutUri: 'security-when',
      backchannelLogoutUriSource: 'read-only',
      backchannelLogoutSessionRequired: 'write',
      scopes: 'security-when',
      clientCredentialsScopes: 'security-when',
      grantTypes: 'security-when',
      responseTypes: 'security-when',
      tokenEndpointAuthMethod: 'security',
      jwks: 'security',
      jwksUri: 'security',
      requirePkce: 'security-when',
      dpopBoundAccessTokens: 'security-when',
      environment: 'security-when',
      isAgent: 'security',
      maxAgentMode: 'security',
      verifiedDomain: 'security',
      firstPartyProfile: 'security',
      firstPartyPolicy: 'security',
      firstPartyReason: 'security',
      accessTokenLifespanSeconds: 'security-when',
      refreshTokenLifespanSeconds: 'security-when',
      createdAt: 'read-only',
      updatedAt: 'read-only',
      lastUsedAt: 'read-only',
    });
  });

  it('gives every security field its effects and a rule, and the others none', () => {
    for (const [name, field] of Object.entries(CLIENT_FIELDS)) {
      expect(field.rule, name).not.toBe('');
      if (field.class === 'security' || field.class === 'security-when') {
        expect(field.effects.length, name).toBeGreaterThan(0);
      } else {
        expect(field.effects, name).toEqual([]);
      }
      if (field.class === 'security-when') expect(field.securityWhen, name).toBeTypeOf('function');
    }
  });

  it('makes every field that is not read-only patchable, and the bodies take exactly those', () => {
    const shapeOf = (schema: z.ZodType) => Object.keys((schema as z.ZodObject).shape);
    expect(PATCHABLE_CLIENT_FIELDS).toEqual(
      Object.keys(CLIENT_FIELDS).filter(
        (name) => CLIENT_FIELDS[name as keyof AdminClient].class !== 'read-only'
      )
    );
    expect(shapeOf(clientPatchBodySchema())).toEqual(PATCHABLE_CLIENT_FIELDS);
    expect(shapeOf(clientCreateBodySchema())).toEqual(PATCHABLE_CLIENT_FIELDS);
  });

  it('has a default for every patchable field but the name, the authentication method and the grant types', () => {
    expect(
      PATCHABLE_CLIENT_FIELDS.filter((name) => !Object.hasOwn(CLIENT_FIELD_DEFAULTS, name))
    ).toEqual(['name', 'grantTypes', 'tokenEndpointAuthMethod']);
  });

  it('reads a list as a set: only removals tighten, an addition loosens', () => {
    expect(listDirection(['a', 'b'], ['b'])).toBe('tightening');
    expect(listDirection(['a'], ['a', 'b'])).toBe('loosening');
    expect(listDirection(['a'], ['b'])).toBe('loosening');
    expect(listDirection(['a', 'b'], ['b', 'a'])).toBe('neutral');
    expect(listDirection(null, ['a'])).toBe('tightening');
    expect(listDirection(['a'], null)).toBe('loosening');
  });
});

describe('the classification of a client update (#632)', () => {
  const classify = (state: AdminClient, body: Record<string, unknown>) =>
    classifyClientPatch(patch(body), state);

  it('makes a general field a write, which needs clients.write and clients.read', () => {
    expect(classify(client(), { name: 'Monthly reports', description: 'For finance' })).toEqual({
      class: 'write',
      effects: [],
      permissions: ['clients.read', 'clients.write'],
    });
  });

  it.each([
    ['the redirect URIs', { redirectUris: ['https://evil.example/cb'] }, ['token-content']],
    ['the authentication method', { tokenEndpointAuthMethod: 'none' }, ['token-content']],
    [
      'the post-logout redirect URIs',
      { postLogoutRedirectUris: ['https://r.example/'] },
      ['posture-loosening'],
    ],
    ['the verified domain', { verifiedDomain: 'example.com' }, ['token-content']],
    ['the agent flag', { isAgent: true }, ['token-content']],
  ])('makes a change of %s a security change', (_label, body, effects) => {
    expect(classify(client(), body)).toEqual({
      class: 'security',
      effects,
      permissions: ['clients.read', 'clients.security'],
    });
  });

  it('makes first-party trust a security change, granting it and removing it', () => {
    const granted = classify(client({ tokenEndpointAuthMethod: 'private_key_jwt' }), {
      firstPartyProfile: 'web_redirect',
      firstPartyReason: 'The operator runs it.',
    });
    expect(granted.class).toBe('security');
    expect(classify(firstParty(), { firstPartyProfile: null })).toMatchObject({
      class: 'security',
      permissions: ['clients.read', 'clients.security'],
    });
  });

  it('needs both scopes for a mixed change', () => {
    expect(
      classify(client(), { name: 'Reports', redirectUris: ['https://new.example/cb'] })
    ).toEqual({
      class: 'security',
      effects: ['token-content'],
      permissions: ['clients.read', 'clients.write', 'clients.security'],
    });
  });

  it('makes a stricter environment a write and a laxer one a security change', () => {
    expect(classify(client({ environment: 'development' }), { environment: 'production' })).toEqual(
      {
        class: 'write',
        effects: [],
        permissions: ['clients.read', 'clients.write'],
      }
    );
    expect(classify(client(), { environment: 'development' })).toEqual({
      class: 'security',
      effects: ['posture-loosening'],
      permissions: ['clients.read', 'clients.security'],
    });
  });

  it('makes switching PKCE or DPoP off a security change, and on a write', () => {
    expect(classify(client(), { requirePkce: false }).class).toBe('security');
    expect(classify(client({ requirePkce: false }), { requirePkce: true }).class).toBe('write');
    expect(
      classify(client({ dpopBoundAccessTokens: true }), { dpopBoundAccessTokens: false }).class
    ).toBe('security');
    expect(classify(client(), { dpopBoundAccessTokens: true }).class).toBe('write');
  });

  it('makes a shorter token lifetime a write, and a longer one or the realm’s a security change', () => {
    const own = client({ accessTokenLifespanSeconds: 600, refreshTokenLifespanSeconds: 86_400 });
    expect(classify(own, { accessTokenLifespanSeconds: 300 }).class).toBe('write');
    expect(classify(client(), { accessTokenLifespanSeconds: 300 }).class).toBe('write');
    expect(classify(own, { accessTokenLifespanSeconds: 900 }).class).toBe('security');
    expect(classify(own, { refreshTokenLifespanSeconds: null }).class).toBe('security');
  });

  it('makes a scope a write, unless the patch adds one of the qauth: namespace', () => {
    expect(classify(client(), { scopes: ['openid', 'reports:read', 'reports:write'] }).class).toBe(
      'write'
    );
    expect(classify(client(), { scopes: ['openid'] }).class).toBe('write');
    // The client then obtains admin tokens: who administers changes too.
    expect(classify(client(), { scopes: ['openid', 'qauth:admin:read'] })).toMatchObject({
      class: 'security',
      effects: ['token-content', 'administration'],
    });
  });

  it('makes an added grant type a security change, and a removed one a write', () => {
    expect(classify(client(), { grantTypes: ['authorization_code'] }).class).toBe('write');
    expect(
      classify(client(), {
        grantTypes: ['authorization_code', 'refresh_token', 'client_credentials'],
      }).class
    ).toBe('security');
  });

  it('makes a back-channel logout URI set a security change, and removed a write', () => {
    expect(classify(client(), { backchannelLogoutUri: 'https://r.example/logout' }).class).toBe(
      'security'
    );
    expect(
      classify(client({ backchannelLogoutUri: 'https://r.example/logout' }), {
        backchannelLogoutUri: null,
      }).class
    ).toBe('write');
  });

  it('makes a patch that changes nothing a write', () => {
    expect(classify(client(), {})).toEqual({
      class: 'write',
      effects: [],
      permissions: ['clients.read', 'clients.write'],
    });
    expect(
      classify(client(), { redirectUris: ['https://reports.example.com/callback'] }).class
    ).toBe('write');
  });

  it('makes every change of a client that holds an admin scope a security change', () => {
    const console = client({ scopes: ['openid', 'qauth:admin:read', 'qauth:admin:security'] });
    expect(classify(console, { name: 'Console' })).toEqual({
      class: 'security',
      effects: ['administration'],
      permissions: ['clients.read', 'clients.security'],
    });
    // A narrowing too: without the scope no token could add it back.
    expect(classify(console, { scopes: ['openid', 'qauth:admin:read'] })).toMatchObject({
      class: 'security',
      effects: ['administration'],
    });
    expect(classify(console, { accessTokenLifespanSeconds: 1 }).effects).toEqual([
      'administration',
    ]);
    expect(classify(console, { redirectUris: ['https://c.example/cb'] }).effects).toEqual([
      'token-content',
      'administration',
    ]);
  });

  it('suspends a client as a write, unless it holds an admin scope', () => {
    expect(classifyClientDisable(client())).toEqual({
      class: 'write',
      effects: [],
      permissions: ['clients.write'],
    });
    expect(classifyClientDisable(client({ scopes: ['qauth:admin:read'] }))).toEqual({
      class: 'security',
      effects: ['administration'],
      permissions: ['clients.security'],
    });
  });

  it('makes a scope added to a client_credentials client without a list a security change', () => {
    const machine = client({
      grantTypes: ['client_credentials'],
      responseTypes: [],
      redirectUris: [],
      scopes: ['reports:read'],
    });
    expect(classify(machine, { scopes: ['reports:read', 'reports:write'] })).toMatchObject({
      class: 'security',
      effects: ['token-content'],
    });
    // With a list, a scope it leaves out is not issued to the client as itself.
    const listed = client({
      grantTypes: ['client_credentials'],
      responseTypes: [],
      redirectUris: [],
      scopes: ['reports:read'],
      clientCredentialsScopes: ['reports:read'],
    });
    expect(classify(listed, { scopes: ['reports:read', 'reports:write'] }).class).toBe('write');
    expect(classify(machine, { scopes: [] }).class).toBe('write');
  });

  it('leaves a member the patch does not name as stored, and classifies one its rules change', () => {
    const native = client({
      tokenEndpointAuthMethod: 'private_key_jwt',
      jwksUri: 'https://r.example/jwks',
      firstPartyProfile: 'native_backend',
      // Written by hand, a member missing.
      firstPartyPolicy: { flows: ['login', 'register'] },
      firstPartyReason: 'The operator ships the app.',
      redirectUris: ['https://r.example/cb', 'https://r.example/cb'],
    });
    const applied = applyClientPatch(native, { name: 'Renamed' });
    expect(applied.client.firstPartyPolicy).toEqual(native.firstPartyPolicy);
    expect(applied.client.redirectUris).toEqual(native.redirectUris);
    expect(classify(native, { name: 'Renamed' }).class).toBe('write');
    // A rule that changes a member the patch did not name: the policy the
    // profile clears is classified as its own change.
    expect(classify(native, { firstPartyReason: null, firstPartyProfile: null })).toMatchObject({
      class: 'security',
    });
  });

  it('fails closed through the registry on a member the table does not take', () => {
    const update = operation(CLIENT_OPERATION_IDS.update);
    const state = client();
    for (const body of [{ clientSecretHash: 'x' }, { enabled: true }, { developerId: DEVELOPER }]) {
      const result = classifyRequest(
        OPERATION_REGISTRY,
        update,
        patch(body),
        state,
        adminClientVersion(state)
      );
      expect(result.failedClosed, JSON.stringify(body)).toBe('unknown-field');
      expect(result.class).toBe('security');
      expect([...result.permissions].sort()).toEqual([
        'clients.read',
        'clients.security',
        'clients.write',
      ]);
    }
  });

  it('classifies through the registry as it does alone, bound to the state version', () => {
    const update = operation(CLIENT_OPERATION_IDS.update);
    const state = client();
    const body = { name: 'Reports' };
    const result = classifyRequest(
      OPERATION_REGISTRY,
      update,
      patch(body),
      state,
      adminClientVersion(state)
    );
    const alone = classify(state, body);
    expect(result.failedClosed).toBeNull();
    expect(result).toMatchObject({
      class: alone.class,
      effects: alone.effects,
      stateVersion: adminClientVersion(state),
    });
    expect([...result.permissions].sort()).toEqual([...alone.permissions].sort());
  });
});

describe('a merge patch of a client (#632)', () => {
  it('applies RFC 7396: null removes a member, an object merges', () => {
    expect(mergePatch({ a: 1, b: { c: 2, d: 3 } }, { a: null, b: { c: null, e: 4 } })).toEqual({
      b: { d: 3, e: 4 },
    });
    expect(mergePatch({ a: [1, 2] }, { a: [3] })).toEqual({ a: [3] });
  });

  it('gives a null member its default, and refuses null on a member without one', () => {
    const applied = applyClientPatch(
      client({ description: 'Old', environment: 'development', accessTokenLifespanSeconds: 60 }),
      { description: null, environment: null, accessTokenLifespanSeconds: null, name: null }
    );
    expect(applied.client).toMatchObject({
      description: null,
      environment: 'production',
      accessTokenLifespanSeconds: null,
      name: 'Reports',
    });
    expect(applied.problems).toEqual([
      { pointer: '/name', message: 'name is required and has no default' },
    ]);
  });

  it('drops repeats from the lists and stores the verified domain in its stored form', () => {
    const applied = applyClientPatch(client(), {
      redirectUris: ['https://a.example/cb', 'https://a.example/cb'],
      scopes: ['openid', 'openid'],
      verifiedDomain: 'Reports.Example.COM',
    });
    expect(applied.client.redirectUris).toEqual(['https://a.example/cb']);
    expect(applied.client.scopes).toEqual(['openid']);
    expect(applied.client.verifiedDomain).toBe('reports.example.com');
  });

  it('removes the policy and the reason with the first-party profile', () => {
    const native = client({
      tokenEndpointAuthMethod: 'private_key_jwt',
      jwksUri: 'https://r.example/jwks',
      firstPartyProfile: 'native_backend',
      firstPartyPolicy: {
        flows: ['login'],
        email_code_after_password: true,
        pkce_required: true,
      },
      firstPartyReason: 'The operator ships the app.',
    });
    expect(applyClientPatch(native, { firstPartyProfile: null }).client).toMatchObject({
      firstPartyProfile: null,
      firstPartyPolicy: null,
      firstPartyReason: null,
    });
  });

  it('shows a stored policy in camelCase and stores a patched one as the column names it', () => {
    const native = client({
      tokenEndpointAuthMethod: 'private_key_jwt',
      jwksUri: 'https://r.example/jwks',
      firstPartyProfile: 'native_backend',
      firstPartyPolicy: {
        flows: ['login', 'reset'],
        email_code_after_password: false,
        pkce_required: true,
      },
      firstPartyReason: 'The operator ships the app.',
    });
    expect(native.firstPartyPolicy).toEqual({
      flows: ['login', 'reset'],
      emailCodeAfterPassword: false,
      pkceRequired: true,
    });
    expect(storedFirstPartyPolicy(native.firstPartyPolicy)).toEqual({
      flows: ['login', 'reset'],
      email_code_after_password: false,
      pkce_required: true,
    });
    // A patch that names only the profile gets every member, its defaults.
    const made = applyClientPatch(client(), { firstPartyProfile: 'native_backend' });
    expect(made.client.firstPartyPolicy).toEqual({
      flows: ['login'],
      emailCodeAfterPassword: false,
      pkceRequired: true,
    });
  });

  it('merges a native_backend policy member by member and fills in its defaults', () => {
    const native = client({
      tokenEndpointAuthMethod: 'private_key_jwt',
      jwksUri: 'https://r.example/jwks',
      firstPartyProfile: 'native_backend',
      firstPartyPolicy: {
        flows: ['login'],
        email_code_after_password: true,
        pkce_required: true,
      },
      firstPartyReason: 'The operator ships the app.',
    });
    const applied = applyClientPatch(native, { firstPartyPolicy: { pkceRequired: false } });
    expect(applied.client.firstPartyPolicy).toEqual({
      flows: ['login'],
      emailCodeAfterPassword: true,
      pkceRequired: false,
    });
  });

  it('records an admin as the source of a back-channel logout URI it sets', () => {
    const set = applyClientPatch(client(), { backchannelLogoutUri: 'https://r.example/logout' });
    expect(set.client.backchannelLogoutUriSource).toBe('admin');
    const cleared = applyClientPatch(
      client({
        backchannelLogoutUri: 'https://r.example/logout',
        backchannelLogoutUriSource: 'client',
      }),
      { backchannelLogoutUri: null }
    );
    expect(cleared.client.backchannelLogoutUriSource).toBeNull();
  });

  it('changes neither the state nor the body', () => {
    const state = client();
    const body = { redirectUris: ['https://b.example/cb'] };
    const before = structuredClone({ state, body });
    applyClientPatch(state, body);
    expect({ state, body }).toEqual(before);
  });
});

describe('the checks of a client’s settings (#632)', () => {
  const problems = (state: AdminClient, body: Record<string, unknown>, all = false) =>
    clientSettingsProblems(applyClientPatch(state, body), context, all);

  it("refuses a token lifetime longer than the realm's, by the client's environment", () => {
    expect(problems(client(), { accessTokenLifespanSeconds: 901 })).toEqual([
      {
        pointer: '/accessTokenLifespanSeconds',
        message:
          "accessTokenLifespanSeconds is longer than the realm's access token lifetime for this environment, 900 seconds: a client's own lifetime may only be shorter",
      },
    ]);
    expect(problems(client(), { accessTokenLifespanSeconds: 900 })).toEqual([]);
    expect(
      problems(client({ environment: 'development' }), { accessTokenLifespanSeconds: 3600 })
    ).toEqual([]);
    expect(problems(client(), { refreshTokenLifespanSeconds: 2_592_001 })).toMatchObject([
      { pointer: '/refreshTokenLifespanSeconds' },
    ]);
  });

  it('checks the redirect URIs as every registration path does', () => {
    expect(
      problems(client(), {
        redirectUris: [
          'https://ok.example/cb',
          'http://reports.example.com/cb',
          'https://x.example/#f',
        ],
      }).map(({ pointer }) => pointer)
    ).toEqual(['/redirectUris/1', '/redirectUris/2']);
  });

  it('refuses first-party trust for a client a developer owns, a secret client and no reason', () => {
    const owned = client({ developerId: DEVELOPER, provisionedByOperator: false });
    expect(
      problems(owned, { firstPartyProfile: 'web_redirect' }).map(({ pointer }) => pointer)
    ).toEqual(['/firstPartyProfile', '/tokenEndpointAuthMethod', '/firstPartyReason']);
  });

  it('accepts first-party trust for an operator client with private_key_jwt, keys and a reason', () => {
    expect(
      problems(client(), {
        tokenEndpointAuthMethod: 'private_key_jwt',
        jwksUri: 'https://reports.example.com/jwks.json',
        firstPartyProfile: 'web_redirect',
        firstPartyReason: 'The operator runs the reports app.',
      })
    ).toEqual([]);
  });

  it('needs keys for private_key_jwt, one key set at most, and an https jwksUri', () => {
    expect(problems(client(), { tokenEndpointAuthMethod: 'private_key_jwt' })).toMatchObject([
      { pointer: '/tokenEndpointAuthMethod', message: 'private_key_jwt requires jwks or jwksUri' },
    ]);
    expect(
      problems(client(), { jwksUri: 'http://r.example/jwks' }).map(({ pointer }) => pointer)
    ).toEqual(['/jwksUri']);
  });

  it('keeps the grant, response and client_credentials rules', () => {
    expect(
      problems(client(), { grantTypes: ['client_credentials'] }).map(({ pointer }) => pointer)
    ).toEqual(['/responseTypes']);
    expect(
      problems(
        client({ grantTypes: ['client_credentials'], responseTypes: [], redirectUris: [] }),
        {
          clientCredentialsScopes: ['reports:write'],
        }
      ).map(({ pointer }) => pointer)
    ).toEqual(['/clientCredentialsScopes']);
  });

  it('gives a verified domain only to a client an operator provisioned', () => {
    expect(
      problems(client({ provisionedByOperator: false }), { verifiedDomain: 'example.com' })
    ).toMatchObject([{ pointer: '/verifiedDomain' }]);
    expect(problems(client(), { verifiedDomain: 'example.com' })).toEqual([]);
  });

  it('checks a client lifetime against the tier of the environment a patch moves it to', () => {
    const local = client({ environment: 'development', accessTokenLifespanSeconds: 3000 });
    expect(problems(local, { environment: 'production' })).toMatchObject([
      { pointer: '/accessTokenLifespanSeconds' },
    ]);
    expect(problems(local, { environment: 'production', accessTokenLifespanSeconds: 600 })).toEqual(
      []
    );
  });

  it('checks only what the patch names: a stored value does not block an unrelated change', () => {
    const stored = client({ accessTokenLifespanSeconds: 3600 });
    expect(problems(stored, { name: 'Renamed' })).toEqual([]);
    expect(problems(stored, {}, true)).toMatchObject([{ pointer: '/accessTokenLifespanSeconds' }]);
  });
});

describe('a CIMD client (#632, ADR-012 Decision 3)', () => {
  const DOCUMENT = 'https://app.example.com/oauth/client.json';
  const cimd = () => client({ clientId: DOCUMENT, metadata: { registrationType: 'cimd' } });

  it('names its document, and is refused a change with 409 naming it', () => {
    expect(cimd().metadataDocument).toBe(DOCUMENT);
    expect(client().metadataDocument).toBeNull();
    let refusal: unknown;
    try {
      refuseDocumentClient(cimd());
    } catch (error) {
      refusal = error;
    }
    expect(refusal).toBeInstanceOf(ClientManagedByDocumentError);
    expect(refusal).toMatchObject({ statusCode: 409, document: DOCUMENT });
    expect((refusal as Error).message).toContain(DOCUMENT);
    expect(() => refuseDocumentClient(client())).not.toThrow();
  });

  it('is refused by the update’s and the deletion’s state, not by the enable’s', async () => {
    const row = clientRow({ clientId: DOCUMENT, metadata: { registrationType: 'cimd' } });
    const request = {
      adminPipeline: { authority: { targetRealm: { id: REALM } } },
      server: { repositories: { oauthClients: { findById: vi.fn(async () => row) } } },
    } as unknown as FastifyRequest;
    const input = { ...patch({ name: 'x' }) };
    for (const id of [CLIENT_OPERATION_IDS.update, CLIENT_OPERATION_IDS.delete]) {
      await expect(operation(id).loadState?.(request, input)).rejects.toBeInstanceOf(
        ClientManagedByDocumentError
      );
    }
    for (const id of [CLIENT_OPERATION_IDS.enable, CLIENT_OPERATION_IDS.disable]) {
      await expect(
        operation(id).loadState?.(request, { ...input, body: {} })
      ).resolves.toMatchObject({ metadataDocument: DOCUMENT });
    }
  });
});

describe('the state of a client operation (#632)', () => {
  it('is 404 for a client the realm does not have, one of another realm included', async () => {
    const findById = vi.fn(async () => undefined);
    const request = {
      adminPipeline: { authority: { targetRealm: { id: REALM } }, transaction: 'tx' },
      server: { repositories: { oauthClients: { findById } } },
    } as unknown as FastifyRequest;
    await expect(
      operation(CLIENT_OPERATION_IDS.delete).loadState?.(request, { ...patch({}), body: {} })
    ).rejects.toBeInstanceOf(NotFoundError);
    // Keyed by the realm of the path, in the handler's transaction.
    expect(findById).toHaveBeenCalledWith(REALM, CLIENT, 'tx');
    await expect(
      operation(CLIENT_OPERATION_IDS.delete).loadState?.(request, {
        ...patch({}),
        params: { realmId: REALM, clientId: 'reports' },
      })
    ).rejects.toBeInstanceOf(NotFoundError);
  });
});

describe('the client representation (#632)', () => {
  it('never holds the secret hash, nor a private member of a key', () => {
    const shown = adminClientOf(
      clientRow({
        jwks: {
          keys: [{ kty: 'OKP', crv: 'Ed25519', x: 'cHVibGlj', d: 'cHJpdmF0ZQ', kid: 'k1' }],
        },
      })
    );
    const text = JSON.stringify(shown);
    expect(text).not.toContain(SECRET_HASH);
    expect(text).not.toContain('argon2');
    expect(Object.keys(shown)).not.toContain('clientSecretHash');
    expect(Object.keys(adminClientSchema.shape)).not.toContain('clientSecretHash');
    expect(shown.jwks).toEqual({
      keys: [{ kty: 'OKP', crv: 'Ed25519', x: 'cHVibGlj', kid: 'k1' }],
    });
    expect(adminClientSchema.parse(shown)).toEqual(shown);
  });

  it('versions every member but the last use', () => {
    const base = client();
    expect(adminClientVersion(client({ lastUsedAt: Date.UTC(2026, 10, 3) }))).toBe(
      adminClientVersion(base)
    );
    expect(adminClientVersion(client({ name: 'Other' }))).not.toBe(adminClientVersion(base));
    expect(adminClientVersion(base)).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it('tells a client that registered itself', () => {
    expect(client({ dynamicRegisteredAt: Date.UTC(2026, 10, 1) }).dynamicallyRegistered).toBe(true);
    expect(client({ metadata: { registrationType: 'dynamic' } }).dynamicallyRegistered).toBe(true);
    expect(client().dynamicallyRegistered).toBe(false);
  });
});

describe('the client operations in the registry (#632)', () => {
  it('reads with clients.read, and writes by the class of what changes', () => {
    const shape = Object.values(CLIENT_OPERATION_IDS).map((id) => {
      const entry = operation(id);
      return [entry.id, entry.class, entry.effects, entry.permissions];
    });
    expect(shape).toEqual([
      ['clients.list', 'read', [], ['clients.read']],
      ['clients.get', 'read', [], ['clients.read']],
      ['clients.create', 'security', ['token-content'], ['clients.security']],
      [
        'clients.update',
        'security',
        ['token-content', 'posture-loosening', 'administration'],
        ['clients.write', 'clients.security', 'clients.read'],
      ],
      ['clients.preview', 'read', [], ['clients.read']],
      ['clients.delete', 'security', ['token-content'], ['clients.security']],
      ['clients.enable', 'security', ['token-content'], ['clients.security']],
      ['clients.disable', 'security', ['administration'], ['clients.write', 'clients.security']],
    ]);
    for (const [permission, cls] of [
      ['clients.read', 'read'],
      ['clients.write', 'write'],
      ['clients.security', 'security'],
    ]) {
      expect(OPERATION_REGISTRY.permissions.get(permission)?.class).toBe(cls);
    }
  });

  it('reserves the security operations, and only the update and the suspension classify', () => {
    for (const id of ['clients.create', 'clients.update', 'clients.delete']) {
      expect(
        RESERVED_OPERATIONS.find((entry) => entry.id === id),
        id
      ).toBeDefined();
    }
    expect(
      RESERVED_OPERATIONS.find((entry) => entry.id === 'clients.update')?.requestDependent
    ).toBeDefined();
    const classifying = Object.values(CLIENT_OPERATION_IDS).filter(
      (id) => operation(id).classify !== undefined
    );
    expect(classifying).toEqual(['clients.update', 'clients.disable']);
  });

  it('names the admin as the cause of a new client’s event', () => {
    const created = getEventType('urn:qauth:event:client.created:v1-rc.0');
    expect(
      created?.data.safeParse({
        registration: 'admin_api',
        isPublic: false,
        isAgent: false,
        grantTypes: ['client_credentials'],
        scopes: ['reports:read'],
        authMethod: 'client_secret_basic',
      }).success
    ).toBe(true);
  });
});

describe('what an approver is shown of a client operation (#632)', () => {
  const render = (id: string, body: unknown, state?: AdminClient) => {
    const entry = operation(id);
    if (entry.render === undefined) throw new Error(`${id} renders nothing`);
    return entry.render({
      operationId: id,
      method: 'PATCH',
      params: { realmId: REALM, clientId: CLIENT },
      query: {},
      body,
      ...(state === undefined ? {} : { state }),
    });
  };

  it('shows a list as each entry it removes and adds, and any other field beside the value it replaces', () => {
    const shown = render(
      CLIENT_OPERATION_IDS.update,
      {
        name: 'Monthly reports',
        redirectUris: ['https://reports.example.com/callback', 'https://new.example/cb'],
        scopes: ['openid'],
      },
      client()
    );
    expect(shown.title).toBe('Change the settings of a client');
    expect(shown.fields).toEqual([
      { label: 'client', value: 'reports (Reports)' },
      { label: 'owner', value: 'no developer: an operator or an admin manages it' },
      { label: 'name', before: 'Reports', value: 'Monthly reports' },
      { label: 'redirectUris added', value: 'https://new.example/cb' },
      { label: 'scopes removed', value: 'reports:read' },
    ]);
  });

  it('shows every entry of a padded list whole, so none hides behind another', () => {
    const padded = `https://reports.example.com/callback/${'a'.repeat(480)}`;
    const shown = render(
      CLIENT_OPERATION_IDS.update,
      {
        redirectUris: ['https://reports.example.com/callback', padded, 'https://evil.example/cb'],
      },
      client()
    );
    expect(shown.fields?.slice(CLIENT_HEADER_LINES)).toEqual([
      { label: 'redirectUris added', value: padded },
      { label: 'redirectUris added', value: 'https://evil.example/cb' },
    ]);
  });

  it('refuses a security change an approver could not be shown whole, and holds a write to nothing', () => {
    const long = `https://reports.example.com/${'a'.repeat(1000)}`;
    const body = { redirectUris: [long] };
    const state = client();
    const applied = applyClientPatch(state, body);
    expect(clientChangeLines(state, applied.client, CLIENT_HEADER_LINES).problems).toMatchObject([
      { pointer: '/redirectUris' },
    ]);
    expect(() => assertShownInFull(patch(body), state, applied)).toThrow(
      expect.objectContaining({ statusCode: 422 })
    );
    // More lines than one approval holds.
    const many = { scopes: Array.from({ length: 50 }, (_, index) => `scope:${index}`) };
    const own = client({ grantTypes: ['client_credentials'], responseTypes: [], redirectUris: [] });
    expect(() => assertShownInFull(patch(many), own, applyClientPatch(own, many))).toThrow(
      expect.objectContaining({ statusCode: 422 })
    );
    // A write needs no approval: a long description is shown to nobody.
    const description = { description: 'é'.repeat(2000) };
    expect(() =>
      assertShownInFull(patch(description), state, applyClientPatch(state, description))
    ).not.toThrow();
  });

  it('refuses to show an update, a deletion or an enable without the client it was filed against', () => {
    for (const id of [
      CLIENT_OPERATION_IDS.update,
      CLIENT_OPERATION_IDS.delete,
      CLIENT_OPERATION_IDS.enable,
    ]) {
      expect(() => render(id, {}), id).toThrow();
    }
  });

  it('shows a new client’s settings, never a secret, and what deleting one does', () => {
    const created = render(CLIENT_OPERATION_IDS.create, {
      name: 'Batch',
      tokenEndpointAuthMethod: 'client_secret_basic',
      grantTypes: ['client_credentials'],
    });
    expect(created.title).toBe('Register a client');
    expect((created.fields ?? []).map((field) => field.label)).toEqual([
      'effect',
      'name',
      'grantTypes',
      'tokenEndpointAuthMethod',
    ]);
    const deleted = render(CLIENT_OPERATION_IDS.delete, {}, client());
    expect((deleted.fields ?? []).at(-1)?.value).toContain('refresh tokens');
    expect(JSON.stringify(deleted)).not.toContain(SECRET_HASH);
  });

  it('shows a string as it is and any other value as JSON', () => {
    expect(shownValue('x'.repeat(600))).toHaveLength(600);
    expect(shownValue(['a'])).toBe('["a"]');
    expect(shownValue(null)).toBe('null');
  });

  it('refuses a registration an approver could not be shown whole, or one with a private key', () => {
    const body = clientCreateBodySchema();
    const base = {
      name: 'Batch',
      tokenEndpointAuthMethod: 'private_key_jwt',
      grantTypes: ['client_credentials'],
    };
    expect(body.safeParse(base).success).toBe(true);
    expect(
      body.safeParse({ ...base, scopes: Array.from({ length: 50 }, (_, index) => `s:${index}`) })
        .success
    ).toBe(false);
    expect(
      body.safeParse({ ...base, redirectUris: [`https://r.example/${'a'.repeat(1100)}`] }).success
    ).toBe(false);
    const privateKey = { kty: 'OKP', crv: 'Ed25519', x: 'cHVibGlj', d: 'cHJpdmF0ZQ' };
    expect(body.safeParse({ ...base, jwks: { keys: [privateKey] } }).success).toBe(false);
    expect(clientPatchBodySchema().safeParse({ jwks: { keys: [privateKey] } }).success).toBe(false);
  });
});

describe('the preview of a client update (#632)', () => {
  it('lists each change with its direction, class and whether it is bound to the environment', () => {
    const state = client();
    const preview = previewClientPatch(
      OPERATION_REGISTRY,
      { realmId: REALM, clientId: CLIENT },
      { name: 'Renamed', environment: 'development', redirectUris: ['http://127.0.0.1:8080/cb'] },
      state
    );
    expect(preview.classification).toMatchObject({
      class: 'security',
      failedClosed: null,
      stateVersion: adminClientVersion(state),
    });
    expect(
      preview.changes.map(({ path, direction, classification, environmentBound }) => [
        path,
        direction,
        classification.class,
        environmentBound,
      ])
    ).toEqual([
      ['name', 'neutral', 'write', false],
      ['redirectUris', 'loosening', 'security', true],
      ['environment', 'loosening', 'security', true],
    ]);
  });
});

describe('the client routes in the admin OpenAPI document (#632)', () => {
  it("pass the API conventions against the server's own registry, and publish no secret hash", async () => {
    const [{ default: Fastify }, { default: swagger }, zod, { adminOpenapiOptions }, pipeline] =
      await Promise.all([
        import('fastify'),
        import('@fastify/swagger'),
        import('fastify-type-provider-zod'),
        import('../openapi-options'),
        import('../pipeline'),
      ]);
    const { checkApiConventions } = await import('../../api-conventions/openapi-conventions');
    const { clientRoutes } = await import('./routes');

    const app = Fastify({ logger: false });
    try {
      app.setValidatorCompiler(zod.validatorCompiler);
      app.setSerializerCompiler(zod.serializerCompiler);
      await app.register(swagger, adminOpenapiOptions);
      const uncounted: AdminRateLimitCheck = async () => ({ isAllowed: true, key: 'uncounted' });
      await app.register(pipeline.adminPipeline, {
        registry: OPERATION_REGISTRY,
        refusalsByAddress: uncounted,
        callsBySubject: uncounted,
        routes: async (scope) => {
          await scope.register(clientRoutes);
        },
      });
      await app.ready();

      const document = app.swagger() as unknown as {
        paths: Record<string, Record<string, Record<string, unknown>>>;
        components?: unknown;
      };
      expect(Object.keys(document.paths)).toEqual([
        '/admin/v1-rc.0/realms/{realmId}/clients',
        '/admin/v1-rc.0/realms/{realmId}/clients/{clientId}',
        '/admin/v1-rc.0/realms/{realmId}/clients/{clientId}/preview',
        '/admin/v1-rc.0/realms/{realmId}/clients/{clientId}/enable',
        '/admin/v1-rc.0/realms/{realmId}/clients/{clientId}/disable',
      ]);
      const one = document.paths['/admin/v1-rc.0/realms/{realmId}/clients/{clientId}'];
      expect(one['patch']).toMatchObject({
        operationId: 'clients.update',
        'x-qauth-class': 'security',
      });
      expect(JSON.stringify(one['patch']['requestBody'])).toContain('AdminClientPatch');
      expect(JSON.stringify(one['get']['responses'])).toContain('AdminClient');
      expect(JSON.stringify(document)).not.toMatch(/secretHash|secret_hash/i);
      const report = checkApiConventions(document, { operations: OPERATION_REGISTRY });
      expect(report.violations).toEqual([]);
      expect(report.checkedOperations).toBe(8);
    } finally {
      await app.close();
    }
  });
});

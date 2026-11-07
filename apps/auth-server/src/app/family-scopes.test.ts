import { generateKeyPairSync } from 'node:crypto';

import { jwtPlugin } from '@qauth-labs/fastify-plugin-jwt';
import {
  createTestSigner,
  type TestSigner,
} from '@qauth-labs/fastify-plugin-signer/src/testing/memory-signer';
import Fastify, { type FastifyInstance, type RouteOptions } from 'fastify';
import { serializerCompiler, validatorCompiler } from 'fastify-type-provider-zod';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

// The routes and the error handler read the validated env; stub it so no env
// parse runs.
vi.mock('../config/env', () => ({ env: { NODE_ENV: 'test' } }));

import {
  API_FAMILY_AUDIENCES,
  API_FAMILY_PREFIXES,
  API_FAMILY_SCOPES,
  type FamilyOperationClass,
  type ScopedApiFamily,
} from './api-conventions/families';
import { tokenRealm } from './helpers/realm-url';
import { requestRealm } from './helpers/request-realm';
import errorHandler from './plugins/error-handler';
import { registerAccountConsentRoutes } from './routes/account/consents';
import { registerDeveloperApiKeyRoutes } from './routes/developer/api-keys';
import { registerDeveloperClientRoutes } from './routes/developer/clients';
import { registerDeveloperConsentRoutes } from './routes/developer/consents';

/**
 * The scopes of the developer and account APIs (#933), on the routes the
 * server serves: every route's guard requires its family's scope of the
 * `x-qauth-class` its schema publishes, so a developer token with only the
 * read scope reads and gets 403 on every write, and the reverse.
 *
 * The routes are the real modules, behind the real JWT plugin over the
 * in-memory signer and the real error handler. Each route's handler is
 * replaced as it is registered, and its later `preValidation` hooks (media
 * type, `If-Match`) and its response schema are left out: what is under test
 * is the guard, its first `preValidation` hook, and nothing past it touches a
 * repository.
 */

const ISSUER = 'https://auth.test.example.com';
const USER_ID = '11111111-1111-4111-8111-111111111111';
const REALM = { id: 'aaaaaaaa-0000-4000-8000-00000000000a', name: 'a', issuer: ISSUER };
const SOME_ID = '0b9f7d4e-5c1a-4f7e-9d2b-3a6c8e1f0a42';

/** One served operation, as its route registered it. */
interface Operation {
  readonly family: ScopedApiFamily;
  readonly method: string;
  readonly url: string;
  readonly operationId: string;
  readonly operationClass: FamilyOperationClass;
  readonly permission: string;
}

let app: FastifyInstance;
let signer: TestSigner;
const operations: Operation[] = [];

function familyOf(url: string): ScopedApiFamily {
  if (url.startsWith(API_FAMILY_PREFIXES.developer)) return 'developer';
  if (url.startsWith(API_FAMILY_PREFIXES.account)) return 'account';
  throw new Error(`${url} is no route of the account or developer API`);
}

/** Record each route's published class, and keep its guard alone in front of a stub handler. */
function onRoute(route: RouteOptions): void {
  const schema = (route.schema ?? {}) as Record<string, unknown>;
  const methods = [route.method].flat();
  if (methods.includes('HEAD') && methods.length === 1) return;
  operations.push({
    family: familyOf(route.url),
    method: methods.find((method) => method !== 'HEAD') ?? 'GET',
    url: route.url,
    operationId: String(schema['operationId']),
    operationClass: schema['x-qauth-class'] as FamilyOperationClass,
    permission: String(schema['x-qauth-permission']),
  });
  const [guard] = [route.preValidation].flat();
  route.preValidation = guard;
  route.schema = { ...schema, response: undefined };
  route.handler = async () => ({ ran: true });
}

beforeAll(async () => {
  signer = createTestSigner();
  const pem = generateKeyPairSync('ed25519')
    .privateKey.export({ type: 'pkcs8', format: 'pem' })
    .toString();
  await signer.addRealm({ id: REALM.id, issuer: REALM.issuer, ed25519PrivateKey: pem });

  app = Fastify({ logger: false });
  app.setValidatorCompiler(validatorCompiler);
  app.setSerializerCompiler(serializerCompiler);
  app.decorate('repositories', {
    users: {
      findById: vi.fn(async (realmId: string, id: string) =>
        realmId === REALM.id && id === USER_ID ? { id, enabled: true, realmId } : undefined
      ),
    },
    oauthClients: { findByClientId: vi.fn(async () => undefined) },
  } as never);
  app.decorateRequest('realm', null);
  app.addHook('onRequest', async (request) => {
    request.realm = REALM as never;
  });
  await app.register(jwtPlugin, {
    signer: signer.signer,
    requestRealm: (request) => tokenRealm(requestRealm(request)),
    accessTokenLifespan: 900,
    refreshTokenLifespan: 86400,
  });
  await app.register(errorHandler);
  await app.register(
    async (scope) => {
      scope.addHook('onRoute', onRoute);
      // As the developer module does: a merge patch parses as JSON.
      scope.addContentTypeParser(
        'application/merge-patch+json',
        { parseAs: 'string' },
        (_request, body, done) => done(null, JSON.parse(String(body)))
      );
      registerDeveloperClientRoutes(scope);
      registerDeveloperApiKeyRoutes(scope);
      registerDeveloperConsentRoutes(scope);
    },
    { prefix: API_FAMILY_PREFIXES.developer }
  );
  await app.register(
    async (scope) => {
      scope.addHook('onRoute', onRoute);
      registerAccountConsentRoutes(scope);
    },
    { prefix: API_FAMILY_PREFIXES.account }
  );
  await app.ready();
}, 60_000);

afterAll(async () => {
  await app?.close();
});

function token(family: ScopedApiFamily, scope?: string): Promise<string> {
  return app.jwtUtils.signAccessToken(REALM, {
    sub: USER_ID,
    clientId: 'family-client',
    aud: API_FAMILY_AUDIENCES[family],
    ...(scope === undefined ? {} : { scope }),
  });
}

function call(operation: Operation, bearer: string) {
  return app.inject({
    method: operation.method as 'GET',
    url: operation.url.replace(/:[A-Za-z]+/g, SOME_ID),
    headers: { authorization: `Bearer ${bearer}` },
  });
}

/** The operations of `family` whose class is `operationClass`. */
function operationsOf(family: ScopedApiFamily, operationClass: FamilyOperationClass) {
  return operations.filter(
    (operation) => operation.family === family && operation.operationClass === operationClass
  );
}

describe('the scopes of the developer and account APIs (#933)', () => {
  it('registers every operation the server serves, each with a read or write class', () => {
    expect(operations.map((operation) => operation.operationId).sort()).toEqual([
      'account.consents.delete',
      'account.consents.list',
      'developer.clients.apiKeys.create',
      'developer.clients.apiKeys.delete',
      'developer.clients.apiKeys.list',
      'developer.clients.create',
      'developer.clients.delete',
      'developer.clients.get',
      'developer.clients.list',
      'developer.clients.regenerateSecret',
      'developer.clients.update',
      'developer.consents.delete',
      'developer.consents.list',
    ]);
    for (const operation of operations) {
      expect(['read', 'write'], operation.operationId).toContain(operation.operationClass);
      // The permission is one of the class: `clients.read`, `consents.write`, ...
      expect(
        operation.permission.endsWith(`.${operation.operationClass}`),
        operation.operationId
      ).toBe(true);
    }
  });

  it('refuses a developer token with only the read scope on create, update, delete, secret regeneration, API keys and consent revocation', async () => {
    const readOnly = await token('developer', API_FAMILY_SCOPES.developer.read);
    const writes = operationsOf('developer', 'write');
    expect(writes.map((operation) => operation.operationId).sort()).toEqual([
      'developer.clients.apiKeys.create',
      'developer.clients.apiKeys.delete',
      'developer.clients.create',
      'developer.clients.delete',
      'developer.clients.regenerateSecret',
      'developer.clients.update',
      'developer.consents.delete',
    ]);
    for (const operation of writes) {
      const response = await call(operation, readOnly);
      expect(response.statusCode, operation.operationId).toBe(403);
      expect(response.json(), operation.operationId).toMatchObject({ code: 'forbidden' });
      expect(response.headers['www-authenticate'], operation.operationId).toBe(
        'Bearer realm="OAuth", error="insufficient_scope", scope="qauth:developer:write"'
      );
    }
  });

  it('lets the same token read', async () => {
    const readOnly = await token('developer', API_FAMILY_SCOPES.developer.read);
    const reads = operationsOf('developer', 'read');
    expect(reads.length).toBe(4);
    for (const operation of reads) {
      const response = await call(operation, readOnly);
      expect(response.statusCode, `${operation.operationId}: ${response.body}`).toBe(200);
    }
  });

  it.each(['developer', 'account'] as const)(
    'needs the read scope to read and the write scope to write on the %s API',
    async (family) => {
      const scopes = API_FAMILY_SCOPES[family];
      for (const operationClass of ['read', 'write'] as const) {
        const other = operationClass === 'read' ? scopes.write : scopes.read;
        for (const operation of operationsOf(family, operationClass)) {
          for (const scope of [undefined, other, 'openid profile', `${scopes[operationClass]}x`]) {
            const response = await call(operation, await token(family, scope));
            expect(response.statusCode, `${operation.operationId} with ${scope}`).toBe(403);
            expect(response.headers['www-authenticate']).toBe(
              `Bearer realm="OAuth", error="insufficient_scope", scope="${scopes[operationClass]}"`
            );
          }
          const granted = await call(
            operation,
            await token(family, `openid ${scopes.read} ${scopes.write}`)
          );
          expect([401, 403], `${operation.operationId}: ${granted.body}`).not.toContain(
            granted.statusCode
          );
        }
      }
    }
  );

  it("never takes one family's scope for another's", async () => {
    const account = operationsOf('account', 'read')[0];
    const developer = operationsOf('developer', 'read')[0];
    if (account === undefined || developer === undefined) throw new Error('no read operation');
    const developerScopes = `${API_FAMILY_SCOPES.developer.read} ${API_FAMILY_SCOPES.developer.write}`;
    const accountScopes = `${API_FAMILY_SCOPES.account.read} ${API_FAMILY_SCOPES.account.write}`;
    expect((await call(account, await token('account', developerScopes))).statusCode).toBe(403);
    expect((await call(developer, await token('developer', accountScopes))).statusCode).toBe(403);
  });
});

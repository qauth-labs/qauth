import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  decodeJwtClaims,
  E2E_REALM_NAME,
  type E2eInfrastructure,
  generateJwtPem,
  type PemKeyPair,
  pkcePair,
  provisionRealmKeys,
  registerPasswordAccount,
  resetE2eState,
  signInWithPassword,
  startE2eInfrastructure,
} from '../testing/e2e-harness';
import { API_FAMILY_AUDIENCES } from './api-conventions/families';
import { PERMISSION_REGISTRY } from './helpers/admin-permissions';
import { BUILT_IN_ROLES } from './helpers/admin-roles';
import { ADMIN_SCOPE_LIST } from './helpers/admin-scopes';

/**
 * ADMIN ROLES AND GRANTS WITH THE ISSUER-BOUND REALM RULE (#510, ADR-019
 * Decision 7), against a real Postgres and Redis.
 *
 * No admin route ships yet (#511 adds the listener and its pipeline), so the
 * suite adds a probe route under the admin prefix, beside the real app: the
 * admin family's guard with the admin issuer rule, then
 * `resolveAdminAuthority` for the realm in the path. It answers the effective
 * permissions. Grants and roles are written through the booted app's own
 * repositories, which carry the app's permission catalog.
 *
 * - An operator-realm admin acts on the realms of its grants, and on every
 *   realm with a grant on every realm.
 * - A realm-local admin acts on its own realm only, never on another realm or
 *   on the operator realm. The default realm's tokens are realm-local once the
 *   operator flag moves to another realm, the operator-realm split.
 * - A realm outside the grants answers exactly as a realm that does not exist.
 * - A revoked grant, a disabled role and a disabled account count from the
 *   next request, with the same token.
 * - The token endpoint withholds an admin scope the account's grants do not
 *   reach, refuses the admin audience to an account with no grant, and reads
 *   the grants again on every refresh.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const ADMIN = API_FAMILY_AUDIENCES.admin;
const ALL_ADMIN_SCOPES = ADMIN_SCOPE_LIST.join(' ');
const REDIRECT_URI = 'https://console.example.com/callback';
const CLIENT_SECRET = 'admin-machine-secret-of-sufficient-length-42';

function probePath(realmId: string): string {
  return `/admin/v1-rc.0/realms/${realmId}/probe`;
}

/** The permission ids of `classes`, sorted, as the probe answers them. */
function idsOfClasses(...classes: string[]): string[] {
  return PERMISSION_REGISTRY.active
    .filter((permission) => classes.includes(permission.class))
    .map((permission) => permission.id)
    .sort();
}

describe('admin roles and grants with the issuer-bound realm rule (#510, real containers)', () => {
  let infra: E2eInfrastructure | undefined;
  let jwt: PemKeyPair | undefined;
  let booted: BootedAuthServer | undefined;
  let dockerUp = false;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    jwt = await generateJwtPem();
    booted = await bootAuthServer(baseEnvironment(infra, jwt), {
      // Imported from the module registry the booted app loaded (the harness
      // resets it per boot), so the errors are the classes its handler knows.
      routes: async (scope) => {
        const { requireFamilyToken } = await import('./helpers/family-token');
        const { adminAuthorityError, adminIssuerResolver, resolveAdminAuthority } =
          await import('./helpers/admin-authority');
        scope.get<{ Params: { realmId: string } }>(
          '/admin/v1-rc.0/realms/:realmId/probe',
          {
            preHandler: requireFamilyToken('admin', {
              issuerResolver: adminIssuerResolver(),
              subjects: ['user'],
            }),
            config: { surface: 'api' },
          },
          async (request) => {
            const claims = request.jwtPayload;
            if (claims?.iss === undefined) throw new Error('the guard set no claims');
            const { realmId } = request.params;
            const authority = await resolveAdminAuthority(request.server, {
              iss: claims.iss,
              sub: claims.sub,
              scopes: claims.scope,
              targetRealmId: realmId,
            });
            if (!authority.allowed) throw adminAuthorityError(authority.refusal, realmId);
            return {
              realm: authority.targetRealm.id,
              operator: authority.operator,
              permissions: [...authority.permissions].sort(),
            };
          }
        );
      },
    });
  }, 240_000);

  afterAll(async () => {
    await booted?.close();
    await infra?.teardown();
  });

  beforeEach(async (ctx) => {
    if (!dockerUp || !booted) {
      ctx.skip();
      return;
    }
    await resetE2eState(booted.app);
  });

  function app(): FastifyInstance {
    if (!booted) throw new Error('server not booted');
    return booted.app;
  }

  async function defaultRealmId(): Promise<string> {
    const realm = await app().repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm) throw new Error('default realm missing');
    return realm.id;
  }

  async function tenant(name: string): Promise<string> {
    const host = `${name}.example.com`;
    const { realm } = await app().repositories.realms.createWithPrimaryHost(
      { name, issuer: `https://${host}`, enabled: true },
      host
    );
    return realm.id;
  }

  /** An account of `realmId`, written directly: no sign-in needed. */
  async function account(realmId: string): Promise<string> {
    return (await app().repositories.users.create({ realmId })).id;
  }

  /** The default realm as the JWT plugin takes it: its id and its issuer (#491). */
  async function defaultTokenRealm(): Promise<{ id: string; issuer: string }> {
    const realm = await app().repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm?.issuer) throw new Error('default realm missing');
    return { id: realm.id, issuer: realm.issuer };
  }

  /** An admin token of the default realm, signed with its keys, for `userId`. */
  async function adminToken(userId: string, scope = ALL_ADMIN_SCOPES): Promise<string> {
    return app().jwtUtils.signAccessToken(await defaultTokenRealm(), {
      sub: userId,
      clientId: 'admin-console',
      aud: ADMIN,
      scope,
    });
  }

  function probe(realmId: string, token: string): Promise<LightMyRequestResponse> {
    return app().inject({
      method: 'GET',
      url: probePath(realmId),
      headers: { authorization: `Bearer ${token}` },
    });
  }

  /** `resolveAdminAuthority` called directly, for a token of the default realm, on the real rows. */
  async function authorityFor(userId: string, targetRealmId: string) {
    const { resolveAdminAuthority } = await import('./helpers/admin-authority');
    return resolveAdminAuthority(app(), {
      iss: (await defaultTokenRealm()).issuer,
      sub: userId,
      scopes: ALL_ADMIN_SCOPES,
      targetRealmId,
    });
  }

  function grant(
    userId: string,
    targetRealmId: string | null,
    role: string | { roleId: string } = 'viewer'
  ) {
    return app().repositories.adminGrants.create({
      userId,
      role:
        typeof role === 'string' ? { kind: 'built-in', name: role } : { kind: 'custom', ...role },
      targetRealmId,
      createdBy: null,
    });
  }

  /** Move the operator flag from the default realm to a new realm, as the operator-realm split does. */
  async function splitOperatorRealm(): Promise<string> {
    const ops = await tenant('ops');
    const defaultRealm = await defaultRealmId();
    await app().db.transaction(async (tx) => {
      await app().repositories.realms.setOperator(defaultRealm, false, tx);
      await app().repositories.realms.setOperator(ops, true, tx);
    });
    return ops;
  }

  describe('an operator-realm admin', () => {
    it('acts on the realm of its grant and not on another', async () => {
      const operator = await defaultRealmId();
      const a = await tenant('alpha');
      const b = await tenant('beta');
      const admin = await account(operator);
      await grant(admin, a, 'security-admin');
      const token = await adminToken(admin);

      const onA = await probe(a, token);
      expect(onA.statusCode).toBe(200);
      expect(onA.json()).toEqual({
        realm: a,
        operator: true,
        permissions: [...BUILT_IN_ROLES['security-admin'].permissionIds].sort(),
      });
      for (const other of [b, operator]) {
        const refused = await probe(other, token);
        expect(refused.statusCode).toBe(404);
        expect(refused.json()).toMatchObject({ status: 404, code: 'not_found' });
      }
    });

    it('acts on any realm, the operator realm included, with a grant on every realm', async () => {
      const operator = await defaultRealmId();
      const realms = [operator, await tenant('alpha'), await tenant('beta')];
      const admin = await account(operator);
      await grant(admin, null, 'viewer');
      const token = await adminToken(admin);

      for (const realmId of realms) {
        const response = await probe(realmId, token);
        expect(response.statusCode).toBe(200);
        expect(response.json()).toEqual({
          realm: realmId,
          operator: true,
          permissions: idsOfClasses('read'),
        });
      }
    });

    it('uses only the classes its token carries, whatever the role', async () => {
      const operator = await defaultRealmId();
      const a = await tenant('alpha');
      const admin = await account(operator);
      await grant(admin, a, 'security-admin');

      const readSecurity = await probe(
        a,
        await adminToken(admin, 'qauth:admin:read qauth:admin:security')
      );
      expect(readSecurity.json()).toMatchObject({ permissions: idsOfClasses('read', 'security') });
      expect(
        (readSecurity.json() as { permissions: string[] }).permissions.filter(
          (id) => PERMISSION_REGISTRY.get(id)?.class === 'write'
        )
      ).toEqual([]);
    });
  });

  describe('a realm-local admin', () => {
    it('acts on its own realm, and never on another realm or on the operator realm', async () => {
      // The default realm, which JWT_ISSUER names, stops being the operator
      // realm: its tokens are realm-local from here on.
      const ops = await splitOperatorRealm();
      const own = await defaultRealmId();
      const b = await tenant('beta');
      const admin = await account(own);
      await grant(admin, own, 'editor');
      const token = await adminToken(admin);

      const onOwn = await probe(own, token);
      expect(onOwn.statusCode).toBe(200);
      expect(onOwn.json()).toEqual({
        realm: own,
        operator: false,
        permissions: idsOfClasses('read', 'write'),
      });
      for (const other of [b, ops]) {
        expect((await probe(other, token)).statusCode).toBe(404);
      }
    });

    it('cannot be granted another realm or every realm, by the repository or by hand', async () => {
      await splitOperatorRealm();
      const own = await defaultRealmId();
      const b = await tenant('beta');
      const admin = await account(own);
      await expect(grant(admin, null)).rejects.toThrow(/operator realm/);
      await expect(grant(admin, b)).rejects.toThrow(/own realm only/);
      await expect(
        app().dbPool.query(
          `INSERT INTO admin_grants (user_id, built_in_role, target_realm_id) VALUES ($1, 'viewer', NULL)`,
          [admin]
        )
      ).rejects.toMatchObject({
        code: '23514',
        constraint: 'admin_grants_all_realms_operator_only',
      });
    });
  });

  describe('a realm outside the grants', () => {
    it('answers exactly as a realm that does not exist', async () => {
      const operator = await defaultRealmId();
      const a = await tenant('alpha');
      const b = await tenant('beta');
      const admin = await account(operator);
      await grant(admin, a);
      const token = await adminToken(admin);

      // The same realm id in both requests: once it exists outside the grant,
      // once it does not exist at all.
      const outside = await probe(b, token);
      await app().repositories.realms.delete(b);
      const missing = await probe(b, token);
      const comparable = (response: LightMyRequestResponse) => {
        const body = { ...(response.json() as Record<string, unknown>) };
        delete body['trace_id'];
        return { status: response.statusCode, type: response.headers['content-type'], body };
      };
      expect(outside.statusCode).toBe(404);
      expect(comparable(outside)).toEqual(comparable(missing));
    });
  });

  describe('on the next request, with the same token', () => {
    it('a revoked grant stops working', async () => {
      const operator = await defaultRealmId();
      const a = await tenant('alpha');
      const admin = await account(operator);
      const live = await grant(admin, a, 'editor');
      const token = await adminToken(admin);

      expect((await probe(a, token)).statusCode).toBe(200);
      await app().repositories.adminGrants.revoke(operator, live.id);
      expect((await probe(a, token)).statusCode).toBe(404);
    });

    it('a disabled role grants nothing, and enabled again it grants its permissions', async () => {
      const operator = await defaultRealmId();
      const a = await tenant('alpha');
      const admin = await account(operator);
      // Written straight to the test database: no route reads custom roles
      // until the admin API's role routes ship (#679), so the app's service
      // roles do not build their repository (#495), and the app may not reach
      // `@qauth-labs/infra-db` to build one. The repository's own checks are
      // `admin-grants.integration.test.ts`'s.
      const setRole = (changes: string, values: unknown[]) =>
        app().dbPool.query(
          `UPDATE admin_roles SET ${changes}, updated_at = updated_at + 1 WHERE id = $1`,
          values
        );
      const {
        rows: [role],
      } = await app().dbPool.query<{ id: string }>(
        `INSERT INTO admin_roles (realm_id, name, permission_ids)
         VALUES ($1, 'policy-editor', '["realms.policies.write", "realms.read"]') RETURNING id`,
        [a]
      );
      await grant(admin, a, { roleId: role.id });
      const token = await adminToken(admin);

      expect((await probe(a, token)).json()).toMatchObject({
        permissions: ['realms.policies.write', 'realms.read'],
      });
      await setRole('disabled_at = updated_at', [role.id]);
      expect((await probe(a, token)).statusCode).toBe(404);
      await setRole(`disabled_at = NULL, permission_ids = '["realms.read"]'`, [role.id]);
      expect((await probe(a, token)).json()).toMatchObject({ permissions: ['realms.read'] });
    });

    it('a disabled account is refused, by the guard and by resolveAdminAuthority itself', async () => {
      const operator = await defaultRealmId();
      const admin = await account(operator);
      await grant(admin, null);
      const token = await adminToken(admin);

      expect((await probe(operator, token)).statusCode).toBe(200);
      await app().repositories.users.update(operator, admin, { enabled: false });
      const refused = await probe(operator, token);
      expect(refused.statusCode).toBe(401);
      expect(refused.json()).toMatchObject({ code: 'invalid_access_token' });
      // The guard refused first; the authority's own check, on the same rows.
      await expect(authorityFor(admin, operator)).resolves.toEqual({
        allowed: false,
        refusal: 'account_inactive',
      });
    });
  });

  describe('a token the admin API does not accept', () => {
    it("is refused for another realm's account under the default realm's issuer, for another realm's token, and when an agent holds it", async () => {
      const operator = await defaultRealmId();
      const a = await tenant('alpha');
      const admin = await account(operator);
      await grant(admin, null, 'security-admin');
      // A realm-A account in a token of the default realm: its subject lives
      // elsewhere.
      const ofA = await account(a);
      await grant(ofA, a);
      expect((await probe(a, await adminToken(ofA))).statusCode).toBe(401);
      // The guard refused it for the request's realm; the authority refuses it
      // too, since the realm the issuer names is not the account's.
      await expect(authorityFor(ofA, a)).resolves.toEqual({
        allowed: false,
        refusal: 'account_inactive',
      });

      // Realm A signs its own tokens, under its own issuer (#491). Its admin's
      // token names an enabled realm, but it verifies with none of the keys of
      // the realm whose host it is sent to, nor would a token signed with the
      // default realm's keys pass under realm A's issuer.
      await provisionRealmKeys(app(), 'alpha');
      const realmA = await app().repositories.realms.findById(a);
      if (!realmA?.issuer) throw new Error('realm alpha missing');
      const ofAToken = await app().jwtUtils.signAccessToken(
        { id: realmA.id },
        { sub: ofA, clientId: 'admin-console', aud: ADMIN, scope: ALL_ADMIN_SCOPES }
      );
      expect((await probe(a, ofAToken)).statusCode).toBe(401);
      const { deploymentIssuerKeyResolver } = await import('./helpers/admin-authority');
      const keys = deploymentIssuerKeyResolver(app());
      await expect(keys.verifyAccessToken(realmA, ofAToken)).resolves.toMatchObject({
        iss: realmA.issuer,
        sub: ofA,
      });
      await expect(keys.verifyAccessToken(realmA, await adminToken(admin))).rejects.toThrow();

      const delegated = await app().jwtUtils.signAccessToken(await defaultTokenRealm(), {
        sub: admin,
        clientId: 'agent',
        aud: ADMIN,
        scope: ALL_ADMIN_SCOPES,
        act: { sub: 'agent' },
      });
      expect((await probe(a, delegated)).statusCode).toBe(401);
    });
  });

  describe('the token endpoint', () => {
    async function adminConsole(userId: string): Promise<string> {
      const realm = await defaultRealmId();
      const client = await app().repositories.oauthClients.create({
        realmId: realm,
        clientId: 'admin-console',
        clientSecretHash: 'unused-public-client',
        tokenEndpointAuthMethod: 'none',
        name: 'Admin console',
        redirectUris: [REDIRECT_URI],
        scopes: ['openid', ...ADMIN_SCOPE_LIST],
        grantTypes: ['authorization_code', 'refresh_token'],
        audience: [ADMIN],
        enabled: true,
        requirePkce: true,
        provisionedByOperator: true,
      });
      // Realm first (#489): the realm, the account, the client.
      await app().repositories.oauthConsents.upsertGrant(
        realm,
        userId,
        client.id,
        ['openid', ...ADMIN_SCOPE_LIST],
        [ADMIN]
      );
      return client.id;
    }

    /** A code for `scope`, through the real `/oauth/authorize` with a stored consent. */
    async function codeFor(
      cookie: string,
      scope: string,
      resource: string | undefined
    ): Promise<{ code: string; verifier: string }> {
      const { verifier, challenge } = pkcePair();
      const response = await app().inject({
        method: 'GET',
        url: `/oauth/authorize?${new URLSearchParams({
          response_type: 'code',
          client_id: 'admin-console',
          redirect_uri: REDIRECT_URI,
          scope,
          ...(resource === undefined ? {} : { resource }),
          code_challenge: challenge,
          code_challenge_method: 'S256',
          state: 'admin-state',
        })}`,
        headers: { cookie },
      });
      expect(response.statusCode).toBe(302);
      const code = new URL(response.headers['location'] as string).searchParams.get('code');
      if (code === null) throw new Error(`no code: ${response.headers['location']}`);
      return { code, verifier };
    }

    function tokenRequest(form: Record<string, string>): Promise<LightMyRequestResponse> {
      return app().inject({
        method: 'POST',
        url: '/oauth/token',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        payload: new URLSearchParams(form).toString(),
      });
    }

    function redeem(code: { code: string; verifier: string }) {
      return tokenRequest({
        grant_type: 'authorization_code',
        code: code.code,
        redirect_uri: REDIRECT_URI,
        client_id: 'admin-console',
        code_verifier: code.verifier,
      });
    }

    async function failureReasons(): Promise<unknown[]> {
      const { rows } = await app().dbPool.query<{ data: Record<string, unknown> }>(
        `SELECT data FROM events WHERE type = 'urn:qauth:event:token.request_failed:v1-rc.0' ORDER BY seq`
      );
      return rows.map((row) => row.data['reason']);
    }

    it('withholds the admin scopes the grants do not reach, and reads the grants again on refresh', async () => {
      const email = 'viewer-admin@example.com';
      const userId = await registerPasswordAccount(app(), email);
      const cookie = (await signInWithPassword(app(), email)).header() as string;
      await adminConsole(userId);
      const viewer = await grant(userId, null, 'viewer');

      const issued = await redeem(await codeFor(cookie, `openid ${ALL_ADMIN_SCOPES}`, ADMIN));
      expect(issued.statusCode).toBe(200);
      const body = issued.json<{ access_token: string; refresh_token: string; scope: string }>();
      expect(body.scope).toBe('openid qauth:admin:read');
      expect(decodeJwtClaims(body.access_token)).toMatchObject({
        aud: ADMIN,
        scope: 'openid qauth:admin:read',
      });
      expect((await probe(await defaultRealmId(), body.access_token)).json()).toMatchObject({
        permissions: idsOfClasses('read'),
      });

      // The grant is revoked: the refresh is refused, and the refresh token is
      // left as it was.
      await app().repositories.adminGrants.revoke(await defaultRealmId(), viewer.id);
      const refresh = () =>
        tokenRequest({
          grant_type: 'refresh_token',
          refresh_token: body.refresh_token,
          client_id: 'admin-console',
        });
      const refused = await refresh();
      expect(refused.statusCode).toBe(400);
      expect(refused.json()).toMatchObject({ error: 'invalid_target' });
      expect(await failureReasons()).toEqual(['admin_audience_without_grant']);

      // An editor grant later: the same refresh token now reaches two classes.
      await grant(userId, null, 'editor');
      const refreshed = await refresh();
      expect(refreshed.statusCode).toBe(200);
      expect(refreshed.json()).toMatchObject({
        scope: 'openid qauth:admin:read qauth:admin:write',
      });
    });

    it('withholds every admin scope from an account with no grant, and refuses it the admin audience', async () => {
      const email = 'no-grant@example.com';
      const userId = await registerPasswordAccount(app(), email);
      const cookie = (await signInWithPassword(app(), email)).header() as string;
      await adminConsole(userId);

      const refused = await redeem(await codeFor(cookie, `openid ${ALL_ADMIN_SCOPES}`, ADMIN));
      expect(refused.statusCode).toBe(400);
      expect(refused.json()).toMatchObject({ error: 'invalid_target' });
      expect(await failureReasons()).toEqual(['admin_audience_without_grant']);

      // Without the admin audience the token is issued, without the scopes.
      const plain = await redeem(await codeFor(cookie, `openid ${ALL_ADMIN_SCOPES}`, undefined));
      expect(plain.statusCode).toBe(200);
      const body = plain.json<{ access_token: string; scope: string }>();
      expect(body.scope).toBe('openid');
      expect(decodeJwtClaims(body.access_token)).toMatchObject({
        aud: 'admin-console',
        scope: 'openid',
      });

      // A code that asked only for admin scopes is refused, never answered
      // with no scope, and is not spent: once a grant exists it redeems.
      const onlyAdmin = await codeFor(cookie, ALL_ADMIN_SCOPES, undefined);
      const nothingLeft = await redeem(onlyAdmin);
      expect(nothingLeft.statusCode).toBe(400);
      expect(nothingLeft.json()).toMatchObject({ error: 'invalid_scope' });
      expect((await failureReasons()).at(-1)).toBe('admin_scope_without_grant');
      await grant(userId, null, 'viewer');
      const redeemed = await redeem(onlyAdmin);
      expect(redeemed.statusCode).toBe(200);
      expect(redeemed.json()).toMatchObject({ scope: 'qauth:admin:read' });
    });

    it('gives a client_credentials token neither the admin audience nor an admin scope', async () => {
      await app().repositories.oauthClients.create({
        realmId: await defaultRealmId(),
        clientId: 'admin-machine',
        clientSecretHash: await app().passwordHasher.hashPassword(CLIENT_SECRET),
        tokenEndpointAuthMethod: 'client_secret_post',
        name: 'admin-machine',
        redirectUris: [],
        grantTypes: ['client_credentials'],
        scopes: ['probe:read', ...ADMIN_SCOPE_LIST],
        audience: [ADMIN, 'https://api.example.com'],
        enabled: true,
      });
      const machine = (form: Record<string, string>) =>
        tokenRequest({
          grant_type: 'client_credentials',
          client_id: 'admin-machine',
          client_secret: CLIENT_SECRET,
          ...form,
        });

      const toAdmin = await machine({ scope: 'probe:read', resource: ADMIN });
      expect(toAdmin.statusCode).toBe(400);
      expect(toAdmin.json()).toMatchObject({ error: 'invalid_target' });

      const scoped = await machine({
        scope: `probe:read ${ALL_ADMIN_SCOPES}`,
        resource: 'https://api.example.com',
      });
      expect(scoped.statusCode).toBe(200);
      expect(scoped.json()).toMatchObject({ scope: 'probe:read' });

      const onlyAdmin = await machine({
        scope: ALL_ADMIN_SCOPES,
        resource: 'https://api.example.com',
      });
      expect(onlyAdmin.statusCode).toBe(400);
      expect(onlyAdmin.json()).toMatchObject({ error: 'invalid_scope' });
      expect(await failureReasons()).toEqual([
        'admin_audience_without_grant',
        'admin_scope_without_grant',
      ]);
    });
  });
});

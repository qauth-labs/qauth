import { KEY_ACTIVATION_DELAY_MS } from '@qauth-labs/fastify-plugin-signer';
import { requireDockerOrSkip, truncateDomainTablesStatement } from '@qauth-labs/shared-testing';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import { decodeProtectedHeader, type JSONWebKeySet } from 'jose';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  allowConsentScreen,
  baseEnvironment,
  bootAuthServer,
  type BootAuthServerOptions,
  type BootedAuthServer,
  E2E_PASSWORD,
  E2E_REALM_NAME,
  type E2eInfrastructure,
  generateJwtPem,
  type PemKeyPair,
  pkcePair,
  registerPasswordAccount,
  signInWithPassword,
  startE2eInfrastructure,
} from '../testing/e2e-harness';
import { startTcpRelay, type TcpRelay } from '../testing/tcp-relay';
import type { KeyRetirementOutcome } from './helpers/key-retirement';

/**
 * EMERGENCY KEY RETIREMENT (ADR-019 Decision 9, issue #551), against a real
 * Postgres and Redis.
 *
 * A token-signing key that may be compromised is retired at once: it leaves
 * the JWKS, a new key signs, and its `kid` goes on the denylist every token
 * verification checks. The node that retires it refuses its tokens at once;
 * every other running node within 10 s, through its copy of the denylist,
 * rather than after the 60-second key refresh. The refresh-token families
 * and browser sessions of the realm used since the key began to sign are
 * revoked; those from before are not.
 *
 * A retirement runs here on a node (`retireOnNode`: the node's own key
 * rotation, and its copy of the denylist told at once) and through the
 * break-glass command's wiring (`keysRetireDependencies`) over a booted
 * server, whose copy only its timed read updates, as a node beside the
 * command's host. App modules are imported after each boot, so they are the
 * instances the server loaded.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const FORM = { 'content-type': 'application/x-www-form-urlencoded' };
const MINUTE = 60_000;
const MACHINE_ID = 'retirement-machine';
const MACHINE_SECRET = 'retirement-machine-secret-of-sufficient-length';
const AGENT_ID = 'retirement-agent';
const AGENT_SECRET = 'retirement-agent-secret-of-sufficient-length-42';
const AGENT_REDIRECT_URI = 'https://agent.example.com/callback';
const AGENT_SCOPES = ['openid', 'notes:read'];
const HYBRID = { HYBRID_SIGNING_ENABLED: 'true', SIGNING_ALGORITHM_MODE: 'ed25519+ml-dsa-65' };
const OPERATOR = 'retirement-operator';
const EMERGENCY_RETIRED = 'urn:qauth:event:key.emergency_retired:v1-rc.0';
/** How long another node may take to refuse a retired key's tokens (#551). */
const OTHER_NODE_BOUND_MS = 10_000;

/** A `token_signing` key as the realm's key store holds it. */
interface StoredTokenKey {
  readonly kid: string;
  readonly algorithm: string;
  readonly status: string;
}

describe('emergency key retirement (#551)', () => {
  let infra: E2eInfrastructure | undefined;
  let jwt: PemKeyPair | undefined;
  let dockerUp = false;
  const booted: BootedAuthServer[] = [];
  const relays: TcpRelay[] = [];

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    jwt = await generateJwtPem();
  }, 240_000);

  afterAll(async () => {
    await infra?.teardown();
  });

  beforeEach(async (ctx) => {
    if (!dockerUp) {
      ctx.skip();
      return;
    }
    await emptyStores();
  }, 120_000);

  afterEach(async () => {
    await Promise.all(booted.splice(0).map(async (server) => server.close()));
    await Promise.all(relays.splice(0).map(async (relay) => relay.stop()));
  });

  /**
   * A deployment that sets no key variable, plus `extra`: the store holds the
   * keys. A key variable that holds a compromised key refuses the boot, so
   * no suite here sets one.
   */
  function variables(extra: Record<string, string> = {}): Record<string, string> {
    if (!infra || !jwt) throw new Error('infrastructure not started');
    const environment: Record<string, string> = { ...baseEnvironment(infra, jwt), ...extra };
    delete environment['JWT_PRIVATE_KEY'];
    delete environment['JWT_PUBLIC_KEY'];
    return environment;
  }

  async function boot(
    environment: Record<string, string> = variables(),
    options: BootAuthServerOptions = {}
  ): Promise<FastifyInstance> {
    const server = await bootAuthServer(environment, options);
    booted.push(server);
    return server.app;
  }

  async function closeAll(): Promise<void> {
    await Promise.all(booted.splice(0).map(async (server) => server.close()));
  }

  /** Empty the database and Redis through a throwaway server: the next boot is a first one. */
  async function emptyStores(): Promise<void> {
    const server = await bootAuthServer(variables());
    await server.app.dbPool.query(truncateDomainTablesStatement());
    await server.app.redis.flushdb();
    await server.close();
  }

  async function realmId(app: FastifyInstance): Promise<string> {
    const realm = await app.repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm) throw new Error(`no realm ${E2E_REALM_NAME}`);
    return realm.id;
  }

  async function storedTokenKeys(app: FastifyInstance): Promise<StoredTokenKey[]> {
    const { rows } = await app.dbPool.query<StoredTokenKey>(
      `SELECT kid, algorithm, status FROM realm_keys
        WHERE realm_id = $1 AND purpose = 'token_signing' ORDER BY algorithm, kid`,
      [await realmId(app)]
    );
    return rows;
  }

  async function activeKid(app: FastifyInstance, algorithm: string): Promise<string> {
    const key = (await storedTokenKeys(app)).find(
      (row) => row.algorithm === algorithm && row.status === 'active'
    );
    if (!key) throw new Error(`no active ${algorithm} key`);
    return key.kid;
  }

  async function seedMachineClient(app: FastifyInstance): Promise<void> {
    await app.repositories.oauthClients.create({
      realmId: await realmId(app),
      clientId: MACHINE_ID,
      clientSecretHash: await app.passwordHasher.hashPassword(MACHINE_SECRET),
      tokenEndpointAuthMethod: 'client_secret_post',
      name: 'Retirement test machine',
      redirectUris: [],
      scopes: ['reports:read'],
      grantTypes: ['client_credentials'],
      enabled: true,
    });
  }

  async function machineToken(app: FastifyInstance): Promise<string> {
    const response = await app.inject({
      method: 'POST',
      url: '/oauth/token',
      headers: FORM,
      payload: new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: MACHINE_ID,
        client_secret: MACHINE_SECRET,
        scope: 'reports:read',
      }).toString(),
    });
    expect(response.statusCode, response.body).toBe(200);
    return response.json<{ access_token: string }>().access_token;
  }

  /** RFC 7662 introspection by the machine client, which the token was issued to. */
  async function introspect(app: FastifyInstance, token: string): Promise<Record<string, unknown>> {
    const response = await app.inject({
      method: 'POST',
      url: '/oauth/introspect',
      headers: FORM,
      payload: new URLSearchParams({
        token,
        client_id: MACHINE_ID,
        client_secret: MACHINE_SECRET,
      }).toString(),
    });
    expect(response.statusCode, response.body).toBe(200);
    return response.json<Record<string, unknown>>();
  }

  function userinfo(app: FastifyInstance, token: string): Promise<LightMyRequestResponse> {
    return app.inject({
      method: 'GET',
      url: '/oauth/userinfo',
      headers: { authorization: `Bearer ${token}` },
    });
  }

  async function jwksKids(app: FastifyInstance): Promise<unknown[]> {
    const response = await app.inject({ method: 'GET', url: '/.well-known/jwks.json' });
    expect(response.statusCode).toBe(200);
    return response.json<JSONWebKeySet>().keys.map((key) => key.kid);
  }

  /**
   * A signed-in user's access token from the code flow, for an agent client
   * with the user's consent: its `aud` is the agent, so userinfo takes it.
   */
  async function userAccessToken(app: FastifyInstance): Promise<string> {
    const email = 'retirement-user@example.test';
    const userId = await registerPasswordAccount(app, email);
    const jar = await signInWithPassword(app, email, E2E_PASSWORD);
    const realm = await realmId(app);
    const client = await app.repositories.oauthClients.create({
      realmId: realm,
      clientId: AGENT_ID,
      clientSecretHash: await app.passwordHasher.hashPassword(AGENT_SECRET),
      tokenEndpointAuthMethod: 'client_secret_post',
      name: 'Retirement test agent',
      redirectUris: [AGENT_REDIRECT_URI],
      scopes: AGENT_SCOPES,
      grantTypes: ['authorization_code'],
      isAgent: true,
      enabled: true,
      requirePkce: true,
    });
    await app.repositories.oauthConsents.upsertGrant(realm, userId, client.id, AGENT_SCOPES);

    const pkce = pkcePair();
    const authorize = await app.inject({
      method: 'GET',
      url: `/oauth/authorize?${new URLSearchParams({
        response_type: 'code',
        client_id: AGENT_ID,
        redirect_uri: AGENT_REDIRECT_URI,
        scope: AGENT_SCOPES.join(' '),
        code_challenge: pkce.challenge,
        code_challenge_method: 'S256',
        state: 'retirement-state',
      }).toString()}`,
      headers: { cookie: jar.header() as string },
    });
    expect(authorize.statusCode, authorize.body).toBe(302);
    let location = String(authorize.headers['location']);
    if (location.startsWith('/ui/consent?')) {
      location = await allowConsentScreen(app, jar.header() as string, location);
    }
    const code = new URL(location).searchParams.get('code');
    if (code === null) throw new Error(`authorize returned no code: ${location}`);
    const token = await app.inject({
      method: 'POST',
      url: '/oauth/token',
      headers: FORM,
      payload: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: AGENT_REDIRECT_URI,
        client_id: AGENT_ID,
        client_secret: AGENT_SECRET,
        code_verifier: pkce.verifier,
      }).toString(),
    });
    expect(token.statusCode, token.body).toBe(200);
    return token.json<{ access_token: string }>().access_token;
  }

  /**
   * Retire `kid` on `app`, as a node runs it: its own key rotation, and its
   * copy of the denylist told the retired kids once the transaction commits.
   */
  async function retireOnNode(app: FastifyInstance, kid: string): Promise<KeyRetirementOutcome> {
    const { retireKeyNow } = await import('./helpers/key-retirement');
    const { invalidateKeyDenylist } = await import('./helpers/key-denylist');
    const { hostKeyRetirementApproval } = await import('./helpers/keys-retire');
    const rotation = app.keyRotation;
    if (rotation === null) throw new Error('the node holds no signer');
    return retireKeyNow(
      {
        retire: (input) => rotation.retireNow(input),
        refreshTokens: app.repositories.refreshTokens,
        events: app.repositories.events,
        adminAuditLog: app.repositories.adminAuditLog,
        sessions: app.sessionService,
        invalidateDenylist: (retired) =>
          invalidateKeyDenylist(
            app.keyDenylist,
            {
              redis: () => app.redis,
              listDenied: () => app.repositories.realmPublicKeys.listDenied(),
            },
            app.log,
            retired
          ),
      },
      { realmId: await realmId(app), kid, approval: hostKeyRetirementApproval(OPERATOR) }
    );
  }

  /** Poll `check` every 100 ms until it holds, for at most `limitMs`; the time it took. */
  async function within(limitMs: number, check: () => Promise<boolean>): Promise<number> {
    const started = Date.now();
    for (;;) {
      if (await check()) return Date.now() - started;
      if (Date.now() - started > limitMs) {
        throw new Error(`not within ${limitMs} ms`);
      }
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  }

  it('refuses the key at once on the node that retires it, within 10 s on a running one, and signs with a new key', async () => {
    const a = await boot();
    await seedMachineClient(a);
    const accessToken = await userAccessToken(a);
    const machine = await machineToken(a);
    const kid = await activeKid(a, 'EdDSA');
    expect(decodeProtectedHeader(machine)['kid']).toBe(kid);

    // A second node, running before the retirement: it verifies the key's
    // tokens, so its signer holds the realm's key list, which it would keep
    // for a minute.
    const b = await boot();
    expect(await introspect(b, machine)).toMatchObject({ active: true });
    expect((await userinfo(b, accessToken)).statusCode).toBe(200);
    expect(await jwksKids(b)).toContain(kid);

    const { record } = await retireOnNode(a, kid);
    expect(record.retired).toEqual([expect.objectContaining({ kid, previousStatus: 'active' })]);
    const [replacement] = record.replacements;
    expect(replacement).toMatchObject({ algorithm: 'EdDSA' });

    // The node that retired it: at once.
    expect(await introspect(a, machine)).toEqual({ active: false });
    const refused = await userinfo(a, accessToken);
    expect(refused.statusCode).toBe(401);
    expect(await jwksKids(a)).not.toContain(kid);
    const fresh = await machineToken(a);
    expect(decodeProtectedHeader(fresh)['kid']).toBe(replacement?.kid);
    expect(await introspect(a, fresh)).toMatchObject({ active: true });

    // The other running node: within the bound, without the key refresh.
    const tookMs = await within(
      OTHER_NODE_BOUND_MS,
      async () => (await introspect(b, machine))['active'] === false
    );
    expect(tookMs).toBeLessThan(OTHER_NODE_BOUND_MS);
    expect((await userinfo(b, accessToken)).statusCode).toBe(401);
    expect(await jwksKids(b)).not.toContain(kid);
    expect(decodeProtectedHeader(await machineToken(b))['kid']).toBe(replacement?.kid);

    // The store: the key compromised, its kid denied, a new key active.
    const realm = await realmId(a);
    expect(await storedTokenKeys(a)).toEqual(
      expect.arrayContaining([
        { kid, algorithm: 'EdDSA', status: 'compromised' },
        { kid: replacement?.kid, algorithm: 'EdDSA', status: 'active' },
      ])
    );
    const { rows: denied } = await a.dbPool.query(
      `SELECT kid FROM realm_key_denylist WHERE realm_id = $1`,
      [realm]
    );
    expect(denied).toEqual([{ kid }]);
  }, 180_000);

  it('revokes the families and sessions of the realm used while the key was active, not those from before', async () => {
    const app = await boot();
    const realm = await realmId(app);
    const kid = await activeKid(app, 'EdDSA');
    const now = Date.now();
    const activeFrom = now - 10 * MINUTE;
    // A switch is written the activation delay ahead: the key may sign from then.
    const signedSince = activeFrom - KEY_ACTIVATION_DELAY_MS;
    const before = now - 120 * MINUTE;
    const during = now - MINUTE;
    // The key was made a quarter of an hour ago, and began to sign ten minutes ago.
    await app.dbPool.query(
      `UPDATE realm_keys SET created_at = $3, activate_at = $4 WHERE realm_id = $1 AND kid = $2`,
      [realm, kid, now - 15 * MINUTE, activeFrom]
    );
    // Rows only: a sign-in would add a session and a family of its own.
    const { rows: users } = await app.dbPool.query<{ id: string }>(
      `INSERT INTO users (realm_id) VALUES ($1) RETURNING id`,
      [realm]
    );
    const userId = users[0]?.id as string;
    const { rows: clients } = await app.dbPool.query<{ id: string }>(
      `INSERT INTO oauth_clients (realm_id, client_id, client_secret_hash, name, redirect_uris)
       VALUES ($1, 'retirement-app', 'h', 'Retirement test app', '["https://app.example.com/cb"]')
       RETURNING id`,
      [realm]
    );
    const client = { id: clients[0]?.id as string };

    /** A live session, created and last seen at the times given. */
    async function session(createdAt: number, lastSeenAt: number): Promise<string> {
      const { rows } = await app.dbPool.query<{ id: string }>(
        `INSERT INTO sessions (realm_id, user_id, auth_time, expires_at, created_at, last_seen_at)
         VALUES ($1, $2, $3, $4, $3, $5) RETURNING id`,
        [realm, userId, createdAt, now + 24 * 60 * MINUTE, lastSeenAt]
      );
      return rows[0]?.id as string;
    }

    /** A live refresh-token family of one token, created and last used at the times given. */
    async function family(createdAt: number, lastUsedAt: number | null): Promise<string> {
      const { rows } = await app.dbPool.query<{ family_id: string }>(
        `INSERT INTO refresh_tokens
           (token_hash, user_id, oauth_client_id, family_id, family_created_at,
            family_session_expires_at, expires_at, created_at, last_used_at)
         VALUES (md5(random()::text) || md5(random()::text), $1, $2, gen_random_uuid(),
                 $3, $4, $4, $3, $5)
         RETURNING family_id`,
        [userId, client.id, createdAt, now + 24 * 60 * MINUTE, lastUsedAt]
      );
      return rows[0]?.family_id as string;
    }

    const sessions = {
      before: await session(before, before),
      usedSince: await session(before, during),
      createdSince: await session(during, during),
    };
    const families = {
      before: await family(before, before),
      neverUsed: await family(before, null),
      usedSince: await family(before, during),
      createdSince: await family(during, null),
    };

    const outcome = await retireOnNode(app, kid);

    expect(outcome.record.signedSince).toBe(signedSince);
    expect(outcome.families).toEqual({ families: 2, tokens: 2 });
    expect(outcome.sessions.ended).toBe(2);
    const { rows: sessionRows } = await app.dbPool.query<{ id: string; reason: string | null }>(
      `SELECT id, revoked_reason AS reason FROM sessions WHERE realm_id = $1`,
      [realm]
    );
    const reasonOf = new Map(sessionRows.map((row) => [row.id, row.reason]));
    expect(reasonOf.get(sessions.before)).toBeNull();
    expect(reasonOf.get(sessions.usedSince)).toBe('key_retired');
    expect(reasonOf.get(sessions.createdSince)).toBe('key_retired');
    const { rows: tokenRows } = await app.dbPool.query<{
      family_id: string;
      revoked: boolean;
      revoked_reason: string | null;
    }>(`SELECT family_id, revoked, revoked_reason FROM refresh_tokens WHERE oauth_client_id = $1`, [
      client.id,
    ]);
    const revokedOf = new Map(tokenRows.map((row) => [row.family_id, row.revoked_reason]));
    expect(revokedOf.get(families.before)).toBeNull();
    expect(revokedOf.get(families.neverUsed)).toBeNull();
    expect(revokedOf.get(families.usedSince)).toBe('key_retired');
    expect(revokedOf.get(families.createdSince)).toBe('key_retired');
  }, 180_000);

  it('retires both keys of a hybrid pair together, and the new pair signs', async () => {
    const app = await boot(variables(HYBRID));
    await seedMachineClient(app);
    const token = await machineToken(app);
    const header = decodeProtectedHeader(token);
    const pair = [String(header['kid']), String(header['pqc_kid'])];

    // Named by its ML-DSA-65 half: its Ed25519 partner goes with it.
    const { record } = await retireOnNode(app, pair[1] as string);

    expect(record.retired.map((key) => key.kid).sort()).toEqual([...pair].sort());
    expect(record.replacements.map((key) => key.algorithm)).toEqual(['EdDSA', 'ML-DSA-65']);
    expect(await storedTokenKeys(app)).toEqual(
      expect.arrayContaining([
        { kid: pair[0], algorithm: 'EdDSA', status: 'compromised' },
        { kid: pair[1], algorithm: 'ML-DSA-65', status: 'compromised' },
      ])
    );
    expect(await introspect(app, token)).toEqual({ active: false });
    const kids = await jwksKids(app);
    expect(kids).not.toContain(pair[0]);
    expect(kids).not.toContain(pair[1]);
    expect(decodeProtectedHeader(await machineToken(app))).toMatchObject({
      kid: record.replacements[0]?.kid,
      pqc_kid: record.replacements[1]?.kid,
    });
  }, 180_000);

  it('runs from the break-glass command, recorded and announced, and a running node refuses the key within 10 s', async () => {
    const app = await boot();
    await seedMachineClient(app);
    const machine = await machineToken(app);
    const kid = await activeKid(app, 'EdDSA');
    const realm = await realmId(app);
    expect(await jwksKids(app)).toContain(kid);

    const { keysRetireDependencies, runKeysRetire } = await import('./helpers/keys-retire');
    const { env } = await import('../config/env');
    const out: string[] = [];
    const err: string[] = [];
    const deps = keysRetireDependencies(app, {
      kekEnv: process.env,
      enabledSignatureAlgorithms: env.enabledSignatureAlgorithms,
      hybridSigning: env.HYBRID_SIGNING_ENABLED,
      operatingSystemUser: () => OPERATOR,
      out: (line) => out.push(line),
      err: (line) => err.push(line),
    });

    expect(await runKeysRetire(['--kid', kid, '--yes'], E2E_REALM_NAME, deps)).toBe(0);
    expect(err).toEqual([]);
    expect(out).toContain(`Retired ${kid} (EdDSA, was active): compromised.`);

    // The command told no node: the server's own copy reads the change.
    await within(
      OTHER_NODE_BOUND_MS,
      async () => (await introspect(app, machine))['active'] === false
    );
    await within(OTHER_NODE_BOUND_MS, async () => !(await jwksKids(app)).includes(kid));
    expect(decodeProtectedHeader(await machineToken(app))['kid']).not.toBe(kid);

    // Recorded in the admin audit log by the operating-system user, and
    // announced as a critical admin and security event naming the kid.
    const { rows: audit } = await app.dbPool.query(
      `SELECT actor_kind, actor_id, operation_class FROM admin_audit_log
        WHERE realm_id = $1 AND operation_id = 'keys.retire'`,
      [realm]
    );
    expect(audit).toEqual([
      { actor_kind: 'break_glass_operator', actor_id: OPERATOR, operation_class: 'security' },
    ]);
    const { rows: events } = await app.dbPool.query(
      `SELECT category, actor_type, actor_id, data FROM events WHERE realm_id = $1 AND type = $2`,
      [realm, EMERGENCY_RETIRED]
    );
    expect(events).toEqual([
      {
        category: 'admin',
        actor_type: 'operator_cli',
        actor_id: OPERATOR,
        data: { keyId: kid, purpose: 'token_signing' },
      },
    ]);

    // A second run, for a key retired already, changes no key and ends the
    // sessions again: recorded and announced, as every run is.
    out.length = 0;
    expect(await runKeysRetire(['--kid', kid, '--yes'], E2E_REALM_NAME, deps)).toBe(0);
    expect(err).toEqual([]);
    expect(out[0]).toContain('the key is retired already');
    const { rows: audited } = await app.dbPool.query(
      `SELECT count(*)::int AS n FROM admin_audit_log WHERE realm_id = $1 AND operation_id = 'keys.retire'`,
      [realm]
    );
    expect(audited).toEqual([{ n: 2 }]);
    const { rows: announced } = await app.dbPool.query(
      `SELECT count(*)::int AS n FROM events WHERE realm_id = $1 AND type = $2`,
      [realm, EMERGENCY_RETIRED]
    );
    expect(announced).toEqual([{ n: 2 }]);
  }, 180_000);

  it('keeps the denylist across a restart, and reads it with Redis down', async () => {
    if (!infra) throw new Error('infrastructure not started');
    const app = await boot();
    await seedMachineClient(app);
    const machine = await machineToken(app);
    const kid = await activeKid(app, 'EdDSA');
    const realm = await realmId(app);
    await retireOnNode(app, kid);
    await closeAll();

    // A node that starts after the retirement, whose Redis then goes away.
    const redis = new URL(infra.redis.connectionUrl);
    const relay = await startTcpRelay({ host: redis.hostname, port: Number(redis.port) });
    relays.push(relay);
    const restarted = await boot(
      variables({ REDIS_URL: relay.through(infra.redis.connectionUrl) })
    );
    const denylist = restarted.keyDenylist;
    if (denylist === null) throw new Error('the node holds no denylist');
    expect(denylist.isCurrent()).toBe(true);
    expect(denylist.isDenied(realm, kid)).toBe(true);
    expect(await introspect(restarted, machine)).toEqual({ active: false });

    await relay.stop();
    // The read the timer makes, now: Redis does not answer, the database does.
    await denylist.refresh();
    expect(denylist.isCurrent()).toBe(true);
    expect(denylist.isDenied(realm, kid)).toBe(true);
  }, 180_000);

  it('refuses every token on a node that cannot read the denylist past its bound, and serves again once it can', async () => {
    const app = await boot(variables(), {
      keyDenylistTiming: { refreshIntervalMs: 200, maxStalenessMs: 1_000 },
    });
    await seedMachineClient(app);
    const accessToken = await userAccessToken(app);
    const machine = await machineToken(app);
    expect(await introspect(app, machine)).toMatchObject({ active: true });
    expect((await userinfo(app, accessToken)).statusCode).toBe(200);

    // Neither the database nor Redis answers the denylist: the table is out
    // of reach, and the snapshot is gone, which only the database refills.
    await app.dbPool.query(`ALTER TABLE realm_key_denylist RENAME TO realm_key_denylist_away`);
    try {
      await app.redis.del('qauth:key-denylist');
      // A read that began before the table went may have stored one more
      // snapshot: it lives 5 s, and the copy is trusted 1 s past the read.
      await within(10_000, async () => (await introspect(app, machine))['active'] === false);
      expect(app.keyDenylist?.isCurrent()).toBe(false);
      expect((await userinfo(app, accessToken)).statusCode).toBe(401);
    } finally {
      await app.dbPool.query(
        `ALTER TABLE IF EXISTS realm_key_denylist_away RENAME TO realm_key_denylist`
      );
    }

    await within(10_000, async () => (await introspect(app, machine))['active'] === true);
    expect((await userinfo(app, accessToken)).statusCode).toBe(200);
  }, 180_000);
});

import { createHmac } from 'node:crypto';

import { createRealmKey } from '@qauth-labs/fastify-plugin-signer';
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance } from 'fastify';
import { createLocalJWKSet, type JSONWebKeySet, jwtVerify } from 'jose';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  allowConsentScreen,
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  E2E_REALM_NAME,
  type E2eInfrastructure,
  generateJwtPem,
  type PemKeyPair,
  pkcePair,
  registerPasswordAccount,
  signInWithPassword,
  startE2eInfrastructure,
} from '../testing/e2e-harness';
import {
  createInternalPki,
  eventually,
  type InternalPki,
  type IssuedCredentials,
  tlsExchange,
  type TlsFileDirectory,
  writeTlsFiles,
} from '../testing/internal-pki';
import { METRICS_PEER } from '../testing/service-role-env';
import { createInternalClient, InternalClientError } from './internal/client';

/**
 * THE SIGNER SERVICE BETWEEN PROCESSES (ADR-019 Decision 9, issue #497),
 * against a real Postgres and Redis.
 *
 * One process holds the signer alone, with the KEK and the keys, and serves
 * the signer service on its internal listener over mutual TLS. Three others
 * hold `web`, `api` and `delivery`, with no KEK and no key variable: each
 * presents its own role's certificate and signs through the signer. The
 * suite then stops the signer, and starts it again on the same port.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const SIGNER_SAN = 'signer.qauth.internal';
const PEERS = {
  web: 'spiffe://qauth.test/web',
  api: 'spiffe://qauth.test/api',
  delivery: 'spiffe://qauth.test/delivery',
} as const;
type Caller = keyof typeof PEERS;

const MACHINE_CLIENT_ID = 'signer-service-machine';
const MACHINE_SECRET = 'signer-service-machine-secret-of-32-characters';
const MACHINE_SCOPE = 'reports:read';
const APP_CLIENT_ID = 'signer-service-app';
const APP_SECRET = 'signer-service-app-secret-of-32-characters!';
const REDIRECT_URI = 'https://app.example.com/callback';
const EMAIL = 'signer-service@example.test';
const SUBSCRIPTION = 'signer-service-subscription';
const FORM = { 'content-type': 'application/x-www-form-urlencoded' } as const;

/** The variables a process without the signer must not have: key material of any kind. */
const KEY_VARIABLES = ['KEK', 'JWT_PRIVATE_KEY', 'JWT_PUBLIC_KEY', 'SESSION_COOKIE_SECRET'];

function form(values: Record<string, string>): string {
  return new URLSearchParams(values).toString();
}

async function caught(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  throw new Error('expected the call to fail');
}

describe('the signer service over mutual TLS, between processes (#497)', () => {
  let infra: E2eInfrastructure | undefined;
  let jwt: PemKeyPair | undefined;
  let dockerUp = false;
  let pki: InternalPki;
  let signerFiles: TlsFileDirectory;
  const peerFiles = new Map<Caller, TlsFileDirectory>();
  const peerCredentials = new Map<Caller, IssuedCredentials>();
  const booted: BootedAuthServer[] = [];
  let signer: BootedAuthServer | undefined;
  let signerPort = 0;
  const callers = new Map<Caller, FastifyInstance>();
  let realm: { id: string; issuer: string };

  /** The signer's process: the KEK, the keys, and the internal listener for the others. */
  function signerEnvironment(): Record<string, string> {
    if (!infra || !jwt) throw new Error('infrastructure not started');
    return {
      ...baseEnvironment(infra, jwt),
      SERVICE_ROLES: 'signer',
      INTERNAL_HOST: '127.0.0.1',
      INTERNAL_TLS_CERT_PATH: signerFiles.files.certPath,
      INTERNAL_TLS_KEY_PATH: signerFiles.files.keyPath,
      INTERNAL_TLS_CA_PATH: signerFiles.files.caPath,
      INTERNAL_PEER_ROLES: JSON.stringify({
        [PEERS.web]: 'web',
        [PEERS.api]: 'api',
        [PEERS.delivery]: 'delivery',
        ...METRICS_PEER,
      }),
    };
  }

  /** A process of `caller`'s role alone: no KEK, no key, its own certificate. */
  function callerEnvironment(caller: Caller): Record<string, string> {
    if (!infra || !jwt) throw new Error('infrastructure not started');
    const files = peerFiles.get(caller);
    if (files === undefined) throw new Error(`no files for ${caller}`);
    const base = Object.fromEntries(
      Object.entries(baseEnvironment(infra, jwt)).filter(([name]) => !KEY_VARIABLES.includes(name))
    );
    return {
      ...base,
      SERVICE_ROLES: caller,
      // An IP address, so the signer is known by SIGNER_SAN.
      SIGNER_URL: `https://127.0.0.1:${signerPort}`,
      SIGNER_SAN,
      INTERNAL_TLS_CERT_PATH: files.files.certPath,
      INTERNAL_TLS_KEY_PATH: files.files.keyPath,
      INTERNAL_TLS_CA_PATH: files.files.caPath,
      INTERNAL_PEER_ROLES: JSON.stringify(METRICS_PEER),
    };
  }

  async function startSigner(): Promise<BootedAuthServer> {
    const server = await bootAuthServer(signerEnvironment(), {
      internalListener: () => (signerPort === 0 ? {} : { port: signerPort }),
    });
    booted.push(server);
    if (server.internalUrl === undefined) throw new Error('the signer has no internal listener');
    signerPort = Number(new URL(server.internalUrl).port);
    signer = server;
    return server;
  }

  function app(caller: Caller): FastifyInstance {
    const found = callers.get(caller);
    if (found === undefined) throw new Error(`no ${caller} process`);
    return found;
  }

  /** The refusals the signer counted for `role/operation`, reason `not_allowed`. */
  async function refusalsOf(role: Caller, operation: string): Promise<number> {
    if (!signer) throw new Error('the signer is not running');
    const metric = await signer.app.metrics.signerRefusals.get();
    return (
      metric.values.find(
        (value) =>
          value.labels['role'] === role &&
          value.labels['operation'] === operation &&
          value.labels['reason'] === 'not_allowed'
      )?.value ?? 0
    );
  }

  /** A raw call to the signer service as `caller`'s certificate. */
  async function rawCall(caller: Caller, route: string, body: unknown) {
    const issued = peerCredentials.get(caller);
    if (issued === undefined) throw new Error(`no credentials for ${caller}`);
    const client = createInternalClient({
      url: `https://127.0.0.1:${signerPort}`,
      cert: issued.cert,
      key: issued.key,
      ca: pki.caPem,
      expectedServerSan: SIGNER_SAN,
    });
    try {
      const response = await client.request({
        method: 'POST',
        path: `/internal/signer/v1-rc.0${route}`,
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
      });
      return { status: response.status, body: JSON.parse(response.body.toString()) as unknown };
    } finally {
      client.close();
    }
  }

  function issueMachineToken() {
    return app('api').inject({
      method: 'POST',
      url: '/oauth/token',
      headers: FORM,
      payload: form({
        grant_type: 'client_credentials',
        scope: MACHINE_SCOPE,
        client_id: MACHINE_CLIENT_ID,
        client_secret: MACHINE_SECRET,
      }),
    });
  }

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    jwt = await generateJwtPem();
    pki = createInternalPki();
    signerFiles = writeTlsFiles(pki.issue({ dnsNames: [SIGNER_SAN] }), pki.caPem);
    for (const [caller, san] of Object.entries(PEERS) as [Caller, string][]) {
      const issued = pki.issue({ uris: [san] });
      peerCredentials.set(caller, issued);
      peerFiles.set(caller, writeTlsFiles(issued, pki.caPem));
    }

    const started = await startSigner();
    const found = await started.app.repositories.realms.findByName(E2E_REALM_NAME);
    if (!found?.issuer) throw new Error('the signer did not boot the default realm');
    realm = { id: found.id, issuer: found.issuer };

    for (const caller of Object.keys(PEERS) as Caller[]) {
      const environment = callerEnvironment(caller);
      for (const name of KEY_VARIABLES) expect(environment[name], name).toBeUndefined();
      const server = await bootAuthServer(environment, { signerClient: {} });
      booted.push(server);
      callers.set(caller, server.app);
    }

    const api = app('api');
    await api.repositories.oauthClients.create({
      realmId: realm.id,
      clientId: MACHINE_CLIENT_ID,
      clientSecretHash: await api.passwordHasher.hashPassword(MACHINE_SECRET),
      tokenEndpointAuthMethod: 'client_secret_post',
      name: 'Signer service machine client',
      redirectUris: [],
      scopes: [MACHINE_SCOPE],
      grantTypes: ['client_credentials'],
      enabled: true,
    });
    await api.repositories.oauthClients.create({
      realmId: realm.id,
      clientId: APP_CLIENT_ID,
      clientSecretHash: await api.passwordHasher.hashPassword(APP_SECRET),
      tokenEndpointAuthMethod: 'client_secret_post',
      name: 'Signer service app',
      redirectUris: [REDIRECT_URI],
      scopes: ['openid', 'email'],
      grantTypes: ['authorization_code', 'refresh_token'],
      enabled: true,
      requirePkce: true,
    });
  }, 300_000);

  afterAll(async () => {
    for (const server of booted.reverse()) await server.close().catch(() => undefined);
    await infra?.teardown();
    signerFiles?.remove();
    for (const files of peerFiles.values()) files.remove();
  });

  beforeEach((ctx) => {
    if (!dockerUp) ctx.skip();
  });

  it('issues a token on the api role, with no key variable and no KEK, that verifies against the realm JWKS', async () => {
    const issued = await issueMachineToken();
    expect(issued.statusCode, issued.body).toBe(200);
    const token = issued.json<{ access_token: string }>().access_token;
    const jwks = await app('api').inject({ method: 'GET', url: '/.well-known/jwks.json' });
    expect(jwks.statusCode).toBe(200);
    const { payload } = await jwtVerify(token, createLocalJWKSet(jwks.json<JSONWebKeySet>()), {
      issuer: realm.issuer,
    });
    expect(payload['client_id'] ?? payload['sub']).toBe(MACHINE_CLIENT_ID);
  });

  it('hands the cookie secrets to the web role, and refuses the api and delivery roles', async () => {
    const secrets = await app('web').signer.getCookieSecrets('web', realm.id);
    expect(secrets.current.secret.length).toBeGreaterThanOrEqual(32);

    for (const caller of ['api', 'delivery'] as const) {
      const before = await refusalsOf(caller, 'getCookieSecrets');
      const answer = await rawCall(caller, '/cookie-secrets', { realmId: realm.id });
      expect(answer.status, caller).toBe(403);
      expect(answer.body).toEqual({
        error: { code: 'SIGNER_ACCESS_DENIED', caller, operation: 'getCookieSecrets' },
      });
      // The process's own remote signer: a 503, never the secrets. (Its
      // error class is the booted app's copy, after the harness reset the
      // modules: compared by shape.)
      const refused = await caught(app(caller).signer.getCookieSecrets('web', realm.id));
      expect(refused).toMatchObject({
        name: 'TemporarilyUnavailableError',
        statusCode: 503,
        details: { reason: 'signer_role_refused' },
      });
      expect(await refusalsOf(caller, 'getCookieSecrets')).toBe(before + 2);
    }
  });

  it('signs a webhook for the delivery role, and refuses the web role', async () => {
    if (!signer) throw new Error('the signer is not running');
    const [created] = await createRealmKey(
      {
        db: signer.app.db,
        kekEnv: signerEnvironment(),
        warn: () => undefined,
        enabledSignatureAlgorithms: ['EdDSA'],
        hybridSigning: false,
      },
      { realmName: E2E_REALM_NAME, purpose: 'webhook_signing', scopeId: SUBSCRIPTION }
    );
    const secret = created?.secret;
    if (secret === undefined) throw new Error('the webhook key showed no secret');
    const request = {
      realmId: realm.id,
      subscriptionId: SUBSCRIPTION,
      id: 'evt_signer_service',
      timestamp: Math.floor(Date.now() / 1000),
      body: '{"event":"signer-service"}',
    };

    const signature = await app('delivery').signer.signWebhook('delivery', request);
    const expected = createHmac('sha256', Buffer.from(secret.replace(/^whsec_/, ''), 'base64'))
      .update(`${request.id}.${request.timestamp}.${request.body}`)
      .digest('base64');
    expect(signature).toBe(`v1,${expected}`);

    const before = await refusalsOf('web', 'signWebhook');
    expect(await caught(app('web').signer.signWebhook('delivery', request))).toMatchObject({
      details: { reason: 'signer_role_refused' },
    });
    expect(await refusalsOf('web', 'signWebhook')).toBe(before + 1);
  });

  it('refuses a caller without a valid client certificate at the handshake', async () => {
    const target = { host: '127.0.0.1', port: signerPort };
    const path = '/internal/signer/v1-rc.0/jwks';
    expect((await tlsExchange(target, { ca: pki.caPem }, path)).received).toBe('');
    const forged = createInternalPki('Another CA').issue({ uris: [PEERS.api] });
    expect(
      (await tlsExchange(target, { ca: pki.caPem, cert: forged.cert, key: forged.key }, path))
        .received
    ).toBe('');
    const client = createInternalClient({
      url: `https://127.0.0.1:${signerPort}`,
      cert: forged.cert,
      key: forged.key,
      ca: pki.caPem,
      expectedServerSan: SIGNER_SAN,
    });
    try {
      const refused = await caught(
        client.request({
          method: 'POST',
          path,
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ realmId: realm.id }),
        })
      );
      expect(refused).toBeInstanceOf(InternalClientError);
      expect((refused as InternalClientError).code).toBe('unreachable');
    } finally {
      client.close();
    }
  });

  it('answers 503 to token issuance while the signer is stopped, keeps the JWKS, userinfo and introspection, and recovers when it is back', async () => {
    // A person signs in on web (its cookies signed with the cookie key from
    // the signer) and the api role redeems the code: both through the signer.
    await registerPasswordAccount(app('api'), EMAIL);
    const web = app('web');
    const jar = await signInWithPassword(web, EMAIL);
    const pkce = pkcePair();
    const authorize = await web.inject({
      method: 'GET',
      url: `/oauth/authorize?${form({
        response_type: 'code',
        client_id: APP_CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        scope: 'openid email',
        code_challenge: pkce.challenge,
        code_challenge_method: 'S256',
        state: 'signer-service',
      })}`,
      headers: { cookie: jar.header() as string },
    });
    expect(authorize.statusCode, authorize.body).toBe(302);
    let location = authorize.headers['location'];
    if (typeof location !== 'string') throw new Error('authorize did not redirect');
    if (location.startsWith('/ui/consent?')) {
      location = await allowConsentScreen(web, jar.header() as string, location);
    }
    const code = new URL(location).searchParams.get('code');
    if (code === null) throw new Error(`authorize returned no code: ${location}`);
    const api = app('api');
    const redeemed = await api.inject({
      method: 'POST',
      url: '/oauth/token',
      headers: FORM,
      payload: form({
        grant_type: 'authorization_code',
        code,
        redirect_uri: REDIRECT_URI,
        code_verifier: pkce.verifier,
        client_id: APP_CLIENT_ID,
        client_secret: APP_SECRET,
      }),
    });
    expect(redeemed.statusCode, redeemed.body).toBe(200);
    const accessToken = redeemed.json<{ access_token: string }>().access_token;
    const jwksBefore = (await api.inject({ method: 'GET', url: '/.well-known/jwks.json' })).json();

    // Stop the signer.
    await signer?.close();
    booted.splice(booted.indexOf(signer as BootedAuthServer), 1);
    signer = undefined;

    const refused = await issueMachineToken();
    expect(refused.statusCode, refused.body).toBe(503);
    expect(refused.json()).toMatchObject({ error: 'temporarily_unavailable' });

    const jwks = await api.inject({ method: 'GET', url: '/.well-known/jwks.json' });
    expect(jwks.statusCode).toBe(200);
    expect(jwks.json()).toEqual(jwksBefore);
    const userinfo = await api.inject({
      method: 'GET',
      url: '/oauth/userinfo',
      headers: { authorization: `Bearer ${accessToken}` },
    });
    expect(userinfo.statusCode, userinfo.body).toBe(200);
    expect(userinfo.json()).toHaveProperty('sub');
    const introspection = await api.inject({
      method: 'POST',
      url: '/oauth/introspect',
      headers: FORM,
      payload: form({ token: accessToken, client_id: APP_CLIENT_ID, client_secret: APP_SECRET }),
    });
    expect(introspection.statusCode, introspection.body).toBe(200);
    expect(introspection.json()).toMatchObject({ active: true, iss: realm.issuer });

    // Start it again on the same port: the callers find it with no restart,
    // once the circuit, if it opened, lets a call probe it.
    await startSigner();
    await eventually(async () => (await issueMachineToken()).statusCode === 200, 20_000, 250);
    const secrets = await app('web').signer.getCookieSecrets('web', realm.id);
    expect(secrets.current.secret.length).toBeGreaterThanOrEqual(32);
  }, 120_000);
});

import { randomUUID } from 'node:crypto';

import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import { calculateJwkThumbprint, CompactSign, exportJWK, generateKeyPair, type JWK } from 'jose';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  CookieJar,
  decodeHtmlEntities,
  decodeJwtClaims,
  E2E_PASSWORD,
  E2E_REALM_NAME,
  type E2eInfrastructure,
  extractCsrfToken,
  generateJwtPem,
  type PemKeyPair,
  pkcePair,
  provisionRealmKeys,
  registerPasswordAccount,
  resetE2eState,
  signInWithPassword,
  startE2eInfrastructure,
} from '../testing/e2e-harness';
import type { RealmRow } from './helpers/request-realm';

/**
 * EVERY ABSOLUTE URL COMES FROM THE REALM ROW, AGAINST A REAL POSTGRES AND
 * REDIS (ADR-019 Decision 1, issue #490).
 *
 * Each test boots the real auth-server, whose boot step creates the default
 * realm on `auth.example.com` (from `JWT_ISSUER`), and adds a second realm,
 * `beta`, on `beta.example.com`. `TRUST_PROXY` names one proxy, 10.0.4.12, so
 * a request from any other peer is an untrusted one: its `X-Forwarded-*`
 * headers must count for nothing. Checked on the discovery documents, the
 * RFC 9207 `iss` of an authorization response, the verification mail link and
 * the DPoP `htu` a proof must name.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const HOST_A = 'auth.example.com';
const HOST_B = 'beta.example.com';
const ISSUER_A = `https://${HOST_A}`;
const ISSUER_B = `https://${HOST_B}`;
const PROXY = '10.0.4.12';
/** A peer TRUST_PROXY does not list. */
const UNTRUSTED_PEER = '192.0.2.7';
const FORM = { 'content-type': 'application/x-www-form-urlencoded' };
const REDIRECT_URI = 'https://client.example.com/callback';
const APP_CLIENT_ID = 'urls-app';
/** A client the user is asked to consent to: not operator-provisioned. */
const CONSENT_CLIENT_ID = 'urls-consent';
/** An endpoint host of the default realm (DEFAULT_REALM_ENDPOINT_HOSTS). */
const ENDPOINT_HOST = 'auth-internal.example.com';
const MACHINE_CLIENT_ID = 'urls-machine';
const MACHINE_SECRET = 'machine-client-secret-of-sufficient-length-42';

/**
 * What a client that tries to steer the server's URLs sends from an untrusted
 * peer: another realm's host, a host that is no realm, another scheme and a
 * prefix, in the forwarded headers Fastify and proxies know.
 */
const SPOOFED_HEADER_SETS: readonly Record<string, string>[] = [
  { 'x-forwarded-host': HOST_B },
  { 'x-forwarded-host': 'evil.example.net' },
  { 'x-forwarded-proto': 'http', 'x-forwarded-port': '8443' },
  { 'x-forwarded-host': 'evil.example.net', 'x-forwarded-prefix': '/evil' },
  { forwarded: 'host=evil.example.net;proto=http' },
];

interface TwoRealms {
  readonly app: FastifyInstance;
  readonly realmA: RealmRow;
  readonly realmB: RealmRow;
}

/** A DPoP key of the client's: the private key it signs proofs with and its thumbprint. */
interface DpopKey {
  readonly privateKey: CryptoKey;
  readonly jwk: JWK;
  readonly thumbprint: string;
}

async function dpopKey(): Promise<DpopKey> {
  const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
  const jwk = await exportJWK(publicKey);
  return { privateKey, jwk, thumbprint: await calculateJwkThumbprint(jwk, 'sha256') };
}

/** A fresh DPoP proof for `POST <htu>` (RFC 9449 §4.2). */
async function proof(key: DpopKey, htu: string): Promise<string> {
  const claims = { jti: randomUUID(), htm: 'POST', htu, iat: Math.floor(Date.now() / 1000) };
  return new CompactSign(new TextEncoder().encode(JSON.stringify(claims)))
    .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: key.jwk })
    .sign(key.privateKey);
}

/** Every string in a JSON document that looks like an absolute URL. */
function urlsIn(value: unknown): string[] {
  if (typeof value === 'string') return /^[a-z][a-z0-9+.-]*:\/\//i.test(value) ? [value] : [];
  if (Array.isArray(value)) return value.flatMap(urlsIn);
  if (value !== null && typeof value === 'object') return Object.values(value).flatMap(urlsIn);
  return [];
}

describe('every absolute URL comes from the realm row (#490)', () => {
  let infra: E2eInfrastructure | undefined;
  let jwt: PemKeyPair | undefined;
  let dockerUp = false;
  const booted: BootedAuthServer[] = [];

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    jwt = await generateJwtPem();
  }, 240_000);

  afterAll(async () => {
    await infra?.teardown();
  });

  beforeEach((ctx) => {
    if (!dockerUp) ctx.skip();
  });

  afterEach(async () => {
    await Promise.all(booted.splice(0).map(async (server) => server.close()));
  });

  /**
   * Boot on an empty state: the default realm on HOST_A and `beta` on HOST_B,
   * DPoP on. `environment` overrides the base settings; `log` collects the
   * server's warnings.
   */
  async function boot(
    environment: Record<string, string> = {},
    log?: Record<string, unknown>[]
  ): Promise<TwoRealms> {
    if (!infra || !jwt) throw new Error('infrastructure not started');
    const server = await bootAuthServer(
      { ...baseEnvironment(infra, jwt), TRUST_PROXY: PROXY, DPOP_ENABLED: 'true', ...environment },
      log === undefined
        ? {}
        : { logStream: { write: (line) => log.push(JSON.parse(line) as Record<string, unknown>) } }
    );
    booted.push(server);
    const { app } = server;
    await resetE2eState(app);

    const realmA = await app.repositories.realms.findByName(E2E_REALM_NAME);
    if (!realmA) throw new Error('the default realm boot step left no realm');
    const { realm: realmB } = await app.repositories.realms.createWithPrimaryHost(
      { name: 'beta', issuer: ISSUER_B, enabled: true },
      HOST_B
    );
    // Its own keys: the realm's tokens are signed with them (#491).
    await provisionRealmKeys(app, 'beta');
    return { app, realmA, realmB };
  }

  /** An operator-provisioned public client, so authorization errors go back to it with `iss`. */
  async function seedAppClient(app: FastifyInstance, realm: RealmRow): Promise<void> {
    await app.repositories.oauthClients.create({
      realmId: realm.id,
      clientId: APP_CLIENT_ID,
      clientSecretHash: 'unused-public-client',
      tokenEndpointAuthMethod: 'none',
      name: 'URL test app',
      redirectUris: [REDIRECT_URI],
      scopes: ['openid'],
      grantTypes: ['authorization_code'],
      enabled: true,
      requirePkce: true,
      provisionedByOperator: true,
    });
  }

  /** A confidential machine client whose access tokens are DPoP-bound. */
  async function seedMachineClient(app: FastifyInstance, realm: RealmRow): Promise<void> {
    await app.repositories.oauthClients.create({
      realmId: realm.id,
      clientId: MACHINE_CLIENT_ID,
      clientSecretHash: await app.passwordHasher.hashPassword(MACHINE_SECRET),
      tokenEndpointAuthMethod: 'client_secret_post',
      name: 'URL test machine',
      redirectUris: [],
      scopes: ['reports:read'],
      grantTypes: ['client_credentials'],
      dpopBoundAccessTokens: true,
      enabled: true,
    });
  }

  async function discovery(
    app: FastifyInstance,
    path: string,
    headers: Record<string, string>,
    remoteAddress = UNTRUSTED_PEER
  ): Promise<LightMyRequestResponse> {
    return app.inject({ method: 'GET', url: path, headers, remoteAddress });
  }

  /** `prompt=none` with no session: an authorization error response carrying `iss`. */
  async function silentAuthorize(
    app: FastifyInstance,
    headers: Record<string, string>
  ): Promise<LightMyRequestResponse> {
    const query = new URLSearchParams({
      response_type: 'code',
      client_id: APP_CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      scope: 'openid',
      state: 'state-1',
      code_challenge: pkcePair().challenge,
      code_challenge_method: 'S256',
      prompt: 'none',
    });
    return app.inject({
      method: 'GET',
      url: `/oauth/authorize?${query}`,
      headers,
      remoteAddress: UNTRUSTED_PEER,
    });
  }

  /**
   * Register an account and return the link base of the verification mail it
   * was sent. Each call comes from its own untrusted peer, since registration
   * is limited per client address.
   */
  async function registrationMailLink(
    app: FastifyInstance,
    email: string,
    headers: Record<string, string>,
    remoteAddress: string
  ): Promise<string> {
    const emailService = app.emailService;
    const original = emailService.sendVerificationEmail;
    const links: string[] = [];
    emailService.sendVerificationEmail = async (realmId, to, token, link, options) => {
      if (to === email) links.push(link.baseUrl);
      return original.call(emailService, realmId, to, token, link, options);
    };
    try {
      const response = await app.inject({
        method: 'POST',
        url: '/auth/register',
        headers,
        remoteAddress,
        payload: { email, password: E2E_PASSWORD },
      });
      expect(response.statusCode).toBe(202);
      const deadline = Date.now() + 5_000;
      while (links.length === 0 && Date.now() < deadline) {
        await new Promise((resolve) => setTimeout(resolve, 20));
      }
    } finally {
      emailService.sendVerificationEmail = original;
    }
    expect(links).toHaveLength(1);
    return links[0] as string;
  }

  /** A plain (unbound) machine client in `realm`, for introspection. */
  async function seedIntrospectingClient(
    app: FastifyInstance,
    realm: RealmRow,
    clientId: string
  ): Promise<void> {
    await app.repositories.oauthClients.create({
      realmId: realm.id,
      clientId,
      clientSecretHash: await app.passwordHasher.hashPassword(MACHINE_SECRET),
      tokenEndpointAuthMethod: 'client_secret_post',
      name: `URL test ${clientId}`,
      redirectUris: [],
      scopes: ['reports:read'],
      grantTypes: ['client_credentials'],
      enabled: true,
    });
  }

  async function clientCredentialsToken(
    app: FastifyInstance,
    host: string,
    clientId: string
  ): Promise<string> {
    const response = await app.inject({
      method: 'POST',
      url: '/oauth/token',
      headers: { ...FORM, host },
      payload: new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: clientId,
        client_secret: MACHINE_SECRET,
        scope: 'reports:read',
      }).toString(),
    });
    expect(response.statusCode).toBe(200);
    return response.json<{ access_token: string }>().access_token;
  }

  async function introspect(
    app: FastifyInstance,
    host: string,
    clientId: string,
    token: string
  ): Promise<Record<string, unknown>> {
    const response = await app.inject({
      method: 'POST',
      url: '/oauth/introspect',
      headers: { ...FORM, host },
      payload: new URLSearchParams({
        token,
        client_id: clientId,
        client_secret: MACHINE_SECRET,
      }).toString(),
    });
    expect(response.statusCode).toBe(200);
    return response.json<Record<string, unknown>>();
  }

  async function revoke(
    app: FastifyInstance,
    host: string,
    clientId: string,
    token: string
  ): Promise<LightMyRequestResponse> {
    return app.inject({
      method: 'POST',
      url: '/oauth/revoke',
      headers: { ...FORM, host },
      payload: new URLSearchParams({
        token,
        token_type_hint: 'access_token',
        client_id: clientId,
        client_secret: MACHINE_SECRET,
      }).toString(),
    });
  }

  /** A public client that is not operator-provisioned, so the user is asked to consent. */
  async function seedConsentClient(app: FastifyInstance, realm: RealmRow): Promise<void> {
    await app.repositories.oauthClients.create({
      realmId: realm.id,
      clientId: CONSENT_CLIENT_ID,
      clientSecretHash: 'unused-public-client',
      tokenEndpointAuthMethod: 'none',
      name: 'URL test consent app',
      redirectUris: [REDIRECT_URI],
      scopes: ['openid'],
      grantTypes: ['authorization_code'],
      enabled: true,
      requirePkce: true,
    });
  }

  async function dpopClientCredentials(
    app: FastifyInstance,
    headers: Record<string, string>,
    dpop: string
  ): Promise<LightMyRequestResponse> {
    return app.inject({
      method: 'POST',
      url: '/oauth/token',
      headers: { ...FORM, ...headers, dpop },
      remoteAddress: UNTRUSTED_PEER,
      payload: new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: MACHINE_CLIENT_ID,
        client_secret: MACHINE_SECRET,
        scope: 'reports:read',
      }).toString(),
    });
  }

  it("builds each realm's discovery documents on that realm's issuer", async () => {
    const { app } = await boot();

    for (const [host, issuer] of [
      [HOST_A, ISSUER_A],
      [HOST_B, ISSUER_B],
    ] as const) {
      for (const path of [
        '/.well-known/oauth-authorization-server',
        '/.well-known/openid-configuration',
      ]) {
        const response = await discovery(app, path, { host });
        expect(response.statusCode).toBe(200);
        const document = response.json<Record<string, unknown>>();
        expect(document['issuer']).toBe(issuer);
        const urls = urlsIn(document);
        expect(urls.length).toBeGreaterThan(5);
        for (const url of urls) expect(url.startsWith(`${issuer}/`) || url === issuer).toBe(true);
      }
    }
  }, 120_000);

  it('lets a spoofed X-Forwarded-* from an untrusted peer change no URL of realm A', async () => {
    const { app, realmA } = await boot();
    await seedAppClient(app, realmA);
    await seedMachineClient(app, realmA);

    const plainAs = await discovery(app, '/.well-known/oauth-authorization-server', {
      host: HOST_A,
    });
    const plainOidc = await discovery(app, '/.well-known/openid-configuration', { host: HOST_A });
    const plainAuthorize = await silentAuthorize(app, { host: HOST_A });
    expect(plainAuthorize.statusCode).toBe(302);
    const location = new URL(plainAuthorize.headers['location'] as string);
    expect(`${location.origin}${location.pathname}`).toBe(REDIRECT_URI);
    expect(location.searchParams.get('error')).toBe('login_required');
    expect(location.searchParams.get('iss')).toBe(ISSUER_A);

    for (const [index, spoofed] of SPOOFED_HEADER_SETS.entries()) {
      const headers = { host: HOST_A, ...spoofed };

      // The documents are the same bytes, whatever the forwarded headers say.
      const as = await discovery(app, '/.well-known/oauth-authorization-server', headers);
      expect(as.body).toBe(plainAs.body);
      const oidc = await discovery(app, '/.well-known/openid-configuration', headers);
      expect(oidc.body).toBe(plainOidc.body);

      // The authorization response names realm A's issuer.
      const authorize = await silentAuthorize(app, headers);
      expect(authorize.statusCode).toBe(302);
      expect(new URL(authorize.headers['location'] as string).searchParams.get('iss')).toBe(
        ISSUER_A
      );

      // The verification mail links to realm A's auth server.
      expect(
        await registrationMailLink(
          app,
          `spoof-${index}@example.com`,
          headers,
          `192.0.2.${10 + index}`
        )
      ).toBe(ISSUER_A);

      // A DPoP proof must name realm A's token endpoint: a proof for the URL
      // the forwarded headers describe is refused, and A's is accepted.
      const key = await dpopKey();
      const steered = await dpopClientCredentials(
        app,
        headers,
        await proof(key, `${ISSUER_B}/oauth/token`)
      );
      expect(steered.json()).toMatchObject({ error: 'invalid_dpop_proof' });
      const honest = await dpopClientCredentials(
        app,
        headers,
        await proof(key, `${ISSUER_A}/oauth/token`)
      );
      expect(honest.statusCode).toBe(200);
      expect(honest.json()).toMatchObject({ token_type: 'DPoP' });
      expect(decodeJwtClaims(honest.json<{ access_token: string }>().access_token)['cnf']).toEqual({
        jkt: key.thumbprint,
      });

      for (const response of [as, oidc, authorize, steered, honest]) {
        expect(JSON.stringify(response.headers)).not.toContain('evil.example.net');
        expect(response.body).not.toContain('evil.example.net');
        expect(response.body).not.toContain('http://auth.example.com');
      }
    }
  }, 180_000);

  it('answers a spoofed Host with 421 and no URL at all', async () => {
    const { app } = await boot();

    const response = await discovery(app, '/.well-known/openid-configuration', {
      host: 'evil.example.net',
    });
    expect(response.statusCode).toBe(421);
    expect(response.headers['location']).toBeUndefined();
    expect(JSON.stringify(response.headers)).not.toContain('evil.example.net');
    expect(response.body).not.toContain('evil.example.net');
    // No realm URL either: the refusal carries no realm context.
    expect(response.body).not.toContain(HOST_A);
    expect(response.body).not.toContain(HOST_B);
  }, 120_000);

  it('gives realm B its own issuer: iss, mail link and DPoP htu (ADR-019 Decision 1)', async () => {
    const { app, realmB } = await boot();
    await seedAppClient(app, realmB);
    await seedMachineClient(app, realmB);

    const authorize = await silentAuthorize(app, { host: HOST_B });
    expect(authorize.statusCode).toBe(302);
    expect(new URL(authorize.headers['location'] as string).searchParams.get('iss')).toBe(ISSUER_B);

    expect(
      await registrationMailLink(app, 'beta@example.com', { host: HOST_B }, UNTRUSTED_PEER)
    ).toBe(ISSUER_B);

    // A proof sent to realm B names realm B's token endpoint (#480 follow-up):
    // B's is accepted, and one for the default realm's endpoint is refused.
    const key = await dpopKey();
    const forA = await dpopClientCredentials(
      app,
      { host: HOST_B },
      await proof(key, `${ISSUER_A}/oauth/token`)
    );
    expect(forA.json()).toMatchObject({ error: 'invalid_dpop_proof' });
    const forB = await dpopClientCredentials(
      app,
      { host: HOST_B },
      await proof(key, `${ISSUER_B}/oauth/token`)
    );
    expect(forB.statusCode).toBe(200);
    expect(forB.json()).toMatchObject({ token_type: 'DPoP' });
  }, 120_000);

  it('keeps working with a JWT_ISSUER that ends with a slash: discovery drops it, the token pin keeps it', async () => {
    const { app, realmA } = await boot({ JWT_ISSUER: `${ISSUER_A}/` });
    await seedIntrospectingClient(app, realmA, 'urls-a');
    await seedAppClient(app, realmA);

    const document = (
      await discovery(app, '/.well-known/openid-configuration', { host: HOST_A })
    ).json<Record<string, unknown>>();
    expect(document['issuer']).toBe(ISSUER_A);
    expect(document['token_endpoint']).toBe(`${ISSUER_A}/oauth/token`);

    // RFC 9207 §2.4: the `iss` of an authorization response is the discovery
    // `issuer`, byte for byte, so a client's simple string comparison holds.
    const authorize = await silentAuthorize(app, { host: HOST_A });
    expect(authorize.statusCode).toBe(302);
    expect(new URL(authorize.headers['location'] as string).searchParams.get('iss')).toBe(
      document['issuer']
    );

    // Tokens carry the realm's issuer as discovery publishes it, without the
    // slash (#491), and the realm's introspection pin accepts them.
    const token = await clientCredentialsToken(app, HOST_A, 'urls-a');
    expect(decodeJwtClaims(token)['iss']).toBe(document['issuer']);
    expect(await introspect(app, HOST_A, 'urls-a', token)).toMatchObject({ active: true });
  }, 120_000);

  it("refuses at realm B's introspection a token that names realm A's issuer", async () => {
    const { app, realmA, realmB } = await boot();
    // The same client_id in both realms names two clients (#487), so realm B's
    // client passes introspection's same-client check for a token of A's: only
    // the issuer pin can refuse it.
    await seedIntrospectingClient(app, realmA, 'urls-client');
    await seedIntrospectingClient(app, realmB, 'urls-client');

    const tokenOfA = await clientCredentialsToken(app, HOST_A, 'urls-client');
    expect(decodeJwtClaims(tokenOfA)['iss']).toBe(ISSUER_A);
    expect(await introspect(app, HOST_A, 'urls-client', tokenOfA)).toMatchObject({
      active: true,
    });
    expect(await introspect(app, HOST_B, 'urls-client', tokenOfA)).toEqual({ active: false });
  }, 120_000);

  it('warns at boot when EMAIL_BASE_URL is not the issuer the mailed links now start at', async () => {
    const log: Record<string, unknown>[] = [];
    const { app } = await boot({ EMAIL_BASE_URL: 'https://mail.example.org' }, log);

    expect(log).toContainEqual(
      expect.objectContaining({
        level: 40,
        variable: 'EMAIL_BASE_URL',
        msg: expect.stringContaining('EMAIL_BASE_URL is not read since 0.2.0'),
      })
    );
    expect(
      await registrationMailLink(app, 'mail@example.com', { host: HOST_A }, UNTRUSTED_PEER)
    ).toBe(ISSUER_A);

    const quiet: Record<string, unknown>[] = [];
    await boot({}, quiet);
    expect(quiet.filter((line) => line['variable'] === 'EMAIL_BASE_URL')).toEqual([]);

    // Optional since #490: unset (blank, as `${EMAIL_BASE_URL:-}` in compose
    // expands to), the server boots, warns about nothing and links mail to
    // the issuer.
    const unset: Record<string, unknown>[] = [];
    const { app: withoutBase } = await boot({ EMAIL_BASE_URL: '' }, unset);
    expect(unset.filter((line) => line['variable'] === 'EMAIL_BASE_URL')).toEqual([]);
    expect(
      await registrationMailLink(withoutBase, 'unset@example.com', { host: HOST_A }, UNTRUSTED_PEER)
    ).toBe(ISSUER_A);
  }, 180_000);

  it('lets a spoofed X-Forwarded-* from an untrusted peer change no consent iss', async () => {
    const { app, realmA } = await boot();
    await seedConsentClient(app, realmA);
    const email = 'consent-spoof@example.com';
    await registerPasswordAccount(app, email);
    const jar = await signInWithPassword(app, email);

    for (const [index, spoofed] of SPOOFED_HEADER_SETS.entries()) {
      const headers = { host: HOST_A, ...spoofed };
      const send = (options: {
        method: 'GET' | 'POST';
        url: string;
        headers?: Record<string, string>;
        payload?: string;
      }) =>
        app.inject({
          ...options,
          headers: { ...headers, ...options.headers, cookie: jar.header() as string },
          remoteAddress: UNTRUSTED_PEER,
        });

      const authorize = await send({
        method: 'GET',
        url: `/oauth/authorize?${new URLSearchParams({
          response_type: 'code',
          client_id: CONSENT_CLIENT_ID,
          redirect_uri: REDIRECT_URI,
          scope: 'openid',
          state: `consent-${index}`,
          code_challenge: pkcePair().challenge,
          code_challenge_method: 'S256',
        }).toString()}`,
      });
      expect(authorize.statusCode).toBe(302);
      const consentUrl = authorize.headers['location'] as string;
      expect(consentUrl.startsWith('/ui/consent?')).toBe(true);

      const screen = await send({ method: 'GET', url: consentUrl });
      expect(screen.statusCode).toBe(200);
      jar.absorb(screen.headers['set-cookie']);
      const hidden = Object.fromEntries(
        [...screen.body.matchAll(/<input type="hidden" name="([^"]+)" value="([^"]*)"/g)].map(
          ([, name, value]) => [name, decodeHtmlEntities(value)]
        )
      );
      // Both answers of the consent screen are authorization responses.
      const decision = index % 2 === 0 ? 'deny' : 'allow';
      const decided = await send({
        method: 'POST',
        url: '/ui/consent',
        headers: FORM,
        payload: new URLSearchParams({
          ...hidden,
          csrf_token: extractCsrfToken(screen.body),
          decision,
        }).toString(),
      });
      expect(decided.statusCode).toBe(302);
      const location = new URL(decided.headers['location'] as string);
      expect(`${location.origin}${location.pathname}`).toBe(REDIRECT_URI);
      expect(location.searchParams.get('iss')).toBe(ISSUER_A);
      if (decision === 'deny') {
        expect(location.searchParams.get('error')).toBe('access_denied');
      } else {
        expect(location.searchParams.get('code')).not.toBeNull();
      }

      for (const response of [authorize, screen, decided]) {
        expect(JSON.stringify(response.headers)).not.toContain('evil.example.net');
        expect(response.body).not.toContain('evil.example.net');
      }
    }
  }, 180_000);

  it('builds no URL on an endpoint host: its answers name the issuer (DEFAULT_REALM_ENDPOINT_HOSTS)', async () => {
    const { app, realmA } = await boot({ DEFAULT_REALM_ENDPOINT_HOSTS: ENDPOINT_HOST });
    await seedMachineClient(app, realmA);
    await seedAppClient(app, realmA);

    // The documents are the same bytes as on the primary host.
    for (const path of [
      '/.well-known/oauth-authorization-server',
      '/.well-known/openid-configuration',
    ]) {
      const viaEndpoint = await discovery(app, path, { host: ENDPOINT_HOST });
      expect(viaEndpoint.statusCode).toBe(200);
      expect(viaEndpoint.body).toBe((await discovery(app, path, { host: HOST_A })).body);
      expect(viaEndpoint.body).not.toContain(ENDPOINT_HOST);
    }

    // A DPoP proof names the published token endpoint, not the endpoint host's.
    const key = await dpopKey();
    const steered = await dpopClientCredentials(
      app,
      { host: ENDPOINT_HOST },
      await proof(key, `https://${ENDPOINT_HOST}/oauth/token`)
    );
    expect(steered.json()).toMatchObject({ error: 'invalid_dpop_proof' });
    const honest = await dpopClientCredentials(
      app,
      { host: ENDPOINT_HOST },
      await proof(key, `${ISSUER_A}/oauth/token`)
    );
    expect(honest.statusCode).toBe(200);

    // A registration through the endpoint host links its mail to the issuer.
    expect(
      await registrationMailLink(
        app,
        'endpoint@example.com',
        { host: ENDPOINT_HOST },
        UNTRUSTED_PEER
      )
    ).toBe(ISSUER_A);

    // The browser routes answer only on the primary host.
    const authorize = await silentAuthorize(app, { host: ENDPOINT_HOST });
    expect(authorize.statusCode).toBe(421);
    expect(authorize.headers['location']).toBeUndefined();
  }, 120_000);

  it("signs realm B's tokens with its own issuer and keys: B accepts them, A does not (#491)", async () => {
    const { app, realmA, realmB } = await boot();
    // The same client_id names a client in each realm (#487), so realm A's
    // client passes introspection's same-client check for a token of B's:
    // only its keys and issuer pin can refuse it.
    await seedIntrospectingClient(app, realmA, 'urls-client');
    await seedIntrospectingClient(app, realmB, 'urls-client');

    const tokenOfB = await clientCredentialsToken(app, HOST_B, 'urls-client');
    expect(decodeJwtClaims(tokenOfB)['iss']).toBe(ISSUER_B);

    // Realm A refuses it: introspection reports it inactive, and revocation
    // answers 200 (RFC 7009 §2.2) but denylists nothing...
    expect(await introspect(app, HOST_A, 'urls-client', tokenOfB)).toEqual({ active: false });
    expect((await revoke(app, HOST_A, 'urls-client', tokenOfB)).statusCode).toBe(200);
    // ...so realm B still reports it active, and B's own revocation works.
    expect(await introspect(app, HOST_B, 'urls-client', tokenOfB)).toMatchObject({
      active: true,
    });
    expect((await revoke(app, HOST_B, 'urls-client', tokenOfB)).statusCode).toBe(200);
    expect(await introspect(app, HOST_B, 'urls-client', tokenOfB)).toEqual({ active: false });
  }, 120_000);

  it("builds a trusted proxy's request on the row of the realm it names, never on the header's text", async () => {
    const { app } = await boot();

    // The proxy forwards the host in another case and with a port: the realm is
    // found, and every URL is the row's issuer, not the forwarded spelling.
    const response = await discovery(
      app,
      '/.well-known/openid-configuration',
      {
        host: 'internal-lb.local',
        'x-forwarded-host': 'BETA.example.com:8443',
        'x-forwarded-proto': 'http',
      },
      PROXY
    );
    expect(response.statusCode).toBe(200);
    const document = response.json<Record<string, unknown>>();
    expect(document['issuer']).toBe(ISSUER_B);
    for (const url of urlsIn(document)) {
      expect(url === ISSUER_B || url.startsWith(`${ISSUER_B}/`)).toBe(true);
    }
    expect(response.body).not.toContain('8443');
    expect(response.body).not.toContain('BETA');
    expect(response.body).not.toContain('internal-lb.local');
  }, 120_000);
});

import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  type CookieJar,
  decodeJwtClaims,
  type E2eInfrastructure,
  generateJwtPem,
  type PemKeyPair,
  pkcePair,
  registerPasswordAccount,
  resetE2eState,
  signInWithPassword,
  startE2eInfrastructure,
} from '../testing/e2e-harness';

/**
 * THE ID TOKEN RELEASES PROFILE CLAIMS ONLY UNDER THE `profile` SCOPE (#755).
 *
 * OIDC Core §5.4 ties `name` to the `profile` scope. UserInfo has followed that
 * rule, but the authorization code grant put `name` in the ID token whatever
 * was granted, so a client that asked only for `openid` read the user's name
 * from the ID token. Both now resolve the profile claims through one helper
 * (`helpers/profile-claims.ts`).
 *
 * Driven against a real Postgres and Redis through the real routes: a password
 * account is registered, verified and signed in at `/ui/login`, then the same
 * browser runs `/oauth/authorize` → `/oauth/token`, and the access token from
 * that exchange is presented to `/oauth/userinfo`. The second test holds the
 * two release points together, so neither can drift from the other.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const REALM = 'master';
const CLIENT_ID = 'e2e-profile-client';
const REDIRECT_URI = 'https://client.example.com/callback';
const CLIENT_SCOPES = ['openid', 'email', 'profile'];
const EMAIL = 'ada@example.test';

/**
 * The standard claims OIDC Core §5.4 releases under the `profile` scope. QAuth
 * asserts only `name` today; comparing the whole list means a profile claim
 * added to one release point and not the other fails here.
 */
const PROFILE_SCOPE_CLAIMS = [
  'name',
  'family_name',
  'given_name',
  'middle_name',
  'nickname',
  'preferred_username',
  'profile',
  'picture',
  'website',
  'gender',
  'birthdate',
  'zoneinfo',
  'locale',
  'updated_at',
] as const;

/** The profile-scope claims a claim set carries, keyed by name. */
function profileClaimsOf(claims: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(
    PROFILE_SCOPE_CLAIMS.filter((claim) => claim in claims).map((claim) => [claim, claims[claim]])
  );
}

describe('ID token profile claims follow the profile scope (#755, real containers)', () => {
  let infra: E2eInfrastructure | undefined;
  let jwt: PemKeyPair | undefined;
  let dockerUp = false;

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

  interface Deployment {
    readonly app: FastifyInstance;
    /** The signed-in browser of the account named "Ada Lovelace". */
    readonly jar: CookieJar;
  }

  /**
   * Boot a deployment on the defaults, seed a public PKCE client, and sign in
   * a verified password account whose stored name is "Ada Lovelace".
   *
   * Consent for every scope the client may request is stored up front, so
   * `/oauth/authorize` mints a code without the consent screen (the screen is
   * not what this suite is about).
   */
  async function withDeployment<T>(body: (deployment: Deployment) => Promise<T>): Promise<T> {
    if (infra === undefined || jwt === undefined) throw new Error('infrastructure not started');
    let booted: BootedAuthServer | undefined;
    try {
      booted = await bootAuthServer(baseEnvironment(infra, jwt));
      const { app } = booted;
      await resetE2eState(app);

      const realm =
        (await app.repositories.realms.findByName(REALM)) ??
        (await app.repositories.realms.create({ name: REALM, enabled: true }));
      const client = await app.repositories.oauthClients.create({
        realmId: realm.id,
        clientId: CLIENT_ID,
        clientSecretHash: 'unused-public-client',
        tokenEndpointAuthMethod: 'none',
        name: 'E2E profile-claims client',
        redirectUris: [REDIRECT_URI],
        scopes: CLIENT_SCOPES,
        enabled: true,
        requirePkce: true,
      });

      const userId = await registerPasswordAccount(app, EMAIL);
      await app.repositories.users.update(realm.id, userId, {
        firstName: 'Ada',
        lastName: 'Lovelace',
      });
      await app.repositories.oauthConsents.upsertGrant(userId, client.id, realm.id, CLIENT_SCOPES);

      const jar = await signInWithPassword(app, EMAIL);
      return await body({ app, jar });
    } finally {
      await booted?.close();
    }
  }

  /**
   * Run the code flow for `scopes` as the signed-in browser and present the
   * resulting access token to UserInfo.
   *
   * @returns the decoded ID token claims and the UserInfo response body.
   */
  async function issueAndReadUserinfo(
    { app, jar }: Deployment,
    scopes: readonly string[]
  ): Promise<{ idToken: Record<string, unknown>; userinfo: Record<string, unknown> }> {
    const pkce = pkcePair();
    const authorize = await app.inject({
      method: 'GET',
      url: `/oauth/authorize?${new URLSearchParams({
        response_type: 'code',
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        scope: scopes.join(' '),
        code_challenge: pkce.challenge,
        code_challenge_method: 'S256',
        state: 'e2e-state',
      }).toString()}`,
      headers: { cookie: jar.header() as string },
    });
    expect(authorize.statusCode).toBe(302);
    const location = authorize.headers['location'];
    if (typeof location !== 'string') throw new Error('authorize did not redirect');
    const code = new URL(location).searchParams.get('code');
    if (code === null) throw new Error(`authorize returned no code: ${location}`);

    const token = await app.inject({
      method: 'POST',
      url: '/oauth/token',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      payload: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: REDIRECT_URI,
        client_id: CLIENT_ID,
        code_verifier: pkce.verifier,
      }).toString(),
    });
    expect(token.statusCode).toBe(200);
    const body = token.json() as { access_token?: string; id_token?: string; scope?: string };
    expect(body.scope).toBe(scopes.join(' '));
    if (typeof body.id_token !== 'string') {
      throw new Error(`token response carried no id_token: ${token.body}`);
    }
    if (typeof body.access_token !== 'string') {
      throw new Error(`token response carried no access_token: ${token.body}`);
    }

    const userinfo = await app.inject({
      method: 'GET',
      url: '/oauth/userinfo',
      headers: { authorization: `Bearer ${body.access_token}` },
    });
    expect(userinfo.statusCode).toBe(200);

    return {
      idToken: decodeJwtClaims(body.id_token),
      userinfo: userinfo.json() as Record<string, unknown>,
    };
  }

  it('omits name from the ID token under openid alone and releases it under openid profile', async () => {
    await withDeployment(async (deployment) => {
      const openidOnly = await issueAndReadUserinfo(deployment, ['openid']);
      // Absent, not null or empty: the key itself is missing.
      expect('name' in openidOnly.idToken).toBe(false);

      const withProfile = await issueAndReadUserinfo(deployment, ['openid', 'profile']);
      expect(withProfile.idToken['name']).toBe('Ada Lovelace');
    });
  });

  it('releases the same profile claims in the ID token and at UserInfo for the same grant', async () => {
    await withDeployment(async (deployment) => {
      for (const scopes of [
        ['openid'],
        ['openid', 'email'],
        ['openid', 'profile'],
        ['openid', 'email', 'profile'],
      ]) {
        const { idToken, userinfo } = await issueAndReadUserinfo(deployment, scopes);

        expect(profileClaimsOf(idToken), `scope "${scopes.join(' ')}"`).toEqual(
          profileClaimsOf(userinfo)
        );
        // The comparison above must not pass by both sides being empty when
        // the scope releases something.
        expect(profileClaimsOf(idToken)).toEqual(
          scopes.includes('profile') ? { name: 'Ada Lovelace' } : {}
        );
      }
    });
  });
});

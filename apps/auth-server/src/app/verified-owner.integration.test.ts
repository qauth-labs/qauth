import {
  sealUpstreamOidcConfig,
  type UpstreamOidcConfigInput,
} from '@qauth-labs/fastify-plugin-federation/src/testing/upstream-oidc-fixtures';
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  E2E_PASSWORD,
  E2E_REALM_NAME,
  type E2eInfrastructure,
  generateJwtPem,
  registerPasswordAccount,
  resetE2eState,
  startE2eInfrastructure,
} from '../testing/e2e-harness';
import { softPasskey } from '../testing/soft-passkey';

/**
 * AN AGENT OWNER IS A VERIFIED ACCOUNT (ADR-015 Decision 8 and question 13,
 * ADR-020 §3, #846), end to end against real Postgres and Redis.
 *
 * A dynamic registration of an agent client with a developer's token makes
 * that developer the agent's owner, and only an account whose primary
 * identity is proved may be one. The suite registers agent clients with
 * `POST /oauth/register` for accounts of every kind Decision 8's table names
 * that QAuth creates today:
 *
 * - a password account whose mailbox code was entered, and one whose code
 *   was not, which `REQUIRE_VERIFIED_ACCOUNT=false` lets sign in and take a
 *   developer token: its registration is refused with 403 `access_denied`,
 *   recorded as `user.agent_ownership_refused`, and writes no client;
 * - a passkey-only account, with no email address, created through the
 *   server's own registration ceremony, whose UV flag the provider checked;
 * - an account whose primary identity is a wallet credential, which only
 *   QAuth's verifier writes (an older release created such accounts; no
 *   wallet sign-in creates one now, ADR-009 §1);
 * - an upstream account, while its provider's verified switch is on, off,
 *   and once the realm switched the provider off.
 *
 * A passkey an unverified password account adds later does not make it a
 * verified owner; an account whose primary credential was removed is none.
 * An anonymous registration has no owner and is not checked, nor is a client
 * that is no agent.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const RP_ID = 'auth.example.com';
const DEVELOPER_AUDIENCE = 'urn:qauth:aud:developer:v1-rc.0';
const DEVELOPER_SCOPES = 'qauth:developer:read qauth:developer:write';
const REFUSED = 'urn:qauth:event:user.agent_ownership_refused:v1-rc.0';
const UPSTREAM_TYPE = 'oidc_corp';
const UPSTREAM_ISSUER = 'https://idp.example.com';

/** A wallet credential's data, as QAuth's verifier writes it. */
const WALLET_DATA = {
  credential_format: 'dc+sd-jwt',
  credential_type: 'https://credentials.example.com/identity',
  issuer: 'https://issuer.example.com',
  wallet_binding: 'binding',
  subject_resolution: 'asserted',
  enrolled_at: 1,
};

describe('an agent owner is a verified account (#846, real containers)', () => {
  let infra: E2eInfrastructure | undefined;
  let booted: BootedAuthServer | undefined;
  let dockerUp = false;
  let accounts = 0;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    booted = await bootAuthServer({
      ...baseEnvironment(infra, await generateJwtPem()),
      // The setting that lets an unverified password account sign in: it
      // seeds the default realm's policy, and the rule never reads it.
      REQUIRE_VERIFIED_ACCOUNT: 'false',
      WEBAUTHN_ENABLED: 'true',
      // A test registers several accounts and clients from one address.
      REGISTRATION_RATE_LIMIT: '10000',
      VERIFICATION_RATE_LIMIT: '10000',
      REGISTER_CLIENT_RATE_LIMIT: '10000',
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

  async function realmId(): Promise<string> {
    const realm = await app().repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm) throw new Error('default realm missing');
    return realm.id;
  }

  /** A fresh address. */
  function address(): string {
    return `owner-${++accounts}-${Date.now()}@example.com`;
  }

  /** The token `/auth/login` gives the developer portal. */
  async function portalToken(email: string): Promise<string> {
    const login = await app().inject({
      method: 'POST',
      url: '/auth/login',
      payload: { email, password: E2E_PASSWORD },
    });
    expect(login.statusCode, login.body).toBe(200);
    return login.json<{ access_token: string }>().access_token;
  }

  /** The portal's token for an account with no password. */
  async function developerToken(userId: string): Promise<string> {
    return app().jwtUtils.signAccessToken(
      { id: await realmId() },
      { sub: userId, clientId: 'system', aud: DEVELOPER_AUDIENCE, scope: DEVELOPER_SCOPES }
    );
  }

  /** A password account whose address was never confirmed. */
  async function unverifiedPasswordAccount(): Promise<{ userId: string; token: string }> {
    const email = address();
    const registered = await app().inject({
      method: 'POST',
      url: '/auth/register',
      payload: { email, password: E2E_PASSWORD },
    });
    expect(registered.statusCode, registered.body).toBe(202);
    const credential = await app().repositories.userCredentials.findByRealmProviderSub(
      await realmId(),
      'password',
      email
    );
    if (!credential) throw new Error('registration left no password credential');
    return { userId: credential.userId, token: await portalToken(email) };
  }

  /**
   * A passkey-only account, created through the server's own registration
   * ceremony: the WebAuthn provider checks the soft authenticator's answer.
   */
  async function passkeyAccount(): Promise<string> {
    // Imported from the module graph the booted app loaded.
    const { createServerPasskeyAccounts, createServerPasskeys } =
      await import('./helpers/passkey-sign-in');
    const realm = await realmId();
    const ceremonies = createServerPasskeys(app(), {
      mailer: { sendUncounted: () => undefined },
      requestOf: () => undefined,
    });
    const key = `registration-${++accounts}`;
    const started = await ceremonies.startRegistration({ realmId: realm, clientId: 'app', key });
    const passkey = softPasskey(RP_ID);
    const verified = await ceremonies.verifyRegistration({
      realmId: realm,
      clientId: 'app',
      key,
      response: passkey.create(started.options),
    });
    if (verified.kind !== 'verified') throw new Error(`the registration was ${verified.kind}`);
    const created = await createServerPasskeyAccounts(app(), {
      registered: async () => undefined,
    })({ realmId: realm, clientId: 'app', registration: verified.registration });
    if (created.kind !== 'created') throw new Error(`the account was ${created.kind}`);
    return created.userId;
  }

  /** The realm's provider of {@link UPSTREAM_TYPE}, with the verified switch given. */
  async function addUpstreamProvider(marksVerified: boolean): Promise<void> {
    const realm = await realmId();
    const config: UpstreamOidcConfigInput = {
      issuer: UPSTREAM_ISSUER,
      clientId: 'qauth',
      clientAuthentication: { method: 'client_secret_basic', clientSecret: 'upstream-secret' },
    };
    await app().repositories.realmUpstreamProviders.create({
      realmId: realm,
      type: UPSTREAM_TYPE,
      displayName: 'Corp',
      displayOrder: 0,
      hidden: false,
      enabled: true,
      marksVerified,
      config: await sealUpstreamOidcConfig(
        app().signer,
        { realmId: realm, providerId: UPSTREAM_TYPE, caller: 'api' },
        config
      ),
    });
  }

  /** An account the provider of {@link UPSTREAM_TYPE} created, as the upstream sign-in writes it. */
  async function upstreamAccount(): Promise<string> {
    const user = await app().repositories.users.create(
      { realmId: await realmId() },
      {
        providerType: UPSTREAM_TYPE,
        externalSub: `sub-${++accounts}`,
        credentialData: { kind: 'upstream', iss: UPSTREAM_ISSUER, verified: true },
      }
    );
    return user.id;
  }

  /** `POST /oauth/register`, with the developer's token when one is given. */
  function registerClient(
    token: string | undefined,
    isAgent = true
  ): Promise<LightMyRequestResponse> {
    return app().inject({
      method: 'POST',
      url: '/oauth/register',
      headers: token === undefined ? {} : { authorization: `Bearer ${token}` },
      payload: {
        client_name: 'Agent',
        redirect_uris: ['https://agent.example.com/callback'],
        ...(isAgent ? { is_agent: true } : {}),
      },
    });
  }

  /** The clients `userId` owns, with their agent flag. */
  async function clientsOf(userId: string): Promise<{ is_agent: boolean }[]> {
    const { rows } = await app().dbPool.query<{ is_agent: boolean }>(
      'SELECT is_agent FROM oauth_clients WHERE developer_id = $1 ORDER BY created_at',
      [userId]
    );
    return rows;
  }

  /** Every `user.agent_ownership_refused` event, with its subject. */
  async function refusals(): Promise<{ subject_id: string; data: Record<string, unknown> }[]> {
    const { rows } = await app().dbPool.query<{
      subject_id: string;
      data: Record<string, unknown>;
    }>('SELECT subject_id, data FROM events WHERE type = $1 ORDER BY seq', [REFUSED]);
    return rows;
  }

  /** Expect `response` to be the refusal, and `userId` to own no client. */
  async function expectRefused(response: LightMyRequestResponse, userId: string): Promise<void> {
    expect(response.statusCode, response.body).toBe(403);
    expect(response.json<{ error: string }>().error).toBe('access_denied');
    expect(await clientsOf(userId)).toEqual([]);
  }

  describe("Decision 8's table, row by row", () => {
    it('password: a verified owner once the mailbox code was entered', async () => {
      const email = address();
      const userId = await registerPasswordAccount(app(), email);

      const response = await registerClient(await portalToken(email));

      expect(response.statusCode, response.body).toBe(201);
      expect(response.json<{ is_agent?: boolean }>().is_agent).toBe(true);
      expect(await clientsOf(userId)).toEqual([{ is_agent: true }]);
      expect(await refusals()).toEqual([]);
    });

    it('password: no owner while the address is unconfirmed, though REQUIRE_VERIFIED_ACCOUNT=false lets it sign in; the refusal is recorded', async () => {
      const { userId, token } = await unverifiedPasswordAccount();

      await expectRefused(await registerClient(token), userId);

      expect(await refusals()).toEqual([
        {
          subject_id: userId,
          data: {
            action: 'client_registration',
            reason: 'account_not_verified',
            primaryIdentity: 'password',
          },
        },
      ]);
    });

    it('webauthn: a passkey-only account with no email address is a verified owner', async () => {
      const userId = await passkeyAccount();
      const primary = await app().repositories.userCredentials.findPrimaryByUserId(
        await realmId(),
        userId
      );
      expect(primary).toMatchObject({
        providerType: 'webauthn',
        isPrimary: true,
        credentialData: expect.objectContaining({ user_verified: true }),
      });
      const { rows } = await app().dbPool.query(
        `SELECT 1 FROM user_credentials WHERE user_id = $1 AND provider_type = 'password'`,
        [userId]
      );
      expect(rows).toEqual([]);

      const response = await registerClient(await developerToken(userId));

      expect(response.statusCode, response.body).toBe(201);
      expect(await clientsOf(userId)).toEqual([{ is_agent: true }]);
    });

    it("wallet: an account whose primary identity QAuth's verifier accepted is a verified owner", async () => {
      const user = await app().repositories.users.create(
        { realmId: await realmId() },
        { providerType: 'wallet', externalSub: 'did:example:owner', credentialData: WALLET_DATA }
      );

      const response = await registerClient(await developerToken(user.id));

      expect(response.statusCode, response.body).toBe(201);
      expect(await clientsOf(user.id)).toEqual([{ is_agent: true }]);
    });

    it("oidc_*: an upstream account is a verified owner while its provider's switch is on", async () => {
      await addUpstreamProvider(true);
      const userId = await upstreamAccount();

      const response = await registerClient(await developerToken(userId));

      expect(response.statusCode, response.body).toBe(201);
      expect(await clientsOf(userId)).toEqual([{ is_agent: true }]);
    });

    it("oidc_*: no owner while the provider's switch is off, whatever the credential says", async () => {
      await addUpstreamProvider(false);
      const userId = await upstreamAccount();

      await expectRefused(await registerClient(await developerToken(userId)), userId);

      expect(await refusals()).toEqual([
        {
          subject_id: userId,
          data: {
            action: 'client_registration',
            reason: 'account_not_verified',
            primaryIdentity: 'upstream',
          },
        },
      ]);
    });

    it('oidc_*: no owner once the realm switched the provider off', async () => {
      await addUpstreamProvider(true);
      const userId = await upstreamAccount();
      await app().repositories.realmUpstreamProviders.update(await realmId(), UPSTREAM_TYPE, {
        enabled: false,
      });

      await expectRefused(await registerClient(await developerToken(userId)), userId);
      expect((await refusals()).map((row) => row.data['reason'])).toEqual(['account_not_verified']);
    });
  });

  describe('only the primary identity counts', () => {
    it('an unverified account that adds a passkey later is still no verified owner', async () => {
      const { userId, token } = await unverifiedPasswordAccount();
      // A passkey whose registration checked the UV flag, stored as an
      // enrolment stores it.
      const passkey = softPasskey(RP_ID);
      const added = await app().repositories.userCredentials.create({
        realmId: await realmId(),
        userId,
        providerType: 'webauthn',
        externalSub: passkey.credentialId,
        credentialData: passkey.credentialData,
      });
      expect(added.isPrimary).toBe(false);

      await expectRefused(await registerClient(token), userId);
      await expectRefused(await registerClient(await developerToken(userId)), userId);
      expect((await refusals()).map((row) => row.data['reason'])).toEqual([
        'account_not_verified',
        'account_not_verified',
      ]);
    });

    it('an account whose primary credential was removed is no verified owner', async () => {
      const userId = await passkeyAccount();
      const realm = await realmId();
      const primary = await app().repositories.userCredentials.findPrimaryByUserId(realm, userId);
      if (!primary) throw new Error('the account has no primary credential');
      // A second passkey, then the first one removed.
      const passkey = softPasskey(RP_ID);
      await app().repositories.userCredentials.create({
        realmId: realm,
        userId,
        providerType: 'webauthn',
        externalSub: passkey.credentialId,
        credentialData: passkey.credentialData,
      });
      await app().dbPool.query('DELETE FROM user_credentials WHERE id = $1', [primary.id]);

      await expectRefused(await registerClient(await developerToken(userId)), userId);
      expect(await refusals()).toEqual([
        {
          subject_id: userId,
          data: {
            action: 'client_registration',
            reason: 'no_primary_identity',
            primaryIdentity: 'none',
          },
        },
      ]);
    });
  });

  describe('what is not checked', () => {
    it('an anonymous registration of an agent client has no owner', async () => {
      const response = await registerClient(undefined);

      expect(response.statusCode, response.body).toBe(201);
      expect(await refusals()).toEqual([]);
    });

    it('an unverified account still registers a client that is no agent', async () => {
      const { userId, token } = await unverifiedPasswordAccount();

      const response = await registerClient(token, false);

      expect(response.statusCode, response.body).toBe(201);
      expect(await clientsOf(userId)).toEqual([{ is_agent: false }]);
      expect(await refusals()).toEqual([]);
    });
  });
});

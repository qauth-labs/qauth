/**
 * Realm scoping of id lookups against the real DDL (ADR-019 Decision 1, #489).
 *
 * Two realms, each with the same `client_id`, a user, a consent, an API key, a
 * password credential and its verification token, a refresh token and an
 * authorization code. Every id-keyed read, update and delete is asked for
 * realm A's row with realm B's id and must answer as it answers an unknown id;
 * asked with realm A's id it finds the row, so a refusal is the realm's doing.
 *
 * `refresh_tokens`, `authorization_codes` and `email_verification_tokens` have
 * no realm column: their reads are scoped through the client or the
 * credential, which is what this suite proves on Postgres.
 *
 * Requires Docker; skips locally without it and fails on CI
 * (`requireDockerOrSkip`).
 */
import { randomUUID } from 'node:crypto';

import { NotFoundError } from '@qauth-labs/shared-errors';
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  createApiKeysRepository,
  createAuthorizationCodesRepository,
  createEmailVerificationTokensRepository,
  createOAuthClientsRepository,
  createOAuthConsentsRepository,
  createRealmsRepository,
  createRefreshTokensRepository,
  createUserCredentialsRepository,
  createUsersRepository,
} from './index';
import { type IntegrationDb, setupIntegrationDb } from './integration-setup';

describe('realm scoping of id lookups (real Postgres, #489)', () => {
  let ctx: IntegrationDb | undefined;
  let dockerUp = false;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    ctx = await setupIntegrationDb();
  }, 180_000);

  afterAll(async () => {
    await ctx?.teardown();
  });

  beforeEach(async (testCtx) => {
    if (!dockerUp || !ctx) {
      testCtx.skip();
      return;
    }
    await ctx.reset();
  });

  function db() {
    if (!ctx) throw new Error('integration db not initialised');
    return ctx.database.db;
  }

  /** One realm's rows, all named alike in both realms where a name is chosen. */
  async function seedRealmRows(name: string, tag: string) {
    const realm = await createRealmsRepository(db()).create({ name });
    const user = await createUsersRepository(db()).create({ realmId: realm.id });
    const client = await createOAuthClientsRepository(db()).create({
      realmId: realm.id,
      // The same `client_id` in both realms: client ids are per realm.
      clientId: 'shared-client',
      clientSecretHash: 'secret-hash',
      name: `Client ${tag}`,
      developerId: user.id,
      redirectUris: ['https://app.example.com/cb'],
      scopes: ['read'],
      grantTypes: ['authorization_code', 'refresh_token'],
    });
    const credential = await createUserCredentialsRepository(db()).create({
      realmId: realm.id,
      userId: user.id,
      providerType: 'password',
      // The same address in both realms: an account is one realm's.
      externalSub: 'alice@example.com',
      credentialData: { password_hash: 'argon2-hash', email_verified: false },
    });
    const consent = await createOAuthConsentsRepository(db()).upsertGrant(
      user.id,
      client.id,
      realm.id,
      ['read']
    );
    const apiKey = await createApiKeysRepository(db()).create({
      realmId: realm.id,
      clientId: client.id,
      developerId: user.id,
      name: 'k',
      keyHash: 'argon2id$h',
      prefix: `qauth_${tag.repeat(16)}`,
      last4: tag.repeat(4),
    });
    const now = Date.now();
    const verificationTokenHash = tag.repeat(64);
    await createEmailVerificationTokensRepository(db()).create({
      credentialId: credential.id,
      tokenHash: verificationTokenHash,
      expiresAt: now + 60_000,
    });
    const refreshTokenHash = tag.repeat(64);
    await createRefreshTokensRepository(db()).create({
      userId: user.id,
      oauthClientId: client.id,
      tokenHash: refreshTokenHash,
      familyId: randomUUID(),
      familyCreatedAt: now,
      familySessionExpiresAt: null,
      expiresAt: now + 60_000,
      scopes: ['read'],
    });
    const code = `code-${tag}`;
    await createAuthorizationCodesRepository(db()).create({
      code,
      oauthClientId: client.id,
      userId: user.id,
      redirectUri: 'https://app.example.com/cb',
      codeChallenge: 'challenge',
      codeChallengeMethod: 'S256',
      scopes: ['read'],
      expiresAt: now + 60_000,
    });
    return {
      realm,
      user,
      client,
      credential,
      consent,
      apiKey,
      verificationTokenHash,
      refreshTokenHash,
      code,
    };
  }

  async function seedTwoRealms() {
    const a = await seedRealmRows('realm-a', 'a');
    const b = await seedRealmRows('realm-b', 'b');
    return { a, b };
  }

  it('reads find a row only in its own realm', async () => {
    const { a, b } = await seedTwoRealms();
    const users = createUsersRepository(db());
    const clients = createOAuthClientsRepository(db());
    const consents = createOAuthConsentsRepository(db());
    const apiKeys = createApiKeysRepository(db());
    const credentials = createUserCredentialsRepository(db());
    const refreshTokens = createRefreshTokensRepository(db());
    const codes = createAuthorizationCodesRepository(db());
    const verificationTokens = createEmailVerificationTokensRepository(db());

    // Found in realm A: the refusals below are the realm's.
    expect((await users.findById(a.realm.id, a.user.id))?.id).toBe(a.user.id);
    expect((await clients.findById(a.realm.id, a.client.id))?.id).toBe(a.client.id);
    expect((await consents.findActive(a.realm.id, a.user.id, a.client.id))?.id).toBe(a.consent.id);
    expect((await apiKeys.findById(a.realm.id, a.apiKey.id))?.id).toBe(a.apiKey.id);
    expect((await apiKeys.findByPrefix(a.realm.id, a.apiKey.prefix))?.id).toBe(a.apiKey.id);
    expect((await credentials.findById(a.realm.id, a.credential.id))?.id).toBe(a.credential.id);
    expect(await refreshTokens.findByTokenHash(a.realm.id, a.refreshTokenHash)).toBeDefined();
    expect(
      await refreshTokens.findByTokenHashIncludingRevoked(a.realm.id, a.refreshTokenHash)
    ).toBeDefined();
    expect(await codes.findByCode(a.realm.id, a.code)).toBeDefined();
    expect(
      await verificationTokens.findByTokenHash(a.realm.id, a.verificationTokenHash)
    ).toBeDefined();

    // Realm A's rows asked for at realm B: unknown, as a random id is.
    expect(await users.findById(b.realm.id, a.user.id)).toBeUndefined();
    await expect(users.findByIdOrThrow(b.realm.id, a.user.id)).rejects.toBeInstanceOf(
      NotFoundError
    );
    expect(await clients.findById(b.realm.id, a.client.id)).toBeUndefined();
    await expect(clients.findByIdOrThrow(b.realm.id, a.client.id)).rejects.toBeInstanceOf(
      NotFoundError
    );
    expect(await clients.listByDeveloper(b.realm.id, a.user.id)).toEqual([]);
    expect(await clients.countByDeveloper(b.realm.id, a.user.id)).toBe(0);
    expect(await consents.findActive(b.realm.id, a.user.id, a.client.id)).toBeUndefined();
    expect(await consents.listActiveForUser(b.realm.id, a.user.id)).toEqual([]);
    expect(await consents.listActiveForUserWithClient(b.realm.id, a.user.id)).toEqual([]);
    expect(await apiKeys.findById(b.realm.id, a.apiKey.id)).toBeUndefined();
    expect(await apiKeys.findByPrefix(b.realm.id, a.apiKey.prefix)).toBeUndefined();
    expect(await apiKeys.listByClient(b.realm.id, a.client.id)).toEqual([]);
    expect(await credentials.findById(b.realm.id, a.credential.id)).toBeUndefined();
    expect(await refreshTokens.findByTokenHash(b.realm.id, a.refreshTokenHash)).toBeUndefined();
    expect(
      await refreshTokens.findByTokenHashIncludingRevoked(b.realm.id, a.refreshTokenHash)
    ).toBeUndefined();
    expect(await codes.findByCode(b.realm.id, a.code)).toBeUndefined();
    expect(
      await verificationTokens.findByTokenHash(b.realm.id, a.verificationTokenHash)
    ).toBeUndefined();
  });

  it('writes by id change nothing in another realm', async () => {
    const { a, b } = await seedTwoRealms();
    const users = createUsersRepository(db());
    const clients = createOAuthClientsRepository(db());
    const consents = createOAuthConsentsRepository(db());
    const apiKeys = createApiKeysRepository(db());

    await expect(
      users.update(b.realm.id, a.user.id, { firstName: 'Mallory' })
    ).rejects.toBeInstanceOf(NotFoundError);
    await expect(users.updateLastLogin(b.realm.id, a.user.id)).rejects.toBeInstanceOf(
      NotFoundError
    );
    expect(await users.delete(b.realm.id, a.user.id)).toBe(false);
    await expect(
      clients.update(b.realm.id, a.client.id, { name: 'Mallory' })
    ).rejects.toBeInstanceOf(NotFoundError);
    expect(await clients.delete(b.realm.id, a.client.id)).toBe(false);
    await expect(consents.revoke(b.realm.id, a.consent.id)).rejects.toBeInstanceOf(NotFoundError);
    expect(await apiKeys.revoke(b.realm.id, a.apiKey.id)).toBeUndefined();

    // Realm A's rows are as they were.
    const user = await users.findById(a.realm.id, a.user.id);
    expect(user?.firstName).toBeNull();
    expect(user?.lastLoginAt).toBeNull();
    expect((await clients.findById(a.realm.id, a.client.id))?.name).toBe('Client a');
    expect(await consents.findActive(a.realm.id, a.user.id, a.client.id)).toBeDefined();
    expect((await apiKeys.findById(a.realm.id, a.apiKey.id))?.revokedAt).toBeNull();
  });
});

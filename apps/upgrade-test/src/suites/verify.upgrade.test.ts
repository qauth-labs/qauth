import { randomBytes } from 'node:crypto';

import { beforeAll, describe, expect, it } from 'vitest';

import { serverPath, upgradeConfig } from '../config';
import { storedApiKey } from '../helpers/database';
import { createPkcePair } from '../helpers/pkce';
import {
  authorizeInBrowser,
  introspect,
  listApiKeys,
  listConsents,
  passwordLogin,
  refresh,
  refusedRefresh,
} from '../helpers/qauth';
import { SCOPES } from '../helpers/scenario';
import { readState, type UpgradeState } from '../state';

/**
 * Step 2 of the upgrade test, against the NEW build after the migration
 * runner ran on the baseline's database: the data the populate step wrote
 * through the baseline must still work (#475, ADR-018 §5).
 *
 * The tests run in file order. The refresh-token rotation is last, because
 * replaying the rotated token afterwards revokes its whole family.
 */
describe('after the upgrade, the data the baseline wrote still works', () => {
  let state: UpgradeState;
  let baseUrl: string;
  let databaseUrl: string;

  beforeAll(() => {
    ({ baseUrl, databaseUrl } = upgradeConfig());
    state = readState(upgradeConfig().statePath);
  });

  it('keeps the issuer the baseline had', async () => {
    expect(baseUrl, 'the new build runs with the baseline’s issuer').toBe(state.baseUrl);
    const response = await fetch(serverPath(baseUrl, '/.well-known/openid-configuration'));
    expect(response.status).toBe(200);
    expect(((await response.json()) as Record<string, unknown>)['issuer']).toBe(state.baseUrl);
  });

  it('introspects the old access token as active until it expires', async () => {
    const now = Math.floor(Date.now() / 1000);
    expect(
      state.tokens.accessTokenExpiresAt,
      `the access token expired ${now - state.tokens.accessTokenExpiresAt} s before this check, so the job took longer than the token lifetime`
    ).toBeGreaterThan(now);
    const introspection = await introspect(baseUrl, state.appClient, state.tokens.accessToken);
    expect(introspection['active'], JSON.stringify(introspection)).toBe(true);
    expect(introspection['sub']).toBe(state.endUser.userId);
    expect(introspection['client_id']).toBe(state.appClient.clientId);
    expect(introspection['exp']).toBe(state.tokens.accessTokenExpiresAt);
  });

  it('signs both users in with their old passwords', async () => {
    const developer = await passwordLogin(baseUrl, state.developer.email, state.developer.password);
    expect(developer.userId).toBe(state.developer.userId);
    const endUser = await passwordLogin(baseUrl, state.endUser.email, state.endUser.password);
    expect(endUser.userId).toBe(state.endUser.userId);
  });

  it('lists the consent the end user granted', async () => {
    const endUser = await passwordLogin(baseUrl, state.endUser.email, state.endUser.password);
    const consents = await listConsents(baseUrl, endUser.accessToken);
    const consent = consents.find((row) => row.clientId === state.consent.clientId);
    expect(consent, `GET /api/consents: ${JSON.stringify(consents)}`).toBeDefined();
    expect([...(consent?.scopes ?? [])].sort()).toEqual([...state.consent.scopes].sort());
  });

  it('honours the consent in the hosted sign-in: the end user is not asked again', async () => {
    const authorization = await authorizeInBrowser({
      baseUrl,
      clientId: state.appClient.clientId,
      redirectUri: state.appClient.redirectUri,
      scope: SCOPES.join(' '),
      email: state.endUser.email,
      password: state.endUser.password,
      pkce: createPkcePair(),
      state: randomBytes(16).toString('base64url'),
      nonce: randomBytes(16).toString('base64url'),
    });
    expect(authorization.consented, 'the stored consent covers the same scopes').toBe(false);
  });

  it('lists the API key and verifies it against the stored hash', async () => {
    const developer = await passwordLogin(baseUrl, state.developer.email, state.developer.password);
    const keys = await listApiKeys(baseUrl, developer.accessToken, state.devClient.id);
    const listed = keys.find((key) => key['id'] === state.apiKey.id);
    expect(listed, `GET /api/clients/:id/api-keys: ${JSON.stringify(keys)}`).toBeDefined();
    expect(listed?.['prefix']).toBe(state.apiKey.prefix);
    expect(listed?.['last4']).toBe(state.apiKey.last4);
    expect(listed?.['revokedAt'] ?? null).toBeNull();

    const stored = await storedApiKey(databaseUrl, state.apiKey.key);
    expect(stored, 'the api_keys row is still there').not.toBeNull();
    expect(stored?.id).toBe(state.apiKey.id);
    expect(stored?.clientRowId).toBe(state.devClient.id);
    expect(stored?.revoked).toBe(false);
    expect(stored?.verifies, 'the plaintext verifies against the stored argon2id hash').toBe(true);
  });

  it('rotates the old refresh token, and refuses it once rotated', async () => {
    const rotated = await refresh(baseUrl, state.appClient, state.tokens.refreshToken);
    expect(rotated.refreshToken, 'the rotation issues a refresh token').toBeTruthy();
    expect(rotated.refreshToken).not.toBe(state.tokens.refreshToken);
    const introspection = await introspect(baseUrl, state.appClient, rotated.accessToken);
    expect(introspection['active'], JSON.stringify(introspection)).toBe(true);
    expect(introspection['sub']).toBe(state.endUser.userId);

    const replay = await refusedRefresh(baseUrl, state.appClient, state.tokens.refreshToken);
    expect(replay, 'a rotated refresh token is refused (RFC 9700 §4.14.2)').toEqual({
      status: 400,
      error: 'invalid_grant',
    });
  });
});

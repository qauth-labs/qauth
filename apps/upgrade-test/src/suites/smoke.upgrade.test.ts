import { beforeAll, describe, expect, it } from 'vitest';

import { serverPath, upgradeConfig } from '../config';
import { storedApiKey } from '../helpers/database';
import { introspect, listApiKeys, passwordLogin, refresh, userinfo } from '../helpers/qauth';
import { writeScenario } from '../helpers/scenario';
import type { UpgradeState } from '../state';

/**
 * Smoke tests that hold for every release since the first baseline, on
 * whichever server is up (#475, ADR-018 §5):
 *
 * - the new build after the upgrade;
 * - the BASELINE release on the migrated database, the rolling-upgrade leg.
 *   That is the proof of "expand, then contract": old code must still read and
 *   write every table it uses after the new migrations ran, so a migration
 *   that drops or renames a column the old code uses fails here.
 *
 * They write a fresh scenario rather than reuse the populate step's data, so
 * both the old and the new server are made to insert rows into the migrated
 * schema, not only to read them.
 */
describe('smoke: a fresh scenario on the running server', () => {
  let baseUrl: string;
  let databaseUrl: string;
  let mailUrl: string;
  let scenario: UpgradeState | undefined;

  beforeAll(() => {
    ({ baseUrl, databaseUrl, mailUrl } = upgradeConfig());
  });

  function written(): UpgradeState {
    expect(scenario, 'the scenario test above failed, so there is nothing to check').toBeDefined();
    return scenario as UpgradeState;
  }

  it('reports healthy and serves discovery and its keys', async () => {
    const health = await fetch(serverPath(baseUrl, '/health'));
    expect(health.status).toBe(200);
    expect(((await health.json()) as Record<string, unknown>)['status']).toBe('ok');

    const discovery = await fetch(serverPath(baseUrl, '/.well-known/openid-configuration'));
    expect(discovery.status).toBe(200);
    const metadata = (await discovery.json()) as Record<string, unknown>;
    expect(metadata['issuer']).toBe(baseUrl);
    expect(typeof metadata['jwks_uri']).toBe('string');

    const jwks = await fetch(metadata['jwks_uri'] as string);
    expect(jwks.status).toBe(200);
    const keys = ((await jwks.json()) as { keys?: unknown[] }).keys;
    expect(Array.isArray(keys) && keys.length > 0, 'the key set has a key').toBe(true);
  });

  it('registers users, creates clients, runs the code flow with PKCE, consents and mints an API key', async () => {
    scenario = await writeScenario(baseUrl, databaseUrl, mailUrl);
  });

  it('answers userinfo, rotates the refresh token and introspects the new access token', async () => {
    const { appClient, endUser, tokens } = written();
    const claims = await userinfo(baseUrl, tokens.accessToken);
    expect(claims['sub']).toBe(endUser.userId);

    const rotated = await refresh(baseUrl, appClient, tokens.refreshToken);
    expect(rotated.refreshToken).toBeTruthy();
    expect(rotated.refreshToken).not.toBe(tokens.refreshToken);
    const introspection = await introspect(baseUrl, appClient, rotated.accessToken);
    expect(introspection['active'], JSON.stringify(introspection)).toBe(true);
  });

  it('lists the new API key and verifies it against the stored hash', async () => {
    const { apiKey, developer, devClient } = written();
    const login = await passwordLogin(baseUrl, developer.email, developer.password);
    const keys = await listApiKeys(baseUrl, login.accessToken, devClient.id);
    expect(keys.map((key) => key['id'])).toContain(apiKey.id);
    const stored = await storedApiKey(databaseUrl, apiKey.key);
    expect(stored?.verifies, 'the plaintext verifies against the stored argon2id hash').toBe(true);
  });
});

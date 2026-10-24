import { randomBytes } from 'node:crypto';

import { expect } from 'vitest';

import { STATE_FORMAT, type UpgradeState } from '../state';
import { markClientDevelopment } from './database';
import { waitForVerificationToken } from './mail';
import { createPkcePair } from './pkce';
import {
  authorizeInBrowser,
  createApiKey,
  createClient,
  exchangeCode,
  introspect,
  jwtClaims,
  listConsents,
  passwordLogin,
  register,
  verifyEmail,
} from './qauth';

/** Where the app client's codes go. Port 9 (discard) never answers: the test reads the redirect. */
export const REDIRECT_URI = 'http://127.0.0.1:9/upgrade-test/callback';

/** What the end user is asked to consent to. `offline_access` brings the refresh token. */
export const SCOPES = ['openid', 'profile', 'email', 'offline_access'] as const;

/** A password strong enough for the strength check of every release. */
function newPassword(): string {
  return `Upgrade-${randomBytes(12).toString('base64url')}-7`;
}

/**
 * The data the upgrade test writes into a running QAuth, through its HTTP API
 * only, save for the one operator step static API keys need:
 *
 * 1. a developer and an end user register with a password and verify their
 *    address with the token from the verification mail;
 * 2. the developer signs in and creates two confidential clients;
 * 3. the end user runs the authorization code flow with PKCE against the first
 *    one, signs in on the hosted page and allows it for good (a consent);
 * 4. the code is exchanged for an access token, an ID token and a refresh token;
 * 5. the operator marks the second client `development`, and the developer
 *    mints a static API key for it.
 *
 * The populate step runs it against the baseline release and saves the result;
 * the smoke tests run it against whichever server is up.
 */
export async function writeScenario(
  baseUrl: string,
  databaseUrl: string,
  mailUrl: string
): Promise<UpgradeState> {
  const run = randomBytes(5).toString('hex');
  const developerAccount = {
    email: `upgrade-developer-${run}@example.com`,
    password: newPassword(),
  };
  const endUserAccount = { email: `upgrade-user-${run}@example.com`, password: newPassword() };

  await register(baseUrl, developerAccount.email, developerAccount.password);
  await register(baseUrl, endUserAccount.email, endUserAccount.password);
  for (const account of [developerAccount, endUserAccount]) {
    const token = await waitForVerificationToken(mailUrl, account.email);
    await verifyEmail(baseUrl, token, account.password);
  }

  const developer = await passwordLogin(baseUrl, developerAccount.email, developerAccount.password);
  const appClient = await createClient(baseUrl, developer.accessToken, {
    name: `Upgrade test app ${run}`,
    redirectUri: REDIRECT_URI,
    scopes: [...SCOPES],
  });
  const devClient = await createClient(baseUrl, developer.accessToken, {
    name: `Upgrade test developer tool ${run}`,
    redirectUri: REDIRECT_URI,
    scopes: ['openid'],
  });

  const pkce = createPkcePair();
  const state = randomBytes(16).toString('base64url');
  const authorization = await authorizeInBrowser({
    baseUrl,
    clientId: appClient.clientId,
    redirectUri: REDIRECT_URI,
    scope: SCOPES.join(' '),
    email: endUserAccount.email,
    password: endUserAccount.password,
    pkce,
    state,
    nonce: randomBytes(16).toString('base64url'),
  });
  expect(authorization.consented, 'a new user is asked for consent').toBe(true);

  const tokens = await exchangeCode(
    baseUrl,
    appClient,
    authorization.code,
    REDIRECT_URI,
    pkce.verifier
  );
  expect(tokens.refreshToken, 'offline_access brings a refresh token').toBeTruthy();
  const accessTokenExpiresAt = jwtClaims(tokens.accessToken)['exp'];
  expect(Number.isInteger(accessTokenExpiresAt), 'the access token carries exp').toBe(true);

  const endUser = await passwordLogin(baseUrl, endUserAccount.email, endUserAccount.password);
  const introspection = await introspect(baseUrl, appClient, tokens.accessToken);
  expect(introspection['active'], 'the new access token is active').toBe(true);
  expect(introspection['sub'], 'the access token belongs to the end user').toBe(endUser.userId);

  const consents = await listConsents(baseUrl, endUser.accessToken);
  const consent = consents.find((row) => row.clientId === appClient.clientId);
  expect(consent, `the consent is listed: ${JSON.stringify(consents)}`).toBeDefined();

  await markClientDevelopment(databaseUrl, devClient.id);
  const apiKey = await createApiKey(
    baseUrl,
    developer.accessToken,
    devClient.id,
    `upgrade-test ${run}`
  );

  return {
    format: STATE_FORMAT,
    baseUrl,
    populatedAt: Math.floor(Date.now() / 1000),
    developer: { userId: developer.userId, ...developerAccount },
    endUser: { userId: endUser.userId, ...endUserAccount },
    appClient: { ...appClient, redirectUri: REDIRECT_URI },
    devClient,
    tokens: {
      accessToken: tokens.accessToken,
      accessTokenExpiresAt: accessTokenExpiresAt as number,
      refreshToken: tokens.refreshToken as string,
      idToken: tokens.idToken ?? null,
    },
    consent: { clientId: appClient.clientId, scopes: [...(consent?.scopes ?? [])] },
    apiKey,
  };
}

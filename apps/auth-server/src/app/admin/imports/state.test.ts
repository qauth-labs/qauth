import { defaultsFromEnv } from '@qauth-labs/fastify-plugin-realm-policy';
import { parseRealmFile, realmFileClientSchema } from '@qauth-labs/realm-file';
import { describe, expect, it } from 'vitest';

import type { OAuthClientRecord } from '../clients/representation';
import { planImport } from './plan';
import { normalizedClientOf, realmFileClientOf, unmanagedReason } from './state';

/**
 * The realm as an import reads it (#518): a stored client becomes the entry a
 * realm file lists for it, which the format accepts and which plans no change
 * against itself, with no secret; and the clients no realm file may name are
 * told apart from those it manages.
 */

const REALM = '018f2d6e-8a8b-7c3d-9e0f-1a2b3c4d5e6f';
const SECRET_HASH = '$argon2id$v=19$m=19456,t=2,p=1$c2VjcmV0LXNhbHQ$aGFzaC1vZi10aGUtc2VjcmV0';
const PRIVATE_D = 'nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A';

/** A stored client, as the repository returns it, every column filled as the seed manifest fills it. */
function row(overrides: Record<string, unknown> = {}): OAuthClientRecord {
  return {
    id: '018f2d6e-8a8b-7c3d-9e0f-000000000001',
    realmId: REALM,
    clientId: 'portal',
    clientSecretHash: SECRET_HASH,
    name: 'Portal',
    description: null,
    developerId: null,
    provisionedByOperator: true,
    dynamicRegisteredAt: null,
    metadata: null,
    enabled: true,
    suspended: false,
    suspendedAt: null,
    redirectUris: ['https://portal.example.com/callback'],
    postLogoutRedirectUris: [],
    backchannelLogoutUri: null,
    backchannelLogoutUriSource: null,
    backchannelLogoutSessionRequired: false,
    scopes: ['openid'],
    clientCredentialsScopes: null,
    audience: null,
    grantTypes: ['authorization_code', 'refresh_token'],
    responseTypes: ['code'],
    tokenEndpointAuthMethod: 'client_secret_basic',
    jwks: null,
    jwksUri: null,
    requirePkce: true,
    dpopBoundAccessTokens: false,
    environment: 'production',
    isAgent: false,
    maxAgentMode: null,
    idJagTargets: [],
    webauthnAllowedOrigins: [],
    verifiedDomain: null,
    firstPartyProfile: null,
    firstPartyPolicy: null,
    firstPartyReason: null,
    hostedFlows: null,
    registrationChallenge: null,
    accessTokenLifespanSeconds: null,
    refreshTokenLifespanSeconds: null,
    createdAt: Date.UTC(2026, 10, 1),
    updatedAt: Date.UTC(2026, 10, 2),
    lastUsedAt: null,
    ...overrides,
  } as unknown as OAuthClientRecord;
}

const ROWS: readonly [string, OAuthClientRecord][] = [
  ['a confidential web client', row()],
  [
    'a machine client with an audience and key set',
    row({
      clientId: 'worker',
      grantTypes: ['client_credentials'],
      responseTypes: [],
      redirectUris: [],
      scopes: ['reports:read'],
      clientCredentialsScopes: ['reports:read'],
      audience: ['https://api.example.com'],
      tokenEndpointAuthMethod: 'private_key_jwt',
      jwks: {
        keys: [
          {
            kty: 'OKP',
            crv: 'Ed25519',
            x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
            d: PRIVATE_D,
          },
        ],
      },
      description: 'Nightly reports',
    }),
  ],
  [
    'a development agent',
    row({
      clientId: 'agent',
      isAgent: true,
      maxAgentMode: 'readonly',
      tokenEndpointAuthMethod: 'none',
      redirectUris: ['http://127.0.0.1/callback'],
      environment: 'development',
      idJagTargets: ['https://as.example.com'],
    }),
  ],
];

describe('a stored client as a realm file lists it (#518)', () => {
  it.each(ROWS)(
    '%s: the format accepts it, it holds no secret, and it plans no change',
    (_, stored) => {
      const entry = realmFileClientOf(stored);
      expect(realmFileClientSchema.safeParse(entry).success).toBe(true);
      const text = JSON.stringify(entry);
      expect(text).not.toContain(SECRET_HASH);
      expect(text).not.toContain(PRIVATE_D);

      const state = {
        realmId: REALM,
        realmName: 'acme',
        policiesVersion: 1,
        policies: defaultsFromEnv({}) as unknown as Record<string, unknown>,
        setSecrets: [],
        clients: [entry],
        unmanagedClients: new Map<string, string>(),
        reservedClientId: () => undefined,
      };
      const file = parseRealmFile({ realm: 'acme', clients: [entry] });
      expect(planImport(state, file).changes).toEqual([]);
    }
  );
});

describe('a stored value the format normalizes (#518)', () => {
  it('compares as the file holds it, so a file built from the state plans no change', () => {
    // The admin API stores a first-party reason as given; the format trims it.
    const stored = row({
      clientId: 'own-app',
      tokenEndpointAuthMethod: 'private_key_jwt',
      jwksUri: 'https://own.example.com/jwks.json',
      firstPartyProfile: 'web_redirect',
      firstPartyReason: 'Our own app\n',
    });
    const entry = normalizedClientOf(stored);
    expect(entry.first_party_reason).toBe('Our own app');
    const state = {
      realmId: REALM,
      realmName: 'acme',
      policiesVersion: 1,
      policies: defaultsFromEnv({}) as unknown as Record<string, unknown>,
      setSecrets: [],
      clients: [entry],
      unmanagedClients: new Map<string, string>(),
      reservedClientId: () => undefined,
    };
    const file = parseRealmFile({ realm: 'acme', clients: [realmFileClientOf(stored)] });
    expect(planImport(state, file).changes).toEqual([]);
  });

  it('keeps a stored value the format cannot hold, so a file that names the client shows the change', () => {
    const stored = row({ firstPartyProfile: 'web_redirect', firstPartyReason: '   ' });
    expect(normalizedClientOf(stored)).toEqual(realmFileClientOf(stored));
  });
});

describe('the clients no realm file may name (#518)', () => {
  const context = {
    systemClientId: 'system',
    serviceAccountClients: new Set(['018f2d6e-8a8b-7c3d-9e0f-00000000000a']),
  };

  it('manages an operator-provisioned client no developer owns', () => {
    expect(unmanagedReason(row(), context)).toBeUndefined();
  });

  it.each([
    ['a developer’s', row({ developerId: '018f2d6e-8a8b-7c3d-9e0f-0000000000d1' }), 'developer'],
    [
      'a self-registered',
      row({ dynamicRegisteredAt: Date.UTC(2026, 10, 1), provisionedByOperator: false }),
      'registered itself',
    ],
    ['the system', row({ clientId: 'system' }), 'system client'],
    ['a service account’s', row({ id: '018f2d6e-8a8b-7c3d-9e0f-00000000000a' }), 'service account'],
    ['an unprovisioned', row({ provisionedByOperator: false }), 'no operator provisioned'],
  ])('refuses %s client', (_, stored, why) => {
    expect(unmanagedReason(stored, context)).toContain(why);
  });
});

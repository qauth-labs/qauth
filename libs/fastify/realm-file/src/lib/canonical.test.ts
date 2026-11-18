import { describe, expect, it } from 'vitest';

import { fixtures } from '../testing/fixtures';
import { canonicalRealmFile, serializeRealmFile } from './canonical';
import { parseRealmFile, type RealmFile } from './realm-file';

/** The growth rule of #515: arrays that are sets are written in a canonical order. */

const jwk = (kid: string) => ({
  kty: 'OKP',
  crv: 'Ed25519',
  x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
  kid,
});

const file = (): RealmFile =>
  parseRealmFile({
    realm: 'master',
    system_client: {
      redirect_uris: ['https://portal.example.com/b', 'https://portal.example.com/a'],
      jwks_uri: 'https://portal.example.com/.well-known/jwks.json',
    },
    resources: [
      {
        resource: 'https://z.example.com/mcp',
        scopes: [
          { scope: 'files:write', text: { tr: 'Dosyalarını değiştir', en: 'Change your files' } },
          { scope: 'files:read', text: { en: 'Read your files' } },
        ],
        clients: ['web', 'api'],
      },
      {
        resource: 'https://a.example.com/mcp',
        scopes: [{ scope: 'x:read', text: { en: 'Read' } }],
        clients: 'any_client',
      },
    ],
    clients: [
      {
        client_id: 'web',
        name: 'Web',
        grant_types: ['refresh_token', 'authorization_code'],
        scopes: ['profile', 'openid', 'profile'],
        redirect_uris: ['https://web.example.com/b', 'https://web.example.com/a'],
        token_endpoint_auth_method: 'private_key_jwt',
        jwks: { keys: [jwk('z'), jwk('a')] },
        first_party_profile: 'native_backend',
        first_party_policy: { flows: ['reset', 'login'] },
        first_party_reason: 'Our own app.',
      },
      {
        client_id: 'api',
        name: 'API',
        grant_types: ['client_credentials'],
        scopes: ['b', 'a'],
        token_endpoint_auth_method: 'client_secret_basic',
      },
    ],
    policies: {
      registration: { dynamicRegistrationAllowedScopes: ['profile', 'openid'] },
      admin: { twoAdminMandatoryOperations: ['realms.policies.update', 'clients.delete'] },
    },
    format: 'urn:qauth:realm-file:v1-rc.0',
  });

describe('canonicalRealmFile', () => {
  const canonical = canonicalRealmFile(file()) as unknown as Record<string, never>;

  it('puts format and realm first, then the sections in their order', () => {
    expect(Object.keys(canonical)).toEqual([
      'format',
      'realm',
      'policies',
      'clients',
      'resources',
      'system_client',
    ]);
  });

  it('sorts each list of entries by its natural key', () => {
    expect(file().clients?.map(({ client_id }) => client_id)).toEqual(['web', 'api']);
    expect(canonicalRealmFile(file()).clients?.map(({ client_id }) => client_id)).toEqual([
      'api',
      'web',
    ]);
    expect(canonicalRealmFile(file()).resources?.map(({ resource }) => resource)).toEqual([
      'https://a.example.com/mcp',
      'https://z.example.com/mcp',
    ]);
  });

  it("sorts a client's sets, each value once, nested ones included", () => {
    const web = canonicalRealmFile(file()).clients?.find(({ client_id }) => client_id === 'web');
    expect(web?.grant_types).toEqual(['authorization_code', 'refresh_token']);
    expect(web?.scopes).toEqual(['openid', 'profile']);
    expect(web?.redirect_uris).toEqual(['https://web.example.com/a', 'https://web.example.com/b']);
    expect(web?.first_party_policy?.flows).toEqual(['login', 'reset']);
  });

  it("keeps a key set's keys in the order written, each with its members sorted", () => {
    const web = canonicalRealmFile(file()).clients?.find(({ client_id }) => client_id === 'web');
    expect(web?.jwks?.keys.map((key) => key['kid'])).toEqual(['z', 'a']);
    for (const key of web?.jwks?.keys ?? []) {
      expect(Object.keys(key)).toEqual(['crv', 'kid', 'kty', 'x']);
    }
  });

  it('writes two key sets that differ only in member order as the same text', () => {
    const withKey = (key: Record<string, unknown>) =>
      parseRealmFile({
        realm: 'master',
        clients: [
          {
            client_id: 'api',
            name: 'API',
            grant_types: ['client_credentials'],
            token_endpoint_auth_method: 'private_key_jwt',
            jwks: { keys: [key] },
          },
        ],
      });
    const { kid, ...rest } = jwk('a');
    const reordered = { kid, x5c: ['leaf', 'intermediate'], ...rest };
    const original = { ...jwk('a'), x5c: ['leaf', 'intermediate'] };
    const text = serializeRealmFile(canonicalRealmFile(withKey(original)));
    expect(serializeRealmFile(canonicalRealmFile(withKey(reordered)))).toBe(text);
    // A certificate chain keeps its order.
    expect(text.indexOf('"leaf"')).toBeLessThan(text.indexOf('"intermediate"'));
  });

  it("sorts a resource's scopes by scope and its clients", () => {
    const [, z] = canonicalRealmFile(file()).resources ?? [];
    expect(z?.scopes.map(({ scope }) => scope)).toEqual(['files:read', 'files:write']);
    expect(z?.clients).toEqual(['api', 'web']);
  });

  it('sorts the policy fields the registry declares sets, and only those', () => {
    const { policies } = canonicalRealmFile(file());
    expect(policies?.registration.dynamicRegistrationAllowedScopes).toEqual(['openid', 'profile']);
    expect(policies?.admin.twoAdminMandatoryOperations).toEqual([
      'clients.delete',
      'realms.policies.update',
    ]);
    expect(canonicalRealmFile(file()).system_client?.redirect_uris).toEqual([
      'https://portal.example.com/a',
      'https://portal.example.com/b',
    ]);
  });

  it("sorts a scope's texts by locale, the format's one map whose keys the file chooses", () => {
    const [, resource] = canonicalRealmFile(file()).resources ?? [];
    const write = resource?.scopes.find(({ scope }) => scope === 'files:write');
    expect(Object.keys(write?.text ?? {})).toEqual(['en', 'tr']);
  });

  it('changes nothing a parse would read differently, and is stable', () => {
    const once = canonicalRealmFile(file());
    expect(canonicalRealmFile(once)).toEqual(once);
    expect(parseRealmFile(JSON.parse(serializeRealmFile(once)))).toEqual(once);
  });

  it('leaves the input as it was', () => {
    const input = file();
    const before = structuredClone(input);
    canonicalRealmFile(input);
    expect(input).toEqual(before);
  });

  it.each(fixtures('valid'))('keeps valid/$name valid', ({ value }) => {
    const canonical = canonicalRealmFile(parseRealmFile(value));
    expect(parseRealmFile(JSON.parse(serializeRealmFile(canonical)))).toEqual(canonical);
  });
});

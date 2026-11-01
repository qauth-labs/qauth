import { describe, expect, it } from 'vitest';

import { manifestSchema } from '../../scripts/seed-manifest';
import {
  DEFAULT_SYSTEM_CLIENT_REASON,
  describeSystemClientResult,
  systemClientConfigFromEnv,
  systemClientSpecSchema,
} from './provision';

const JWKS = {
  keys: [{ kty: 'OKP', crv: 'Ed25519', x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo' }],
};
const CALLBACK = 'https://portal.example.com/auth/callback';

describe('systemClientSpecSchema (#631)', () => {
  it('defaults the client id and the written reason', () => {
    expect(systemClientSpecSchema.parse({ redirect_uris: [CALLBACK], jwks: JWKS })).toEqual({
      client_id: 'system',
      redirect_uris: [CALLBACK],
      jwks: JWKS,
      first_party_reason: DEFAULT_SYSTEM_CLIENT_REASON,
    });
  });

  it("needs exactly one of the portal's key forms", () => {
    expect(systemClientSpecSchema.safeParse({ redirect_uris: [CALLBACK] }).success).toBe(false);
    expect(
      systemClientSpecSchema.safeParse({
        redirect_uris: [CALLBACK],
        jwks: JWKS,
        jwks_uri: 'https://portal.example.com/jwks.json',
      }).success
    ).toBe(false);
    expect(
      systemClientSpecSchema.safeParse({
        redirect_uris: [CALLBACK],
        jwks_uri: 'https://portal.example.com/jwks.json',
      }).success
    ).toBe(true);
  });

  it('refuses private keys and a jwks_uri that is not https', () => {
    for (const spec of [
      { redirect_uris: [CALLBACK], jwks: { keys: [{ ...JWKS.keys[0], d: 'private' }] } },
      { redirect_uris: [CALLBACK], jwks: { keys: [{ kty: 'oct', k: 'c2VjcmV0' }] } },
      // An RSA key's primes without `d` are private material too.
      {
        redirect_uris: [CALLBACK],
        jwks: { keys: [{ kty: 'RSA', n: 'bg', e: 'AQAB', p: 'cA', q: 'cQ' }] },
      },
      // A key the token endpoint could never verify an assertion with.
      { redirect_uris: [CALLBACK], jwks: { keys: [{ kty: 'OKP' }] } },
      { redirect_uris: [CALLBACK], jwks: { keys: [] } },
      { redirect_uris: [CALLBACK], jwks_uri: 'http://portal.example.com/jwks.json' },
    ]) {
      expect(systemClientSpecSchema.safeParse(spec).success, JSON.stringify(spec)).toBe(false);
    }
  });

  it('takes an https callback, or http on a loopback address for a local portal, and nothing else', () => {
    for (const uri of [
      CALLBACK,
      'http://localhost:3001/auth/callback',
      'http://127.0.0.1:3001/auth/callback',
    ]) {
      expect(
        systemClientSpecSchema.safeParse({ redirect_uris: [uri], jwks: JWKS }).success,
        uri
      ).toBe(true);
    }
    for (const uri of [
      'http://portal.example.com/auth/callback',
      'com.example.portal:/callback',
      'https://portal.example.com/auth/callback#frag',
      'https://bad_host.example.com/cb',
      'not a uri',
    ]) {
      expect(
        systemClientSpecSchema.safeParse({ redirect_uris: [uri], jwks: JWKS }).success,
        uri
      ).toBe(false);
    }
    expect(systemClientSpecSchema.safeParse({ redirect_uris: [], jwks: JWKS }).success).toBe(false);
  });

  it('refuses an unknown member', () => {
    expect(
      systemClientSpecSchema.safeParse({
        redirect_uris: [CALLBACK],
        jwks: JWKS,
        token_endpoint_auth_method: 'client_secret_basic',
      }).success
    ).toBe(false);
  });
});

describe("the manifest's system_client section (#631)", () => {
  it('may be the only entry of a manifest', () => {
    const parsed = manifestSchema.parse({
      realm: 'master',
      system_client: { redirect_uris: [CALLBACK], jwks: JWKS, first_party_reason: 'Our portal.' },
    });
    expect(parsed.system_client).toMatchObject({
      client_id: 'system',
      first_party_reason: 'Our portal.',
    });
  });

  it('refuses the system client listed under clients or cimd_clients too', () => {
    expect(
      manifestSchema.safeParse({
        realm: 'master',
        clients: [{ client_id: 'system', name: 'System', grant_types: ['refresh_token'] }],
        system_client: { redirect_uris: [CALLBACK], jwks: JWKS },
      }).success
    ).toBe(false);
    expect(
      manifestSchema.safeParse({
        realm: 'master',
        cimd_clients: [{ client_id: 'https://portal.example.com/client.json', scopes: [] }],
        system_client: {
          client_id: 'https://portal.example.com/client.json',
          redirect_uris: [CALLBACK],
          jwks: JWKS,
        },
      }).success
    ).toBe(false);
  });
});

describe('systemClientConfigFromEnv (#631)', () => {
  it('leaves the system client alone when nothing is set', () => {
    expect(systemClientConfigFromEnv({})).toEqual({ configured: false });
    expect(
      systemClientConfigFromEnv({ SYSTEM_CLIENT_ID: 'portal', DEFAULT_REALM_NAME: 'acme' })
    ).toEqual({ configured: false });
    expect(systemClientConfigFromEnv({ SYSTEM_CLIENT_REDIRECT_URI: '  ' })).toEqual({
      configured: false,
    });
  });

  it('reads the callback, the keys, the client id and the realm', () => {
    expect(
      systemClientConfigFromEnv({
        SYSTEM_CLIENT_REDIRECT_URI: CALLBACK,
        SYSTEM_CLIENT_JWKS: JSON.stringify(JWKS),
        SYSTEM_CLIENT_ID: 'portal',
        DEFAULT_REALM_NAME: 'acme',
      })
    ).toEqual({
      configured: true,
      realm: 'acme',
      spec: {
        client_id: 'portal',
        redirect_uris: [CALLBACK],
        jwks: JWKS,
        first_party_reason: DEFAULT_SYSTEM_CLIENT_REASON,
      },
    });
    expect(
      systemClientConfigFromEnv({
        SYSTEM_CLIENT_REDIRECT_URI: CALLBACK,
        SYSTEM_CLIENT_JWKS_URI: 'https://portal.example.com/jwks.json',
      })
    ).toEqual({
      configured: true,
      realm: 'master',
      spec: {
        client_id: 'system',
        redirect_uris: [CALLBACK],
        jwks_uri: 'https://portal.example.com/jwks.json',
        first_party_reason: DEFAULT_SYSTEM_CLIENT_REASON,
      },
    });
  });

  it('refuses a half-written configuration, naming the variable', () => {
    const problems = (env: Record<string, string>) => {
      const config = systemClientConfigFromEnv(env);
      expect(config.configured, JSON.stringify(env)).toBe('invalid');
      return config.configured === 'invalid' ? config.problems.join('\n') : '';
    };
    expect(problems({ SYSTEM_CLIENT_JWKS: JSON.stringify(JWKS) })).toContain(
      'SYSTEM_CLIENT_REDIRECT_URI'
    );
    expect(problems({ SYSTEM_CLIENT_REDIRECT_URI: CALLBACK })).toContain('SYSTEM_CLIENT_JWKS');
    expect(
      problems({ SYSTEM_CLIENT_REDIRECT_URI: CALLBACK, SYSTEM_CLIENT_JWKS: '{keys' })
    ).toContain('SYSTEM_CLIENT_JWKS is not JSON');
    expect(
      problems({
        SYSTEM_CLIENT_REDIRECT_URI: 'http://portal.example.com/cb',
        SYSTEM_CLIENT_JWKS: JSON.stringify(JWKS),
      })
    ).toContain('SYSTEM_CLIENT_REDIRECT_URI');
    expect(
      problems({
        SYSTEM_CLIENT_REDIRECT_URI: CALLBACK,
        SYSTEM_CLIENT_JWKS: JSON.stringify({ keys: [{ ...JWKS.keys[0], d: 'x' }] }),
      })
    ).toContain('PUBLIC keys only');
  });
});

describe('describeSystemClientResult (#631)', () => {
  it('tells the operator what to do when the realm does not exist yet', () => {
    expect(describeSystemClientResult({ status: 'realm_not_found', realm: 'master' })).toContain(
      'run this again after that boot'
    );
  });

  it('names the row it refused and why', () => {
    expect(
      describeSystemClientResult({
        status: 'refused',
        realm: 'master',
        clientId: 'system',
        reason: 'developer_owned',
      })
    ).toContain(`"system" in realm "master" is a developer's client`);
  });
});

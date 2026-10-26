import { describe, expect, it } from 'vitest';

import { isCimdClientIdShape, manifestSchema } from './seed-manifest';

/**
 * Validation of the seed manifest, and of its `cimd_clients` section (#770).
 * What an entry writes is covered against real Postgres in
 * `cimd-client-grants.integration.test.ts`.
 */
describe('manifestSchema', () => {
  const machineClient = {
    client_id: 'memory-mcp-demo',
    name: 'memory-mcp demo',
    grant_types: ['client_credentials'],
    scopes: ['mcp:read'],
    audience: ['http://localhost:8088'],
    token_endpoint_auth_method: 'client_secret_basic',
  };
  const cimdClient = {
    client_id: 'https://client.example.com/oauth/metadata.json',
    scopes: ['mcp:read', 'offline_access'],
    audience: ['https://mcp.example.com/mcp'],
  };

  it('accepts a manifest written before cimd_clients existed, unchanged', () => {
    const manifest = { realm: 'master', clients: [machineClient] };
    expect(manifestSchema.parse(manifest)).toEqual(manifest);
  });

  it('accepts ID-JAG targets on a provisioned client, apart from its audience (#434)', () => {
    const idJagClient = {
      ...machineClient,
      grant_types: ['urn:ietf:params:oauth:grant-type:token-exchange'],
      id_jag_targets: ['https://as.partner.example', 'https://mcp.partner.example/mcp'],
    };
    const parsed = manifestSchema.parse({ realm: 'master', clients: [idJagClient] });
    expect(parsed.clients?.[0]?.id_jag_targets).toEqual(idJagClient.id_jag_targets);
    expect(parsed.clients?.[0]?.audience).toEqual(machineClient.audience);
  });

  it.each([
    ['an empty string', ['']],
    ['a string instead of a list', 'https://as.partner.example'],
  ])('refuses ID-JAG targets holding %s', (_label, idJagTargets) => {
    const result = manifestSchema.safeParse({
      realm: 'master',
      clients: [{ ...machineClient, id_jag_targets: idJagTargets }],
    });
    expect(result.success).toBe(false);
  });

  it('accepts a manifest with only CIMD entries, or with both kinds', () => {
    expect(manifestSchema.safeParse({ realm: 'master', cimd_clients: [cimdClient] }).success).toBe(
      true
    );
    expect(
      manifestSchema.safeParse({
        realm: 'master',
        clients: [machineClient],
        cimd_clients: [cimdClient, { client_id: 'https://other.example.com/c', scopes: [] }],
      }).success
    ).toBe(true);
  });

  it.each([
    [{ realm: 'master' }],
    [{ realm: 'master', clients: [] }],
    [{ realm: 'master', clients: [], cimd_clients: [] }],
  ])('refuses a manifest with no client: %j', (manifest) => {
    expect(manifestSchema.safeParse(manifest).success).toBe(false);
  });

  it('refuses a client_id listed under both clients and cimd_clients', () => {
    const result = manifestSchema.safeParse({
      realm: 'master',
      clients: [{ ...machineClient, client_id: cimdClient.client_id }],
      cimd_clients: [cimdClient],
    });
    expect(result.success).toBe(false);
  });

  it('refuses the same CIMD client_id twice', () => {
    const result = manifestSchema.safeParse({
      realm: 'master',
      cimd_clients: [cimdClient, { ...cimdClient, scopes: [] }],
    });
    expect(result.success).toBe(false);
  });

  it.each([
    ['a field the document owns', { name: 'Example' }],
    ['a redirect URI', { redirect_uris: ['https://client.example.com/cb'] }],
    ['a secret', { client_secret: 'x' }],
    ['ID-JAG targets (#434)', { id_jag_targets: ['https://as.partner.example'] }],
  ])('refuses a CIMD entry carrying %s', (_label, extra) => {
    const result = manifestSchema.safeParse({
      realm: 'master',
      cimd_clients: [{ ...cimdClient, ...extra }],
    });
    expect(result.success).toBe(false);
  });

  it.each(['urn:qauth:aud:developer:v1-rc.0', 'URN:QAUTH:AUD:account:v1-rc.0'])(
    'refuses a CIMD entry granting the reserved audience %s (#509)',
    (audience) => {
      const result = manifestSchema.safeParse({
        realm: 'master',
        cimd_clients: [{ ...cimdClient, audience: ['https://mcp.example.com/mcp', audience] }],
      });
      expect(result.success).toBe(false);
      expect(result.error?.issues[0]).toMatchObject({
        path: ['cimd_clients', 0, 'audience', 1],
        message: expect.stringContaining(
          `"${audience}" is in the "urn:qauth:aud:" audience namespace`
        ),
      });
    }
  );

  it('lets a provisioned client list a reserved audience (#509)', () => {
    const accountConsole = { ...machineClient, audience: ['urn:qauth:aud:account:v1-rc.0'] };
    expect(manifestSchema.parse({ realm: 'master', clients: [accountConsole] })).toEqual({
      realm: 'master',
      clients: [accountConsole],
    });
  });

  it('requires a CIMD entry to state its scopes', () => {
    const withoutScopes = { client_id: cimdClient.client_id, audience: cimdClient.audience };
    expect(
      manifestSchema.safeParse({ realm: 'master', cimd_clients: [withoutScopes] }).success
    ).toBe(false);
  });

  // #507: QAuth's own scopes are never granted to a self-described client.
  it.each(['qauth:admin:read', 'QAuth:admin:security', 'qauth:other'])(
    'refuses a CIMD entry granting %s, naming it',
    (scope) => {
      const result = manifestSchema.safeParse({
        realm: 'master',
        cimd_clients: [{ ...cimdClient, scopes: ['mcp:read', scope] }],
      });
      expect(result.success).toBe(false);
      expect(result.error?.issues[0]).toMatchObject({
        path: ['cimd_clients', 0, 'scopes', 1],
        message: expect.stringContaining(`"${scope}" is in the "qauth:" scope namespace`),
      });
    }
  );

  it("grants a CIMD entry other servers' admin: scopes, which are ordinary scopes", () => {
    const parsed = manifestSchema.parse({
      realm: 'master',
      cimd_clients: [{ ...cimdClient, scopes: ['admin:org', 'admin:read'] }],
    });
    expect(parsed.cimd_clients?.[0]?.scopes).toEqual(['admin:org', 'admin:read']);
  });

  // An operator-provisioned client is the operator's own decision; the admin
  // API's clients are provisioned this way (#510).
  it('leaves the scopes of an operator-provisioned client to the operator', () => {
    const parsed = manifestSchema.parse({
      realm: 'master',
      clients: [{ ...machineClient, scopes: ['qauth:admin:read'] }],
    });
    expect(parsed.clients?.[0]?.scopes).toEqual(['qauth:admin:read']);
  });

  it('refuses a CIMD client_id that is not a CIMD client_id', () => {
    const result = manifestSchema.safeParse({
      realm: 'master',
      cimd_clients: [{ ...cimdClient, client_id: 'http://client.example.com/oauth/metadata.json' }],
    });
    expect(result.success).toBe(false);
  });
});

describe('isCimdClientIdShape', () => {
  it.each([
    'https://client.example.com/oauth/metadata.json',
    'https://client.example.com/c',
    'https://client.example.com:8443/c?v=1',
  ])('accepts %s', (value) => {
    expect(isCimdClientIdShape(value)).toBe(true);
  });

  it.each([
    ['http, not https', 'http://client.example.com/c'],
    ['no path', 'https://client.example.com'],
    ['the root path', 'https://client.example.com/'],
    ['a fragment', 'https://client.example.com/c#x'],
    ['a non-ASCII host', 'https://client.exämple.com/c'],
    ['a space', 'https://client.example.com/a b'],
    ['not a URL', 'memory-mcp-demo'],
  ])('refuses %s', (_label, value) => {
    expect(isCimdClientIdShape(value)).toBe(false);
  });

  describe('webauthn_allowed_origins (#467)', () => {
    const nativeClient = (origins: unknown) => ({
      realm: 'master',
      clients: [
        {
          client_id: 'native-app',
          name: 'Native app',
          grant_types: ['authorization_code'],
          webauthn_allowed_origins: origins,
        },
      ],
    });
    const APK_ORIGIN = 'android:apk-key-hash:sYUC8p5I9SxqFernBPHmDxz_YVZXmVJdW8s-m3RTTqE';

    it('accepts an Android app origin and an https origin, in the browser form', () => {
      const parsed = manifestSchema.parse(
        nativeClient([APK_ORIGIN, 'https://App.Example.com:443'])
      );
      expect(parsed.clients?.[0].webauthn_allowed_origins).toEqual([
        APK_ORIGIN,
        'https://app.example.com',
      ]);
    });

    it.each([
      ['a path', 'https://app.example.com/login'],
      ['plain http off localhost', 'http://app.example.com'],
      ['a hex fingerprint', 'android:apk-key-hash:FA:C6:17'],
      ['an IP address', 'https://192.0.2.1'],
    ])('refuses %s, naming the entry', (_name, origin) => {
      const result = manifestSchema.safeParse(nativeClient([origin]));
      expect(result.success).toBe(false);
      expect(result.error?.issues[0].message).toContain(`"${origin}"`);
    });

    it('refuses more than 20 origins', () => {
      expect(
        manifestSchema.safeParse(nativeClient(Array.from({ length: 21 }, () => APK_ORIGIN))).success
      ).toBe(false);
    });
  });

  describe('dpop_bound_access_tokens (#480)', () => {
    const dpopClient = (value: unknown) => ({
      realm: 'master',
      clients: [
        {
          client_id: 'agent-root',
          name: 'Agent root',
          grant_types: ['authorization_code', 'refresh_token'],
          ...(value === undefined ? {} : { dpop_bound_access_tokens: value }),
        },
      ],
    });

    it('accepts true and false, and leaves it out when omitted', () => {
      expect(manifestSchema.parse(dpopClient(true)).clients?.[0].dpop_bound_access_tokens).toBe(
        true
      );
      expect(manifestSchema.parse(dpopClient(false)).clients?.[0].dpop_bound_access_tokens).toBe(
        false
      );
      expect(
        manifestSchema.parse(dpopClient(undefined)).clients?.[0].dpop_bound_access_tokens
      ).toBeUndefined();
    });

    it.each([
      ['the string "true"', 'true'],
      ['a number', 1],
      ['null', null],
    ])('refuses %s', (_name, value) => {
      expect(manifestSchema.safeParse(dpopClient(value)).success).toBe(false);
    });
  });
});

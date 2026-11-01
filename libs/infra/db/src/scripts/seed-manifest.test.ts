import { describe, expect, it } from 'vitest';

import {
  firstPartyColumnsOf,
  isCimdClientIdShape,
  manifestSchema,
  parseManifest,
} from './seed-manifest';

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

  describe('verified_domain (#593)', () => {
    const verifiedClient = (value: unknown) => ({
      realm: 'master',
      clients: [
        {
          client_id: 'notes',
          name: 'Notes',
          grant_types: ['authorization_code'],
          ...(value === undefined ? {} : { verified_domain: value }),
        },
      ],
    });

    it('stores the domain lower case and in its xn-- form, and leaves it out when omitted', () => {
      expect(
        manifestSchema.parse(verifiedClient('Notes.Example.com')).clients?.[0].verified_domain
      ).toBe('notes.example.com');
      expect(
        manifestSchema.parse(verifiedClient('bücher.example')).clients?.[0].verified_domain
      ).toBe('xn--bcher-kva.example');
      expect(
        manifestSchema.parse(verifiedClient(undefined)).clients?.[0].verified_domain
      ).toBeUndefined();
    });

    it.each([
      ['a URL', 'https://notes.example.com'],
      ['a port', 'notes.example.com:443'],
      ['an IP address', '192.0.2.1'],
      ['a single label', 'intranet'],
    ])('refuses %s, naming the entry', (_name, value) => {
      const result = manifestSchema.safeParse(verifiedClient(value));
      expect(result.success).toBe(false);
      expect(result.error?.issues[0].message).toContain(`"${value}"`);
    });

    it('refuses a redirect URI the consent screen cannot show, naming it', () => {
      const result = manifestSchema.safeParse({
        realm: 'master',
        clients: [
          {
            client_id: 'notes',
            name: 'Notes',
            grant_types: ['authorization_code'],
            redirect_uris: ['https://notes.example.com/cb', 'https://notes_app.example.com/cb'],
          },
        ],
      });
      expect(result.success).toBe(false);
      expect(result.error?.issues[0].message).toContain('"https://notes_app.example.com/cb"');
    });

    it('refuses it on a CIMD entry, whose verified domain is the host of its client id', () => {
      expect(
        manifestSchema.safeParse({
          realm: 'master',
          cimd_clients: [
            {
              client_id: 'https://client.example.com/c',
              scopes: [],
              verified_domain: 'other.example.com',
            },
          ],
        }).success
      ).toBe(false);
    });
  });

  describe('client_credentials_scopes (#891)', () => {
    /** A relying party that signs users in and receives SSF events as itself. */
    const receiverClient = (overrides: Record<string, unknown>) => ({
      realm: 'master',
      clients: [
        {
          client_id: 'notes-app',
          name: 'Notes',
          grant_types: ['authorization_code', 'refresh_token', 'client_credentials'],
          redirect_uris: ['https://notes.example.com/callback'],
          scopes: ['openid', 'notes:read', 'ssf:stream'],
          audience: ['https://auth.example.com'],
          ...overrides,
        },
      ],
    });

    it('accepts a list of scopes the client holds, and leaves it out when omitted', () => {
      expect(
        manifestSchema.parse(receiverClient({ client_credentials_scopes: ['ssf:stream'] }))
          .clients?.[0].client_credentials_scopes
      ).toEqual(['ssf:stream']);
      expect(
        manifestSchema.parse(receiverClient({})).clients?.[0].client_credentials_scopes
      ).toBeUndefined();
    });

    it('refuses a scope the client does not hold in scopes, naming it', () => {
      const result = manifestSchema.safeParse(
        receiverClient({ client_credentials_scopes: ['ssf:stream', 'notes:write'] })
      );
      expect(result.success).toBe(false);
      expect(result.error?.issues).toHaveLength(1);
      expect(result.error?.issues[0].path).toEqual(['clients', 0, 'client_credentials_scopes']);
      expect(result.error?.issues[0].message).toContain('"notes:write"');
    });

    it('refuses any scope when the entry has no scopes', () => {
      const result = manifestSchema.safeParse(
        receiverClient({ scopes: undefined, client_credentials_scopes: ['ssf:stream'] })
      );
      expect(result.success).toBe(false);
      expect(result.error?.issues[0].message).toContain('"ssf:stream"');
    });

    it('refuses it on a client without the client_credentials grant', () => {
      const result = manifestSchema.safeParse(
        receiverClient({
          grant_types: ['authorization_code', 'refresh_token'],
          client_credentials_scopes: ['ssf:stream'],
        })
      );
      expect(result.success).toBe(false);
      expect(result.error?.issues[0].message).toContain('client_credentials grant');
    });

    it('refuses an empty list, and says how to give the client no token of its own', () => {
      const result = manifestSchema.safeParse(receiverClient({ client_credentials_scopes: [] }));
      expect(result.success).toBe(false);
      expect(result.error?.issues[0].message).toContain('leave client_credentials out');
    });

    it.each([
      ['a string instead of a list', 'ssf:stream'],
      ['an empty string', ['']],
      ['null', null],
    ])('refuses %s', (_name, value) => {
      expect(
        manifestSchema.safeParse(receiverClient({ client_credentials_scopes: value })).success
      ).toBe(false);
    });

    it('refuses it on a CIMD entry, which has no client_credentials grant', () => {
      expect(
        manifestSchema.safeParse({
          realm: 'master',
          cimd_clients: [
            {
              client_id: 'https://client.example.com/c',
              scopes: ['ssf:stream'],
              client_credentials_scopes: ['ssf:stream'],
            },
          ],
        }).success
      ).toBe(false);
    });
  });
});

describe('first-party profiles (#631, ADR-017 Decision 2)', () => {
  const KEYS = {
    keys: [{ kty: 'OKP', crv: 'Ed25519', x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo' }],
  };
  const nativeBackend = {
    client_id: 'notes-backend',
    name: 'Notes',
    grant_types: ['authorization_code', 'refresh_token'],
    redirect_uris: ['com.example.notes:/callback'],
    token_endpoint_auth_method: 'private_key_jwt',
    jwks: KEYS,
    first_party_profile: 'native_backend',
    first_party_reason: 'Notes is our own app, published under our brand.',
  };
  const webFrontEnd = {
    client_id: 'console',
    name: 'Console',
    grant_types: ['authorization_code', 'refresh_token'],
    redirect_uris: ['https://console.example.com/callback'],
    token_endpoint_auth_method: 'private_key_jwt',
    jwks_uri: 'https://console.example.com/jwks.json',
    first_party_profile: 'web_redirect',
    first_party_reason: 'Our own console.',
  };

  /** The messages of a refused entry. */
  function refusal(client: Record<string, unknown>): string[] {
    const result = manifestSchema.safeParse({ realm: 'master', clients: [client] });
    expect(result.success, JSON.stringify(client)).toBe(false);
    return result.error?.issues.map((issue) => issue.message) ?? [];
  }

  function without(client: Record<string, unknown>, ...keys: string[]): Record<string, unknown> {
    return Object.fromEntries(Object.entries(client).filter(([key]) => !keys.includes(key)));
  }

  it('accepts a native backend and fills its policy defaults', () => {
    const parsed = manifestSchema.parse({ realm: 'master', clients: [nativeBackend] });
    const client = parsed.clients?.[0];
    expect(client?.first_party_profile).toBe('native_backend');
    expect(client && firstPartyColumnsOf(client)).toEqual({
      profile: 'native_backend',
      policy: { flows: ['login'], email_code_after_password: false, pkce_required: true },
      reason: 'Notes is our own app, published under our brand.',
    });
  });

  it('keeps the policy the operator wrote, and trims the reason', () => {
    const parsed = manifestSchema.parse({
      realm: 'master',
      clients: [
        {
          ...nativeBackend,
          first_party_policy: { flows: ['login', 'register', 'reset'], pkce_required: false },
          first_party_reason: '  Our own app.  ',
        },
      ],
    });
    const client = parsed.clients?.[0];
    expect(client && firstPartyColumnsOf(client)).toEqual({
      profile: 'native_backend',
      policy: {
        flows: ['login', 'register', 'reset'],
        email_code_after_password: false,
        pkce_required: false,
      },
      reason: 'Our own app.',
    });
  });

  it('accepts a web front-end, with no policy', () => {
    const parsed = manifestSchema.parse({ realm: 'master', clients: [webFrontEnd] });
    const client = parsed.clients?.[0];
    expect(client && firstPartyColumnsOf(client)).toEqual({
      profile: 'web_redirect',
      policy: null,
      reason: 'Our own console.',
    });
  });

  it('writes no first-party column for an entry without a profile', () => {
    const parsed = manifestSchema.parse({
      realm: 'master',
      clients: [without(webFrontEnd, 'first_party_profile', 'first_party_reason')],
    });
    const client = parsed.clients?.[0];
    expect(client && firstPartyColumnsOf(client)).toEqual({
      profile: null,
      policy: null,
      reason: null,
    });
  });

  it('refuses a profile without a written reason, or with a blank or overlong one', () => {
    for (const client of [
      without(nativeBackend, 'first_party_reason'),
      without(webFrontEnd, 'first_party_reason'),
    ]) {
      expect(refusal(client).join('\n')).toContain(
        'first_party_profile requires first_party_reason'
      );
    }
    expect(refusal({ ...webFrontEnd, first_party_reason: '   ' })).not.toEqual([]);
    expect(refusal({ ...webFrontEnd, first_party_reason: 'x'.repeat(1001) })).not.toEqual([]);
    expect(
      manifestSchema.safeParse({
        realm: 'master',
        clients: [{ ...webFrontEnd, first_party_reason: 'x'.repeat(1000) }],
      }).success
    ).toBe(true);
  });

  it('refuses a reason or a policy without the profile it belongs to', () => {
    expect(refusal(without(webFrontEnd, 'first_party_profile')).join('\n')).toContain(
      'first_party_reason applies only together with first_party_profile'
    );
    expect(refusal({ ...webFrontEnd, first_party_policy: {} }).join('\n')).toContain(
      'first_party_policy applies only to first_party_profile=native_backend'
    );
  });

  it('refuses a native profile without the backend keys', () => {
    const messages = refusal(without(nativeBackend, 'jwks')).join('\n');
    expect(messages).toContain('first_party_profile=native_backend requires the backend');
  });

  it('refuses a native profile without a browser-leg redirect URI', () => {
    for (const redirectUris of [
      undefined,
      [],
      ['http://notes.example.com/callback'],
      ['http://localhost:8080/callback'],
      ['notes:/callback'],
    ]) {
      const client =
        redirectUris === undefined
          ? without(nativeBackend, 'redirect_uris')
          : { ...nativeBackend, redirect_uris: redirectUris };
      expect(refusal(client).join('\n'), JSON.stringify(redirectUris)).toContain(
        'requires at least one redirect URI for the browser leg'
      );
    }
    for (const redirectUri of [
      'https://notes.example.com/app/callback',
      'com.example.notes:/callback',
      'http://127.0.0.1/callback',
      'http://[::1]:8080/callback',
    ]) {
      expect(
        manifestSchema.safeParse({
          realm: 'master',
          clients: [
            { ...nativeBackend, redirect_uris: ['http://localhost:8080/callback', redirectUri] },
          ],
        }).success,
        redirectUri
      ).toBe(true);
    }
  });

  it('refuses a native profile without the authorization_code grant', () => {
    expect(refusal({ ...nativeBackend, grant_types: ['refresh_token'] }).join('\n')).toContain(
      'first_party_profile=native_backend requires the authorization_code grant'
    );
  });

  it('refuses a profile on a client that does not use private_key_jwt, or on an agent', () => {
    for (const method of ['client_secret_basic', 'client_secret_post', 'none']) {
      expect(
        refusal({ ...webFrontEnd, token_endpoint_auth_method: method }).join('\n'),
        method
      ).toContain('first_party_profile requires token_endpoint_auth_method=private_key_jwt');
    }
    expect(refusal(without(webFrontEnd, 'token_endpoint_auth_method')).join('\n')).toContain(
      'first_party_profile requires token_endpoint_auth_method=private_key_jwt'
    );
    expect(refusal({ ...webFrontEnd, is_agent: true }).join('\n')).toContain(
      'first_party_profile cannot be set on an agent'
    );
  });

  it('refuses an unknown profile and a policy that does not parse', () => {
    expect(refusal({ ...nativeBackend, first_party_profile: 'native_attested' })).not.toEqual([]);
    for (const policy of [
      { flows: [] },
      { flows: ['login', 'login'] },
      { flows: ['signup'] },
      { dpop: true },
      'login',
    ]) {
      expect(
        refusal({ ...nativeBackend, first_party_policy: policy }),
        JSON.stringify(policy)
      ).not.toEqual([]);
    }
  });
});

describe('parseManifest: the system client id', () => {
  const SECTION = {
    redirect_uris: ['https://portal.example.com/callback'],
    jwks: {
      keys: [{ kty: 'OKP', crv: 'Ed25519', x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo' }],
    },
  };

  it("takes SYSTEM_CLIENT_ID for a section that names no client_id, as the auth server's id", () => {
    const parsed = parseManifest(
      { realm: 'master', system_client: SECTION },
      { SYSTEM_CLIENT_ID: ' portal ' }
    );
    expect(parsed.system_client?.client_id).toBe('portal');
  });

  it('keeps a client_id the section names, and falls back to system without SYSTEM_CLIENT_ID', () => {
    expect(
      parseManifest(
        { realm: 'master', system_client: { ...SECTION, client_id: 'named' } },
        { SYSTEM_CLIENT_ID: 'portal' }
      ).system_client?.client_id
    ).toBe('named');
    for (const env of [{}, { SYSTEM_CLIENT_ID: '  ' }]) {
      expect(
        parseManifest({ realm: 'master', system_client: SECTION }, env).system_client?.client_id
      ).toBe('system');
    }
  });

  it('refuses a clients entry that names the id SYSTEM_CLIENT_ID gave the section', () => {
    expect(() =>
      parseManifest(
        {
          realm: 'master',
          system_client: SECTION,
          clients: [
            {
              client_id: 'portal',
              name: 'Portal',
              grant_types: ['client_credentials'],
              token_endpoint_auth_method: 'client_secret_basic',
            },
          ],
        },
        { SYSTEM_CLIENT_ID: 'portal' }
      )
    ).toThrow(/listed twice/);
  });
});

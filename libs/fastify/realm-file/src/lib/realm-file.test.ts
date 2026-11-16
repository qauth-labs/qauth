import { manifestSchema, parseManifest } from '@qauth-labs/infra-db/seed-manifest';
import { REALM_POLICY_REGISTRY } from '@qauth-labs/server-realm-policy';
import { PRIVATE_JWK_MEMBERS } from '@qauth-labs/shared-validation';
import { describe, expect, it } from 'vitest';
import type { z } from 'zod';

import {
  fixtures,
  invalidExpectations,
  readRepoJson,
  SHIPPED_SEED_MANIFESTS,
} from '../testing/fixtures';
import { hasUrlCredentials, URL_CREDENTIALS_MESSAGE, urlCredentialPaths } from './credentials';
import { REALM_FILE_FORMAT } from './format';
import {
  parseRealmFile,
  REALM_FILE_HEADER_KEYS,
  RealmFileError,
  realmFileSchema,
  realmNameWarning,
  safeParseRealmFile,
} from './realm-file';
import { CLIENT_ENVIRONMENTS, REALM_FILE_SECTIONS, realmFileClientSchema } from './sections';

/** The issues `raw` gives; the test fails when it parses. */
function issuesOf(raw: unknown) {
  const result = safeParseRealmFile(raw);
  if (result.success) throw new Error('expected the file to be refused');
  return result.issues;
}

const client = {
  client_id: 'notes-web',
  name: 'Notes',
  grant_types: ['authorization_code'],
  redirect_uris: ['https://notes.example.com/callback'],
};

const publicJwk = {
  kty: 'OKP',
  crv: 'Ed25519',
  x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
};

describe('the fixtures (#515)', () => {
  // Acceptance criterion: every fixture in the valid set parses and every
  // fixture in the invalid set fails with a path to the error.
  it.each(fixtures('valid'))('parses valid/$name', ({ value }) => {
    expect(() => parseRealmFile(value)).not.toThrow();
  });

  const expected = invalidExpectations();

  it('says where every invalid fixture fails, and has no expectation without a fixture', () => {
    expect(Object.keys(expected).sort()).toEqual(fixtures('invalid').map(({ name }) => name));
  });

  it.each(fixtures('invalid'))('refuses invalid/$name at the expected path', ({ name, value }) => {
    const expectation = expected[name];
    const issues = issuesOf(value);
    expect(
      issues.some(
        (issue) =>
          JSON.stringify(issue.path) === JSON.stringify(expectation.path) &&
          issue.message.includes(expectation.message)
      ),
      `${name}: ${JSON.stringify(issues, null, 2)}`
    ).toBe(true);
  });
});

describe('a seed manifest (CFG-12)', () => {
  // Acceptance criterion: today's seed manifest example files parse as realm
  // files. Each is a valid manifest too, so the fixture is a real manifest.
  const manifests = [
    ...SHIPPED_SEED_MANIFESTS.map((path) => ({ name: path, value: readRepoJson(path) })),
    ...fixtures('seed-manifests'),
  ];

  it.each(manifests)('$name is a valid manifest and a valid realm file', ({ value }) => {
    expect(() => parseManifest(value)).not.toThrow();
    expect(() => parseRealmFile(value)).not.toThrow();
  });

  it('keeps every member the manifest gives a section', () => {
    for (const { value } of manifests) {
      const manifest = parseManifest(value) as Record<string, unknown>;
      const file = parseRealmFile(value) as unknown as Record<string, unknown>;
      for (const [key, section] of Object.entries(manifest)) expect(file[key]).toEqual(section);
    }
  });

  it('carries every section of the manifest', () => {
    const fileKeys = Object.keys(realmFileSchema().shape);
    for (const key of Object.keys(manifestSchema.shape)) expect(fileKeys).toContain(key);
  });
});

describe('the top-level keys', () => {
  it('are format, realm and the sections, in that order', () => {
    expect(Object.keys(realmFileSchema().shape)).toEqual([
      ...REALM_FILE_HEADER_KEYS,
      ...REALM_FILE_SECTIONS.map(({ name }) => name),
    ]);
  });

  it('give each section the schema it declares', () => {
    const shape = realmFileSchema().shape as Record<string, z.ZodType>;
    for (const section of REALM_FILE_SECTIONS) {
      const optional = shape[section.name] as unknown as { unwrap(): z.ZodType };
      const value = optional.unwrap();
      const declared =
        section.kind === 'list' ? (value as unknown as { element: z.ZodType }).element : value;
      expect(declared, section.name).toBe(section.schema());
    }
  });

  it('take the format by default and refuse another one, naming both', () => {
    expect(parseRealmFile({ realm: 'master' }).format).toBe(REALM_FILE_FORMAT);
    expect(parseRealmFile({ format: REALM_FILE_FORMAT, realm: 'master' }).format).toBe(
      REALM_FILE_FORMAT
    );
    const [issue] = issuesOf({ format: 'urn:qauth:realm-file:v2', realm: 'master' });
    expect(issue.path).toEqual(['format']);
    expect(issue.message).toContain(REALM_FILE_FORMAT);
    expect(issue.message).toContain('urn:qauth:realm-file:v2');
  });

  // Acceptance criterion: an unknown top-level key is rejected and names the key.
  it('refuse an unknown key, one issue per key, each naming it', () => {
    const issues = issuesOf({ realm: 'master', clinets: [], realm_id: 'x' });
    expect(issues.map(({ path }) => path)).toEqual([['clinets'], ['realm_id']]);
    expect(issues[0].message).toContain('"clinets"');
    expect(issues[0].pointer).toBe('/clinets');
    expect(issues[1].message).toContain('"realm_id"');
  });

  // Acceptance criterion: a section unknown to this server version is
  // rejected with the section name. The growth rules name the sections a
  // later release may add; none is skipped.
  it.each(['scopes', 'roles', 'groups', 'mappers', 'identityProviders', 'agentTypes', 'brand'])(
    'refuse a section of a later release, %s, naming it',
    (section) => {
      const issues = issuesOf({ realm: 'master', [section]: [] });
      expect(issues).toHaveLength(1);
      expect(issues[0].path).toEqual([section]);
      expect(issues[0].message).toContain(`"${section}" is not a section`);
      expect(issues[0].message).toContain('never skipped');
    }
  );

  it('need the realm, a name of one character at least', () => {
    expect(issuesOf({}).map(({ path }) => path)).toEqual([['realm']]);
    expect(issuesOf({ realm: '' }).map(({ path }) => path)).toEqual([['realm']]);
    expect(() => parseRealmFile({ realm: 'master' })).not.toThrow();
  });

  it('refuse what is not an object', () => {
    for (const raw of [null, [], 'master', 1]) {
      expect(issuesOf(raw)[0].path).toEqual([]);
    }
  });
});

describe('a secret value', () => {
  // Acceptance criterion: a file with client_secret or a private JWK member
  // is rejected.
  it.each(['clients', 'cimd_clients'])('is refused as a client_secret of a %s entry', (name) => {
    const entry =
      name === 'clients'
        ? { ...client, client_secret: 'value' }
        : { client_id: 'https://client.example.com/metadata.json', scopes: [], client_secret: 'v' };
    const issues = issuesOf({ realm: 'master', [name]: [entry] });
    expect(issues).toEqual([
      expect.objectContaining({
        path: [name, 0, 'client_secret'],
        message: expect.stringContaining('is a secret'),
      }),
    ]);
  });

  it('is refused as a client_secret of the system client', () => {
    const issues = issuesOf({
      realm: 'master',
      system_client: {
        redirect_uris: ['https://portal.example.com/auth/callback'],
        jwks_uri: 'https://portal.example.com/.well-known/jwks.json',
        client_secret: 'value',
      },
    });
    expect(issues[0]).toMatchObject({
      path: ['system_client', 'client_secret'],
      message: expect.stringContaining('is a secret'),
    });
  });

  it.each([...PRIVATE_JWK_MEMBERS])('is refused as the private JWK member %s', (member) => {
    const issues = issuesOf({
      realm: 'master',
      clients: [
        {
          ...client,
          token_endpoint_auth_method: 'private_key_jwt',
          jwks: { keys: [{ ...publicJwk, [member]: 'AQAB' }] },
        },
      ],
    });
    expect(issues).toContainEqual(
      expect.objectContaining({
        path: ['clients', 0, 'jwks', 'keys', 0],
        message: expect.stringContaining(`"${member}"`),
      })
    );
  });

  it('is refused in a system client key too', () => {
    const issues = issuesOf({
      realm: 'master',
      system_client: {
        redirect_uris: ['https://portal.example.com/auth/callback'],
        jwks: { keys: [{ ...publicJwk, d: 'AQAB' }] },
      },
    });
    expect(issues[0].path).toEqual(['system_client', 'jwks', 'keys', 0]);
  });

  // "Any field annotated as secret": derived from the policy registry, so a
  // secret field another area registers is refused the same way.
  it('is refused for every secret field of the policies, and its <name>Set flag with it', () => {
    const secrets = REALM_POLICY_REGISTRY.fields().filter(({ field }) => field.secret);
    expect(secrets.length).toBeGreaterThan(0);
    for (const { path, segments } of secrets) {
      for (const [member, value] of [
        [segments[segments.length - 1], 'value'],
        [`${segments[segments.length - 1]}Set`, true],
      ] as const) {
        const policies: Record<string, unknown> = {};
        let node = policies;
        for (const segment of segments.slice(0, -1)) {
          node[segment] = {};
          node = node[segment] as Record<string, unknown>;
        }
        node[member] = value;
        const issues = issuesOf({ realm: 'master', policies });
        expect(issues, path).toHaveLength(1);
        expect(issues[0].path).toEqual(['policies', ...segments.slice(0, -1), member]);
        expect(issues[0].message).toContain(`policies.${path}`);
        expect(issues[0].message).toContain('secret');
      }
    }
  });

  it('never appears in a parsed file, nor in its error', () => {
    const result = safeParseRealmFile({
      realm: 'master',
      clients: [{ ...client, client_secret: 'top-secret-value' }],
      policies: { mail: { smtp: { password: 'top-secret-value' } } },
    });
    expect(JSON.stringify(result)).not.toContain('top-secret-value');
    try {
      parseRealmFile({ realm: 'master', clients: [{ ...client, client_secret: 'top-secret' }] });
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(RealmFileError);
      expect((error as Error).message).not.toContain('top-secret');
      expect((error as Error).message).toContain('/clients/0/client_secret');
    }
  });
});

describe('a URL with a user name or password', () => {
  const PASSWORD = 'Hunter2Pass';
  const credentialed = `https://svc:${PASSWORD}@keys.example.com/jwks.json`;
  const backend = {
    client_id: 'notes-api',
    name: 'Notes API',
    grant_types: ['client_credentials'],
    token_endpoint_auth_method: 'private_key_jwt',
    jwks_uri: 'https://keys.example.com/jwks.json',
  };
  const systemClient = {
    redirect_uris: ['https://portal.example.com/auth/callback'],
    jwks_uri: 'https://portal.example.com/.well-known/jwks.json',
  };

  // A secret of its own: the user information of a URL. Each place a file
  // names a URL, and a string the schema does not read as one.
  it.each([
    ['a jwks_uri', { clients: [{ ...backend, jwks_uri: credentialed }] }, '/clients/0/jwks_uri'],
    [
      'a redirect URI',
      { clients: [{ ...client, redirect_uris: [credentialed] }] },
      '/clients/0/redirect_uris/0',
    ],
    [
      'a back-channel logout URI, whose own rule quotes the value',
      { clients: [{ ...client, backchannel_logout_uri: credentialed }] },
      '/clients/0/backchannel_logout_uri',
    ],
    [
      'an audience',
      { clients: [{ ...backend, audience: [credentialed] }] },
      '/clients/0/audience/0',
    ],
    [
      'an ID-JAG target',
      { clients: [{ ...backend, id_jag_targets: [credentialed] }] },
      '/clients/0/id_jag_targets/0',
    ],
    [
      'a CIMD client_id',
      { cimd_clients: [{ client_id: credentialed, scopes: [] }] },
      '/cimd_clients/0/client_id',
    ],
    [
      'a resource indicator',
      { resources: [{ resource: credentialed, scopes: [], clients: 'any_client' }] },
      '/resources/0/resource',
    ],
    [
      "the system client's jwks_uri",
      { system_client: { ...systemClient, jwks_uri: credentialed } },
      '/system_client/jwks_uri',
    ],
    [
      'a policy field',
      { policies: { mail: { fromName: credentialed } } },
      '/policies/mail/fromName',
    ],
    ['the format', { format: credentialed }, '/format'],
  ])('is refused as %s, and never quoted', (_, sections, pointer) => {
    const raw = { realm: 'master', ...sections };
    const issues = issuesOf(raw);
    expect(issues.filter((issue) => issue.pointer === pointer)).toEqual([
      { path: expect.any(Array), pointer, message: URL_CREDENTIALS_MESSAGE },
    ]);
    expect(JSON.stringify(issues)).not.toContain(PASSWORD);
    expect(() => parseRealmFile(raw)).toThrow(RealmFileError);
    expect(() => parseRealmFile(raw)).not.toThrow(PASSWORD);
  });

  // The parser reads a URL as a URL parser does, as Node's fetch would.
  it.each([
    `https:/svc:${PASSWORD}@keys.example.com/jwks.json`,
    `HTTPS://svc:${PASSWORD}@keys.example.com/jwks.json`,
    `https:\\\\svc:${PASSWORD}@keys.example.com/jwks.json`,
    'https://svc@keys.example.com/jwks.json',
    'ftp://svc:pw@files.example.com/',
    // Text that starts with a URL: a URL parser reads the authority up to the
    // first slash, so everything before the @ is a user name to it.
    'https://example.com is ours; mail me@example.com',
  ])('is found in %s', (value) => {
    expect(hasUrlCredentials(value)).toBe(true);
  });

  it.each([
    'Notes: support@example.com',
    'mailto:ops@example.com',
    'no-reply@example.com',
    'See https://example.com, or mail me@example.com',
    'https://keys.example.com/jwks.json?owner=ops@example.com',
    'https://keys.example.com/@ops/jwks.json',
  ])('is not found in %s', (value) => {
    expect(hasUrlCredentials(value)).toBe(false);
  });

  it('leaves text that only holds an @ alone', () => {
    expect(() =>
      parseRealmFile({
        realm: 'master',
        clients: [
          { ...client, name: 'Notes: support@example.com', description: 'mailto:ops@example.com' },
        ],
        policies: { mail: { fromAddress: 'no-reply@example.com' } },
      })
    ).not.toThrow();
  });

  it('is found at any depth without a recursion, in document order', () => {
    let deep: unknown = credentialed;
    for (let level = 0; level < 100_000; level++) deep = [deep];
    expect(urlCredentialPaths(deep)).toHaveLength(1);
    expect(urlCredentialPaths({ b: [credentialed], a: { c: credentialed } })).toEqual([
      ['b', 0],
      ['a', 'c'],
    ]);
  });
});

describe('a key set', () => {
  // The seed manifest drops a member of `jwks` beside `keys`; a realm file
  // refuses it, so a misspelt `keys` or private keys under another name fail.
  it.each([
    ['clients', { clients: [{ ...client, token_endpoint_auth_method: 'private_key_jwt' }] }],
    [
      'system_client',
      { system_client: { redirect_uris: ['https://portal.example.com/auth/callback'] } },
    ],
  ])('of %s holds keys and nothing else', (name, sections) => {
    const raw = JSON.parse(JSON.stringify({ realm: 'master', ...sections })) as Record<
      string,
      unknown
    >;
    const holder = (
      name === 'clients' ? (raw['clients'] as unknown[])[0] : raw['system_client']
    ) as Record<string, unknown>;
    holder['jwks'] = { keys: [publicJwk], private_keys: [{ ...publicJwk, d: 'secret' }] };
    const prefix = name === 'clients' ? ['clients', 0] : ['system_client'];
    const issues = issuesOf(raw);
    expect(issues).toEqual([
      expect.objectContaining({
        path: [...prefix, 'jwks', 'private_keys'],
        message: expect.stringContaining('"private_keys" is not a field of'),
      }),
    ]);
    holder['jwks'] = { keys: [publicJwk] };
    expect(() => parseRealmFile(raw)).not.toThrow();
  });
});

describe('the clients sections', () => {
  it('take a seed-manifest client with its OAuth metadata names, as the manifest does', () => {
    const entry = {
      client_id: 'notes-api',
      name: 'Notes API',
      description: 'The notes service.',
      grant_types: ['client_credentials'],
      response_types: [],
      scopes: ['notes:sync'],
      audience: ['https://notes.example.com/api'],
      redirect_uris: [],
      require_pkce: true,
      token_endpoint_auth_method: 'private_key_jwt',
      is_agent: true,
      max_agent_mode: 'readonly',
      jwks_uri: 'https://notes.example.com/.well-known/jwks.json',
    };
    expect(parseRealmFile({ realm: 'master', clients: [entry] }).clients).toEqual([entry]);
    expect(() =>
      parseRealmFile({
        realm: 'master',
        clients: [{ ...entry, jwks_uri: undefined, jwks: { keys: [publicJwk] } }],
      })
    ).not.toThrow();
  });

  it.each(CLIENT_ENVIRONMENTS)('take the environment %s', (environment) => {
    const file = parseRealmFile({ realm: 'master', clients: [{ ...client, environment }] });
    expect(file.clients?.[0]?.environment).toBe(environment);
  });

  it('leave the environment out when the entry does: production, the column default', () => {
    expect(parseRealmFile({ realm: 'master', clients: [client] }).clients?.[0]).not.toHaveProperty(
      'environment'
    );
    expect(CLIENT_ENVIRONMENTS[CLIENT_ENVIRONMENTS.length - 1]).toBe('production');
  });

  it("keep the seed manifest's rules between members", () => {
    const issues = issuesOf({
      realm: 'master',
      clients: [{ ...client, token_endpoint_auth_method: 'private_key_jwt' }],
    });
    expect(issues[0]).toMatchObject({ path: ['clients', 0, 'token_endpoint_auth_method'] });
  });

  it('refuse a typo of a member as an unknown field', () => {
    const issues = issuesOf({
      realm: 'master',
      clients: [{ ...client, grant_type: ['authorization_code'] }],
    });
    expect(issues).toEqual([
      expect.objectContaining({
        path: ['clients', 0, 'grant_type'],
        message: '"grant_type" is not a field of a clients entry',
      }),
    ]);
  });

  it('refuse what marks a client as developer-owned or dynamically registered', () => {
    for (const member of ['developer_id', 'dynamic_registered_at']) {
      const [issue] = issuesOf({ realm: 'master', clients: [{ ...client, [member]: 'x' }] });
      expect(issue.message).toContain('operator-managed clients only');
    }
  });
});

describe('natural keys', () => {
  it('name each section that has one, and only policies has none', () => {
    expect(
      Object.fromEntries(REALM_FILE_SECTIONS.map(({ name, naturalKey }) => [name, naturalKey]))
    ).toEqual({
      policies: undefined,
      clients: 'client_id',
      cimd_clients: 'client_id',
      resources: 'resource',
      system_client: 'client_id',
    });
  });

  it('refuse a client_id listed twice across the client sections', () => {
    const cimd = 'https://client.example.com/oauth/metadata.json';
    const issues = issuesOf({
      realm: 'master',
      clients: [{ ...client, client_id: cimd, name: 'Twice' }],
      cimd_clients: [{ client_id: cimd, scopes: [] }],
    });
    expect(issues).toEqual([
      expect.objectContaining({
        path: ['cimd_clients', 0, 'client_id'],
        message: expect.stringContaining('is listed at clients.0 already'),
      }),
    ]);
  });

  it('compare the system client by the id it takes, SYSTEM_CLIENT_ID included', () => {
    const system = {
      redirect_uris: ['https://portal.example.com/auth/callback'],
      jwks_uri: 'https://portal.example.com/.well-known/jwks.json',
    };
    const raw = {
      realm: 'master',
      clients: [{ ...client, client_id: 'portal' }],
      system_client: system,
    };
    expect(parseRealmFile(raw).system_client?.client_id).toBe('system');
    const result = safeParseRealmFile(raw, { env: { SYSTEM_CLIENT_ID: 'portal' } });
    expect(result.success).toBe(false);
    expect(!result.success && result.issues[0].path).toEqual(['system_client', 'client_id']);
  });

  it('refuse a resource listed twice', () => {
    const resource = {
      resource: 'https://mcp.example.com/mcp',
      scopes: [{ scope: 'files:read', text: { en: 'Read your files' } }],
      clients: 'any_client',
    };
    const issues = issuesOf({ realm: 'master', resources: [resource, resource] });
    expect(issues[0].path).toEqual(['resources', 1, 'resource']);
  });
});

describe('the policies section', () => {
  it('is the registry document view: camelCase groups, each field defaulted', () => {
    const file = parseRealmFile({
      realm: 'master',
      policies: { tokens: { accessTokenLifespanSeconds: 600 } },
    });
    expect(file.policies?.tokens.accessTokenLifespanSeconds).toBe(600);
    expect(file.policies).toEqual(
      REALM_POLICY_REGISTRY.parse({ tokens: { accessTokenLifespanSeconds: 600 } }, 'document')
    );
  });

  it('names the realm representation, less its <name>Set flags', () => {
    const representation = REALM_POLICY_REGISTRY.toRepresentation(
      REALM_POLICY_REGISTRY.parse({}, 'document')
    ) as Record<string, Record<string, unknown>>;
    const flags = REALM_POLICY_REGISTRY.fields()
      .filter(({ field }) => field.secret)
      .map(({ segments }) => [...segments.slice(0, -1), `${segments[segments.length - 1]}Set`]);
    for (const flag of flags) {
      let node: Record<string, unknown> = representation;
      for (const segment of flag.slice(0, -1)) node = node[segment] as Record<string, unknown>;
      delete node[flag[flag.length - 1]];
    }
    expect(parseRealmFile({ realm: 'master', policies: representation }).policies).toEqual(
      representation
    );
  });

  it('is left out of a file that does not name it', () => {
    expect(parseRealmFile({ realm: 'master' })).not.toHaveProperty('policies');
  });
});

describe('realmNameWarning', () => {
  it('warns when the target realm is another, and only then', () => {
    expect(realmNameWarning({ realm: 'master' }, 'master')).toBeUndefined();
    expect(realmNameWarning({ realm: 'notes-sandbox' }, 'notes')).toContain('"notes-sandbox"');
  });
});

describe('realmFileClientSchema', () => {
  it('is strict, as the manifest client is', () => {
    expect(realmFileClientSchema.safeParse({ ...client, unknown: 1 }).success).toBe(false);
  });
});

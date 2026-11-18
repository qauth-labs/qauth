import { defaultsFromEnv } from '@qauth-labs/fastify-plugin-realm-policy';
import {
  parseRealmFile,
  type RealmFileClient,
  realmFileClientSchema,
} from '@qauth-labs/realm-file';
import { describe, expect, it } from 'vitest';

import { IMPORT_CLIENT_FIELD_NAMES } from './client-fields';
import { type ImportChange, type ImportPlan, planDigest, planImport } from './plan';
import { ImportPlanError, type ImportState } from './section';

/**
 * The import plan of a realm file (#518), without a listener: a fixture
 * state and file give the expected plan change by change; every client
 * field of #518's table moves the right way in both directions; the plan's
 * class is the strictest change's; the digest is stable and moves with
 * anything the plan would do; a file built from the state plans nothing;
 * nothing is deleted unless the import prunes; and the secrets the file's
 * choices need are named, never their values.
 */

const REALM = '018f2d6e-8a8b-7c3d-9e0f-1a2b3c4d5e6f';

type Document = Record<string, Record<string, unknown>>;

/** The policies of an empty environment, edited. */
function policiesOf(edit: (document: Document) => void = () => undefined): Document {
  const document = structuredClone(defaultsFromEnv({})) as unknown as Document;
  edit(document);
  return document;
}

const client = (entry: Record<string, unknown>): RealmFileClient =>
  realmFileClientSchema.parse(entry);

const APP = {
  client_id: 'app',
  name: 'App',
  grant_types: ['authorization_code', 'refresh_token'],
  redirect_uris: ['https://app.example.com/callback'],
  scopes: ['openid', 'profile'],
};

const WORKER = {
  client_id: 'worker',
  name: 'Report worker',
  grant_types: ['client_credentials'],
  scopes: ['reports:read'],
  client_credentials_scopes: ['reports:read'],
  token_endpoint_auth_method: 'private_key_jwt',
  jwks_uri: 'https://worker.example.com/jwks.json',
};

/** A realm with the default policies, APP and WORKER, and two clients no file may name. */
function stateOf(edit: Partial<ImportState> = {}): ImportState {
  return {
    realmId: REALM,
    realmName: 'acme',
    policiesVersion: 7,
    policies: policiesOf(),
    setSecrets: [],
    clients: [client(APP), client(WORKER)],
    unmanagedClients: new Map([
      ['system', 'the system client, which the system_client section describes'],
      ['dev-app', 'a client a developer owns'],
    ]),
    ...edit,
  };
}

/** A file: `realm` and the sections given. */
const fileOf = (sections: Record<string, unknown>) =>
  parseRealmFile({ realm: 'acme', ...sections });

/** The members of a change a test compares, beside its values. */
const summary = (change: ImportChange) => ({
  section: change.section,
  key: change.key,
  path: change.path,
  op: change.op,
  direction: change.direction,
  class: change.class,
  effects: change.effects,
  permissions: change.permissions,
});

describe('the plan of a fixture state and file (#518)', () => {
  it('lists every change, section by section, with what each needs', () => {
    const file = fileOf({
      policies: policiesOf((document) => {
        document['password']['minScore'] = 1;
        document['tokens']['accessTokenLifespanSeconds'] = 300;
      }),
      clients: [
        {
          ...APP,
          name: 'The App',
          redirect_uris: [...APP.redirect_uris, 'https://app.example.com/other'],
        },
        {
          client_id: 'cli',
          name: 'Command line',
          grant_types: ['authorization_code'],
          redirect_uris: ['http://127.0.0.1/callback'],
          token_endpoint_auth_method: 'none',
          environment: 'development',
        },
      ],
    });
    const plan = planImport(stateOf(), file);

    expect(plan.changes.map(summary)).toEqual([
      {
        section: 'policies',
        key: null,
        path: 'tokens.accessTokenLifespanSeconds',
        op: 'update',
        direction: 'tightening',
        class: 'write',
        effects: [],
        permissions: ['realms.policies.write'],
      },
      {
        section: 'policies',
        key: null,
        path: 'password.minScore',
        op: 'update',
        direction: 'loosening',
        class: 'security',
        effects: ['credential-path'],
        permissions: ['realms.policies.security'],
      },
      {
        section: 'clients',
        key: 'app',
        path: 'name',
        op: 'update',
        direction: 'neutral',
        class: 'write',
        effects: [],
        permissions: ['clients.write'],
      },
      {
        section: 'clients',
        key: 'app',
        path: 'redirect_uris',
        op: 'update',
        direction: 'loosening',
        class: 'security',
        effects: ['token-content'],
        permissions: ['clients.security'],
      },
      {
        section: 'clients',
        key: 'cli',
        path: '',
        op: 'create',
        direction: 'loosening',
        class: 'security',
        effects: ['token-content'],
        permissions: ['clients.security'],
      },
    ]);

    const [lifetime, score, name, redirects, created] = plan.changes;
    expect([lifetime.before, lifetime.after]).toEqual([900, 300]);
    expect([score.before, score.after]).toEqual([2, 1]);
    expect([name.before, name.after]).toEqual(['App', 'The App']);
    expect(redirects.before).toEqual(['https://app.example.com/callback']);
    expect(redirects.after).toEqual([
      'https://app.example.com/callback',
      'https://app.example.com/other',
    ]);
    expect(created.before).toBeNull();
    expect(created.after).toMatchObject({
      client_id: 'cli',
      name: 'Command line',
      token_endpoint_auth_method: 'none',
      require_pkce: true,
      environment: 'development',
    });
    // A public client gets no secret; a development client with a loopback
    // redirect URI describes the environment it runs in.
    expect([created.needsSecret, created.environmentBound]).toEqual([false, true]);
    expect(created.scopes).toEqual(['qauth:admin:security']);
    expect(lifetime.scopes).toEqual(['qauth:admin:write']);

    expect(plan).toMatchObject({
      realmId: REALM,
      baseVersion: 7,
      prune: false,
      class: 'security',
      effects: ['credential-path', 'token-content'],
      permissions: [
        'clients.security',
        'clients.write',
        'realms.policies.security',
        'realms.policies.write',
      ],
      scopes: ['qauth:admin:write', 'qauth:admin:security'],
      approvalRequired: true,
      secretsToSet: [],
      warnings: [],
    });
    // WORKER is not in the file and the import does not prune: it stays.
    expect(plan.changes.some((change) => change.key === 'worker')).toBe(false);
  });

  it('warns when the file names another realm, and plans it all the same', () => {
    const plan = planImport(stateOf(), parseRealmFile({ realm: 'acme-sandbox' }));
    expect(plan.changes).toEqual([]);
    expect(plan.warnings).toEqual([
      'the file describes the realm "acme-sandbox" and is imported into "acme": the target realm is the one the import names',
    ]);
  });

  it('refuses a section it does not plan yet, naming it', () => {
    const file = fileOf({
      resources: [
        {
          resource: 'https://api.example.com/mcp',
          scopes: [{ scope: 'x:read', text: { en: 'Read' } }],
          clients: 'any_client',
        },
      ],
    });
    expect(() => planImport(stateOf(), file)).toThrow(ImportPlanError);
    try {
      planImport(stateOf(), file);
    } catch (error) {
      expect((error as ImportPlanError).issues).toEqual([
        {
          pointer: '/resources',
          message:
            'this server does not import the resources section yet: leave it out of the file, and change it through its own operations',
        },
      ]);
    }
  });

  it('refuses a file that names a client no realm file manages', () => {
    const file = fileOf({ clients: [APP, { ...APP, client_id: 'dev-app' }] });
    try {
      planImport(stateOf(), file);
      expect.unreachable('a developer’s client is never taken over');
    } catch (error) {
      expect(error).toBeInstanceOf(ImportPlanError);
      expect((error as ImportPlanError).issues).toEqual([
        {
          pointer: '/clients/1/client_id',
          message:
            'names a client of the realm that no realm file manages (a client a developer owns): an import never takes it over',
        },
      ]);
    }
  });

  it('gives a new client that authenticates with a secret needsSecret, and one with an admin scope administration', () => {
    const plan = planImport(
      stateOf(),
      fileOf({
        clients: [
          APP,
          WORKER,
          {
            client_id: 'console',
            name: 'Console',
            grant_types: ['client_credentials'],
            scopes: ['qauth:admin:read'],
            token_endpoint_auth_method: 'private_key_jwt',
            jwks_uri: 'https://console.example.com/jwks.json',
          },
          { client_id: 'web', name: 'Web', grant_types: ['client_credentials'] },
        ],
      })
    );
    const byKey = new Map(plan.changes.map((change) => [change.key, change]));
    expect(byKey.get('console')).toMatchObject({
      op: 'create',
      effects: ['token-content', 'administration'],
      needsSecret: false,
    });
    // client_secret_basic is the seed manifest's default.
    expect(byKey.get('web')).toMatchObject({ op: 'create', needsSecret: true });
  });
});

/** The change of `field` when the realm's client is `before` and the file's `after`. */
function changeOfField(
  field: string,
  before: Record<string, unknown>,
  after: Record<string, unknown>
): ImportChange | undefined {
  const plan = planImport(stateOf({ clients: [client(before)] }), fileOf({ clients: [after] }));
  return plan.changes.find((change) => change.path === field);
}

const BASE = {
  client_id: 'c',
  name: 'C',
  grant_types: ['authorization_code'],
  redirect_uris: ['https://c.example.com/callback'],
};
const SIGNED = {
  ...BASE,
  token_endpoint_auth_method: 'private_key_jwt',
  jwks_uri: 'https://c.example.com/jwks.json',
};
const MACHINE = { client_id: 'c', name: 'C', grant_types: ['client_credentials'] };
const KEY = { kty: 'OKP', crv: 'Ed25519', x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo' };
const OTHER_KEY = {
  kty: 'OKP',
  crv: 'Ed25519',
  x: 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'.slice(0, 43),
};

/** One field of #518's table: a stricter entry, a looser one, and which way the change from the first to the second moves. */
interface DirectionCase {
  readonly field: string;
  readonly stricter: Record<string, unknown>;
  readonly looser: Record<string, unknown>;
}

const DIRECTION_CASES: readonly DirectionCase[] = [
  {
    field: 'redirect_uris',
    stricter: BASE,
    looser: { ...BASE, redirect_uris: [...BASE.redirect_uris, 'https://c.example.com/two'] },
  },
  {
    field: 'scopes',
    stricter: { ...BASE, scopes: ['openid'] },
    looser: { ...BASE, scopes: ['openid', 'email'] },
  },
  {
    field: 'grant_types',
    stricter: BASE,
    looser: { ...BASE, grant_types: ['authorization_code', 'refresh_token'] },
  },
  {
    field: 'response_types',
    stricter: { ...MACHINE, response_types: [] },
    looser: { ...MACHINE, response_types: ['code'] },
  },
  {
    field: 'audience',
    stricter: { ...MACHINE, audience: ['https://api.example.com'] },
    looser: { ...MACHINE, audience: ['https://api.example.com', 'https://other.example.com'] },
  },
  { field: 'require_pkce', stricter: BASE, looser: { ...BASE, require_pkce: false } },
  {
    field: 'token_endpoint_auth_method',
    stricter: SIGNED,
    looser: { ...SIGNED, token_endpoint_auth_method: 'client_secret_basic' },
  },
  {
    field: 'token_endpoint_auth_method',
    stricter: { ...BASE, token_endpoint_auth_method: 'client_secret_post' },
    looser: { ...BASE, token_endpoint_auth_method: 'none' },
  },
  { field: 'is_agent', stricter: SIGNED, looser: { ...SIGNED, is_agent: true } },
  {
    field: 'max_agent_mode',
    stricter: { ...SIGNED, is_agent: true },
    looser: { ...SIGNED, is_agent: true, max_agent_mode: 'readonly' },
  },
  {
    field: 'max_agent_mode',
    stricter: { ...SIGNED, is_agent: true, max_agent_mode: 'readonly' },
    looser: { ...SIGNED, is_agent: true, max_agent_mode: 'exec' },
  },
  { field: 'environment', stricter: BASE, looser: { ...BASE, environment: 'development' } },
  {
    field: 'environment',
    stricter: { ...BASE, environment: 'production' },
    looser: { ...BASE, environment: 'staging' },
  },
];

describe('the direction of each client field of #518’s table, both ways', () => {
  it.each(DIRECTION_CASES)(
    '$field: toward the stricter tightens, toward the looser loosens',
    ({ field, stricter, looser }) => {
      expect(changeOfField(field, stricter, looser)?.direction).toBe('loosening');
      expect(changeOfField(field, looser, stricter)?.direction).toBe('tightening');
    }
  );

  it('counts any change of a key set or its URL as loosening, its direction unknown', () => {
    const one = { ...BASE, token_endpoint_auth_method: 'private_key_jwt', jwks: { keys: [KEY] } };
    const two = { ...one, jwks: { keys: [OTHER_KEY] } };
    expect(changeOfField('jwks', one, two)?.direction).toBe('loosening');
    expect(changeOfField('jwks', two, one)?.direction).toBe('loosening');
    const moved = { ...SIGNED, jwks_uri: 'https://keys.example.com/jwks.json' };
    expect(changeOfField('jwks_uri', SIGNED, moved)?.direction).toBe('loosening');
    expect(changeOfField('jwks_uri', moved, SIGNED)?.direction).toBe('loosening');
  });

  it('leaves the two secret methods as strict as each other', () => {
    const basic = { ...BASE, token_endpoint_auth_method: 'client_secret_basic' };
    const post = { ...BASE, token_endpoint_auth_method: 'client_secret_post' };
    expect(changeOfField('token_endpoint_auth_method', basic, post)?.direction).toBe('neutral');
    expect(changeOfField('token_endpoint_auth_method', post, basic)?.direction).toBe('neutral');
  });

  it('ranks private_key_jwt above a secret above none, both ways', () => {
    const none = { ...SIGNED, token_endpoint_auth_method: 'none' };
    expect(changeOfField('token_endpoint_auth_method', SIGNED, none)?.direction).toBe('loosening');
    expect(changeOfField('token_endpoint_auth_method', none, SIGNED)?.direction).toBe('tightening');
  });

  it('gives a looser environment the effect posture-loosening, and a stricter one none', () => {
    const development = { ...BASE, environment: 'development' };
    expect(changeOfField('environment', BASE, development)).toMatchObject({
      class: 'security',
      effects: ['posture-loosening'],
      environmentBound: true,
    });
    expect(changeOfField('environment', development, BASE)).toMatchObject({
      class: 'write',
      effects: [],
    });
  });

  it('keeps the name and the description neutral, both ways', () => {
    const named = { ...BASE, name: 'Other', description: 'A description' };
    for (const field of ['name', 'description']) {
      expect(changeOfField(field, BASE, named)?.direction).toBe('neutral');
      expect(changeOfField(field, named, BASE)?.direction).toBe('neutral');
    }
  });

  it('has a direction for every member of a clients entry but its natural key', () => {
    expect(IMPORT_CLIENT_FIELD_NAMES).toEqual(
      Object.keys(realmFileClientSchema.shape).filter((name) => name !== 'client_id')
    );
  });
});

describe('the class of a plan (#518)', () => {
  it('is write when every change is a display field, and security once one change is', () => {
    const display = planImport(
      stateOf(),
      fileOf({ clients: [{ ...APP, name: 'Renamed', description: 'Shown to admins' }, WORKER] })
    );
    expect(display.changes.map((change) => change.path)).toEqual(['name', 'description']);
    expect(display).toMatchObject({
      class: 'write',
      effects: [],
      permissions: ['clients.write'],
      scopes: ['qauth:admin:write'],
      approvalRequired: false,
    });

    const withSecurity = planImport(
      stateOf(),
      fileOf({
        clients: [
          {
            ...APP,
            name: 'Renamed',
            redirect_uris: [...APP.redirect_uris, 'https://app.example.com/more'],
          },
          WORKER,
        ],
      })
    );
    expect(withSecurity).toMatchObject({
      class: 'security',
      effects: ['token-content'],
      permissions: ['clients.security', 'clients.write'],
      scopes: ['qauth:admin:write', 'qauth:admin:security'],
      approvalRequired: true,
    });
  });

  it('classifies a field no admin operation writes as a security change, both ways', () => {
    const targets = { ...SIGNED, id_jag_targets: ['https://as.example.com'] };
    for (const [before, after] of [
      [SIGNED, targets],
      [targets, SIGNED],
    ]) {
      expect(changeOfField('id_jag_targets', before, after)).toMatchObject({
        class: 'security',
        effects: ['token-content'],
        permissions: ['clients.security'],
      });
    }
  });

  it('makes every change of a client that holds an admin scope a security change with administration', () => {
    const admin = { ...SIGNED, grant_types: ['client_credentials'], scopes: ['qauth:admin:read'] };
    expect(changeOfField('name', admin, { ...admin, name: 'Renamed' })).toMatchObject({
      class: 'security',
      effects: ['administration'],
    });
  });
});

describe('the digest of a plan (#518)', () => {
  const file = () =>
    fileOf({
      policies: policiesOf((document) => {
        document['password']['minScore'] = 3;
      }),
      clients: [{ ...APP, scopes: ['profile', 'openid', 'email'] }, WORKER],
    });

  it('is stable for equal input, whatever the order the file lists its entries and sets in', () => {
    const first = planImport(stateOf(), file());
    const reordered = fileOf({
      policies: policiesOf((document) => {
        document['password']['minScore'] = 3;
      }),
      clients: [WORKER, { ...APP, scopes: ['email', 'openid', 'profile'] }],
    });
    expect(planImport(stateOf(), file()).digest).toBe(first.digest);
    expect(planImport(stateOf(), reordered).digest).toBe(first.digest);
    expect(first.digest).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(planDigest(first)).toBe(first.digest);
  });

  it('differs for the base version, the realm, the prune flag and any change', () => {
    const base = planImport(stateOf(), file()).digest;
    const digests = [
      planImport(stateOf({ policiesVersion: 8 }), file()).digest,
      planImport(stateOf({ realmId: '018f2d6e-8a8b-7c3d-9e0f-1a2b3c4d5e70' }), file()).digest,
      planImport(stateOf(), file(), { prune: true }).digest,
      planImport(
        stateOf(),
        fileOf({
          policies: policiesOf((document) => {
            document['password']['minScore'] = 4;
          }),
          clients: [{ ...APP, scopes: ['profile', 'openid', 'email'] }, WORKER],
        })
      ).digest,
      planImport(
        stateOf({ clients: [client({ ...APP, name: 'Old name' }), client(WORKER)] }),
        file()
      ).digest,
    ];
    for (const digest of digests) expect(digest).not.toBe(base);
    expect(new Set(digests).size).toBe(digests.length);
  });

  it('leaves the warnings out', () => {
    const named = planImport(stateOf(), file());
    const renamed = planImport(stateOf({ realmName: 'other' }), file());
    expect(renamed.warnings).not.toEqual(named.warnings);
    expect(renamed.digest).toBe(named.digest);
  });
});

describe('a file built from the realm’s state (#518)', () => {
  it('plans no change', () => {
    const state = stateOf({
      policies: policiesOf((document) => {
        document['password']['minScore'] = 4;
        document['tokens']['accessTokenLifespanSeconds'] = 600;
      }),
    });
    const file = parseRealmFile({
      realm: 'acme',
      policies: state.policies,
      clients: state.clients,
    });
    const plan: ImportPlan = planImport(state, file);
    expect(plan.changes).toEqual([]);
    expect(plan).toMatchObject({
      class: 'write',
      effects: [],
      permissions: [],
      scopes: [],
      approvalRequired: false,
      secretsToSet: [],
    });
    // Pruning removes nothing either: the file lists every client.
    expect(planImport(state, file, { prune: true }).changes).toEqual([]);
  });

  it('plans no change when the file leaves out what the seed manifest defaults', () => {
    const explicit = {
      ...APP,
      response_types: ['code'],
      require_pkce: true,
      token_endpoint_auth_method: 'client_secret_basic',
      is_agent: false,
      environment: 'production',
      post_logout_redirect_uris: [],
      id_jag_targets: [],
    };
    const plan = planImport(
      stateOf({ clients: [client(explicit), client(WORKER)] }),
      fileOf({ clients: [APP, WORKER] })
    );
    expect(plan.changes).toEqual([]);
  });
});

describe('deletes (#518)', () => {
  it('never deletes by default: a client the file leaves out stays', () => {
    const plan = planImport(stateOf(), fileOf({ clients: [APP] }));
    expect(plan.changes).toEqual([]);
  });

  it('deletes a client the file leaves out only when the import prunes', () => {
    const plan = planImport(stateOf(), fileOf({ clients: [APP] }), { prune: true });
    expect(plan.changes.map(summary)).toEqual([
      {
        section: 'clients',
        key: 'worker',
        path: '',
        op: 'delete',
        direction: 'tightening',
        class: 'security',
        effects: ['token-content'],
        permissions: ['clients.security'],
      },
    ]);
    expect(plan.changes[0].before).toMatchObject({ client_id: 'worker', name: 'Report worker' });
    expect(plan.changes[0].after).toBeNull();
    expect(plan.prune).toBe(true);
  });

  it('deletes nothing for a file without a clients section, pruning or not', () => {
    expect(planImport(stateOf(), fileOf({}), { prune: true }).changes).toEqual([]);
  });
});

describe('the secrets a file needs (#518)', () => {
  const smtp = (host = 'smtp.example.com') =>
    policiesOf((document) => {
      document['mail']['provider'] = 'smtp';
      document['mail']['fromAddress'] = 'no-reply@example.com';
      document['mail']['smtp'] = {
        ...(document['mail']['smtp'] as object),
        host,
        port: 587,
        user: 'mailer',
      };
    });

  it('names mail.smtp.password when the file selects smtp and none is stored, on the change that selects it', () => {
    const plan = planImport(stateOf(), fileOf({ policies: smtp() }));
    expect(plan.secretsToSet).toEqual(['mail.smtp.password']);
    const provider = plan.changes.find((change) => change.path === 'mail.provider');
    expect(provider).toMatchObject({ before: 'mock', after: 'smtp', needsSecret: true });
    const from = plan.changes.find((change) => change.path === 'mail.fromAddress');
    expect(from?.needsSecret).toBe(false);
  });

  it('names none when the password is stored and the server stays the same', () => {
    const plan = planImport(
      stateOf({ policies: smtp(), setSecrets: ['mail.smtp.password'] }),
      fileOf({ policies: smtp() })
    );
    expect(plan.secretsToSet).toEqual([]);
  });

  it('names the password again when the file moves the smtp server', () => {
    const plan = planImport(
      stateOf({ policies: smtp(), setSecrets: ['mail.smtp.password'] }),
      fileOf({ policies: smtp('smtp.other.example.com') })
    );
    expect(plan.secretsToSet).toEqual(['mail.smtp.password']);
    expect(plan.changes.find((change) => change.path === 'mail.smtp.host')?.needsSecret).toBe(true);
  });

  it('keeps a stored secret: a file holds none, so no change sets or clears it', () => {
    const plan = planImport(
      stateOf({ policies: smtp(), setSecrets: ['mail.smtp.password'] }),
      fileOf({ policies: smtp() })
    );
    expect(plan.changes).toEqual([]);
  });

  it('names none for a file without policies', () => {
    expect(planImport(stateOf(), fileOf({})).secretsToSet).toEqual([]);
  });
});

describe('values that carry a secret (#518)', () => {
  it('masks the user name and password of a URL the realm stores', () => {
    const stored = { ...SIGNED, jwks_uri: 'https://keys.example.com/jwks.json' };
    const state = stateOf({
      clients: [
        { ...client(stored), jwks_uri: 'https://user:s3cret-value@keys.example.com/jwks.json' },
      ],
    });
    const plan = planImport(state, fileOf({ clients: [SIGNED] }));
    const change = plan.changes.find((entry) => entry.path === 'jwks_uri');
    expect(change?.before).toBe('https://***@keys.example.com/jwks.json');
    expect(JSON.stringify(plan)).not.toContain('s3cret-value');
  });
});

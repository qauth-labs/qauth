import { defaultsFromEnv } from '@qauth-labs/fastify-plugin-realm-policy';
import {
  canonicalRealmFile,
  parseRealmFile,
  REALM_FILE_FORMAT,
  REALM_FILE_SECTIONS,
  type RealmFileClient,
  realmFileClientSchema,
  serializeRealmFile,
} from '@qauth-labs/realm-file';
import { describe, expect, it } from 'vitest';

import { IMPORT_SECTIONS, planImport } from '../imports/plan';
import { POLICIES_SECTION } from '../imports/policies-section';
import type { ImportState } from '../imports/section';
import { exportRealmFile, realmFileDisposition, RealmFileExportError } from './realm-file';

/**
 * The export of a realm as a realm file (#530), without a listener: a
 * fixture state gives a file in canonical order whatever order the state
 * lists things in; the file parses, holds no secret, keeps the fields bound
 * to the environment and imports back into the same state with no change;
 * a state no file can describe is refused without quoting a value; the
 * section hook writes what the import plans; and the download's name is
 * safe in a header whatever the realm's name.
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
  grant_types: ['refresh_token', 'authorization_code'],
  redirect_uris: ['https://b.example.com/callback', 'https://a.example.com/callback'],
  scopes: ['profile', 'openid', 'email'],
  environment: 'staging',
};

const WORKER = {
  client_id: 'worker',
  name: 'Report worker',
  grant_types: ['client_credentials'],
  scopes: ['reports:write', 'reports:read'],
  client_credentials_scopes: ['reports:read'],
  token_endpoint_auth_method: 'private_key_jwt',
  jwks: {
    keys: [
      { kty: 'OKP', crv: 'Ed25519', x: 'l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs', kid: 'k1' },
    ],
  },
};

/** A realm with the default policies, APP and WORKER, and a client no file may name. */
function stateOf(edit: Partial<ImportState> = {}): ImportState {
  return {
    realmId: REALM,
    realmName: 'acme',
    policiesVersion: 7,
    policies: policiesOf(),
    setSecrets: [],
    clients: [client(WORKER), client(APP)],
    unmanagedClients: new Map([['dev-app', 'a client a developer owns']]),
    reservedClientId: () => undefined,
    ...edit,
  };
}

const textOf = (state: ImportState): string => serializeRealmFile(exportRealmFile(state));

describe('exportRealmFile (#530)', () => {
  it('writes format, realm, the whole policy document and the operator clients by client_id', () => {
    const file = exportRealmFile(stateOf());
    expect(Object.keys(file)).toEqual(['format', 'realm', 'policies', 'clients']);
    expect(file.format).toBe(REALM_FILE_FORMAT);
    expect(file.realm).toBe('acme');
    // Every field, each at its default here, every set sorted.
    expect(file.policies).toEqual(
      canonicalRealmFile(parseRealmFile({ realm: 'acme', policies: {} })).policies
    );
    expect(file.clients?.map((entry) => entry.client_id)).toEqual(['app', 'worker']);
    const app = file.clients?.[0];
    expect(app?.redirect_uris).toEqual([
      'https://a.example.com/callback',
      'https://b.example.com/callback',
    ]);
    expect(app?.scopes).toEqual(['email', 'openid', 'profile']);
  });

  it('writes the same bytes for the same state, whatever order the state lists it in', () => {
    const first = textOf(stateOf());
    const reordered = stateOf({
      clients: [
        client({
          ...APP,
          scopes: ['email', 'openid', 'profile'],
          redirect_uris: [...APP.redirect_uris].reverse(),
        }),
        client(WORKER),
      ],
      policies: policiesOf((document) => {
        // The same groups, members written in another order.
        const reversed = Object.fromEntries(Object.entries(document['tokens']).reverse());
        document['tokens'] = reversed;
      }),
    });
    expect(textOf(reordered)).toBe(first);
    expect(textOf(stateOf())).toBe(first);
    expect(first.endsWith('}\n')).toBe(true);
    expect(JSON.parse(first)).toEqual(exportRealmFile(stateOf()));
  });

  it('writes a file the format parses, and that imports back into the state with no change', () => {
    const state = stateOf({
      policies: policiesOf((document) => {
        document['password']['minScore'] = 4;
      }),
    });
    const file = parseRealmFile(JSON.parse(textOf(state)));
    for (const prune of [false, true]) {
      const plan = planImport(state, file, { prune });
      expect(plan.changes, `prune: ${String(prune)}`).toEqual([]);
      expect(plan.warnings).toEqual([]);
    }
  });

  it('says the whole clients section, an empty one included', () => {
    const state = stateOf({ clients: [] });
    const file = exportRealmFile(state);
    expect(file.clients).toEqual([]);
    // Imported with prune, an empty list deletes what the target holds.
    const plan = planImport(stateOf(), parseRealmFile(JSON.parse(textOf(state))), { prune: true });
    expect(plan.changes.map(({ key, op }) => ({ key, op }))).toEqual([
      { key: 'app', op: 'delete' },
      { key: 'worker', op: 'delete' },
    ]);
  });

  it('leaves a secret policy field out, with no marker, whatever the state holds', () => {
    const state = stateOf({
      setSecrets: ['mail.smtp.password'],
      policies: policiesOf((document) => {
        document['mail']['provider'] = 'smtp';
        document['mail']['fromAddress'] = 'no-reply@example.com';
        document['mail']['smtp'] = {
          ...(document['mail']['smtp'] as object),
          host: 'smtp.example.com',
          port: 587,
          user: 'mailer',
          // Never in a state; the export drops it should one be there.
          password: 'hunter2-not-exported',
        };
      }),
    });
    const text = textOf(state);
    expect(text).not.toContain('hunter2-not-exported');
    expect(text).not.toMatch(/passwordSet|apiKey/);
    const smtp = (JSON.parse(text) as { policies: Document }).policies['mail']['smtp'];
    expect(smtp).toMatchObject({ host: 'smtp.example.com', port: 587, user: 'mailer' });
    expect(Object.keys(smtp as object)).not.toContain('password');
    // The import names the secret the target lacks; the file only selects smtp.
    const plan = planImport(stateOf(), parseRealmFile(JSON.parse(text)), { prune: false });
    expect(plan.secretsToSet).toEqual(['mail.smtp.password']);
  });

  it('keeps the fields bound to the environment', () => {
    const state = stateOf({
      policies: policiesOf((document) => {
        document['posture']['maxEnvironmentLaxity'] = 'staging';
      }),
      clients: [
        client({
          ...APP,
          environment: 'development',
          redirect_uris: ['http://localhost:8080/callback'],
        }),
      ],
    });
    const file = exportRealmFile(state);
    expect(file.policies?.['posture']).toMatchObject({ maxEnvironmentLaxity: 'staging' });
    expect(file.clients?.[0]).toMatchObject({
      environment: 'development',
      redirect_uris: ['http://localhost:8080/callback'],
    });
  });

  it('refuses a state no realm file can hold, naming the client and never the value', () => {
    const leaked = 'https://reader:s3cret-pass@keys.example.com/jwks.json';
    const state = stateOf({
      clients: [
        client(APP),
        // As a stored row reads it: a client the format refuses keeps its entry.
        {
          ...(client({
            ...WORKER,
            jwks: undefined,
            jwks_uri: 'https://keys.example.com/jwks.json',
          }) as object),
          jwks_uri: leaked,
        } as unknown as RealmFileClient,
      ],
    });
    let thrown: unknown;
    try {
      exportRealmFile(state);
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(RealmFileExportError);
    const { issues, message } = thrown as RealmFileExportError;
    expect(issues).toEqual([
      expect.objectContaining({
        pointer: '/clients/1/jwks_uri',
        message: expect.stringContaining('the clients entry of client_id "worker", at jwks_uri'),
      }),
    ]);
    expect(JSON.stringify(issues)).not.toContain('s3cret-pass');
    expect(message).not.toContain('s3cret-pass');
  });

  it('writes each section of the hook it is given, and every import section has one', () => {
    expect(IMPORT_SECTIONS.map((section) => typeof section.export)).toEqual(
      IMPORT_SECTIONS.map(() => 'function')
    );
    const order = REALM_FILE_SECTIONS.map((section) => section.name);
    const written = Object.keys(exportRealmFile(stateOf())).slice(2);
    expect(written).toEqual(IMPORT_SECTIONS.map((section) => section.name));
    expect(written.map((name) => order.indexOf(name))).toEqual(
      [...written.map((name) => order.indexOf(name))].sort((a, b) => a - b)
    );
    expect(Object.keys(exportRealmFile(stateOf(), [POLICIES_SECTION]))).toEqual([
      'format',
      'realm',
      'policies',
    ]);
  });
});

describe('realmFileDisposition (#530)', () => {
  it('names the file <realm>.realm.json', () => {
    expect(realmFileDisposition('acme')).toBe('attachment; filename="acme.realm.json"');
    expect(realmFileDisposition('acme-prod_2.eu')).toBe(
      'attachment; filename="acme-prod_2.eu.realm.json"'
    );
  });

  it('keeps a name of any characters out of the header syntax, and whole in filename*', () => {
    expect(realmFileDisposition('Müşteri "A"/B')).toBe(
      `attachment; filename="M__teri__A__B.realm.json"; filename*=UTF-8''M%C3%BC%C5%9Fteri%20%22A%22%2FB.realm.json`
    );
    const forged = realmFileDisposition('x"\r\nSet-Cookie: a=b; \\ ');
    // oxlint-disable-next-line no-control-regex
    expect(forged).not.toMatch(/[\u0000-\u001f\u007f\\]/);
    expect(forged.split('"')).toHaveLength(3);
    expect(realmFileDisposition('')).toBe('attachment; filename="realm.realm.json"');
    expect(realmFileDisposition('..')).toBe('attachment; filename="realm.realm.json"');
    expect(realmFileDisposition("o'neil")).toContain("filename*=UTF-8''o%27neil.realm.json");
  });
});

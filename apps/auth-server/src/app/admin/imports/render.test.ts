import { defaultsFromEnv } from '@qauth-labs/fastify-plugin-realm-policy';
import { parseRealmFile, realmFileClientSchema } from '@qauth-labs/realm-file';
import { describe, expect, it } from 'vitest';

import { planImport } from './plan';
import { LOOSENING_MARK, renderPlan } from './render';
import type { ImportState } from './section';

/**
 * The text of an import plan (#518): grouped by section, every loosening
 * change marked, and no secret anywhere in it.
 */

const REALM = '018f2d6e-8a8b-7c3d-9e0f-1a2b3c4d5e6f';
const CREDENTIAL = 'pa55-in-a-url';

type Document = Record<string, Record<string, unknown>>;

function policiesOf(edit: (document: Document) => void = () => undefined): Document {
  const document = structuredClone(defaultsFromEnv({})) as unknown as Document;
  edit(document);
  return document;
}

const APP = {
  client_id: 'app',
  name: 'App',
  grant_types: ['authorization_code'],
  redirect_uris: ['https://app.example.com/callback'],
  token_endpoint_auth_method: 'private_key_jwt',
  jwks_uri: 'https://app.example.com/jwks.json',
};

/** A realm whose smtp password is set, and whose client's key set URL carries a credential. */
const state = (): ImportState => ({
  realmId: REALM,
  realmName: 'acme',
  policiesVersion: 3,
  policies: policiesOf((document) => {
    document['mail']['provider'] = 'smtp';
    document['mail']['fromAddress'] = 'no-reply@example.com';
    document['mail']['smtp'] = {
      ...(document['mail']['smtp'] as object),
      host: 'smtp.example.com',
      port: 587,
      user: 'mailer',
    };
  }),
  setSecrets: ['mail.smtp.password'],
  clients: [
    {
      ...realmFileClientSchema.parse(APP),
      jwks_uri: `https://ops:${CREDENTIAL}@app.example.com/jwks.json`,
    },
    realmFileClientSchema.parse({
      client_id: 'old',
      name: 'Old',
      grant_types: ['client_credentials'],
    }),
  ],
  unmanagedClients: new Map(),
});

/** A file that loosens a policy, tightens one, moves the smtp server, changes and creates clients. */
const file = () =>
  parseRealmFile({
    realm: 'acme',
    policies: policiesOf((document) => {
      document['mail']['provider'] = 'smtp';
      document['mail']['fromAddress'] = 'no-reply@example.com';
      document['mail']['smtp'] = {
        ...(document['mail']['smtp'] as object),
        host: 'smtp.other.example.com',
        port: 587,
        user: 'mailer',
      };
      document['password']['minScore'] = 1;
      document['tokens']['accessTokenLifespanSeconds'] = 300;
    }),
    clients: [
      { ...APP, name: 'The App' },
      { client_id: 'new', name: 'New', grant_types: ['client_credentials'] },
    ],
  });

describe('renderPlan (#518)', () => {
  const plan = planImport(state(), file(), { prune: true });
  const text = renderPlan(plan);
  const lines = text.split('\n');

  it('groups the changes by section, in the plan’s order', () => {
    const headings = lines.filter((line) => /^[a-z_]+ \(\d+\)$/.test(line));
    expect(headings).toEqual([
      `policies (${plan.changes.filter((change) => change.section === 'policies').length})`,
      `clients (${plan.changes.filter((change) => change.section === 'clients').length})`,
    ]);
    expect(lines.indexOf(headings[0])).toBeLessThan(lines.indexOf(headings[1]));
  });

  it('marks every loosening change, and only those', () => {
    const changeLines = lines.filter((line) => /^[! ] [+~-] /.test(line));
    expect(changeLines).toHaveLength(plan.changes.length);
    plan.changes.forEach((change, index) => {
      expect(changeLines[index].startsWith(LOOSENING_MARK)).toBe(change.direction === 'loosening');
    });
    const loosened = changeLines.filter((line) => line.startsWith(LOOSENING_MARK));
    expect(loosened.some((line) => line.includes('password.minScore: 2 → 1'))).toBe(true);
    expect(loosened.some((line) => line.includes('app jwks_uri:'))).toBe(true);
    expect(loosened.some((line) => line.startsWith('! + new'))).toBe(true);
    const tightened = changeLines.find((line) =>
      line.includes('tokens.accessTokenLifespanSeconds')
    );
    expect(tightened?.startsWith(' ')).toBe(true);
    expect(changeLines.find((line) => line.includes('- old'))?.startsWith(' ')).toBe(true);
  });

  it('says what the plan needs, its digest and the secrets to set', () => {
    expect(text).toContain(`Digest: ${plan.digest}`);
    expect(text).toContain('Base: policies version 3; prune: yes');
    expect(text).toContain(
      'Needs: security, with an approval; scopes qauth:admin:write, qauth:admin:security'
    );
    expect(text).toContain('Secrets to set on the realm itself: mail.smtp.password');
    expect(text).toContain('needs a secret');
  });

  it('holds no secret: a URL’s credential is masked, a secret field shows only whether it is set', () => {
    expect(text).not.toContain(CREDENTIAL);
    expect(text).toContain('https://***@app.example.com/jwks.json');
    expect(text).not.toMatch(/"password"\s*:/);
  });

  it('says there is nothing to do for a file that matches the realm', () => {
    const current = state();
    const same = parseRealmFile({
      realm: 'acme',
      policies: current.policies,
      clients: [...current.clients].map((entry) =>
        entry.client_id === 'app' ? { ...entry, jwks_uri: APP.jwks_uri } : entry
      ),
    });
    const empty = planImport({ ...current, clients: same.clients ?? [] }, same);
    expect(empty.changes).toEqual([]);
    expect(renderPlan(empty)).toContain('No change: the file matches the realm.');
    expect(renderPlan(empty)).toContain('Needs: nothing');
  });

  it('shows a secret field as set or not set', () => {
    const secretPlan = {
      ...plan,
      changes: [
        {
          ...plan.changes[0],
          path: 'mail.smtp.password',
          before: true,
          after: false,
          secret: true,
        },
      ],
    };
    expect(renderPlan(secretPlan)).toContain('mail.smtp.password: set → not set');
  });
});

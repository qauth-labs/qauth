import { describe, expect, it, vi } from 'vitest';
import { z } from 'zod';

import { policyField } from './field';
import {
  createPolicyStore,
  PolicySchemaVersionError,
  PolicySecretStoreUnavailableError,
  PolicyVersionConflictError,
  RealmPolicyNotFoundError,
  type RealmPolicyRecord,
  RealmPolicySeedRefusedError,
  type RealmPolicyStorage,
  type RealmPolicyWrite,
} from './policy-store';
import { defaultsFromEnv, REALM_POLICY_ENV, REALM_POLICY_REGISTRY } from './realm-policies';
import { createPolicyRegistry, PolicyValidationError } from './registry';
import { createRealmSecretStore, type RealmSecretStore } from './secret-store';

/**
 * The policy store (#516) over an in-memory storage: reads join the stored
 * fields and the seeds, every write compares the counter and raises it, a
 * secret goes to the secret store and never into a stored document, and the
 * boot fills a realm with no policies and completes one that lacks fields,
 * once.
 */

/** A realm as the in-memory storage keeps it. */
interface MemoryRealm {
  id: string;
  name: string;
  version: number;
  schemaVersion: string | null;
  document: Record<string, unknown>;
  keptOnFill: Record<string, unknown>;
}

interface Tx {
  readonly id: number;
  readonly outer?: Tx;
}

/** An in-memory storage that records every write, with a hook to move a counter mid-update. */
function memoryStorage(realms: MemoryRealm[]) {
  const rows = new Map(realms.map((realm) => [realm.id, realm]));
  const writes: { realmId: string; write: RealmPolicyWrite; tx: Tx | undefined }[] = [];
  const locks: { realmId: string; tx: Tx }[] = [];
  const transactions: (Tx | undefined)[] = [];
  let nextTx = 1;
  let beforeWrite: ((realmId: string) => void) | undefined;
  let afterList: (() => void) | undefined;

  const recordOf = (realm: MemoryRealm): RealmPolicyRecord =>
    structuredClone({
      realmId: realm.id,
      realmName: realm.name,
      version: realm.version,
      schemaVersion: realm.schemaVersion,
      document: realm.document,
      keptOnFill: realm.version === 0 ? realm.keptOnFill : {},
    });

  const storage: RealmPolicyStorage<MemoryRealm, Tx> = {
    recordOf,
    async read(realmId) {
      const realm = rows.get(realmId);
      return realm === undefined ? undefined : recordOf(realm);
    },
    async list() {
      const listed = [...rows.values()].map(recordOf);
      afterList?.();
      return listed;
    },
    async readLocked(realmId, tx) {
      locks.push({ realmId, tx });
      const realm = rows.get(realmId);
      return realm === undefined ? undefined : recordOf(realm);
    },
    async write(realmId, write, tx) {
      writes.push({ realmId, write: structuredClone(write), tx });
      beforeWrite?.(realmId);
      const realm = rows.get(realmId);
      if (realm === undefined || realm.version !== write.expectedVersion) return undefined;
      realm.document = structuredClone(write.document);
      realm.schemaVersion = write.schemaVersion;
      realm.version = write.expectedVersion + 1;
      return recordOf(realm);
    },
    async transaction(work, outer) {
      transactions.push(outer);
      return work({ id: nextTx++, outer });
    },
  };
  return {
    storage,
    rows,
    writes,
    locks,
    transactions,
    onBeforeWrite(hook: (realmId: string) => void) {
      beforeWrite = hook;
    },
    /** Run `hook` once `list` has read the rows: a write another transaction commits after it. */
    onAfterList(hook: () => void) {
      afterList = hook;
    },
  };
}

/** A secret store that records what it is handed. */
function memorySecrets() {
  const puts: { realmId: string; path: string; value: string | null; tx: Tx | undefined }[] = [];
  const secrets: RealmSecretStore<Tx> = {
    async put(realmId, path, value, tx) {
      puts.push({ realmId, path, value, tx });
    },
    async isSet() {
      return false;
    },
    async getForUse() {
      return undefined;
    },
  };
  return { secrets, puts };
}

const SEEDS = defaultsFromEnv({ ACCESS_TOKEN_LIFESPAN: '600', PASSWORD_MIN_SCORE: '3' });
const SECRET = 'smtp-password-that-must-never-be-stored';

/** A realm that has its policies: the seeds, as a fill or a creation stores them. */
function realmWithPolicies(overrides: Partial<MemoryRealm> = {}): MemoryRealm {
  return {
    id: 'realm-a',
    name: 'master',
    version: 3,
    schemaVersion: '1-rc.0',
    document: structuredClone(SEEDS) as unknown as Record<string, unknown>,
    keptOnFill: {},
    ...overrides,
  };
}

/** A realm created before migration 0046: no policies, and a ceiling an operator set. */
function realmWithoutPolicies(overrides: Partial<MemoryRealm> = {}): MemoryRealm {
  return {
    id: 'realm-old',
    name: 'master',
    version: 0,
    schemaVersion: null,
    document: {},
    keptOnFill: { posture: { maxEnvironmentLaxity: 'development' } },
    ...overrides,
  };
}

function storeOver(realms: MemoryRealm[], secrets?: RealmSecretStore<Tx>) {
  const memory = memoryStorage(realms);
  const store = createPolicyStore({ storage: memory.storage, seeds: SEEDS, secrets });
  return { ...memory, store };
}

/** Every string anywhere in a value. */
function stringsIn(value: unknown): string[] {
  if (typeof value === 'string') return [value];
  if (Array.isArray(value)) return value.flatMap(stringsIn);
  if (typeof value === 'object' && value !== null) {
    return Object.entries(value).flatMap(([key, member]) => [key, ...stringsIn(member)]);
  }
  return [];
}

describe('createPolicyStore — reading', () => {
  it('reads a realm with policies as its stored document, at its counter', async () => {
    const { store } = storeOver([realmWithPolicies()]);

    const snapshot = await store.get('realm-a');

    expect(snapshot).toEqual({
      realmId: 'realm-a',
      version: 3,
      hasPolicies: true,
      schemaVersion: '1-rc.0',
      policies: SEEDS,
    });
    expect(snapshot?.policies.tokens.accessTokenLifespanSeconds).toBe(600);
  });

  it('answers undefined for a realm that does not exist', async () => {
    const { store } = storeOver([]);

    expect(await store.get('nowhere')).toBeUndefined();
  });

  it('reads a realm with no policies as its fill: the seeds and the row values the server read', async () => {
    const { store } = storeOver([realmWithoutPolicies()]);

    const snapshot = await store.get('realm-old');

    expect(snapshot?.version).toBe(0);
    expect(snapshot?.hasPolicies).toBe(false);
    expect(snapshot?.schemaVersion).toBe(REALM_POLICY_REGISTRY.version);
    expect(snapshot?.policies).toEqual({
      ...SEEDS,
      posture: { maxEnvironmentLaxity: 'development' },
    });
  });

  it('reads a field the stored document lacks, added by a later release, as its seed', async () => {
    const document = structuredClone(SEEDS) as unknown as Record<string, Record<string, unknown>>;
    delete document['password']['minScore'];
    const { store } = storeOver([realmWithPolicies({ document })]);

    expect((await store.get('realm-a'))?.policies.password.minScore).toBe(3);
  });

  it('reads a row the caller already loaded with no storage call', () => {
    const memory = memoryStorage([]);
    const read = vi.spyOn(memory.storage, 'read');
    const list = vi.spyOn(memory.storage, 'list');
    const store = createPolicyStore({ storage: memory.storage, seeds: SEEDS });

    const snapshot = store.ofRealm(realmWithPolicies({ version: 9 }));

    expect(snapshot.version).toBe(9);
    expect(snapshot.policies).toEqual(SEEDS);
    expect(read).not.toHaveBeenCalled();
    expect(list).not.toHaveBeenCalled();
  });

  it('hands out frozen copies, so changing one changes neither the store nor the next read', async () => {
    const { store } = storeOver([realmWithPolicies()]);
    const first = await store.get('realm-a');
    const tokens = first?.policies.tokens as { accessTokenLifespanSeconds: number };

    expect(Object.isFrozen(tokens)).toBe(true);
    expect(() => {
      tokens.accessTokenLifespanSeconds = 1;
    }).toThrow(TypeError);
    expect((await store.get('realm-a'))?.policies.tokens.accessTokenLifespanSeconds).toBe(600);
  });

  it('refuses a stored document that holds a secret value, naming the path and never the value', async () => {
    const document = structuredClone(SEEDS) as unknown as Record<
      string,
      Record<string, Record<string, unknown>>
    >;
    document['mail']['smtp']['password'] = SECRET;
    const { store } = storeOver([realmWithPolicies({ document })]);

    const refused = await store.get('realm-a').catch((error: unknown) => error);

    expect(refused).toBeInstanceOf(PolicyValidationError);
    expect((refused as PolicyValidationError).issues).toEqual([
      expect.objectContaining({ path: 'mail.smtp.password' }),
    ]);
    expect(JSON.stringify(refused)).not.toContain(SECRET);
    expect((refused as Error).message).not.toContain(SECRET);
  });

  it('refuses a stored value its field refuses', async () => {
    const document = structuredClone(SEEDS) as unknown as Record<string, Record<string, unknown>>;
    document['password']['minScore'] = 9;
    const { store } = storeOver([realmWithPolicies({ document })]);

    await expect(store.get('realm-a')).rejects.toBeInstanceOf(PolicyValidationError);
  });

  it('reads past members a later release stored, which this release does not know', async () => {
    const document = {
      ...structuredClone(SEEDS),
      sessions: { idleSeconds: 1800 },
      tokens: { ...structuredClone(SEEDS.tokens), idTokenLifespanSeconds: 300 },
    };
    const { store } = storeOver([realmWithPolicies({ document })]);

    expect((await store.get('realm-a'))?.policies).toEqual(SEEDS);
  });

  it('refuses seeds the schema refuses, when the store is created', () => {
    expect(() =>
      createPolicyStore({
        storage: memoryStorage([]).storage,
        seeds: { password: { minScore: 9 } },
      })
    ).toThrow(PolicyValidationError);
  });
});

describe('createPolicyStore — update', () => {
  it('applies a merge patch, stores the whole document and raises the counter', async () => {
    const { store, writes, rows } = storeOver([realmWithPolicies()]);

    const snapshot = await store.update(
      'realm-a',
      { tokens: { accessTokenLifespanSeconds: 300 }, password: { minScore: 4 } },
      { expectedVersion: 3 }
    );

    expect(snapshot.version).toBe(4);
    expect(snapshot.policies.tokens.accessTokenLifespanSeconds).toBe(300);
    expect(snapshot.policies.password.minScore).toBe(4);
    expect(snapshot.policies.tokens.refreshTokenLifespanSeconds).toBe(
      SEEDS.tokens.refreshTokenLifespanSeconds
    );
    expect(writes).toHaveLength(1);
    expect(writes[0].write.expectedVersion).toBe(3);
    expect(writes[0].write.schemaVersion).toBe(REALM_POLICY_REGISTRY.version);
    expect(REALM_POLICY_REGISTRY.parse(writes[0].write.document)).toEqual(snapshot.policies);
    expect(rows.get('realm-a')?.version).toBe(4);
  });

  it('refuses a stale expected counter and changes nothing', async () => {
    const { store, writes, rows } = storeOver([realmWithPolicies()]);

    const refused = await store
      .update('realm-a', { password: { minScore: 4 } }, { expectedVersion: 2 })
      .catch((error: unknown) => error);

    expect(refused).toBeInstanceOf(PolicyVersionConflictError);
    expect(refused).toMatchObject({ realmId: 'realm-a', expectedVersion: 2, currentVersion: 3 });
    expect(writes).toEqual([]);
    expect(rows.get('realm-a')?.version).toBe(3);
    expect(rows.get('realm-a')?.document).toEqual(SEEDS);
  });

  it('refuses when the counter moves between the read and the write, and sets no secret', async () => {
    const { secrets, puts } = memorySecrets();
    const memory = storeOver([realmWithPolicies()], secrets);
    memory.onBeforeWrite((realmId) => {
      const realm = memory.rows.get(realmId);
      if (realm) realm.version += 1;
    });

    await expect(
      memory.store.update(
        'realm-a',
        { mail: { smtp: { password: SECRET } } },
        { expectedVersion: 3 }
      )
    ).rejects.toMatchObject({ name: 'PolicyVersionConflictError', currentVersion: undefined });
    expect(puts).toEqual([]);
    expect(memory.rows.get('realm-a')?.document).toEqual(SEEDS);
  });

  it('refuses a realm that does not exist', async () => {
    const { store } = storeOver([]);

    await expect(store.update('nowhere', {}, { expectedVersion: 0 })).rejects.toBeInstanceOf(
      RealmPolicyNotFoundError
    );
  });

  it('refuses a merged document the schema refuses, with its path, and changes nothing', async () => {
    const { store, writes } = storeOver([realmWithPolicies()]);

    const refused = await store
      .update('realm-a', { password: { minScore: 9 } }, { expectedVersion: 3 })
      .catch((error: unknown) => error);

    expect(refused).toBeInstanceOf(PolicyValidationError);
    expect((refused as PolicyValidationError).issues).toEqual([
      expect.objectContaining({ path: 'password.minScore' }),
    ]);
    expect(writes).toEqual([]);
  });

  it('refuses a member the schema does not have, and __proto__', async () => {
    const { store, writes } = storeOver([realmWithPolicies()]);

    await expect(
      store.update('realm-a', { tokens: { lifetime: 5 } }, { expectedVersion: 3 })
    ).rejects.toBeInstanceOf(PolicyValidationError);
    await expect(
      store.update('realm-a', JSON.parse('{"__proto__": {"x": 1}}'), { expectedVersion: 3 })
    ).rejects.toMatchObject({ issues: [{ path: '__proto__' }] });
    await expect(store.update('realm-a', [], { expectedVersion: 3 })).rejects.toBeInstanceOf(
      PolicyValidationError
    );
    expect(writes).toEqual([]);
  });

  it('gives a member the patch sets to null its default, as RFC 7396 removes it', async () => {
    const { store } = storeOver([
      realmWithPolicies({
        document: {
          ...structuredClone(SEEDS),
          registration: {
            ...structuredClone(SEEDS.registration),
            cimd: { enabled: false, trustPolicy: 'allowlist', trustedDomains: ['example.com'] },
          },
        },
      }),
    ]);

    const snapshot = await store.update(
      'realm-a',
      { registration: { cimd: { trustPolicy: null } } },
      { expectedVersion: 3 }
    );

    expect(snapshot.policies.registration.cimd).toEqual({
      enabled: false,
      trustPolicy: 'accept-any-https',
      trustedDomains: ['example.com'],
    });
  });

  it('takes the representation back, its <name>Set flags dropped', async () => {
    const { store, writes } = storeOver([realmWithPolicies()]);
    const representation = REALM_POLICY_REGISTRY.toRepresentation(SEEDS, []);

    const snapshot = await store.update('realm-a', representation, { expectedVersion: 3 });

    expect(snapshot.policies).toEqual(SEEDS);
    expect(stringsIn(writes[0].write.document)).not.toContain('passwordSet');
  });

  it('fills a realm with no policies and applies the patch, from counter 0 to 1', async () => {
    const { store, rows } = storeOver([realmWithoutPolicies()]);

    const snapshot = await store.update(
      'realm-old',
      { password: { minScore: 4 } },
      { expectedVersion: 0 }
    );

    expect(snapshot.version).toBe(1);
    expect(snapshot.policies).toEqual({
      ...SEEDS,
      password: { minScore: 4 },
      posture: { maxEnvironmentLaxity: 'development' },
    });
    expect(rows.get('realm-old')?.schemaVersion).toBe(REALM_POLICY_REGISTRY.version);
  });

  it('carries over the members a later release stored, which this release does not know', async () => {
    const document = {
      ...structuredClone(SEEDS),
      sessions: { idleSeconds: 1800 },
      tokens: { ...structuredClone(SEEDS.tokens), idTokenLifespanSeconds: 300 },
    };
    const { store, rows } = storeOver([realmWithPolicies({ document })]);

    await store.update('realm-a', { password: { minScore: 4 } }, { expectedVersion: 3 });

    expect(rows.get('realm-a')?.document).toMatchObject({
      sessions: { idleSeconds: 1800 },
      tokens: { idTokenLifespanSeconds: 300 },
      password: { minScore: 4 },
    });
  });

  it('refuses to write policies that follow another schema version, changing nothing', async () => {
    const { store, writes } = storeOver([realmWithPolicies({ schemaVersion: '1-rc.7' })]);

    await expect(
      store.update('realm-a', { password: { minScore: 4 } }, { expectedVersion: 3 })
    ).rejects.toBeInstanceOf(PolicySchemaVersionError);
    expect(writes).toEqual([]);
  });

  it('refuses a stored member named __proto__, which would drop its group on the next write', async () => {
    const document = JSON.parse(
      JSON.stringify(SEEDS).replace('"mail":{', '"mail":{"__proto__":{"x":1},')
    ) as Record<string, unknown>;
    const { store, writes } = storeOver([realmWithPolicies({ document })]);

    await expect(store.get('realm-a')).rejects.toMatchObject({
      issues: [{ path: 'mail.__proto__' }],
    });
    await expect(store.update('realm-a', {}, { expectedVersion: 3 })).rejects.toBeInstanceOf(
      PolicyValidationError
    );
    expect(writes).toEqual([]);
  });

  it('writes in the transaction it is given, as a savepoint of it', async () => {
    const { secrets, puts } = memorySecrets();
    const { store, writes, transactions } = storeOver([realmWithPolicies()], secrets);
    const outer: Tx = { id: 100 };

    await store.update(
      'realm-a',
      { mail: { smtp: { password: SECRET } } },
      { expectedVersion: 3, tx: outer }
    );

    expect(transactions).toEqual([outer]);
    expect(writes[0].tx?.outer).toBe(outer);
    expect(puts[0].tx).toBe(writes[0].tx);
  });

  it('refuses an expected counter that is not a whole number, 0 or more', async () => {
    const { store } = storeOver([realmWithPolicies()]);

    for (const expectedVersion of [-1, 2.5, Number.NaN]) {
      await expect(store.update('realm-a', {}, { expectedVersion })).rejects.toThrow(TypeError);
    }
  });
});

describe('createPolicyStore — secrets never reach the stored document', () => {
  it('refuses a patch that sets or clears a secret while there is no secret store, writing nothing', async () => {
    const { store, writes } = storeOver([realmWithPolicies()]);

    for (const patch of [
      { mail: { smtp: { password: SECRET } } },
      { mail: { resend: { apiKey: null } } },
      { password: { minScore: 4 }, mail: { smtp: { password: SECRET } } },
    ]) {
      const refused = await store
        .update('realm-a', patch, { expectedVersion: 3 })
        .catch((error: unknown) => error);
      expect(refused).toBeInstanceOf(PolicySecretStoreUnavailableError);
      expect((refused as Error).message).not.toContain(SECRET);
    }
    expect(writes).toEqual([]);
  });

  it('hands a secret to the secret store and stores a document without it', async () => {
    const { secrets, puts } = memorySecrets();
    const { store, writes, rows } = storeOver([realmWithPolicies()], secrets);

    const snapshot = await store.update(
      'realm-a',
      {
        mail: {
          provider: 'smtp',
          // A whole smtp transport: the mail rule (#529) refuses one without
          // its host, port, user, password or sender.
          fromAddress: 'no-reply@example.com',
          smtp: { host: 'smtp.example.com', port: 587, user: 'mailer', password: SECRET },
          resend: { apiKey: null },
        },
      },
      { expectedVersion: 3 }
    );

    expect(puts.map(({ realmId, path, value }) => ({ realmId, path, value }))).toEqual([
      { realmId: 'realm-a', path: 'mail.smtp.password', value: SECRET },
      { realmId: 'realm-a', path: 'mail.resend.apiKey', value: null },
    ]);
    expect(snapshot.policies.mail.smtp.host).toBe('smtp.example.com');
    for (const stored of [writes[0].write.document, rows.get('realm-a')?.document]) {
      expect(stringsIn(stored)).not.toContain(SECRET);
      expect(JSON.stringify(stored)).not.toContain(SECRET);
      const mail = (stored as { mail: Record<string, Record<string, unknown>> }).mail;
      expect(Object.keys(mail['smtp'])).not.toContain('password');
      expect(Object.keys(mail['resend'] ?? {})).not.toContain('apiKey');
    }
    expect(JSON.stringify(snapshot)).not.toContain(SECRET);
  });

  it('refuses a secret value its field refuses without repeating it, writing nothing', async () => {
    const { secrets, puts } = memorySecrets();
    const { store, writes } = storeOver([realmWithPolicies()], secrets);

    for (const value of ['', 42, { nested: SECRET }, 'x'.repeat(1025)]) {
      const refused = await store
        .update('realm-a', { mail: { smtp: { password: value } } }, { expectedVersion: 3 })
        .catch((error: unknown) => error);
      expect(refused).toBeInstanceOf(PolicyValidationError);
      expect((refused as PolicyValidationError).issues).toEqual([
        { path: 'mail.smtp.password', message: expect.any(String) },
      ]);
      expect(JSON.stringify(refused)).not.toContain(SECRET);
    }
    expect(writes).toEqual([]);
    expect(puts).toEqual([]);
  });

  it('refuses seeds that hold a secret when the store is created, before any write', async () => {
    const memory = memoryStorage([realmWithoutPolicies()]);
    const seeds = { ...structuredClone(SEEDS), mail: { ...structuredClone(SEEDS.mail) } };
    (seeds.mail.smtp as Record<string, unknown>)['password'] = SECRET;

    expect(() => createPolicyStore({ storage: memory.storage, seeds })).toThrow(
      PolicyValidationError
    );
    expect(memory.writes).toEqual([]);
  });
});

describe('createPolicyStore — seedRealms', () => {
  it('fills a realm with no policies with the seeds and the row values the server read', async () => {
    const { store, rows } = storeOver([realmWithoutPolicies()]);

    const report = await store.seedRealms();

    expect(report).toEqual({
      filled: [
        {
          realmId: 'realm-old',
          realmName: 'master',
          keptFromRow: [{ path: 'posture.maxEnvironmentLaxity', differsFromSeed: true }],
        },
      ],
      completed: [],
      skipped: [],
    });
    expect(rows.get('realm-old')).toMatchObject({
      version: 1,
      schemaVersion: REALM_POLICY_REGISTRY.version,
      document: { ...SEEDS, posture: { maxEnvironmentLaxity: 'development' } },
    });
  });

  it('reports each field the fill kept from the row, and whether it differs from the seed', async () => {
    // The seed lists the scopes in another order: a set field's list is the
    // same whatever its order and repeats.
    const { store } = storeOver([
      realmWithoutPolicies({
        keptOnFill: {
          posture: { maxEnvironmentLaxity: 'production' },
          registration: {
            dynamicRegistrationAllowedScopes: [
              'offline_access',
              'email',
              'profile',
              'openid',
              'email',
            ],
          },
        },
      }),
      realmWithoutPolicies({
        id: 'realm-tenant',
        name: 'tenant',
        keptOnFill: { registration: { dynamicRegistrationAllowedScopes: ['openid'] } },
      }),
    ]);

    const { filled } = await store.seedRealms();

    expect(filled).toEqual([
      {
        realmId: 'realm-old',
        realmName: 'master',
        keptFromRow: [
          { path: 'registration.dynamicRegistrationAllowedScopes', differsFromSeed: false },
          { path: 'posture.maxEnvironmentLaxity', differsFromSeed: false },
        ],
      },
      {
        realmId: 'realm-tenant',
        realmName: 'tenant',
        keptFromRow: [
          { path: 'registration.dynamicRegistrationAllowedScopes', differsFromSeed: true },
        ],
      },
    ]);
  });

  it('computes a fill from the row read locked, in its transaction, not from the list', async () => {
    // A plain write of the row (a previous release's node) commits after the
    // list: the trigger keeps the counter at 0, so only the locked read sees
    // it, and the operator's tightened ceiling survives the fill.
    const memory = memoryStorage([realmWithoutPolicies()]);
    memory.onAfterList(() => {
      const realm = memory.rows.get('realm-old');
      if (realm) realm.keptOnFill = { posture: { maxEnvironmentLaxity: 'production' } };
    });
    const store = createPolicyStore({ storage: memory.storage, seeds: SEEDS });

    await store.seedRealms();

    expect(memory.locks).toEqual([{ realmId: 'realm-old', tx: memory.writes[0].tx }]);
    expect(memory.rows.get('realm-old')?.document).toMatchObject({
      posture: { maxEnvironmentLaxity: 'production' },
    });
  });

  it('writes no realm that has its policies: a later change of the environment changes nothing', async () => {
    const memory = memoryStorage([realmWithPolicies()]);
    const store = createPolicyStore({
      storage: memory.storage,
      seeds: defaultsFromEnv({ ACCESS_TOKEN_LIFESPAN: '60', PASSWORD_MIN_SCORE: '0' }),
    });

    expect(await store.seedRealms()).toEqual({ filled: [], completed: [], skipped: [] });
    expect(memory.writes).toEqual([]);
    expect(memory.locks).toEqual([]);
    expect(memory.rows.get('realm-a')?.document).toEqual(SEEDS);
  });

  it('completes a realm that lacks fields of this release from the seeds, once', async () => {
    const document = structuredClone(SEEDS) as unknown as Record<string, Record<string, unknown>>;
    delete document['password'];
    delete document['tokens']['developmentAccessTokenLifespanSeconds'];
    const { store, rows, writes } = storeOver([realmWithPolicies({ document })]);

    const report = await store.seedRealms();

    expect(report.completed).toEqual([
      {
        realmId: 'realm-a',
        realmName: 'master',
        paths: ['tokens.developmentAccessTokenLifespanSeconds', 'password.minScore'],
      },
    ]);
    expect(rows.get('realm-a')).toMatchObject({ version: 4, document: SEEDS });
    expect(await store.seedRealms()).toEqual({ filled: [], completed: [], skipped: [] });
    expect(writes).toHaveLength(1);
  });

  it('drops the repeats of a list the row kept, which an earlier release copied as written', async () => {
    const { store, rows } = storeOver([
      realmWithoutPolicies({
        keptOnFill: {
          registration: { dynamicRegistrationAllowedScopes: ['openid', 'email', 'openid'] },
        },
      }),
    ]);

    expect((await store.seedRealms()).filled).toHaveLength(1);
    expect(rows.get('realm-old')?.document).toMatchObject({
      registration: { dynamicRegistrationAllowedScopes: ['openid', 'email'] },
    });
  });

  it('leaves a realm whose policies follow another schema version as it is, and says so', async () => {
    const document = structuredClone(SEEDS) as unknown as Record<string, Record<string, unknown>>;
    delete document['password'];
    const { store, writes } = storeOver([realmWithPolicies({ document, schemaVersion: '1-rc.7' })]);

    expect(await store.seedRealms()).toEqual({
      filled: [],
      completed: [],
      skipped: [{ realmId: 'realm-a', realmName: 'master', schemaVersion: '1-rc.7' }],
    });
    expect(writes).toEqual([]);
  });

  it('does not read a realm that has every field, so a stored value it refuses does not stop the boot', async () => {
    const document = structuredClone(SEEDS) as unknown as Record<string, Record<string, unknown>>;
    document['password']['minScore'] = 9;
    const { store } = storeOver([realmWithPolicies({ document })]);

    expect(await store.seedRealms()).toEqual({ filled: [], completed: [], skipped: [] });
  });

  it('reports nothing for a realm another writer got to first', async () => {
    const memory = storeOver([realmWithoutPolicies()]);
    memory.onBeforeWrite((realmId) => {
      const realm = memory.rows.get(realmId);
      if (realm) realm.version = 1;
    });

    expect(await memory.store.seedRealms()).toEqual({ filled: [], completed: [], skipped: [] });
  });

  it('refuses the boot when a fill is not a valid document, naming the realm and path only', async () => {
    const { store, writes } = storeOver([
      realmWithoutPolicies({
        name: 'legacy',
        keptOnFill: { registration: { dynamicRegistrationAllowedScopes: ['bad scope'] } },
      }),
    ]);

    const refused = await store.seedRealms().catch((error: unknown) => error);

    expect(refused).toBeInstanceOf(RealmPolicySeedRefusedError);
    expect(refused).toMatchObject({ realmName: 'legacy' });
    expect((refused as Error).message).toContain('registration.dynamicRegistrationAllowedScopes');
    expect((refused as Error).message).not.toContain('bad scope');
    expect(writes).toEqual([]);
  });

  it('runs in the transaction it is given', async () => {
    const { store, transactions, writes } = storeOver([realmWithoutPolicies()]);
    const outer: Tx = { id: 7 };

    await store.seedRealms(outer);

    expect(transactions).toEqual([outer]);
    expect(writes[0].tx?.outer).toBe(outer);
  });

  it('completes a group another area registers after a realm got its policies', async () => {
    const registry = createPolicyRegistry({ env: REALM_POLICY_ENV });
    registry.registerPolicyGroup('password', {
      minScore: policyField(z.number().int().min(0).max(4), {
        seedEnv: 'PASSWORD_MIN_SCORE',
        default: 2,
        direction: 'higher-is-stricter',
        securityWhen: 'loosening',
        effects: ['credential-path'],
        secret: false,
        environmentBound: false,
        doc: { summary: 'The lowest score.', link: 'https://docs.qauth.dev/' },
      }),
    });
    const stored = { id: 'r', name: 'r', version: 2, schemaVersion: '1-rc.0', keptOnFill: {} };
    const memory = memoryStorage([{ ...stored, document: { password: { minScore: 1 } } }]);
    const before = createPolicyStore({
      storage: memory.storage,
      seeds: registry.defaultsFromEnv({}),
      registry,
    });
    expect(await before.seedRealms()).toEqual({ filled: [], completed: [], skipped: [] });

    registry.registerPolicyGroup('sessions', {
      idleSeconds: policyField(z.number().int().positive(), {
        seedEnv: 'SESSION_IDLE_TIMEOUT_TEST',
        default: 1800,
        direction: 'lower-is-stricter',
        securityWhen: 'loosening',
        effects: ['posture-loosening'],
        secret: false,
        environmentBound: false,
        doc: { summary: 'Idle.', link: 'https://docs.qauth.dev/' },
      }),
    });
    const after = createPolicyStore({
      storage: memory.storage,
      seeds: registry.defaultsFromEnv({
        SESSION_IDLE_TIMEOUT_TEST: '600',
        PASSWORD_MIN_SCORE: '4',
      }),
      registry,
    });

    expect((await after.seedRealms()).completed).toEqual([
      { realmId: 'r', realmName: 'r', paths: ['sessions.idleSeconds'] },
    ]);
    // The new group from the environment, the field the realm had as it was.
    expect(memory.rows.get('r')?.document).toEqual({
      password: { minScore: 1 },
      sessions: { idleSeconds: 600 },
    });
  });
});

/**
 * A working secret store over memory (#529): values encrypted by a stand-in
 * cipher in the signer's format, so `isSet` and `getForUse` answer what
 * `put` stored.
 */
function workingSecrets() {
  const rows = new Map<string, { ciphertext: string; keyId: string } | null>();
  const keyOf = (realmId: string, path: string) => `${realmId} ${path}`;
  const flip = (bytes: Buffer) => Buffer.from(bytes.map((byte) => byte ^ 0x5a));
  const secrets = createRealmSecretStore<Tx>({
    storage: {
      async read(realmId, path) {
        const key = keyOf(realmId, path);
        return rows.has(key) ? { ciphertext: rows.get(key)?.ciphertext ?? null } : undefined;
      },
      async write(realmId, path, value) {
        rows.set(keyOf(realmId, path), value);
      },
      async insertIfAbsent(realmId, path, value) {
        if (rows.has(keyOf(realmId, path))) return false;
        rows.set(keyOf(realmId, path), value);
        return true;
      },
    },
    cipher: {
      encrypt: async ({ plaintext }) =>
        `v1.kid-1.${'A'.repeat(16)}.${flip(Buffer.from(plaintext)).toString('base64url')}`,
      decrypt: async ({ ciphertext }) =>
        flip(Buffer.from(ciphertext.split('.')[3] ?? '', 'base64url')).toString('utf8'),
    },
  });
  return { secrets, rows };
}

/** A whole smtp transport but its password. */
const SMTP_TRANSPORT = {
  provider: 'smtp',
  fromAddress: 'no-reply@example.com',
  smtp: { host: 'smtp.example.com', port: 587, user: 'mailer' },
} as const;

describe('createPolicyStore — the mail transport rule on every update (#529)', () => {
  /** The issues of a refused update, or a failure when it was not refused. */
  async function refusedIssues(update: Promise<unknown>) {
    const refused = await update.then(
      () => undefined,
      (error: unknown) => error
    );
    expect(refused).toBeInstanceOf(PolicyValidationError);
    return (refused as PolicyValidationError).issues;
  }

  it('refuses smtp without a password, writing nothing', async () => {
    const { secrets } = workingSecrets();
    const { store, writes } = storeOver([realmWithPolicies()], secrets);

    const issues = await refusedIssues(
      store.update('realm-a', { mail: SMTP_TRANSPORT }, { expectedVersion: 3 })
    );

    expect(issues).toEqual([
      { path: 'mail.smtp.password', message: 'must be set when mail.provider is smtp' },
    ]);
    expect(writes).toEqual([]);
    expect(await secrets.isSet('realm-a', 'mail.smtp.password')).toBe(false);
  });

  it('refuses smtp without its host, port, user or sender, naming each path', async () => {
    const { secrets } = workingSecrets();
    const { store, writes } = storeOver([realmWithPolicies()], secrets);

    const issues = await refusedIssues(
      store.update(
        'realm-a',
        { mail: { provider: 'smtp', smtp: { password: SECRET } } },
        { expectedVersion: 3 }
      )
    );

    expect(issues.map((issue) => issue.path)).toEqual([
      'mail.fromAddress',
      'mail.smtp.host',
      'mail.smtp.port',
      'mail.smtp.user',
    ]);
    expect(JSON.stringify(issues)).not.toContain(SECRET);
    expect(writes).toEqual([]);
    // The password of the refused update was never stored either.
    expect(await secrets.isSet('realm-a', 'mail.smtp.password')).toBe(false);
  });

  it('accepts smtp with the password the same update sets', async () => {
    const { secrets, rows } = workingSecrets();
    const { store } = storeOver([realmWithPolicies()], secrets);

    const snapshot = await store.update(
      'realm-a',
      { mail: { ...SMTP_TRANSPORT, smtp: { ...SMTP_TRANSPORT.smtp, password: SECRET } } },
      { expectedVersion: 3 }
    );

    expect(snapshot.policies.mail.provider).toBe('smtp');
    expect(await secrets.getForUse('realm-a', 'mail.smtp.password')).toBe(SECRET);
    expect(JSON.stringify([...rows])).not.toContain(SECRET);
  });

  it('accepts a later update while the stored password stays set, and refuses one that clears it', async () => {
    const { secrets } = workingSecrets();
    const { store } = storeOver([realmWithPolicies()], secrets);
    await store.update(
      'realm-a',
      { mail: { ...SMTP_TRANSPORT, smtp: { ...SMTP_TRANSPORT.smtp, password: SECRET } } },
      { expectedVersion: 3 }
    );

    // Another group, then another mail field: the password is still set.
    await store.update(
      'realm-a',
      { tokens: { accessTokenLifespanSeconds: 300 } },
      { expectedVersion: 4 }
    );
    await store.update('realm-a', { mail: { fromName: 'Example' } }, { expectedVersion: 5 });

    const issues = await refusedIssues(
      store.update('realm-a', { mail: { smtp: { password: null } } }, { expectedVersion: 6 })
    );
    expect(issues).toEqual([
      { path: 'mail.smtp.password', message: 'must be set when mail.provider is smtp' },
    ]);
    expect(await secrets.getForUse('realm-a', 'mail.smtp.password')).toBe(SECRET);

    // Back to mock, the password may go.
    await store.update(
      'realm-a',
      { mail: { provider: 'mock', smtp: { password: null } } },
      { expectedVersion: 6 }
    );
    expect(await secrets.isSet('realm-a', 'mail.smtp.password')).toBe(false);
  });

  it('refuses resend without an API key and accepts it with one', async () => {
    const { secrets } = workingSecrets();
    const { store } = storeOver([realmWithPolicies()], secrets);
    const resend = { provider: 'resend', fromAddress: 'no-reply@example.com' } as const;

    expect(
      await refusedIssues(store.update('realm-a', { mail: resend }, { expectedVersion: 3 }))
    ).toEqual([
      { path: 'mail.resend.apiKey', message: 'must be set when mail.provider is resend' },
    ]);

    await store.update(
      'realm-a',
      { mail: { ...resend, resend: { apiKey: 're_key' } } },
      { expectedVersion: 3 }
    );
    expect(await secrets.isSet('realm-a', 'mail.resend.apiKey')).toBe(true);
  });

  it('refuses a non-mock transport on a server without a secret store', async () => {
    const { store } = storeOver([realmWithPolicies()]);

    expect(
      await refusedIssues(store.update('realm-a', { mail: SMTP_TRANSPORT }, { expectedVersion: 3 }))
    ).toEqual([{ path: 'mail.smtp.password', message: expect.any(String) }]);
    // Mock needs nothing.
    await store.update('realm-a', { mail: { provider: 'mock' } }, { expectedVersion: 3 });
  });

  it('runs no rule for another registry unless given one', async () => {
    const registry = createPolicyRegistry({ version: '1-rc.0' });
    registry.registerPolicyGroup('sample', {
      size: policyField(z.number().int(), {
        seedEnv: null,
        default: 1,
        direction: 'lower-is-stricter',
        securityWhen: 'never',
        effects: [],
        secret: false,
        environmentBound: false,
        doc: { summary: 'A size.', link: 'https://docs.qauth.dev/reference/realm-policies/' },
      }),
    });
    const rule = vi.fn(() => [{ path: 'sample.size', message: 'is never right' }]);
    const realm = realmWithPolicies({ document: { sample: { size: 1 } } });

    const plain = createPolicyStore({
      storage: memoryStorage([structuredClone(realm)]).storage,
      seeds: {},
      registry,
    });
    await plain.update('realm-a', { sample: { size: 2 } }, { expectedVersion: 3 });

    const ruled = createPolicyStore({
      storage: memoryStorage([structuredClone(realm)]).storage,
      seeds: {},
      registry,
      rules: [rule],
    });
    expect(
      await refusedIssues(ruled.update('realm-a', { sample: { size: 2 } }, { expectedVersion: 3 }))
    ).toEqual([{ path: 'sample.size', message: 'is never right' }]);
    expect(rule).toHaveBeenCalledWith(
      { sample: { size: 2 } },
      expect.objectContaining({ isSet: expect.any(Function) })
    );
  });
});

describe('createPolicyStore — the representation (#529)', () => {
  it('shows passwordSet: true and never the password', async () => {
    const { secrets } = workingSecrets();
    const { store } = storeOver([realmWithPolicies()], secrets);
    await store.update(
      'realm-a',
      { mail: { ...SMTP_TRANSPORT, smtp: { ...SMTP_TRANSPORT.smtp, password: SECRET } } },
      { expectedVersion: 3 }
    );

    const representation = await store.representation('realm-a');

    const mail = representation?.policies['mail'] as Record<string, Record<string, unknown>>;
    expect(mail['smtp']).toEqual({
      host: 'smtp.example.com',
      port: 587,
      secure: true,
      user: 'mailer',
      passwordSet: true,
    });
    expect(mail['resend']).toEqual({ apiKeySet: false });
    expect(representation?.version).toBe(4);
    expect(stringsIn(representation)).not.toContain(SECRET);
    expect(JSON.stringify(representation)).not.toContain(SECRET);
  });

  it('shows every secret unset without a secret store, and nothing for an unknown realm', async () => {
    const { store } = storeOver([realmWithPolicies()]);

    const mail = (await store.representation('realm-a'))?.policies['mail'] as Record<
      string,
      Record<string, unknown>
    >;
    expect(mail['smtp']?.['passwordSet']).toBe(false);
    expect(mail['resend']).toEqual({ apiKeySet: false });
    expect(await store.representation('no-such-realm')).toBeUndefined();
  });
});

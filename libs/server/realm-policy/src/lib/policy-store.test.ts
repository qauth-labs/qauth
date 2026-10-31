import { describe, expect, it, vi } from 'vitest';
import { z } from 'zod';

import { policyField } from './field';
import {
  createPolicyStore,
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
import type { RealmSecretStore } from './secret-store';

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
  const transactions: (Tx | undefined)[] = [];
  let nextTx = 1;
  let beforeWrite: ((realmId: string) => void) | undefined;

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
      return [...rows.values()].map(recordOf);
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
    transactions,
    onBeforeWrite(hook: (realmId: string) => void) {
      beforeWrite = hook;
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

/** A realm created before migration 0045: no policies, and a ceiling an operator set. */
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
          smtp: { host: 'smtp.example.com', password: SECRET },
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

  it('keeps a secret out of every write of the boot fill, whatever the seeds were given', async () => {
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
      filled: [{ realmId: 'realm-old', realmName: 'master' }],
      completed: [],
    });
    expect(rows.get('realm-old')).toMatchObject({
      version: 1,
      schemaVersion: REALM_POLICY_REGISTRY.version,
      document: { ...SEEDS, posture: { maxEnvironmentLaxity: 'development' } },
    });
  });

  it('writes no realm that has its policies: a later change of the environment changes nothing', async () => {
    const memory = memoryStorage([realmWithPolicies()]);
    const store = createPolicyStore({
      storage: memory.storage,
      seeds: defaultsFromEnv({ ACCESS_TOKEN_LIFESPAN: '60', PASSWORD_MIN_SCORE: '0' }),
    });

    expect(await store.seedRealms()).toEqual({ filled: [], completed: [] });
    expect(memory.writes).toEqual([]);
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
    expect(await store.seedRealms()).toEqual({ filled: [], completed: [] });
    expect(writes).toHaveLength(1);
  });

  it('reports nothing for a realm another writer got to first', async () => {
    const memory = storeOver([realmWithoutPolicies()]);
    memory.onBeforeWrite((realmId) => {
      const realm = memory.rows.get(realmId);
      if (realm) realm.version = 1;
    });

    expect(await memory.store.seedRealms()).toEqual({ filled: [], completed: [] });
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
    expect(await before.seedRealms()).toEqual({ filled: [], completed: [] });

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

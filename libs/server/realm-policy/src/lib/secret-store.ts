import { REALM_POLICY_REGISTRY } from './realm-policies';
import { type PolicyRegistry, PolicyValidationError, type RegisteredPolicyField } from './registry';

/**
 * Where a realm keeps the values of its secret policy fields (ADR-019
 * Decisions 9 and 10, issue #516), such as `mail.smtp.password`. A secret is
 * never in the policy document: not on the realm row, not in the admin API's
 * representation (which shows `<name>Set`), not in the realm file. The policy
 * store hands every secret a write sets or clears to this store, in the
 * write's transaction.
 *
 * {@link createRealmSecretStore} implements it (#529): each value is
 * encrypted with the realm's data-at-rest key through the signer, and only
 * the ciphertext is stored (`realm_secrets`). Without one, the policy store
 * refuses every write that sets or clears a secret.
 *
 * Every method takes a realm id and a secret field's path, as the registry
 * names it. An implementation refuses a path that is not a secret field
 * ({@link realmSecretPaths}), and never repeats a value in an error or a log.
 */
export interface RealmSecretStore<Tx = unknown> {
  /**
   * Set the secret at `path` to `value`, or clear it with `null`, in `tx`
   * when one is given: a policy update commits its document and its secrets
   * together, or neither.
   */
  put(realmId: string, path: string, value: string | null, tx?: Tx): Promise<void>;
  /** Whether the secret at `path` holds a value: what the representation shows as `<name>Set`. */
  isSet(realmId: string, path: string, tx?: Tx): Promise<boolean>;
  /**
   * The value of the secret at `path`, or `undefined` when it holds none, for
   * the one component that uses it (the realm's mail sender for the mail
   * secrets). Never for a response, a log, an audit record or an export.
   */
  getForUse(realmId: string, path: string): Promise<string | undefined>;
}

/** The paths of the secret fields of `registry`: the names a {@link RealmSecretStore} keeps values under. */
export function realmSecretPaths(registry: PolicyRegistry = REALM_POLICY_REGISTRY): string[] {
  return registry
    .fields()
    .filter((entry) => entry.field.secret)
    .map((entry) => entry.path);
}

/**
 * The environment key that seeds each secret field of `registry`, by path
 * (`mail.smtp.password` → `SMTP_PASSWORD`): what the boot's seed and its log
 * lines name.
 */
export function secretSeedKeys(
  registry: PolicyRegistry = REALM_POLICY_REGISTRY
): ReadonlyMap<string, string> {
  return new Map(
    registry
      .fields()
      .filter((entry) => entry.field.secret && entry.field.seedEnv !== null)
      .map((entry) => [entry.path, entry.field.seedEnv as string])
  );
}

/** A secret's value as {@link RealmSecretStorage} stores it: ciphertext, and the key that made it. */
export interface EncryptedRealmSecret {
  /** The signer's `data_at_rest` ciphertext, `v1.<kid>.<iv>.<ciphertext>`. */
  readonly ciphertext: string;
  /** The `kid` the ciphertext names. */
  readonly keyId: string;
}

/**
 * The storage port of {@link createRealmSecretStore}: one row per realm and
 * secret path, holding ciphertext or nothing (`null`). The database library
 * implements it over `realm_secrets`; a test, in memory.
 */
export interface RealmSecretStorage<Tx> {
  /**
   * The secret's row: its ciphertext, `null` when it holds none, or
   * `undefined` when the realm has no row for it.
   */
  read(realmId: string, path: string, tx?: Tx): Promise<{ ciphertext: string | null } | undefined>;
  /** Set the row to `value`, or to none with `null`, creating it. */
  write(realmId: string, path: string, value: EncryptedRealmSecret | null, tx?: Tx): Promise<void>;
  /**
   * Create the row with `value` unless the realm has one, whatever it holds.
   *
   * @returns whether this call created it
   */
  insertIfAbsent(
    realmId: string,
    path: string,
    value: EncryptedRealmSecret | null,
    tx?: Tx
  ): Promise<boolean>;
}

/**
 * How a realm secret store encrypts and decrypts: the signer's `data_at_rest`
 * operations (`Signer.encrypt` and `Signer.decrypt`), with the role of the
 * component that calls. The context is authenticated, so a ciphertext only
 * decrypts for the realm and the field it was made for.
 */
export interface RealmSecretCipher {
  encrypt(request: {
    readonly realmId: string;
    readonly plaintext: string;
    readonly context: string;
  }): Promise<string>;
  decrypt(request: {
    readonly realmId: string;
    readonly ciphertext: string;
    readonly context: string;
  }): Promise<string>;
}

/**
 * The prefix of every realm secret's encryption context. It is not the
 * signer's `delivery:` prefix, so the delivery role, which may decrypt only a
 * destination's secret, cannot decrypt a realm secret.
 */
export const REALM_SECRET_CONTEXT_PREFIX = 'realm_secrets:';

/** The encryption context of the secret at `path`: it names the field, so a ciphertext copied to another field does not decrypt. */
export function realmSecretContext(path: string): string {
  return `${REALM_SECRET_CONTEXT_PREFIX}${path}`;
}

/** What {@link RealmSecretStoreWithSeed.seed} did, by secret path. Never a value. */
export interface RealmSecretSeedReport {
  /** The secrets this call stored from the environment. */
  readonly seeded: readonly string[];
  /**
   * The secrets the environment does not set, which this call recorded as
   * holding none: a later boot does not seed them either.
   */
  readonly recordedUnset: readonly string[];
  /** The secrets the realm already had a row for, set or not, which this call left alone. */
  readonly present: readonly string[];
  /**
   * The secrets the environment does not set, or `seeds` leaves out, that
   * this call left without a row as `options.leaveWithoutRow` asks: a later
   * seed may still store them.
   */
  readonly leftWithoutRow: readonly string[];
}

/** How {@link RealmSecretStoreWithSeed.seed} runs. */
export interface RealmSecretSeedOptions<Tx> {
  /**
   * The secrets to leave without a row when `seeds` has no value for them,
   * rather than record them as holding none: a secret the realm's transport
   * needs (#529, from the review of #937), so a later boot whose environment
   * sets it still stores it. A policy update's clear (`put(null)`) records
   * its row whatever this says.
   */
  readonly leaveWithoutRow?: ReadonlySet<string>;
  readonly tx?: Tx;
}

/** The realm secret store, with the boot's seed from the environment. */
export interface RealmSecretStoreWithSeed<Tx> extends RealmSecretStore<Tx> {
  /**
   * Seed the realm's secrets from the environment, once (#529): every secret
   * field that has a seed key and no row in the realm gets the value `seeds`
   * holds for its path, or a row that holds none when `seeds` has no value
   * (unless `options.leaveWithoutRow` names it: then no row). A secret that
   * has a row, set or cleared, is never written: a later change of the
   * environment changes no realm, as for every policy (ADR-019 Decision
   * 10). Of two nodes that seed together, the first write wins.
   *
   * @param seeds - the secret values by path, as `secretSeedsFromEnv` reads
   *   them, less any the caller must not store in this realm
   */
  seed(
    realmId: string,
    seeds: ReadonlyMap<string, string>,
    options?: RealmSecretSeedOptions<Tx>
  ): Promise<RealmSecretSeedReport>;
}

/** What {@link createRealmSecretStore} takes. */
export interface RealmSecretStoreOptions<Tx> {
  readonly storage: RealmSecretStorage<Tx>;
  readonly cipher: RealmSecretCipher;
  /** The registry whose secret fields the store keeps; {@link REALM_POLICY_REGISTRY} by default. */
  readonly registry?: PolicyRegistry;
}

/** A ciphertext in the signer's `data_at_rest` format, and its `kid`. */
const CIPHERTEXT_PATTERN = /^v1\.([A-Za-z0-9_-]{1,255})\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

/**
 * Create a realm secret store over `options.storage` (#529). Each value is
 * encrypted by `options.cipher` under {@link realmSecretContext} before it
 * is stored, and decrypted only by {@link RealmSecretStore.getForUse}.
 *
 * Every refusal names a path and never a value: a path that is not a secret
 * field of the registry is a `TypeError`, and a value its field's type
 * refuses a `PolicyValidationError`.
 */
export function createRealmSecretStore<Tx>(
  options: RealmSecretStoreOptions<Tx>
): RealmSecretStoreWithSeed<Tx> {
  const { storage, cipher } = options;
  const registry = options.registry ?? REALM_POLICY_REGISTRY;
  const secrets = new Map<string, RegisteredPolicyField>(
    registry
      .fields()
      .filter((entry) => entry.field.secret)
      .map((entry) => [entry.path, entry])
  );

  function secretField(path: string): RegisteredPolicyField {
    const entry = typeof path === 'string' ? secrets.get(path) : undefined;
    // Never repeat the path: a value passed in its place by mistake would
    // reach the message.
    if (entry === undefined)
      throw new TypeError('The path is not a secret field of the realm policies');
    return entry;
  }

  async function encrypt(
    realmId: string,
    entry: RegisteredPolicyField,
    value: unknown
  ): Promise<EncryptedRealmSecret> {
    if (typeof value !== 'string' || !entry.field.schema.safeParse(value).success) {
      throw new PolicyValidationError('The secret is not valid', [
        { path: entry.path, message: 'is not a valid value of this secret' },
      ]);
    }
    const ciphertext = await cipher.encrypt({
      realmId,
      plaintext: value,
      context: realmSecretContext(entry.path),
    });
    const keyId =
      typeof ciphertext === 'string' ? CIPHERTEXT_PATTERN.exec(ciphertext)?.[1] : undefined;
    if (keyId === undefined) {
      // Never store what the cipher returned unless it is a ciphertext: it
      // could be the value itself.
      throw new Error('The cipher returned a value that is not a data-at-rest ciphertext');
    }
    return { ciphertext, keyId };
  }

  return Object.freeze({
    async put(realmId: string, path: string, value: string | null, tx?: Tx): Promise<void> {
      const entry = secretField(path);
      await storage.write(
        realmId,
        entry.path,
        value === null ? null : await encrypt(realmId, entry, value),
        tx
      );
    },

    async isSet(realmId: string, path: string, tx?: Tx): Promise<boolean> {
      const entry = secretField(path);
      const row = await storage.read(realmId, entry.path, tx);
      return row !== undefined && row.ciphertext !== null;
    },

    async getForUse(realmId: string, path: string): Promise<string | undefined> {
      const entry = secretField(path);
      const row = await storage.read(realmId, entry.path);
      if (row === undefined || row.ciphertext === null) return undefined;
      return cipher.decrypt({
        realmId,
        ciphertext: row.ciphertext,
        context: realmSecretContext(entry.path),
      });
    },

    async seed(
      realmId: string,
      seeds: ReadonlyMap<string, string>,
      { leaveWithoutRow, tx }: RealmSecretSeedOptions<Tx> = {}
    ): Promise<RealmSecretSeedReport> {
      const seeded: string[] = [];
      const recordedUnset: string[] = [];
      const present: string[] = [];
      const leftWithoutRow: string[] = [];
      for (const entry of secrets.values()) {
        if (entry.field.seedEnv === null) continue;
        // Read first: a boot that finds every row encrypts nothing.
        if ((await storage.read(realmId, entry.path, tx)) !== undefined) {
          present.push(entry.path);
          continue;
        }
        const value = seeds.get(entry.path);
        if (value === undefined && leaveWithoutRow?.has(entry.path)) {
          leftWithoutRow.push(entry.path);
          continue;
        }
        const stored = value === undefined ? null : await encrypt(realmId, entry, value);
        if (!(await storage.insertIfAbsent(realmId, entry.path, stored, tx))) {
          // Another node seeded it since the read: its row stays.
          present.push(entry.path);
        } else if (stored === null) {
          recordedUnset.push(entry.path);
        } else {
          seeded.push(entry.path);
        }
      }
      return { seeded, recordedUnset, present, leftWithoutRow };
    },
  });
}

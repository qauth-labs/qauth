import { isSetDirection } from './field';
import { REALM_POLICY_REGISTRY, REALM_POLICY_RULES, type RealmPolicies } from './realm-policies';
import {
  type PolicyIssue,
  type PolicyRegistry,
  PolicyValidationError,
  type RegisteredPolicyField,
} from './registry';
import type { PolicyRule } from './rules';
import type { RealmSecretStore } from './secret-store';
import { type PolicySchemaUpgrade, REALM_POLICY_UPGRADES, upgradePathsTo } from './upgrades';
import { compareSchemaVersions, isPolicySchemaVersion } from './version';

/**
 * The policy store (ADR-019 Decision 10, issue #516): a realm's policies as
 * one document of the realm policy schema, read from and written to the
 * realm row through a storage port.
 *
 * The realm row keeps the document in two forms, four fields in columns of
 * their own and every other one in a JSON document; the storage joins them
 * into one record and splits a written document again, so nothing above it
 * sees the two forms. Secret fields are never in the document: a write hands
 * them to the realm's secret store ({@link RealmSecretStore}).
 *
 * Every write goes through `update`, which compares the realm's policy
 * counter (`policies_version`, the admin API's `ETag`) with the one its
 * caller read and raises it. The environment only seeds: a new realm gets
 * `defaultsFromEnv` when it is created, and `seedRealms`, run at boot, fills
 * a realm that has no policies yet and completes one that lacks fields a
 * later release added, once, with the first writer winning.
 *
 * A document an earlier release stored under an older schema version is read
 * through the upgrades from its version (#908, `./upgrades.ts`), and the next
 * write stores it under this release's version: `seedRealms` writes it at
 * boot. A document of a later version (a later release's, during a rolling
 * upgrade) is read with this release's schema and never written, and one of
 * an older version the upgrades do not reach is refused.
 */

/** A realm's stored policies as the storage reads them: the two forms joined, unparsed. */
export interface RealmPolicyRecord {
  readonly realmId: string;
  readonly realmName: string;
  /** The policy counter: 0 while the realm has no policies. */
  readonly version: number;
  /** The schema version the stored document follows; `null` while the realm has no policies. */
  readonly schemaVersion: string | null;
  /** The stored document, the column-backed fields included. */
  readonly document: Readonly<Record<string, unknown>>;
  /**
   * For a realm with no policies yet: the values of its row that its fill
   * keeps, at their field paths (what the server read before the policies
   * existed, such as the environment ceiling). Empty otherwise.
   */
  readonly keptOnFill: Readonly<Record<string, unknown>>;
}

/** What {@link RealmPolicyStorage.write} writes. */
export interface RealmPolicyWrite {
  /** A whole policy document, parsed, with no secret field. */
  readonly document: Record<string, unknown>;
  readonly schemaVersion: string;
  /** The counter the realm must still have; the write sets it one higher. */
  readonly expectedVersion: number;
}

/**
 * The storage port of the policy store. The database library implements it
 * over the realms table; a test, in memory.
 */
export interface RealmPolicyStorage<Row, Tx> {
  /** The record of a realm row the caller already loaded. No query. */
  recordOf(row: Row): RealmPolicyRecord;
  /** The record of the realm `realmId`, or `undefined` when there is none. */
  read(realmId: string, tx?: Tx): Promise<RealmPolicyRecord | undefined>;
  /** Every realm's record. */
  list(tx?: Tx): Promise<readonly RealmPolicyRecord[]>;
  /**
   * The record of the realm `realmId` with its row locked until `tx` ends
   * (`SELECT ... FOR NO KEY UPDATE`), or `undefined` when there is none. A
   * write of the policies reads the realm through it: a write of the row that
   * commits first is in what the store reads, and one that comes later waits.
   */
  readLocked(realmId: string, tx: Tx): Promise<RealmPolicyRecord | undefined>;
  /**
   * Write the policies where the realm's counter is still
   * `write.expectedVersion`, setting it one higher, in one statement.
   *
   * @returns the realm's record as written, or `undefined` when the realm is
   *   gone or its counter moved
   */
  write(realmId: string, write: RealmPolicyWrite, tx?: Tx): Promise<RealmPolicyRecord | undefined>;
  /** Run `work` in a transaction: a savepoint of `outer` when one is given. */
  transaction<T>(work: (tx: Tx) => Promise<T>, outer?: Tx): Promise<T>;
}

/** A realm's policies as the store hands them out. Frozen. */
export interface RealmPolicySnapshot {
  readonly realmId: string;
  /**
   * The policy counter the snapshot was read at: the `ETag`, and the
   * `expectedVersion` of an update based on it. 0 while the realm has no
   * policies, which is no `ETag`: such a realm reads as its fill, which
   * depends on the environment of the node that reads it, until a boot
   * writes it.
   */
  readonly version: number;
  /** Whether the realm has its policies (`version` above 0). */
  readonly hasPolicies: boolean;
  /** The schema version of `policies`. */
  readonly schemaVersion: string;
  /**
   * The whole document, every field set. A realm with no policies yet reads
   * as its fill would leave it: the environment's seeds, and the values of
   * its row the server already read. A field missing from a stored document
   * (added by a later release) reads as its seed. A document of an older
   * schema version reads upgraded (#908), so `schemaVersion` is this
   * release's.
   */
  readonly policies: RealmPolicies;
}

/**
 * A realm's policies as the admin API's realm representation shows them
 * (#529): every field's value, and each secret field `<name>` only as
 * `<name>Set`, whether it holds a value. Never a secret's value.
 */
export interface RealmPolicyRepresentation {
  readonly realmId: string;
  /** The policy counter the representation was read at: its `ETag`. */
  readonly version: number;
  readonly hasPolicies: boolean;
  readonly schemaVersion: string;
  /** The `representation` view of the policies. */
  readonly policies: Readonly<Record<string, unknown>>;
}

/** Options of {@link RealmPolicyStore.update}. */
export interface RealmPolicyUpdateOptions<Tx> {
  /**
   * The counter the caller read the policies at (`If-Match`). The update
   * changes nothing unless the realm still has it.
   */
  readonly expectedVersion: number;
  /** The transaction to write in, such as the one of the change's audit record. */
  readonly tx?: Tx;
}

/** A realm the boot's {@link RealmPolicyStore.seedRealms} wrote. */
export interface SeededRealm {
  readonly realmId: string;
  readonly realmName: string;
}

/**
 * A field a fill took from the realm's row rather than from the environment:
 * a value the server read from the row before the policies existed, such as
 * the environment ceiling or a dynamic registration allowlist that holds a
 * scope.
 */
export interface KeptFromRow {
  /** The field's path in the policy document. */
  readonly path: string;
  /** Whether the kept value differs from the environment's seed, which the fill left unused. */
  readonly differsFromSeed: boolean;
}

/**
 * Why a realm's policies follow a schema version the store does not write,
 * and so why {@link RealmPolicyStore.seedRealms} left them as they are:
 *
 * - `newer`: they follow a later schema version (a later release's, during a
 *   rolling upgrade) and lack fields of this release. Completing them would
 *   relabel them.
 * - `no-upgrade`: they follow an older schema version that no upgrade of this
 *   release reaches. Every read of them is refused.
 */
export type PolicySchemaVersionReason = 'newer' | 'no-upgrade';

/** What {@link RealmPolicyStore.seedRealms} did. */
export interface RealmPolicySeedReport {
  /** The realms that had no policies and got them, each with the fields its row kept. */
  readonly filled: readonly (SeededRealm & { readonly keptFromRow: readonly KeptFromRow[] })[];
  /** The realms that lacked fields of this release, and the fields each got from the seeds. */
  readonly completed: readonly (SeededRealm & { readonly paths: readonly string[] })[];
  /**
   * The realms whose policies followed an older schema version (#908), now
   * stored upgraded under this release's: each with the version it followed,
   * and the fields the upgraded document lacked, which took their seeds.
   */
  readonly upgraded: readonly (SeededRealm & {
    readonly from: string;
    readonly paths: readonly string[];
  })[];
  /** The realms left as they are, each with the schema version its policies follow, and why. */
  readonly skipped: readonly (SeededRealm & {
    readonly schemaVersion: string | null;
    readonly reason: PolicySchemaVersionReason;
  })[];
}

/** The policy store. `Row` is a realm row of the storage, `Tx` its transaction. */
export interface RealmPolicyStore<Row, Tx> {
  /** The registry the store parses with. */
  readonly registry: PolicyRegistry;
  /**
   * The policies of a realm row the caller already loaded, such as the realm
   * resolver's or a token flow's. No query.
   *
   * @throws PolicyValidationError when the stored policies are not valid, or
   *   follow an older schema version that no upgrade reaches
   */
  ofRealm(row: Row): RealmPolicySnapshot;
  /**
   * The policies of the realm `realmId`, or `undefined` when there is none.
   *
   * @throws PolicyValidationError when the stored policies are not valid, or
   *   follow an older schema version that no upgrade reaches
   */
  get(realmId: string, tx?: Tx): Promise<RealmPolicySnapshot | undefined>;
  /**
   * The policies of the realm `realmId` as the admin API's realm
   * representation shows them, or `undefined` when there is none: each
   * secret field as `<name>Set`, from the secret store. The value of a secret
   * is never read.
   *
   * @throws PolicyValidationError when the stored policies are not valid
   * @throws PolicySecretStoreUnavailableError when the store has no secret
   *   store, which alone knows whether a secret is set
   */
  representation(realmId: string, tx?: Tx): Promise<RealmPolicyRepresentation | undefined>;
  /**
   * Apply a JSON Merge Patch (RFC 7396) to the realm's policies and store
   * the result, raising the counter, where the realm's counter is still
   * `options.expectedVersion`.
   *
   * The patch is a document of the `input` view, in part: a member set
   * replaces the stored value, `null` removes it so it takes its default, and
   * a member left out keeps its value. A secret field is the exception, as in
   * the `input` view: a value sets it, `null` clears it, and the store hands
   * either to the secret store, never to the document. The merged document
   * must be a valid policy document, and pass every rule of the store
   * (`PolicyStoreOptions.rules`, #529) with the secrets the update leaves
   * set: the mail transport it selects has what it sends with, for one.
   *
   * @throws RealmPolicyNotFoundError when there is no such realm
   * @throws PolicyVersionConflictError when the realm's counter is another
   *   one, or moves before the write; nothing is changed
   * @throws PolicyValidationError when the patch or the merged document is
   *   refused, by its schema or a rule; nothing is changed. Its issues name
   *   paths, never values
   * @throws PolicySecretStoreUnavailableError when the patch sets or clears a
   *   secret, or a rule asks whether one it leaves alone is set, and the store
   *   has no secret store; nothing is changed
   * @throws PolicySchemaVersionError when the stored policies follow a later
   *   schema version than this release's, or an older one that no upgrade
   *   reaches: writing them would relabel a document this release cannot read
   *   whole; nothing is changed. A document of an older version an upgrade
   *   reaches is upgraded, patched and stored under this release's version
   */
  update(
    realmId: string,
    patch: unknown,
    options: RealmPolicyUpdateOptions<Tx>
  ): Promise<RealmPolicySnapshot>;
  /**
   * The boot step (#516): give every realm with no policies its fill (the
   * environment's seeds, with the values of its row the server already
   * read), and give every realm whose document lacks fields of this release
   * their seeds. Each realm to write is read with its row locked, and each
   * write is `UPDATE ... WHERE policies_version = <read>`, so of two nodes
   * that boot together one writes and the other finds the work done, and a
   * plain write of the row is never overwritten with what it changed. A
   * realm that already has every field is not written, nor read further:
   * changing an environment key later changes no realm.
   *
   * A realm whose policies follow an older schema version is upgraded
   * (#908): written once under this release's version, the fields the
   * upgraded document lacks completed from the seeds (`upgraded`). It is
   * written even when the upgraded document lacks nothing: a reader that
   * takes one of the four column-backed fields straight off the row, not
   * through the store, sees an upgraded value only once it is written. One whose
   * policies follow a later version and lack fields of this release, or an
   * older version that no upgrade reaches, is left as it is (`skipped`).
   *
   * A list a realm's row kept from before its policies existed is read with
   * its repeats dropped, as `defaultsFromEnv` drops them from an environment
   * value.
   *
   * @throws RealmPolicySeedRefusedError when a realm the boot would write
   *   (filled, completed or upgraded) has a value the schema refuses; nothing
   *   is written
   */
  seedRealms(tx?: Tx): Promise<RealmPolicySeedReport>;
}

/** What {@link createPolicyStore} takes. */
export interface PolicyStoreOptions<Row, Tx> {
  readonly storage: RealmPolicyStorage<Row, Tx>;
  /**
   * The policies a realm gets from the environment: `defaultsFromEnv` of the
   * environment the server runs with. A field it leaves out takes the
   * field's default.
   */
  readonly seeds: unknown;
  /** Where secret fields are kept. Without one, every write of a secret is refused. */
  readonly secrets?: RealmSecretStore<Tx>;
  /** The registry; {@link REALM_POLICY_REGISTRY} by default. */
  readonly registry?: PolicyRegistry;
  /**
   * The rules every update must pass, over the whole document it would
   * store (#529). {@link REALM_POLICY_RULES} with the default registry, none
   * with another one.
   */
  readonly rules?: readonly PolicyRule[];
  /**
   * The upgrades of documents an earlier release stored under an older
   * schema version (#908), one per version change, each leading to the
   * registry's version in the end. {@link REALM_POLICY_UPGRADES} with the
   * default registry, none with another one.
   */
  readonly upgrades?: readonly PolicySchemaUpgrade[];
}

/** There is no realm of the id. */
export class RealmPolicyNotFoundError extends Error {
  override readonly name = 'RealmPolicyNotFoundError';

  constructor(readonly realmId: string) {
    super(`There is no realm ${realmId}`);
  }
}

/** The realm's policy counter is not the one the caller read (`If-Match`). */
export class PolicyVersionConflictError extends Error {
  override readonly name = 'PolicyVersionConflictError';

  constructor(
    readonly realmId: string,
    readonly expectedVersion: number,
    /** The counter the realm has, or `undefined` when it moved during the write. */
    readonly currentVersion: number | undefined
  ) {
    super(
      currentVersion === undefined
        ? `The policies of realm ${realmId} changed while they were written; read them again`
        : `The policies of realm ${realmId} are at version ${currentVersion}, not ${expectedVersion}; read them again`
    );
  }
}

/** A write sets or clears a secret field, and the store has no secret store. */
export class PolicySecretStoreUnavailableError extends Error {
  override readonly name = 'PolicySecretStoreUnavailableError';

  constructor(
    /** The secret field paths the write names; never their values. */
    readonly paths: readonly string[]
  ) {
    super(
      `${paths.join(', ')}: a secret field is set only through the realm's secret store, which this server does not have yet`
    );
  }
}

/**
 * The stored policies follow a schema version the store cannot write: a later
 * one than its registry's (`newer`), or an older one that none of its
 * upgrades reaches (`no-upgrade`).
 */
export class PolicySchemaVersionError extends Error {
  override readonly name = 'PolicySchemaVersionError';

  constructor(
    readonly realmId: string,
    readonly storedVersion: string | null,
    readonly schemaVersion: string,
    readonly reason: PolicySchemaVersionReason
  ) {
    super(
      reason === 'newer'
        ? `The policies of realm ${realmId} follow schema version ${String(storedVersion)}, later than ${schemaVersion}; a node of the release that wrote them must change them`
        : `The policies of realm ${realmId} follow schema version ${String(storedVersion)}, which no upgrade to ${schemaVersion} reaches`
    );
  }
}

/** A realm's policies cannot be filled or completed at boot. The issues name paths, never values. */
export class RealmPolicySeedRefusedError extends Error {
  override readonly name = 'RealmPolicySeedRefusedError';

  constructor(
    readonly realmName: string,
    readonly issues: readonly PolicyIssue[]
  ) {
    super(
      `The policies of the realm "${realmName}" cannot be filled from the environment: ${issues
        .map((issue) => `${issue.path || '(document)'}: ${issue.message}`)
        .join('; ')}`
    );
  }
}

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' &&
  value !== null &&
  !Array.isArray(value) &&
  (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);

const hasOwn = (value: object, key: string) => Object.prototype.hasOwnProperty.call(value, key);

/** Whether `root` has a member at `segments`, every member on the way an object. */
function hasAt(root: unknown, segments: readonly string[]): boolean {
  let node = root;
  for (const segment of segments) {
    if (!isPlainObject(node) || !hasOwn(node, segment)) return false;
    node = node[segment];
  }
  return true;
}

function valueAt(root: unknown, segments: readonly string[]): unknown {
  let node = root;
  for (const segment of segments) {
    if (!isPlainObject(node) || !hasOwn(node, segment)) return undefined;
    node = node[segment];
  }
  return node;
}

function setAt(root: Record<string, unknown>, segments: readonly string[], value: unknown): void {
  let node = root;
  for (const segment of segments.slice(0, -1)) {
    const next = hasOwn(node, segment) ? node[segment] : undefined;
    if (isPlainObject(next)) {
      node = next;
    } else {
      const created: Record<string, unknown> = {};
      node[segment] = created;
      node = created;
    }
  }
  node[segments[segments.length - 1]] = value;
}

function deepFreeze<T>(value: T): T {
  if (typeof value === 'object' && value !== null && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const member of Object.values(value)) deepFreeze(member);
  }
  return value;
}

/**
 * RFC 7396 JSON Merge Patch of `target` with `patch`. A copy; neither input
 * changes. A member named `__proto__` is refused: as an own member of a
 * parsed JSON object it is a name like any other, but assigning it would set
 * the result's prototype.
 */
function mergePatch(target: unknown, patch: unknown, path: readonly string[]): unknown {
  if (!isPlainObject(patch)) return structuredClone(patch);
  const result: Record<string, unknown> = isPlainObject(target) ? structuredClone(target) : {};
  for (const [name, value] of Object.entries(patch)) {
    if (name === '__proto__') {
      throw new PolicyValidationError('The policy patch is not valid', [
        { path: [...path, name].join('.'), message: 'is not a member of the realm policies' },
      ]);
    }
    if (value === null) {
      delete result[name];
    } else {
      result[name] = mergePatch(result[name], value, [...path, name]);
    }
  }
  return result;
}

/** Where the registry's groups and fields sit: what a stored document may hold. */
interface RegistryLayout {
  readonly fields: readonly RegisteredPolicyField[];
  readonly groupPaths: ReadonlySet<string>;
  readonly fieldPaths: ReadonlyMap<string, RegisteredPolicyField>;
}

function layoutOf(registry: PolicyRegistry): RegistryLayout {
  const fields = registry.fields();
  const groupPaths = new Set<string>();
  const fieldPaths = new Map<string, RegisteredPolicyField>();
  for (const entry of fields) {
    fieldPaths.set(entry.path, entry);
    for (let depth = 1; depth < entry.segments.length; depth++) {
      groupPaths.add(entry.segments.slice(0, depth).join('.'));
    }
  }
  return { fields, groupPaths, fieldPaths };
}

/**
 * The members of a stored document this release does not know: a group or
 * field a later release added, which a write carries over unchanged, so a
 * node of this release never drops what a newer one stored (a rolling
 * upgrade). A value for a secret field, or a group that is not an object, is
 * refused: no release stores either.
 */
function unknownMembersOf(
  layout: RegistryLayout,
  document: Readonly<Record<string, unknown>>
): Record<string, unknown> {
  const unknown: Record<string, unknown> = {};
  const issues: PolicyIssue[] = [];
  const walk = (node: Readonly<Record<string, unknown>>, prefix: readonly string[]) => {
    for (const [name, value] of Object.entries(node)) {
      const segments = [...prefix, name];
      const path = segments.join('.');
      if (name === '__proto__') {
        // An own member of parsed JSON, but assigning it would set a
        // prototype: carried over, it would drop the group it sits in.
        issues.push({ path, message: 'is not a member name the realm policies can hold' });
        continue;
      }
      const field = layout.fieldPaths.get(path);
      if (field !== undefined) {
        if (field.field.secret) {
          issues.push({
            path,
            message: 'holds a value of a secret field, which is never stored in the policies',
          });
        }
        continue;
      }
      if (layout.groupPaths.has(path)) {
        if (isPlainObject(value)) walk(value, segments);
        else issues.push({ path, message: 'is a group of the realm policies, so an object' });
        continue;
      }
      setAt(unknown, segments, structuredClone(value));
    }
  };
  walk(document, []);
  if (issues.length > 0) {
    throw new PolicyValidationError('The stored realm policies are not valid', issues);
  }
  return unknown;
}

/**
 * Whether two policy values are the same; a set field's lists in any order.
 * The values are JSON: a list of a set field holds strings.
 */
function sameValue(a: unknown, b: unknown, set: boolean): boolean {
  if (set && Array.isArray(a) && Array.isArray(b)) {
    const members = (list: unknown[]) =>
      [...new Set(list.map((entry) => JSON.stringify(entry)))].sort();
    return JSON.stringify(members(a)) === JSON.stringify(members(b));
  }
  return JSON.stringify(a) === JSON.stringify(b);
}

/**
 * A list kept from a realm's row before its policies existed, with its
 * repeats dropped, first occurrence first: an earlier release copied an
 * environment value into the row as it was written, repeats included, which
 * the schema refuses for a set field and `defaultsFromEnv` drops.
 */
function withoutRepeats(value: unknown): unknown {
  if (!Array.isArray(value)) return value;
  const seen = new Set<string>();
  return value.filter((entry) => {
    const key = JSON.stringify(entry);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/** `document` with the members of `extra`, which name no path of it. */
function withMembers(
  document: Record<string, unknown>,
  extra: Record<string, unknown>
): Record<string, unknown> {
  const result = structuredClone(document);
  const merge = (target: Record<string, unknown>, source: Record<string, unknown>) => {
    for (const [name, value] of Object.entries(source)) {
      const existing = hasOwn(target, name) ? target[name] : undefined;
      if (isPlainObject(existing) && isPlainObject(value)) merge(existing, value);
      else target[name] = structuredClone(value);
    }
  };
  merge(result, extra);
  return result;
}

/**
 * Where a stored document stands against the store's schema version: one it
 * reads as it is (`current`: this release's version, or no policies yet), an
 * older one the upgrades reach, a later one, or an older one they do not.
 */
type Standing =
  | { readonly kind: 'current' }
  | {
      readonly kind: 'older';
      readonly from: string;
      readonly steps: readonly PolicySchemaUpgrade[];
    }
  | { readonly kind: 'newer' }
  | { readonly kind: 'no-upgrade' };

/** A realm's effective policies and the members its stored document holds that this release does not know. */
interface EffectivePolicies {
  readonly document: Record<string, unknown>;
  readonly unknown: Record<string, unknown>;
  /** The fields the stored document lacks, which took their seeds (a realm with policies only). */
  readonly missing: readonly string[];
  /** The fields a fill kept from the realm's row (a realm with no policies only). */
  readonly kept: readonly KeptFromRow[];
}

/**
 * Create the policy store over `options.storage`.
 *
 * @throws PolicyValidationError when the seeds are not a valid policy document
 */
export function createPolicyStore<Row, Tx>(
  options: PolicyStoreOptions<Row, Tx>
): RealmPolicyStore<Row, Tx> {
  const { storage, secrets } = options;
  const registry = options.registry ?? REALM_POLICY_REGISTRY;
  const rules = options.rules ?? (options.registry === undefined ? REALM_POLICY_RULES : []);
  const upgradePaths = upgradePathsTo(
    options.upgrades ?? (options.registry === undefined ? REALM_POLICY_UPGRADES : []),
    registry.version
  );
  const layout = layoutOf(registry);
  // Parsed once, so seeds the schema refuses fail the boot, and frozen, so
  // nothing a caller does with a snapshot reaches the next one.
  const seeds = deepFreeze(registry.parse(options.seeds, 'document'));
  const secretFields = layout.fields.filter((entry) => entry.field.secret);

  function standingOf(record: RealmPolicyRecord): Standing {
    const stored = record.schemaVersion;
    if (record.version === 0 || stored === registry.version) return { kind: 'current' };
    if (!isPolicySchemaVersion(stored)) return { kind: 'no-upgrade' };
    if (compareSchemaVersions(stored, registry.version) > 0) return { kind: 'newer' };
    const steps = upgradePaths.get(stored);
    return steps === undefined ? { kind: 'no-upgrade' } : { kind: 'older', from: stored, steps };
  }

  /**
   * `record` as this release reads it: a document of an older schema version
   * upgraded to the registry's (#908), any other one as it is.
   *
   * @throws PolicyValidationError when the document follows an older version
   *   that no upgrade reaches (read with this release's schema, a field it
   *   renamed would read as its seed, which may be looser than stored), or an
   *   upgrade fails or gives no document
   */
  function readable(record: RealmPolicyRecord, standing: Standing): RealmPolicyRecord {
    if (standing.kind === 'no-upgrade') {
      const stored = isPolicySchemaVersion(record.schemaVersion)
        ? `schema version ${record.schemaVersion}`
        : 'no schema version';
      throw new PolicyValidationError('The stored realm policies cannot be read', [
        {
          path: '',
          message: `follow ${stored}, which no upgrade to ${registry.version} reaches`,
        },
      ]);
    }
    if (standing.kind !== 'older') return record;
    let document = structuredClone(record.document) as Record<string, unknown>;
    for (const step of standing.steps) {
      // A step that fails, or gives no document, leaves a document this
      // release cannot read: refused like any invalid one, so the boot names
      // the realm and a reader of the realm fails closed.
      let next: unknown;
      try {
        next = step.upgrade(document);
      } catch (error) {
        if (error instanceof PolicyValidationError) throw error;
        next = undefined;
      }
      if (!isPlainObject(next)) {
        throw new PolicyValidationError('The stored realm policies cannot be read', [
          {
            path: '',
            message: `the upgrade from schema version ${step.from} to ${step.to} gave no policy document`,
          },
        ]);
      }
      document = next;
    }
    return { ...record, schemaVersion: registry.version, document };
  }

  /**
   * The policies `record` stands for: its stored fields, and the seed of each
   * field it lacks. A realm with no policies yet stands for its fill, the
   * seeds overlaid with the row values the fill keeps.
   *
   * @throws PolicyValidationError when the result is not a valid document
   */
  function effective(record: RealmPolicyRecord): EffectivePolicies {
    const hasPolicies = record.version > 0;
    const source = hasPolicies ? record.document : record.keptOnFill;
    const unknown = hasPolicies ? unknownMembersOf(layout, record.document) : {};
    const document: Record<string, unknown> = {};
    const missing: string[] = [];
    const kept: KeptFromRow[] = [];
    for (const entry of layout.fields) {
      if (entry.field.secret) continue;
      if (hasAt(source, entry.segments)) {
        const value = structuredClone(valueAt(source, entry.segments));
        if (hasPolicies) {
          setAt(document, entry.segments, value);
          continue;
        }
        const set = isSetDirection(entry.field.direction);
        const keptValue = set ? withoutRepeats(value) : value;
        setAt(document, entry.segments, keptValue);
        kept.push({
          path: entry.path,
          differsFromSeed: !sameValue(keptValue, valueAt(seeds, entry.segments), set),
        });
        continue;
      }
      if (hasPolicies) missing.push(entry.path);
      setAt(document, entry.segments, structuredClone(valueAt(seeds, entry.segments)));
    }
    return { document: registry.parse(document, 'document'), unknown, missing, kept };
  }

  function snapshotOf(stored: RealmPolicyRecord): RealmPolicySnapshot {
    const record = readable(stored, standingOf(stored));
    const hasPolicies = record.version > 0;
    return deepFreeze({
      realmId: record.realmId,
      version: record.version,
      hasPolicies,
      schemaVersion: (hasPolicies ? record.schemaVersion : null) ?? registry.version,
      policies: effective(record).document as RealmPolicies,
    });
  }

  /** The document that goes to storage: parsed, with this release's unknown members carried over. */
  function storedDocument(
    document: Record<string, unknown>,
    unknown: Record<string, unknown>
  ): Record<string, unknown> {
    // The `document` view refuses every secret field: this parse is what
    // keeps a secret out of the realm row, whatever the caller passed.
    return withMembers(registry.parse(document, 'document'), unknown);
  }

  /**
   * Split the secret fields a patch sets or clears off a copy of it. A value
   * is checked by its field's type; the issues name the path, never the value.
   */
  function takeSecrets(patch: Record<string, unknown>): {
    readonly rest: Record<string, unknown>;
    readonly writes: readonly { readonly path: string; readonly value: string | null }[];
  } {
    const rest = structuredClone(patch);
    const writes: { path: string; value: string | null }[] = [];
    const issues: PolicyIssue[] = [];
    for (const entry of secretFields) {
      if (!hasAt(rest, entry.segments)) continue;
      const value = valueAt(rest, entry.segments);
      const parent = valueAt(rest, entry.segments.slice(0, -1)) as Record<string, unknown>;
      delete parent[entry.segments[entry.segments.length - 1]];
      if (value === null) {
        writes.push({ path: entry.path, value: null });
      } else if (typeof value === 'string' && entry.field.schema.safeParse(value).success) {
        writes.push({ path: entry.path, value });
      } else {
        issues.push({
          path: entry.path,
          message: 'is a secret: a valid value sets it, and null clears it',
        });
      }
    }
    if (issues.length > 0) {
      throw new PolicyValidationError('The policy patch is not valid', issues);
    }
    return { rest, writes };
  }

  /** Whether `record` has its policies and every field of this release. */
  function isComplete(record: RealmPolicyRecord): boolean {
    return (
      record.version > 0 &&
      layout.fields.every((entry) => entry.field.secret || hasAt(record.document, entry.segments))
    );
  }

  /**
   * Whether the boot has work on `record`: a realm with no policies, one
   * that lacks fields of this release, or one of an older schema version,
   * which it upgrades, or reports when no upgrade reaches it.
   */
  function needsSeeding(record: RealmPolicyRecord): boolean {
    const { kind } = standingOf(record);
    return kind === 'older' || kind === 'no-upgrade' || !isComplete(record);
  }

  /**
   * Run the store's rules on `document`, the parsed document an update would
   * store, against `previous`, the realm's document before it, with the
   * secrets each leaves set: before, those the secret store holds; after,
   * those `writes` sets, and those set before that it leaves alone.
   *
   * @throws PolicyValidationError naming each issue's path
   */
  async function checkRules(
    realmId: string,
    previous: Readonly<Record<string, unknown>>,
    document: Readonly<Record<string, unknown>>,
    writes: readonly { readonly path: string; readonly value: string | null }[],
    tx: Tx
  ): Promise<void> {
    if (rules.length === 0) return;
    // What each secret holds before and after the update: what the secret
    // store holds, and after it what the update writes. Without a store (and
    // so with no write: `update` refuses a write without one), a secret is
    // unknown, and a rule that asks about one fails closed: the store cannot
    // say the secret is unset when it may be set.
    const before = new Map<string, boolean>();
    const after = new Map<string, boolean>();
    for (const entry of secretFields) {
      if (secrets !== undefined) {
        before.set(entry.path, await secrets.isSet(realmId, entry.path, tx));
      }
      const write = writes.find((candidate) => candidate.path === entry.path);
      if (write !== undefined) after.set(entry.path, write.value !== null);
      else if (before.has(entry.path)) after.set(entry.path, before.get(entry.path) === true);
    }
    const reader = (state: ReadonlyMap<string, boolean>) => (path: string) => {
      const known = state.get(path);
      if (known === undefined) throw new PolicySecretStoreUnavailableError([path]);
      return known;
    };
    const written = (path: string) => {
      const write = writes.find((candidate) => candidate.path === path);
      if (write === undefined) return undefined;
      return write.value === null ? ('cleared' as const) : ('set' as const);
    };
    const context = {
      isSet: reader(after),
      previous,
      wasSet: reader(before),
      written,
    };
    const issues = rules.flatMap((rule) => rule(document, context));
    if (issues.length > 0) {
      throw new PolicyValidationError('The realm policies are not valid', issues);
    }
  }

  async function conflictOrMissing(
    realmId: string,
    expectedVersion: number,
    tx: Tx
  ): Promise<never> {
    const current = await storage.read(realmId, tx);
    if (current === undefined) throw new RealmPolicyNotFoundError(realmId);
    throw new PolicyVersionConflictError(realmId, expectedVersion, undefined);
  }

  return Object.freeze({
    registry,

    ofRealm(row: Row): RealmPolicySnapshot {
      return snapshotOf(storage.recordOf(row));
    },

    async get(realmId: string, tx?: Tx): Promise<RealmPolicySnapshot | undefined> {
      const record = await storage.read(realmId, tx);
      return record === undefined ? undefined : snapshotOf(record);
    },

    async representation(realmId: string, tx?: Tx): Promise<RealmPolicyRepresentation | undefined> {
      const record = await storage.read(realmId, tx);
      if (record === undefined) return undefined;
      const snapshot = snapshotOf(record);
      // Without a secret store, whether a secret is set is unknown: say so
      // rather than show it unset.
      if (secrets === undefined && secretFields.length > 0) {
        throw new PolicySecretStoreUnavailableError(secretFields.map((entry) => entry.path));
      }
      const set: string[] = [];
      for (const entry of secretFields) {
        if (await secrets?.isSet(realmId, entry.path, tx)) set.push(entry.path);
      }
      return deepFreeze({
        realmId: snapshot.realmId,
        version: snapshot.version,
        hasPolicies: snapshot.hasPolicies,
        schemaVersion: snapshot.schemaVersion,
        policies: registry.toRepresentation(snapshot.policies, set),
      });
    },

    async update(
      realmId: string,
      patch: unknown,
      { expectedVersion, tx }: RealmPolicyUpdateOptions<Tx>
    ): Promise<RealmPolicySnapshot> {
      if (!Number.isSafeInteger(expectedVersion) || expectedVersion < 0) {
        throw new TypeError('expectedVersion is a whole number, 0 or more');
      }
      if (!isPlainObject(patch)) {
        throw new PolicyValidationError('The policy patch is not valid', [
          { path: '', message: 'a policy patch is a JSON object' },
        ]);
      }
      const { rest, writes } = takeSecrets(patch);
      if (writes.length > 0 && secrets === undefined) {
        throw new PolicySecretStoreUnavailableError(writes.map((write) => write.path));
      }

      return storage.transaction(async (inner) => {
        // Locked, as in `seedRealms`: the counter of a realm with no policies
        // stays 0 through a plain write of its row.
        const record = await storage.readLocked(realmId, inner);
        if (record === undefined) throw new RealmPolicyNotFoundError(realmId);
        if (record.version !== expectedVersion) {
          throw new PolicyVersionConflictError(realmId, expectedVersion, record.version);
        }
        const standing = standingOf(record);
        if (standing.kind === 'newer' || standing.kind === 'no-upgrade') {
          throw new PolicySchemaVersionError(
            realmId,
            record.schemaVersion,
            registry.version,
            standing.kind
          );
        }
        // A document of an older version is patched as it reads upgraded,
        // and stored under this release's version below.
        const current = effective(readable(record, standing));
        const merged = mergePatch(current.document, rest, []);
        // The `input` view takes the representation's `<name>Set` members and
        // drops them, so a representation sent back changes nothing.
        const next = registry.parse(merged, 'input');
        await checkRules(realmId, current.document, next, writes, inner);
        const written = await storage.write(
          realmId,
          {
            document: storedDocument(next, current.unknown),
            schemaVersion: registry.version,
            expectedVersion,
          },
          inner
        );
        if (written === undefined) return conflictOrMissing(realmId, expectedVersion, inner);
        for (const write of writes) {
          // Checked above: a write of a secret never gets here without a store.
          await secrets?.put(realmId, write.path, write.value, inner);
        }
        return snapshotOf(written);
      }, tx);
    },

    async seedRealms(tx?: Tx): Promise<RealmPolicySeedReport> {
      return storage.transaction(async (inner) => {
        const filled: (SeededRealm & { keptFromRow: readonly KeptFromRow[] })[] = [];
        const completed: (SeededRealm & { paths: readonly string[] })[] = [];
        const upgraded: (SeededRealm & { from: string; paths: readonly string[] })[] = [];
        const skipped: (SeededRealm & {
          schemaVersion: string | null;
          reason: PolicySchemaVersionReason;
        })[] = [];
        for (const listed of await storage.list(inner)) {
          // A realm that has its policies under this release's schema version
          // and every field is not read further: the environment only seeds,
          // so nothing here changes it.
          if (!needsSeeding(listed)) continue;
          // Read again with the row locked before computing what to write. A
          // plain write of the row (a previous release's node during a rolling
          // upgrade) leaves the counter of a realm with no policies at 0, so
          // the counter compare alone would let the fill overwrite it: an
          // operator's tightened ceiling would be lost. Locked, a write that
          // committed first is in the fill, and one that comes later waits.
          const record = await storage.readLocked(listed.realmId, inner);
          if (record === undefined || !needsSeeding(record)) continue;
          const standing = standingOf(record);
          if (standing.kind === 'newer' || standing.kind === 'no-upgrade') {
            skipped.push({
              realmId: record.realmId,
              realmName: record.realmName,
              schemaVersion: record.schemaVersion,
              reason: standing.kind,
            });
            continue;
          }
          let policies: EffectivePolicies;
          try {
            policies = effective(readable(record, standing));
          } catch (error) {
            if (error instanceof PolicyValidationError) {
              throw new RealmPolicySeedRefusedError(record.realmName, error.issues);
            }
            throw error;
          }
          const written = await storage.write(
            record.realmId,
            {
              document: storedDocument(policies.document, policies.unknown),
              schemaVersion: registry.version,
              expectedVersion: record.version,
            },
            inner
          );
          // Another node, or a policy update, wrote first: its document is
          // the realm's, and a field it lacks is completed at the next boot.
          if (written === undefined) continue;
          const realm = { realmId: record.realmId, realmName: record.realmName };
          if (record.version === 0) filled.push({ ...realm, keptFromRow: policies.kept });
          else if (standing.kind === 'older') {
            upgraded.push({ ...realm, from: standing.from, paths: policies.missing });
          } else completed.push({ ...realm, paths: policies.missing });
        }
        return { filled, completed, upgraded, skipped };
      }, tx);
    },
  });
}

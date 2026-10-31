import type { InferSelectModel } from 'drizzle-orm';

import type { realms } from '../schema/core';

type RealmRowModel = InferSelectModel<typeof realms>;

/**
 * The realm policy fields the realm row keeps in columns of their own
 * (ADR-019 Decision 10, issue #516). The four columns existed before the
 * policies did, so they stay the storage of their fields; every other field
 * is a member of `realms.policies`.
 *
 * `keptOnFill` says what a realm that has no policies yet (created before
 * migration 0046) keeps when the boot step fills them from the environment.
 * Before the policies existed the server read two of these columns, so their
 * value is the realm's policy today:
 *
 * - `always`: `max_environment_laxity`, the ADR-008 ceiling an operator sets
 *   on the row (#196), with no environment key.
 * - `when-not-empty`: `dynamic_registration_allowed_scopes`. `/oauth/register`
 *   used the list when it held a scope, and `DEFAULT_DYNAMIC_REGISTRATION_SCOPES`
 *   (written into the column at the first registration) when it held none, so
 *   an empty list takes the environment's value.
 * - `never`: the token lifetimes. Nothing read the columns; the server ran on
 *   `ACCESS_TOKEN_LIFESPAN` and `REFRESH_TOKEN_LIFESPAN`, which the fill
 *   moves onto the row.
 */
export const REALM_POLICY_COLUMNS = Object.freeze([
  Object.freeze({
    path: 'tokens.accessTokenLifespanSeconds',
    column: 'accessTokenLifespan',
    keptOnFill: 'never',
  }),
  Object.freeze({
    path: 'tokens.refreshTokenLifespanSeconds',
    column: 'refreshTokenLifespan',
    keptOnFill: 'never',
  }),
  Object.freeze({
    path: 'registration.dynamicRegistrationAllowedScopes',
    column: 'dynamicRegistrationAllowedScopes',
    keptOnFill: 'when-not-empty',
  }),
  Object.freeze({
    path: 'posture.maxEnvironmentLaxity',
    column: 'maxEnvironmentLaxity',
    keptOnFill: 'always',
  }),
] as const);

/** One entry of {@link REALM_POLICY_COLUMNS}. */
export type RealmPolicyColumn = (typeof REALM_POLICY_COLUMNS)[number];

/** The realm columns that hold policy fields. */
export type RealmPolicyColumnName = RealmPolicyColumn['column'];

/**
 * A realm's stored policies as the policy store reads them
 * (`@qauth-labs/server-realm-policy`): the two storage forms joined into
 * one document, unparsed.
 */
export interface RealmPolicyRecord {
  readonly realmId: string;
  readonly realmName: string;
  /** `realms.policies_version`: 0 while the realm has no policies. */
  readonly version: number;
  /** `realms.policy_schema_version`; NULL while the realm has no policies. */
  readonly schemaVersion: string | null;
  /** The members of `realms.policies`, with the four column-backed fields set from their columns. */
  readonly document: Record<string, unknown>;
  /**
   * For a realm with no policies yet: the column values the fill keeps (see
   * {@link REALM_POLICY_COLUMNS}), at their field paths. Empty otherwise.
   */
  readonly keptOnFill: Record<string, unknown>;
}

/** A policy document split into what the four columns hold and the members of `realms.policies`. */
export interface SplitRealmPolicies {
  readonly columns: { -readonly [C in RealmPolicyColumnName]: RealmRowModel[C] };
  readonly members: Record<string, unknown>;
}

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' &&
  value !== null &&
  !Array.isArray(value) &&
  (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);

const hasOwn = (value: object, key: string) => Object.prototype.hasOwnProperty.call(value, key);

function segmentsOf(path: string): string[] {
  return path.split('.');
}

/** The value at `segments`, or `undefined` when a member on the way is missing. */
function valueAt(root: unknown, segments: readonly string[]): unknown {
  let node = root;
  for (const segment of segments) {
    if (!isPlainObject(node) || !hasOwn(node, segment)) return undefined;
    node = node[segment];
  }
  return node;
}

/** Set `value` at `segments`, making a plain object of every member on the way that is not one. */
function setAt(root: Record<string, unknown>, segments: readonly string[], value: unknown): void {
  let node = root;
  for (const segment of segments.slice(0, -1)) {
    const next = hasOwn(node, segment) ? node[segment] : undefined;
    if (!isPlainObject(next)) {
      const created: Record<string, unknown> = {};
      node[segment] = created;
      node = created;
    } else {
      node = next;
    }
  }
  node[segments[segments.length - 1]] = value;
}

/** Remove the member at `segments`, and every group it leaves empty. */
function deleteAt(root: Record<string, unknown>, segments: readonly string[]): void {
  const [head, ...rest] = segments;
  if (!hasOwn(root, head)) return;
  if (rest.length === 0) {
    delete root[head];
    return;
  }
  const child = root[head];
  if (!isPlainObject(child)) return;
  deleteAt(child, rest);
  if (Object.keys(child).length === 0) delete root[head];
}

/** Whether the fill keeps `value`, the column of `entry`, as the realm's policy. */
function keptOnFill(entry: RealmPolicyColumn, value: unknown): boolean {
  switch (entry.keptOnFill) {
    case 'always':
      return value !== null && value !== undefined;
    case 'when-not-empty':
      return Array.isArray(value) && value.length > 0;
    default:
      return false;
  }
}

/**
 * A realm row's policies, as the policy store reads them: the members of
 * `realms.policies`, with the column-backed fields from their columns (a
 * member of the same path is overruled), and, for a realm with no policies
 * yet, the column values its fill keeps. No query: a row the caller already
 * loaded (the realm resolver's, a token flow's) is enough.
 */
export function realmPolicyRecord(realm: RealmRowModel): RealmPolicyRecord {
  const document: Record<string, unknown> = isPlainObject(realm.policies)
    ? structuredClone(realm.policies)
    : {};
  const kept: Record<string, unknown> = {};
  for (const entry of REALM_POLICY_COLUMNS) {
    const value = realm[entry.column];
    const segments = segmentsOf(entry.path);
    setAt(document, segments, structuredClone(value));
    if (realm.policiesVersion === 0 && keptOnFill(entry, value)) {
      setAt(kept, segments, structuredClone(value));
    }
  }
  return {
    realmId: realm.id,
    realmName: realm.name,
    version: realm.policiesVersion,
    schemaVersion: realm.policySchemaVersion,
    document,
    keptOnFill: kept,
  };
}

/**
 * Split a whole policy document into the four columns and the members of
 * `realms.policies`. The document comes from the policy store, which parsed
 * it with the policy schema; the column values are checked again by the
 * row's own rules (CHECKs and the repository's).
 *
 * @throws TypeError when the document has no value for a column-backed field
 */
export function splitRealmPolicies(document: Record<string, unknown>): SplitRealmPolicies {
  if (!isPlainObject(document)) {
    throw new TypeError('A realm policy document is a JSON object');
  }
  const members = structuredClone(document);
  const columns: Record<string, unknown> = {};
  for (const entry of REALM_POLICY_COLUMNS) {
    const segments = segmentsOf(entry.path);
    const value = valueAt(document, segments);
    if (value === undefined) {
      throw new TypeError(`The realm policy document has no value for ${entry.path}`);
    }
    columns[entry.column] = structuredClone(value);
    deleteAt(members, segments);
  }
  return { columns: columns as SplitRealmPolicies['columns'], members };
}

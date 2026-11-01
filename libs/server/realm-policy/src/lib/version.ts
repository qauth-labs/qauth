/**
 * The version of the realm policy schema (ADR-018 §5, issue #514).
 *
 * The admin API's realm representation carries it as `policySchemaVersion`,
 * the realm row stores it beside the policies, and the realm file names it
 * through its format. It is a string:
 *
 * - `1-rc.<M>` until QAuth 1.0.0. Nothing about a release candidate is
 *   promised, and a breaking change raises `<M>`, so a version never names two
 *   schemas.
 * - `1` from the release that ships 1.0.0. Inside version 1 every change is
 *   additive: a new field comes with a default, and no field is ever removed
 *   or narrowed. A breaking change needs version `2`.
 *
 * Registering a group ({@link PolicyRegistry.registerPolicyGroup}) does not
 * change the version: a group added in a minor release is an additive change,
 * and every field of it has a default.
 *
 * **What a change of the version ships (#908).** The realms keep the
 * documents an earlier release stored, under the version it wrote them in,
 * so the release that changes this constant ships with it:
 *
 * 1. An upgrade from the version before it, appended to
 *    `REALM_POLICY_UPGRADES` (`./upgrades.ts`): what a stored document of the
 *    old version says, written as a document of the new one. The policy store
 *    applies it when it reads such a document, and the next write (the boot's
 *    `seedRealms`, or an update) stores the result under the new version. A
 *    document of an older version the upgrades do not reach is refused, never
 *    read with the new schema. The contract test fails while the upgrades do
 *    not lead from {@link FIRST_REALM_POLICY_SCHEMA_VERSION} to this one.
 * 2. A test that stores a document of the old version and shows each field
 *    the change touches read, updated and written under the new version, and
 *    never looser than stored: a renamed field keeps its value, a narrowed one
 *    takes the nearest value the new schema accepts that is as strict or
 *    stricter, and a removed one is deleted rather than carried over.
 * 3. For one of the four column-backed fields (`REALM_POLICY_COLUMNS` of
 *    `@qauth-labs/infra-db`): the storage joins a column at this release's
 *    path whatever version the document follows, so a change that moves one
 *    changes the join, and the upgrade finds the field there already. Some
 *    readers take these columns straight off the row (the environment
 *    ceiling, the dynamic registration allowlist), not through the store, so
 *    a change that narrows one reaches them only once the boot has written
 *    the upgraded document; until a node of the new release boots, they read
 *    the stored value.
 * 4. The secret store's move, when the change renames a secret field: an
 *    upgrade sees no secret, since none is in a stored document.
 * 5. A release note on the rolling upgrade. The first boot of the new
 *    release writes every realm of the old version under the new one. A node
 *    of the previous release reads such a document with its own schema, as it
 *    reads any document of a later version (members it does not know are
 *    skipped, fields it lacks take its seeds), and refuses to write it. So a
 *    renamed field reads as the old release's seed there, which may be looser
 *    than stored, for as long as old nodes run, and after a downgrade (which
 *    is not supported). The note of a change that renames, narrows or removes
 *    a field says that the previous release's nodes stop before the new
 *    release boots; only a change the previous release reads as strictly
 *    may roll.
 */
export const REALM_POLICY_SCHEMA_VERSION = '1-rc.0';

/**
 * The schema version of the first stored policy documents (migration 0046,
 * #516). The upgrades lead from it to {@link REALM_POLICY_SCHEMA_VERSION}, so
 * a realm whose policies a release stored is read by every later one.
 */
export const FIRST_REALM_POLICY_SCHEMA_VERSION = '1-rc.0';

/** `1`, `2`, … or `<N>-rc.<M>`: the forms a policy schema version takes. */
const SCHEMA_VERSION_PATTERN = /^([1-9][0-9]*)(?:-rc\.(0|[1-9][0-9]*))?$/;

/** Whether `value` is written as a policy schema version (`1-rc.0`, `1`). */
export function isPolicySchemaVersion(value: unknown): value is string {
  return typeof value === 'string' && SCHEMA_VERSION_PATTERN.test(value);
}

/** The order key of a version: its number, then its release candidate, the release itself last. */
function orderOf(version: string): readonly [number, number] {
  const match = SCHEMA_VERSION_PATTERN.exec(version);
  if (match === null) {
    throw new TypeError(`"${version}" is not a policy schema version (1-rc.<M>, or 1 from 1.0.0)`);
  }
  const candidate = match[2] === undefined ? Number.POSITIVE_INFINITY : Number(match[2]);
  return [Number(match[1]), candidate];
}

/**
 * The order of two policy schema versions: below 0 when `a` comes before `b`,
 * 0 when they are the same, above 0 when it comes after. A release candidate
 * comes before its release, and a release before the next version's first
 * candidate: `1-rc.0` < `1-rc.1` < `1` < `2-rc.0` < `2`.
 *
 * @throws TypeError when either is not a policy schema version
 */
export function compareSchemaVersions(a: string, b: string): number {
  const [numberA, candidateA] = orderOf(a);
  const [numberB, candidateB] = orderOf(b);
  if (numberA !== numberB) return numberA - numberB;
  if (candidateA === candidateB) return 0;
  return candidateA < candidateB ? -1 : 1;
}

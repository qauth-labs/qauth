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
 * A bump ships with a converter, or a data migration, for the stored
 * documents of the older version (#516): the policy store refuses to update a
 * realm whose policies follow another version (`PolicySchemaVersionError`),
 * the boot leaves them uncompleted, and a read may fail on them.
 */
export const REALM_POLICY_SCHEMA_VERSION = '1-rc.0';

/** `1`, `2`, … or `<N>-rc.<M>`: the forms a policy schema version takes. */
const SCHEMA_VERSION_PATTERN = /^[1-9][0-9]*(?:-rc\.(?:0|[1-9][0-9]*))?$/;

/** Whether `value` is written as a policy schema version (`1-rc.0`, `1`). */
export function isPolicySchemaVersion(value: unknown): value is string {
  return typeof value === 'string' && SCHEMA_VERSION_PATTERN.test(value);
}

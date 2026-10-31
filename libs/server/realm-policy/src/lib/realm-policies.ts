import type { PolicyField } from './field';
import { BUILT_IN_POLICY_GROUPS } from './groups';
import {
  createPolicyRegistry,
  type JsonSchemaObject,
  type PolicyDiff,
  type PolicyGroupShape,
  type PolicyRegistry,
  type PolicySeedEnv,
  type PolicyView,
} from './registry';

/**
 * The realm policies of QAuth: one registry holding the built-in groups
 * (#514), on which other areas register theirs, and the functions over it.
 */

/** The stored value of a group: every field but the secrets, nested groups as objects. */
export type PolicyGroupValue<S extends PolicyGroupShape> = {
  -readonly [
    K in keyof S as S[K] extends PolicyField<unknown, true> ? never : K
  ]: S[K] extends PolicyField<infer T, false>
    ? T
    : S[K] extends PolicyGroupShape
      ? PolicyGroupValue<S[K]>
      : never;
};

/** A group in the representation: each secret `<name>` as `<name>Set`. */
export type PolicyGroupRepresentation<S extends PolicyGroupShape> = {
  -readonly [
    K in keyof S as S[K] extends PolicyField<unknown, true> ? `${K & string}Set` : K
  ]: S[K] extends PolicyField<unknown, true>
    ? boolean
    : S[K] extends PolicyField<infer T, false>
      ? T
      : S[K] extends PolicyGroupShape
        ? PolicyGroupRepresentation<S[K]>
        : never;
};

type BuiltInGroups = typeof BUILT_IN_POLICY_GROUPS;

/** The policy document of the built-in groups, as stored (no secret appears). */
export type RealmPolicies = {
  -readonly [G in keyof BuiltInGroups]: PolicyGroupValue<BuiltInGroups[G]>;
};

/** The built-in groups as the admin API's realm representation returns them. */
export type RealmPoliciesRepresentation = {
  -readonly [G in keyof BuiltInGroups]: PolicyGroupRepresentation<BuiltInGroups[G]>;
};

/** The registry of QAuth's realm policies, with the built-in groups registered. */
export const REALM_POLICY_REGISTRY: PolicyRegistry = createPolicyRegistry();
for (const [name, shape] of Object.entries(BUILT_IN_POLICY_GROUPS)) {
  REALM_POLICY_REGISTRY.registerPolicyGroup(name, shape);
}

/**
 * Add a group of realm policies, as another area of QAuth does for its own
 * settings (sessions, sign-in methods, brand). The name is taken once: a
 * second group of the same name, in any case, is refused, and so is every
 * other invalid definition (`PolicyRegistry.registerPolicyGroup`).
 */
export function registerPolicyGroup(name: string, shape: PolicyGroupShape): void {
  REALM_POLICY_REGISTRY.registerPolicyGroup(name, shape);
}

/** The changed fields between two policy documents, with direction, class and effects. */
export function diffPolicies(before: unknown, after: unknown): PolicyDiff {
  return REALM_POLICY_REGISTRY.diffPolicies(before, after);
}

/**
 * A new realm's policies from the environment (ADR-019 Decision 10): pass the
 * environment as the server's env schema parsed it, or raw strings.
 */
export function defaultsFromEnv(env: PolicySeedEnv): RealmPolicies {
  return REALM_POLICY_REGISTRY.defaultsFromEnv(env) as RealmPolicies;
}

/** The JSON Schema (draft 2020-12) of a view of the realm policies, `representation` by default. */
export function toJsonSchema(view: PolicyView = 'representation'): JsonSchemaObject {
  return REALM_POLICY_REGISTRY.toJsonSchema(view);
}

/** Parse a stored policy document: unknown members and secret values are refused, defaults filled. */
export function parseRealmPolicies(value: unknown): RealmPolicies {
  return REALM_POLICY_REGISTRY.parse(value, 'document') as RealmPolicies;
}

/** The representation of a policy document, with `<name>Set` true for the secret paths in `setSecrets`. */
export function toRealmPoliciesRepresentation(
  document: unknown,
  setSecrets: Iterable<string> = []
): RealmPoliciesRepresentation {
  return REALM_POLICY_REGISTRY.toRepresentation(
    document,
    setSecrets
  ) as RealmPoliciesRepresentation;
}

import {
  applyKeyAliases,
  authEnvSchema,
  CONFIG_KEY_REGISTRY,
  emailEnvSchema,
  envSchemaShape,
  jwtEnvSchema,
  observabilityEnvSchema,
  passwordEnvSchema,
} from '@qauth-labs/server-config';
import type { z } from 'zod';

import type { PolicyField } from './field';
import { BUILT_IN_POLICY_GROUPS } from './groups';
import {
  createPolicyRegistry,
  type JsonSchemaObject,
  type PolicyDiff,
  type PolicyDiffOptions,
  type PolicyEnvReader,
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

/** The server's parser of each key of the env schemas whose keys seed the built-in groups. */
const SERVER_ENV_PARSERS: ReadonlyMap<string, z.ZodType> = new Map(
  [authEnvSchema, jwtEnvSchema, passwordEnvSchema, observabilityEnvSchema, emailEnvSchema].flatMap(
    (schema) => Object.entries(envSchemaShape(schema))
  )
);

/**
 * The environment as the auth server reads it (`@qauth-labs/server-config`):
 * its key aliases, and each key's parser, so seeding a realm from raw strings
 * and from the parsed environment can never disagree, nor with the server.
 */
export const REALM_POLICY_ENV: PolicyEnvReader = Object.freeze({
  applyAliases(env: PolicySeedEnv): PolicySeedEnv {
    const strings: Record<string, string> = {};
    const parsed: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(env)) {
      if (typeof value === 'string') strings[key] = value;
      else parsed[key] = value;
    }
    // Only raw strings carry the old names; a value already parsed is read
    // under its current name.
    return { ...applyKeyAliases(strings, CONFIG_KEY_REGISTRY).env, ...parsed };
  },
  parserOf: (key: string) => SERVER_ENV_PARSERS.get(key),
});

/** The registry of QAuth's realm policies, with the built-in groups registered. */
export const REALM_POLICY_REGISTRY: PolicyRegistry = createPolicyRegistry({
  env: REALM_POLICY_ENV,
});
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

/**
 * The changed fields between two policy documents, with direction, class and
 * effects. `options` names the secrets set before the change and those it
 * clears, which no document holds.
 */
export function diffPolicies(
  before: unknown,
  after: unknown,
  options?: PolicyDiffOptions
): PolicyDiff {
  return REALM_POLICY_REGISTRY.diffPolicies(before, after, options);
}

/**
 * A new realm's policies from the environment (ADR-019 Decision 10): pass the
 * environment as the server's env schema parsed it, or raw strings, which are
 * read as the server reads them ({@link REALM_POLICY_ENV}).
 *
 * @throws PolicySeedError when a value cannot seed its field
 * @throws KeyAliasConflictError when an old and a current key name disagree
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

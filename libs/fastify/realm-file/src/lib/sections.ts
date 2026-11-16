import {
  cimdClientSpecSchema,
  clientSpecSchema,
  environmentEnum,
  publicJwkSchema,
  resourceSpecSchema,
} from '@qauth-labs/infra-db/seed-manifest';
import { systemClientSpecSchema } from '@qauth-labs/infra-db/system-client';
import { isSetDirection, REALM_POLICY_REGISTRY } from '@qauth-labs/server-realm-policy';
import { z } from 'zod';

/**
 * The sections of the realm file (ADR-018 §5, #515): every top-level key but
 * `format` and `realm`.
 *
 * A section is added with its schema, its natural key and its diff rules
 * (the import plan, #518, adds the diff to each), and as an optional member:
 * a file without it says nothing about what it describes. A server that does
 * not know a section refuses the file and names the section; it never skips
 * one. `clients`, `cimd_clients`, `resources` and `system_client` are the
 * seed manifest's sections, with the manifest's own schemas, so that a
 * manifest is a realm file as it is (ADR-018 §5: the seed manifest becomes a
 * subset of the realm file). The file refuses three mistakes the seed lets
 * pass: a `client_id` listed twice, a member of `jwks` beside `keys`, and a
 * URL with a user name or password (`./credentials`).
 */

/** The values of a client's `environment` (ADR-008), from the laxest to the strictest. */
export const CLIENT_ENVIRONMENTS = environmentEnum.enumValues;

/**
 * A client's key set, `jwks`: its public keys, and no other member. Stricter
 * than the seed manifest's, which drops a member beside `keys` without a
 * word: in a realm file a misspelt `keys` or a key set of private keys under
 * another name is refused. Each key is the manifest's public JWK, which
 * refuses private key material.
 */
const realmFileKeySetSchema = z.strictObject({
  keys: z.array(publicJwkSchema).min(1).max(20),
});

/**
 * A `clients` entry: a seed-manifest client, with its OAuth metadata names
 * (RFC 7591), and its ADR-008 environment, which the manifest does not set.
 * Strict, like the manifest's: a member it does not name is refused, a secret
 * among them, and so is a member of `jwks` beside `keys`.
 */
export const realmFileClientSchema = clientSpecSchema.safeExtend({
  jwks: realmFileKeySetSchema.optional(),
  environment: z
    .enum(CLIENT_ENVIRONMENTS)
    .optional()
    .describe(
      "The client's environment profile (ADR-008): development, staging or production. Left out, the client is production, the fail-safe default; the realm's posture.maxEnvironmentLaxity caps it. A sandbox realm's client says staging here."
    ),
});

/**
 * The `system_client` section: the system client as the migration runner
 * provisions it, with the key set of a realm file, which refuses a member
 * beside `keys`.
 */
export const realmFileSystemClientSchema = systemClientSpecSchema.safeExtend({
  jwks: realmFileKeySetSchema.optional(),
});

/** One section of the realm file. */
export interface RealmFileSection {
  /** Its top-level key. */
  readonly name: string;
  /** One value (`object`), or a list of entries (`list`). */
  readonly kind: 'object' | 'list';
  /**
   * The member that names the item of the realm the value or an entry
   * describes, which an import matches the realm's state by: never an id the
   * server generates. A natural key names one item across every section that
   * has it, so a `client_id` appears once in a file. `undefined` for
   * `policies`, whose fields are matched by their path.
   */
  readonly naturalKey: string | undefined;
  /** One sentence on what it holds, for the JSON Schema and the docs page. */
  readonly summary: string;
  /** The schema of its value, or of one entry of a list. */
  readonly schema: () => z.ZodType;
  /** Its value in canonical order: every set sorted, every list of entries sorted by its natural key. */
  readonly canonical: (value: unknown) => unknown;
}

/** Strings in UTF-16 code unit order, as RFC 8785 orders object members. */
export const byCodeUnit = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const isStringList = (value: unknown): value is string[] =>
  Array.isArray(value) && value.every((member) => typeof member === 'string');

/** A list of strings that is a set: each value once, in code unit order. */
const sortedSet = (values: readonly string[]): string[] => [...new Set(values)].sort(byCodeUnit);

/** Entries sorted by `key`, each in its canonical order. */
function sortedEntries(
  value: unknown,
  key: string,
  canonicalEntry: (entry: unknown) => unknown
): unknown {
  if (!Array.isArray(value)) return structuredClone(value);
  return value
    .map((entry) => canonicalEntry(entry))
    .sort((a, b) => {
      const left = isRecord(a) ? String(a[key]) : '';
      const right = isRecord(b) ? String(b[key]) : '';
      return byCodeUnit(left, right);
    });
}

/**
 * A client entry in canonical order. Every list of strings of a client is a
 * set (its grant types, scopes, audience, redirect URIs, origins and flows),
 * its own and those of a nested object such as `first_party_policy`. A key
 * set (`jwks`) is left as written: a JWK's `x5c` is a certificate chain, in
 * the order its RFC gives it.
 */
function canonicalClient(entry: unknown): unknown {
  if (!isRecord(entry)) return structuredClone(entry);
  const canonical: Record<string, unknown> = {};
  for (const [member, value] of Object.entries(entry)) {
    if (isStringList(value)) canonical[member] = sortedSet(value);
    else if (member !== 'jwks' && isRecord(value)) canonical[member] = canonicalClient(value);
    else canonical[member] = structuredClone(value);
  }
  return canonical;
}

/**
 * A scope of a protected resource in canonical order: its consent texts, a
 * map the file keys by locale, with the locales in code unit order. Every
 * other object of a file has the members of its schema, in the schema's
 * order; this map is the format's only one whose keys the file chooses.
 */
function canonicalScope(entry: unknown): unknown {
  if (!isRecord(entry)) return structuredClone(entry);
  const canonical: Record<string, unknown> = {};
  for (const [member, value] of Object.entries(entry)) {
    canonical[member] =
      member === 'text' && isRecord(value)
        ? Object.fromEntries(
            Object.entries(value)
              .sort(([left], [right]) => byCodeUnit(left, right))
              .map(([locale, text]) => [locale, structuredClone(text)])
          )
        : structuredClone(value);
  }
  return canonical;
}

/** A protected resource in canonical order: its scopes by scope, its clients sorted. */
function canonicalResource(entry: unknown): unknown {
  if (!isRecord(entry)) return structuredClone(entry);
  const canonical: Record<string, unknown> = {};
  for (const [member, value] of Object.entries(entry)) {
    if (member === 'scopes') canonical[member] = sortedEntries(value, 'scope', canonicalScope);
    else if (isStringList(value)) canonical[member] = sortedSet(value);
    else canonical[member] = structuredClone(value);
  }
  return canonical;
}

/** The policies in canonical order: every field the registry declares a set, sorted. */
function canonicalPolicies(value: unknown): unknown {
  const canonical = structuredClone(value);
  for (const { segments, field } of REALM_POLICY_REGISTRY.fields()) {
    if (!isSetDirection(field.direction)) continue;
    let parent: unknown = canonical;
    for (const segment of segments.slice(0, -1)) {
      parent = isRecord(parent) ? parent[segment] : undefined;
    }
    const last = segments[segments.length - 1];
    if (isRecord(parent) && isStringList(parent[last])) parent[last] = sortedSet(parent[last]);
  }
  return canonical;
}

/** The sections, in the order a file written by QAuth gives them. */
export const REALM_FILE_SECTIONS: readonly RealmFileSection[] = Object.freeze([
  {
    name: 'policies',
    kind: 'object',
    naturalKey: undefined,
    summary:
      "The realm's policies, in the shape of the policies of the admin API's realm representation, without the <name>Set flag of a secret field: groups of camelCase fields, each matched by its path. A field left out takes its default.",
    schema: () => REALM_POLICY_REGISTRY.schema('document'),
    canonical: canonicalPolicies,
  },
  {
    name: 'clients',
    kind: 'list',
    naturalKey: 'client_id',
    summary:
      'The operator-managed OAuth clients, each a seed-manifest client with its OAuth metadata names (RFC 7591) and an optional environment, matched by client_id.',
    schema: () => realmFileClientSchema,
    canonical: (value) => sortedEntries(value, 'client_id', canonicalClient),
  },
  {
    name: 'cimd_clients',
    kind: 'list',
    naturalKey: 'client_id',
    summary:
      "The operator's grants to Client ID Metadata Document clients: the scopes each may receive, those the client_credentials grant may issue it and its audience, matched by client_id. Its document owns every other field.",
    schema: () => cimdClientSpecSchema,
    canonical: (value) => sortedEntries(value, 'client_id', canonicalClient),
  },
  {
    name: 'resources',
    kind: 'list',
    naturalKey: 'resource',
    summary:
      "The realm's protected resources: each one's resource indicator (RFC 8707), the scopes it defines with their consent texts, and who may ask for them, matched by resource.",
    schema: () => resourceSpecSchema,
    canonical: (value) => sortedEntries(value, 'resource', canonicalResource),
  },
  {
    name: 'system_client',
    kind: 'object',
    naturalKey: 'client_id',
    summary:
      "The developer portal's system client, as the migration runner provisions it: its redirect URIs, its public keys and its first-party reason, matched by client_id.",
    schema: () => realmFileSystemClientSchema,
    canonical: canonicalClient,
  },
]);

/** The section named `name`, if the format has one. */
export function realmFileSection(name: string): RealmFileSection | undefined {
  return REALM_FILE_SECTIONS.find((section) => section.name === name);
}

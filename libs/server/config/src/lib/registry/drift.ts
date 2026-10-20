import { z } from 'zod';

import type { ConfigKey } from './types';

/**
 * The fields of an env schema, by key name.
 *
 * A plain `z.object` (refinements included) has a `.shape`. A transformed
 * schema such as `jwtEnvSchema` or `cryptoEnvSchema` is a pipe with no
 * `.shape`, so its input object is read instead: those are the keys it reads
 * from the environment.
 *
 * @throws TypeError when the schema is not an object, or a pipe from one
 */
export function envSchemaShape(schema: z.ZodType): Readonly<Record<string, z.ZodType>> {
  if (schema instanceof z.ZodObject) {
    return schema.shape;
  }
  if (schema instanceof z.ZodPipe) {
    // Typed as the core schema; a pipe built with this package's API holds a
    // classic one.
    return envSchemaShape(schema.in as z.ZodType);
  }
  throw new TypeError('An env schema must be a z.object, or a refinement or transform of one.');
}

/** The disagreements {@link findRegistryDrift} finds. */
export interface RegistryDrift {
  /** Keys a schema reads that have no registry entry. */
  readonly unregistered: readonly string[];
  /** Registry entries whose key no schema reads. */
  readonly orphaned: readonly string[];
}

/**
 * Compare the keys a set of schemas reads with the registry entries for them.
 *
 * An old name in a schema counts as unregistered: aliases are resolved before
 * a schema sees the environment, so a schema field under an old name would
 * never receive a value.
 *
 * @param keys - every key the schemas read
 * @param entries - the registry entries that should cover exactly those keys
 */
export function findRegistryDrift(
  keys: Iterable<string>,
  entries: readonly ConfigKey[]
): RegistryDrift {
  const read = new Set(keys);
  const registered = new Set(entries.map((entry) => entry.name));

  return {
    unregistered: [...read].filter((name) => !registered.has(name)).sort(),
    orphaned: [...registered].filter((name) => !read.has(name)).sort(),
  };
}

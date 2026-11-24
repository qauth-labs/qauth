/**
 * Every flag the status data names (`apps/docs-site/src/lib/status.ts`) is a
 * setting the server reads, with the default the status data says. The status
 * feed carries the flag to qauth.dev, which writes "off by default" from it;
 * a default flipped in the config schema and not here would leave that
 * sentence wrong. A flag renamed or removed fails too.
 *
 * The defaults are read by parsing an unset value through the schemas
 * themselves, not by reading their source.
 */
import { describe, expect, it } from 'vitest';

import { FEATURE_STATUS } from '../../apps/docs-site/src/lib/status.ts';
import * as schemas from '../../libs/server/config/src/lib/schemas/index.ts';

/** A schema field, as far as this test needs one. */
interface Field {
  parse(value: unknown): unknown;
}

type Shape = Record<string, Field>;

/** The object shape behind an env schema, through a refinement or a transform. */
function shapeOf(value: unknown): Shape | undefined {
  const schema = value as { shape?: Shape; in?: unknown } | null;
  if (!schema || typeof schema !== 'object') return undefined;
  if (schema.shape && typeof schema.shape === 'object') return schema.shape;
  return schema.in === undefined ? undefined : shapeOf(schema.in);
}

/** Each env field the config schemas define, by name. */
function envFields(): Map<string, Field[]> {
  const fields = new Map<string, Field[]>();
  for (const value of Object.values(schemas)) {
    for (const [name, field] of Object.entries(shapeOf(value) ?? {})) {
      fields.set(name, [...(fields.get(name) ?? []), field]);
    }
  }
  return fields;
}

const FLAGGED = FEATURE_STATUS.flatMap((feature) =>
  feature.flag ? [{ id: feature.id, ...feature.flag }] : []
);

describe('the flags in the status data', () => {
  const fields = envFields();

  it('are read from the config schemas', () => {
    expect(fields.size).toBeGreaterThan(0);
    expect(FLAGGED.length).toBeGreaterThan(0);
  });

  it.each(FLAGGED)('$id: $name defaults to $default', ({ name, default: expected }) => {
    const defined = fields.get(name);
    expect(defined, `${name} is not a setting in libs/server/config`).toBeDefined();
    for (const field of defined ?? []) {
      expect(field.parse(undefined), `${name}'s default in libs/server/config`).toBe(
        expected === 'on'
      );
    }
  });
});

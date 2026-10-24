import { findEventSwitches } from '@qauth-labs/shared-events';
import { describe, expect, it } from 'vitest';
import type { z } from 'zod';

import * as schemas from '../schemas';
import { envSchemaShape } from './drift';
import { CONFIG_KEY_REGISTRY } from './keys';

/**
 * Admin events are always on (ADR-020 §3, issue #459): no environment key and
 * no realm setting turns them off. The registry holds every key every QAuth
 * process reads (its drift tests hold it to the schemas, the auth server's
 * included), and each realm-seed key names the realm policy it seeds, so
 * scanning them covers the configuration and the realm policy fields.
 *
 * A key that reads like a switch for events but turns nothing off, such as
 * one that only pauses a delivery route, goes in ALLOWED with the reason.
 */
const ALLOWED: Readonly<Record<string, string>> = {
  OTEL_EVENTS_ENABLED:
    'Turns on the OpenTelemetry log export of stored events (#541). Every event, admin events included, is stored and chained whatever it says; it decides only whether a copy also leaves as a log record.',
};

function configurationNames(): string[] {
  const names = new Set<string>();
  for (const key of CONFIG_KEY_REGISTRY) {
    names.add(key.name);
    for (const alias of key.aliases) names.add(alias.name);
    for (const segment of key.seeds?.split('.') ?? []) names.add(segment);
  }
  for (const [name, schema] of Object.entries(schemas)) {
    if (!name.endsWith('EnvSchema')) continue;
    for (const field of Object.keys(envSchemaShape(schema as z.ZodType))) names.add(field);
  }
  return [...names];
}

describe('admin events are always on', () => {
  it('no configuration key, old name or seeded realm policy reads like a switch for them', () => {
    const found = findEventSwitches(configurationNames()).filter((name) => !(name in ALLOWED));
    expect(found).toEqual([]);
  });

  it('scans the whole registry', () => {
    const names = configurationNames();
    expect(names).toEqual(expect.arrayContaining(CONFIG_KEY_REGISTRY.map((key) => key.name)));
    expect(names.length).toBeGreaterThan(100);
  });
});

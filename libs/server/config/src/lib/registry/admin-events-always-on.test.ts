import { findEventNames } from '@qauth-labs/shared-events';
import { describe, expect, it } from 'vitest';
import type { z } from 'zod';

import * as schemas from '../schemas';
import { envSchemaShape } from './drift';
import { CONFIG_KEY_REGISTRY } from './keys';
import type { ConfigKey } from './types';

/**
 * Admin events are always on (ADR-020 §3, issues #459 and #827): no
 * environment key and no realm setting turns them off. The registry holds
 * every key every QAuth process reads (its drift tests hold it to the
 * schemas, the auth server's included), and each realm-seed key names the
 * realm policy it seeds, so scanning them covers the configuration and the
 * realm policy fields.
 *
 * The check refuses by default: every key, old name, seeded realm policy
 * segment and env schema field that holds an event word (`event`, `audit`,
 * `log`, `sink`, …) is listed in ALLOWED with the reason it turns nothing
 * off, or the test fails.
 */
const ALLOWED: Readonly<Record<string, string>> = {
  LOG_LEVEL:
    "The lowest level of the server's own process log. Events are not written to that log, and no level stops one.",
  LOG_PRETTY:
    "Formats the server's own process log for a terminal. Events are not written to that log.",
  OTEL_EVENTS_ENABLED:
    'Turns on the OpenTelemetry log export of stored events (#541). Every event, admin events included, is stored and chained whatever it says; it decides only whether a copy also leaves as a log record.',
};

/** Every name a key registry and the env schemas hold. */
function configurationNames(
  registry: readonly ConfigKey[] = CONFIG_KEY_REGISTRY,
  envSchemaFields: readonly string[] = []
): string[] {
  const names = new Set<string>();
  for (const key of registry) {
    names.add(key.name);
    for (const alias of key.aliases) names.add(alias.name);
    for (const segment of key.seeds?.split('.') ?? []) names.add(segment);
  }
  for (const [name, schema] of Object.entries(schemas)) {
    if (!name.endsWith('EnvSchema')) continue;
    for (const field of Object.keys(envSchemaShape(schema as z.ZodType))) names.add(field);
  }
  for (const field of envSchemaFields) names.add(field);
  return [...names];
}

/** A registry entry for a key that is not in the registry. */
function keyNamed(name: string, overrides: Partial<ConfigKey> = {}): ConfigKey {
  return {
    name,
    tier: 'stable',
    role: 'deployment',
    seeds: undefined,
    secret: false,
    default: null,
    since: '0.2.0',
    aliases: [],
    docs: 'A key added by a test.',
    owner: 'observability',
    experimentalValues: [],
    developmentOnly: false,
    ...overrides,
  };
}

describe('admin events are always on', () => {
  it('lists every configuration name that holds an event word, with its reason', () => {
    expect(findEventNames(configurationNames(), ALLOWED)).toEqual([]);
  });

  it('allows only names the registry or a schema holds', () => {
    const names = configurationNames();
    expect(Object.keys(ALLOWED).filter((name) => !names.includes(name))).toEqual([]);
  });

  it('scans the whole registry', () => {
    const names = configurationNames();
    expect(names).toEqual(expect.arrayContaining(CONFIG_KEY_REGISTRY.map((key) => key.name)));
    expect(names.length).toBeGreaterThan(100);
  });

  // The acceptance criterion of #827: a switch named without a switch word
  // fails the test as soon as it enters the registry.
  it.each(['ADMIN_EVENTS', 'EMIT_ADMIN_EVENTS', 'AUDIT_LOG', 'EVENT_STORE_MODE', 'EVENTS_SINK'])(
    'fails when %s is added to the registry without an allow-list entry',
    (name) => {
      const registry = [...CONFIG_KEY_REGISTRY, keyNamed(name)];
      expect(findEventNames(configurationNames(registry), ALLOWED)).toEqual([name]);
    }
  );

  it('fails on an event word in an old name, a seeded realm policy or an env schema field', () => {
    const registry = [
      ...CONFIG_KEY_REGISTRY,
      keyNamed('ADMIN_CHANGES', { aliases: [{ name: 'ADMIN_AUDIT', deprecatedSince: '0.2.0' }] }),
      keyNamed('REALM_CHANGES', { role: 'realm-seed', seeds: 'admin.emitEvents' }),
    ];
    expect(findEventNames(configurationNames(registry, ['eventSink']), ALLOWED)).toEqual([
      'ADMIN_AUDIT',
      'emitEvents',
      'eventSink',
    ]);
  });
});

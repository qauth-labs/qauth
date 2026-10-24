/**
 * Migration 0031 copies audit rows into the event store (#458) with a map
 * written into its SQL. That map must be the event contract's
 * (`LEGACY_EVENT_MAP` of `@qauth-labs/shared-events`): the same old names, the
 * same types, the data each name implies, and the category and subject kind
 * the registry gives each type. The seed-then-migrate suite proves the copy on
 * Postgres; this test catches a drift between the two maps without Docker.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { getEventType, LEGACY_EVENT_MAP } from '@qauth-labs/shared-events';
import { describe, expect, it } from 'vitest';

const MIGRATION = path.resolve(
  __dirname,
  '..',
  '..',
  '..',
  'drizzle',
  '0031_audit_logs_backfill.sql'
);

/** One row of the migration's `legacy_map` VALUES list. */
const MAP_ROW =
  /^\s*\('([a-z0-9_.]+)', '(urn:qauth:event:[a-z0-9_.]+:v\d+(?:-rc\.\d+)?)', '(user|admin)', '(\{.*\})'::jsonb, (?:'([a-z_]+)'|NULL)\),?$/;

function migrationMap() {
  return readFileSync(MIGRATION, 'utf8')
    .split('\n')
    .map((line) => MAP_ROW.exec(line))
    .filter((match): match is RegExpExecArray => match !== null)
    .map(([, event, type, category, implied, subject]) => ({
      event,
      type,
      category,
      data: JSON.parse(implied) as Record<string, string>,
      subject: subject ?? null,
    }));
}

describe('migration 0031 — the map it copies audit rows with', () => {
  it('is the event contract map of every name an audit row was written with', () => {
    const expected = LEGACY_EVENT_MAP.filter((mapping) => mapping.source === 'audit').map(
      (mapping) => {
        const definition = getEventType(mapping.type);
        return {
          event: mapping.event,
          type: mapping.type,
          category: definition?.category,
          data: mapping.data ?? {},
          subject: definition?.subject ?? null,
        };
      }
    );
    expect(migrationMap()).toEqual(expected);
  });

  it('copies the two operator-tool types as admin events and every other type as a user event', () => {
    const admin = migrationMap()
      .filter((row) => row.category === 'admin')
      .map((row) => row.event);
    expect(admin).toEqual(['oauth.client.suspended', 'oauth.client.suspension_lifted']);
  });

  it('only reads audit_logs and leaves no object behind', () => {
    const sql = readFileSync(MIGRATION, 'utf8')
      .split('\n')
      .filter((line) => !line.trim().startsWith('--'))
      .join('\n');
    expect(sql).not.toMatch(/\b(UPDATE|DELETE FROM|TRUNCATE|DROP TABLE|ALTER TABLE)\b/i);
    const created = [...sql.matchAll(/CREATE FUNCTION (\S+)\(/g)].map((match) => match[1]);
    const dropped = [...sql.matchAll(/DROP FUNCTION (\S+)\(/g)].map((match) => match[1]);
    expect(created.every((name) => name.startsWith('pg_temp.'))).toBe(true);
    expect([...dropped].sort()).toEqual([...created].sort());
    expect(sql).not.toMatch(/CREATE (TABLE|INDEX|TYPE|TRIGGER|VIEW)/i);
  });
});

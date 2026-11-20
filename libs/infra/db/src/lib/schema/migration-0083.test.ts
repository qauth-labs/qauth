/**
 * Migration 0083 adds `webhook_subscriptions` (#537): where a realm's events
 * are sent as signed webhooks, which of them, and the reference of each
 * subscription's signing secret. A new, empty table that a release before
 * this one never names, so nothing is rewritten and a rolling upgrade is
 * safe. Its behaviour against a real Postgres is held by
 * `repositories/webhook-subscriptions.integration.test.ts`.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { getTableConfig } from 'drizzle-orm/pg-core';
import { describe, expect, it } from 'vitest';

import { webhookSubscriptions } from './webhook-subscriptions';

const DRIZZLE_DIR = path.resolve(__dirname, '..', '..', '..', 'drizzle');
const MIGRATION_TAG = '0083_webhook_subscriptions';
const MIGRATION_IDX = 83;

interface JournalEntry {
  idx: number;
  tag: string;
}

const journal: { entries: JournalEntry[] } = JSON.parse(
  readFileSync(path.join(DRIZZLE_DIR, 'meta/_journal.json'), 'utf8')
);

/** A migration's statements, split where drizzle-kit splits them, without comments. */
function statementsOf(tag: string): string[] {
  return readFileSync(path.join(DRIZZLE_DIR, `${tag}.sql`), 'utf8')
    .split('--> statement-breakpoint')
    .map((chunk) =>
      chunk
        .split('\n')
        .filter((line) => !line.trim().startsWith('--'))
        .join('\n')
        .trim()
    )
    .filter((statement) => statement !== '');
}

describe('migration 0083 (the webhook subscriptions of a realm)', () => {
  const statements = statementsOf(MIGRATION_TAG);

  it('is in the journal, after 0082', () => {
    const entry = journal.entries.find((candidate) => candidate.tag === MIGRATION_TAG);
    expect(entry?.idx).toBe(MIGRATION_IDX);
    expect(journal.entries[MIGRATION_IDX - 1]?.tag).toBe('0082_admin_act_sessions');
  });

  it('creates one new table, its two foreign keys and two indexes, and touches no other table', () => {
    expect(statements).toHaveLength(5);
    expect(statements[0]).toMatch(/^CREATE TABLE "webhook_subscriptions" \(/);
    expect(statements[1]).toMatch(
      /^ALTER TABLE "webhook_subscriptions" ADD CONSTRAINT "webhook_subscriptions_realm_id_realms_id_fk" FOREIGN KEY \("realm_id"\) REFERENCES "public"\."realms"\("id"\) ON DELETE cascade/
    );
    expect(statements[2]).toMatch(
      /^ALTER TABLE "webhook_subscriptions" ADD CONSTRAINT "webhook_subscriptions_created_by_users_id_fk" FOREIGN KEY \("created_by"\) REFERENCES "public"\."users"\("id"\) ON DELETE set null/
    );
    expect(statements[3]).toMatch(/^CREATE INDEX "idx_webhook_subscriptions_realm_created"/);
    expect(statements[4]).toMatch(/^CREATE INDEX "idx_webhook_subscriptions_overlap"/);
    expect(statements.join('\n')).not.toMatch(
      /\b(DROP|DELETE FROM|INSERT INTO|RENAME)\b|^UPDATE\b/m
    );
  });

  it('holds no secret: the signing secret is a realm key the column only names', () => {
    const columns = getTableConfig(webhookSubscriptions).columns.map((column) => column.name);
    expect(columns).toContain('secret_ref');
    expect(columns.filter((name) => /secret/.test(name))).toEqual([
      'secret_ref',
      'previous_secret_expires_at',
    ]);
    expect(statements[0]).toContain('CONSTRAINT "webhook_subscriptions_url_https"');
    expect(statements[0]).toContain('CONSTRAINT "webhook_subscriptions_disabled_reason"');
  });
});

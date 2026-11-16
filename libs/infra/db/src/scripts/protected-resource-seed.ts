/**
 * The seed manifest's `resources` section (#1087): the protected resources a
 * realm registers, each with the scopes it defines, their consent texts and
 * who may ask for them.
 *
 * Every entry converges the realm's registration of its resource indicator
 * on the entry, in one transaction: registered when the realm has none,
 * rewritten (its version raised) when it differs, left alone when it holds
 * the entry already. A resource the section does not list is never touched,
 * so dropping an entry removes nothing; the admin API's
 * `resourceServers.delete` does.
 *
 * The manifest is the operator's own file, run with the database's
 * credentials, as the first-party profile of a `clients` entry is: the admin
 * API's approval does not apply to it. The report says, per resource, what
 * the run widened or narrowed, so the operator reads the change it made.
 *
 * The logic lives here, apart from the CLI in `seed-oauth-clients.ts`, so it
 * can be tested without running the script.
 */
import type { NodePgDatabase } from 'drizzle-orm/node-postgres';

import {
  createProtectedResourcesRepository,
  type ProtectedResource,
  type ProtectedResourceSettings,
} from '../lib/repositories/protected-resources.repository';
import type { DbClient } from '../types';
import type { ResourceSpec } from './seed-manifest';

/**
 * - `created`: the realm registered no such resource; it does now.
 * - `updated`: the registration changed.
 * - `unchanged`: it already held the entry.
 */
export type ResourceSeedStatus = 'created' | 'updated' | 'unchanged';

/** What one entry did, and what it changed. */
export interface ResourceSeedResult {
  readonly resource: string;
  readonly status: ResourceSeedStatus;
  /** The changes, one line each, empty when nothing changed. */
  readonly changes: readonly string[];
}

/** Any drizzle node-postgres database, whatever schema generic it was built with. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type OperatorDb = NodePgDatabase<any>;

/** The settings an entry writes. */
export function settingsOf(spec: ResourceSpec): ProtectedResourceSettings {
  return {
    scopes: spec.scopes.map((entry) => ({
      scope: entry.scope,
      text: { ...entry.text },
      sensitive: entry.sensitive === true,
    })),
    anyClient: spec.clients === 'any_client',
    clientIds: spec.clients === 'any_client' ? [] : [...spec.clients],
  };
}

/** A stable text of one scope's definition, to compare two of them. */
function scopeKey(entry: ProtectedResourceSettings['scopes'][number]): string {
  const text = Object.keys(entry.text)
    .sort()
    .map((locale) => [locale, entry.text[locale]]);
  return JSON.stringify([entry.sensitive === true, text]);
}

/**
 * The changes from `before` to `after`, one line each, in the operator's
 * terms: a scope added, removed or changed, and who may ask widened or
 * narrowed. Empty when they are the same.
 */
export function resourceChanges(
  before: ProtectedResourceSettings | undefined,
  after: ProtectedResourceSettings
): string[] {
  const lines: string[] = [];
  const old = new Map((before?.scopes ?? []).map((entry) => [entry.scope, entry]));
  const next = new Map(after.scopes.map((entry) => [entry.scope, entry]));
  for (const [scope, entry] of next) {
    const was = old.get(scope);
    if (was === undefined) lines.push(`scope added: ${scope}`);
    else if (scopeKey(was) !== scopeKey(entry)) lines.push(`scope changed: ${scope}`);
  }
  for (const scope of old.keys()) {
    if (!next.has(scope)) lines.push(`scope removed: ${scope}`);
  }
  // Compared as values, never as the report's words: a client_id may read
  // like the words for every client, or hold the separator of a list.
  if (before === undefined) {
    lines.push(`open to: ${who(after)}`);
  } else if (!sameAccess(before, after)) {
    lines.push(`open to: ${who(before)} -> ${who(after)}`);
  }
  return lines;
}

/** Whether two registrations are open to the same clients, whatever the order of the list. */
function sameAccess(a: ProtectedResourceSettings, b: ProtectedResourceSettings): boolean {
  if (a.anyClient !== b.anyClient) return false;
  const left = [...a.clientIds].sort();
  const right = [...b.clientIds].sort();
  return left.length === right.length && left.every((id, index) => id === right[index]);
}

/** Who may ask, as the report names it. */
function who(settings: ProtectedResourceSettings): string {
  return settings.anyClient ? 'any client' : [...settings.clientIds].sort().join(', ');
}

function settingsOfRow(row: ProtectedResource): ProtectedResourceSettings {
  return { scopes: row.scopes, anyClient: row.anyClient, clientIds: row.clientIds };
}

/**
 * Converge the realm's registration of `spec.resource` on the entry, in one
 * transaction. Idempotent.
 *
 * @throws Error when a concurrent writer changed the row under the lock,
 *   which the lock rules out
 */
export async function applyResourceEntry(
  db: OperatorDb,
  realmId: string,
  spec: ResourceSpec
): Promise<ResourceSeedResult> {
  const settings = settingsOf(spec);
  return db.transaction(async (tx) => {
    const client = tx as unknown as DbClient;
    const repository = createProtectedResourcesRepository(client);
    const found = await repository.findByResource(realmId, spec.resource, client);
    if (found === undefined) {
      const created = await repository.create(realmId, spec.resource, settings, client);
      if (created !== undefined) {
        return {
          resource: spec.resource,
          status: 'created' as const,
          changes: resourceChanges(undefined, settings),
        };
      }
    }
    // Registered already, or by a concurrent writer since the read: lock the
    // row and compare it with the entry.
    const current =
      found === undefined ? await repository.findByResource(realmId, spec.resource, client) : found;
    if (current === undefined) {
      throw new Error(`${spec.resource}: the registration went away while the seed ran`);
    }
    const locked = await repository.findByIdForUpdate(realmId, current.id, client);
    if (locked === undefined) {
      throw new Error(`${spec.resource}: the registration went away while the seed ran`);
    }
    const changes = resourceChanges(settingsOfRow(locked), settings);
    if (changes.length === 0) {
      return { resource: spec.resource, status: 'unchanged' as const, changes };
    }
    const updated = await repository.update(realmId, locked.id, settings, locked.version, client);
    if (updated === undefined) {
      throw new Error(`${spec.resource}: the registration changed while the seed ran`);
    }
    return { resource: spec.resource, status: 'updated' as const, changes };
  });
}

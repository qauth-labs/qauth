import { readdirSync, readFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';

import { describe, expect, it } from 'vitest';

import { LEGACY_EVENT_MAP, legacyEventMapping } from './legacy';
import { getEventType } from './registry';

const REPO_ROOT = resolve(__dirname, '..', '..', '..', '..', '..');

function sourceFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return sourceFiles(path);
    return entry.name.endsWith('.ts') && !/\.(test|spec)\.ts$/.test(entry.name) ? [path] : [];
  });
}

/** A dotted event name in single quotes: `'oauth.token.exchange.success'`. */
const QUOTED_NAME = /'([a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+)'/g;

/**
 * Every event name the server writes today, found the way the pull request
 * of #456 lists them: the value of each `event:` property (audit rows, both
 * branches of a ternary included), each `logAuthEvent(...)` name, and the
 * `AuthEventName` union of the log-only names.
 */
function eventNamesIn(source: string): string[] {
  const names = new Set<string>();
  for (const match of source.matchAll(/\bevent:\s*([^\n]+)/g)) {
    for (const name of match[1].matchAll(QUOTED_NAME)) names.add(name[1]);
  }
  for (const match of source.matchAll(/logAuthEvent\(\s*\w+,\s*'([^']+)'/g)) names.add(match[1]);
  const union = /export type AuthEventName =([^;]+);/.exec(source);
  if (union) for (const name of union[1].matchAll(QUOTED_NAME)) names.add(name[1]);
  return [...names];
}

function searchEventNames(dir: string): Map<string, string[]> {
  const found = new Map<string, string[]>();
  for (const file of sourceFiles(join(REPO_ROOT, dir))) {
    for (const name of eventNamesIn(readFileSync(file, 'utf8'))) {
      found.set(name, [...(found.get(name) ?? []), relative(REPO_ROOT, file)]);
    }
  }
  return found;
}

describe('the map from earlier event names to registered types', () => {
  const server = searchEventNames('apps/auth-server/src');
  // The client-suspension script writes audit rows from outside the server.
  const scripts = searchEventNames('libs/infra/db/src/scripts');

  it('finds the event names the server writes today', () => {
    // A guard on the search itself: it must keep finding the known names, so
    // a change of call shape cannot empty it and pass the test below vacuously.
    expect(server.size).toBeGreaterThanOrEqual(40);
    for (const name of [
      'oauth.token.exchange.failure',
      'ui.wallet_login.success',
      'user.register.success',
    ]) {
      expect(server.has(name)).toBe(true);
    }
    expect(scripts.has('oauth.client.suspended')).toBe(true);
  });

  // The acceptance criterion of #456: the map covers every event string a
  // search of apps/auth-server/src finds.
  it('maps every event name a search of apps/auth-server/src finds', () => {
    const unmapped = [...server, ...scripts]
      .filter(([name]) => !legacyEventMapping(name))
      .map(([name, files]) => `${name} (${files.join(', ')})`);
    expect(unmapped).toEqual([]);
  });

  it('holds no name that is written nowhere', () => {
    const stale = LEGACY_EVENT_MAP.map((m) => m.event).filter(
      (name) => !server.has(name) && !scripts.has(name)
    );
    expect(stale).toEqual([]);
  });

  it('maps each name once, to a registered type', () => {
    const names = LEGACY_EVENT_MAP.map((mapping) => mapping.event);
    expect(new Set(names).size).toBe(names.length);
    for (const mapping of LEGACY_EVENT_MAP) {
      expect(getEventType(mapping.type), mapping.event).toBeDefined();
    }
  });

  it('implies only data members that the type declares, with values it accepts', () => {
    for (const mapping of LEGACY_EVENT_MAP) {
      const definition = getEventType(mapping.type);
      for (const [member, value] of Object.entries(mapping.data ?? {})) {
        const schema = definition?.data.shape[member];
        expect(schema, `${mapping.event}: ${member}`).toBeDefined();
        expect(schema?.safeParse(value).success, `${mapping.event}: ${member}=${value}`).toBe(true);
      }
    }
  });

  it('records whether a name was an audit row or only a log line', () => {
    const logOnly = LEGACY_EVENT_MAP.filter((m) => m.source === 'log').map((m) => m.event);
    expect(logOnly.sort()).toEqual(['user.register.failure', 'user.register.success']);
  });
});

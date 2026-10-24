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
 * The event names a source file writes, found the way the pull request of
 * #456 listed them: `audit` holds the value of each `event:` property (an
 * audit row, both branches of a ternary included); `log` holds each
 * `logAuthEvent(...)` name and the `AuthEventName` union of the logged names.
 */
function eventNamesIn(source: string): { audit: string[]; log: string[] } {
  const audit = new Set<string>();
  const log = new Set<string>();
  for (const match of source.matchAll(/\bevent:\s*([^\n]+)/g)) {
    for (const name of match[1].matchAll(QUOTED_NAME)) audit.add(name[1]);
  }
  for (const match of source.matchAll(/logAuthEvent\(\s*\w+,\s*'([^']+)'/g)) log.add(match[1]);
  const union = /export type AuthEventName =([^;]+);/.exec(source);
  if (union) for (const name of union[1].matchAll(QUOTED_NAME)) log.add(name[1]);
  return { audit: [...audit], log: [...log] };
}

/** Each name found under `dir`, with the files that write it, by kind. */
function searchEventNames(dir: string, kind: 'audit' | 'log' | 'all'): Map<string, string[]> {
  const found = new Map<string, string[]>();
  for (const file of sourceFiles(join(REPO_ROOT, dir))) {
    const names = eventNamesIn(readFileSync(file, 'utf8'));
    const picked = kind === 'all' ? [...names.audit, ...names.log] : names[kind];
    for (const name of new Set(picked)) {
      found.set(name, [...(found.get(name) ?? []), relative(REPO_ROOT, file)]);
    }
  }
  return found;
}

describe('the map from earlier event names to registered types', () => {
  const server = searchEventNames('apps/auth-server/src', 'all');
  const scripts = searchEventNames('libs/infra/db/src/scripts', 'all');
  const logged = searchEventNames('apps/auth-server/src', 'log');
  const logNames = LEGACY_EVENT_MAP.filter((m) => m.source === 'log').map((m) => m.event);

  it('finds the log-only event names the server still writes', () => {
    // A guard on the search itself: it must keep finding the log names, so a
    // change of call shape cannot empty it and pass the tests below vacuously.
    for (const name of ['user.login.failure', 'user.register.success', 'user.logout.success']) {
      expect(logged.has(name), name).toBe(true);
    }
  });

  // The acceptance criterion of #456: the map covers every event string a
  // search of apps/auth-server/src finds.
  it('maps every event name a search of apps/auth-server/src finds', () => {
    const unmapped = [...server, ...scripts]
      .filter(([name]) => !legacyEventMapping(name))
      .map(([name, files]) => `${name} (${files.join(', ')})`);
    expect(unmapped).toEqual([]);
  });

  // Since #458 no audit row is written: the server and the suspension tool
  // record events, and the audit names live on only as the input of the
  // backfill (migration 0031, whose own test keeps its copy of the map equal
  // to this one). An audit-row write would bring an `event:` name back.
  it('finds no audit row written anywhere any more', () => {
    const written = [
      ...searchEventNames('apps/auth-server/src', 'audit'),
      ...searchEventNames('libs/infra/db/src/scripts', 'audit'),
    ].map(([name, files]) => `${name} (${files.join(', ')})`);
    expect(written).toEqual([]);
  });

  it('holds no log-only name that is logged nowhere', () => {
    expect(logNames.filter((name) => !logged.has(name))).toEqual([]);
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
    expect([...logNames].sort()).toEqual(['user.register.failure', 'user.register.success']);
  });
});

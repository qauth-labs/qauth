import { findEventSwitches } from '@qauth-labs/shared-events';
import { getTableColumns, getTableName, type Table } from 'drizzle-orm';
import { describe, expect, it } from 'vitest';

import { realmHosts, realms } from './core';

/**
 * Admin events are always on (ADR-020 §3, issue #459): no realm setting turns
 * them off. Realm policies live on the realm row (ADR-019 Decision 10), so no
 * column of a realm's tables may read like a switch for events. The
 * configuration keys are scanned by `server-config`'s twin of this test.
 */
const REALM_TABLES: readonly Table[] = [realms, realmHosts];

function realmFieldNames(): string[] {
  return REALM_TABLES.flatMap((table) =>
    Object.entries(getTableColumns(table)).flatMap(([key, column]) => [key, column.name])
  );
}

describe('admin events are always on', () => {
  it('no realm field reads like a switch for them', () => {
    expect(findEventSwitches(realmFieldNames())).toEqual([]);
  });

  it('scans every column of the realm tables', () => {
    expect(REALM_TABLES.map((table) => getTableName(table))).toEqual(['realms', 'realm_hosts']);
    expect(realmFieldNames()).toEqual(expect.arrayContaining(['passwordPolicy', 'enabled']));
  });
});

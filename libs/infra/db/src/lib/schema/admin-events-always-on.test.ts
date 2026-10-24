import { findEventNames } from '@qauth-labs/shared-events';
import { getTableColumns, getTableName, type Table } from 'drizzle-orm';
import { describe, expect, expectTypeOf, it } from 'vitest';

import { realmHosts, realms } from './core';

/**
 * Admin events are always on (ADR-020 §3, issues #459 and #827): no realm
 * setting turns them off. Realm policies live on the realm row (ADR-019
 * Decision 10), so every column of a realm's tables, and every member a
 * `jsonb` column's type declares, that holds an event word (`event`,
 * `audit`, `log`, `sink`, …) is listed in ALLOWED with the reason it turns
 * nothing off, or the test fails. The configuration keys are scanned by
 * `server-config`'s twin of this test.
 */
const REALM_TABLES: readonly Table[] = [realms, realmHosts];

/** Realm fields that hold an event word but turn nothing off, with the reason. None today. */
const ALLOWED: Readonly<Record<string, string>> = {};

type RealmRow = typeof realms.$inferSelect;

/**
 * The members of each `jsonb` column of the realm tables, as the column's
 * type declares them. `metadata` is a free-form record and the two lists hold
 * strings, so they declare none. A member typed into a column must be listed
 * here (the type test below fails otherwise), and is then scanned as
 * `column.member`.
 */
const REALM_JSONB_MEMBERS = {
  passwordPolicy: [
    'minLength',
    'requireUppercase',
    'requireLowercase',
    'requireDigits',
    'requireSpecialChars',
    'forbiddenPasswords',
    'maxLength',
    'preventReuse',
  ],
  supportedLocales: [],
  dynamicRegistrationAllowedScopes: [],
  metadata: [],
} as const;

type JsonbMembers = Readonly<Record<string, readonly string[]>>;

/** The member names an object type declares; none for an index signature or an array. */
type DeclaredMembers<T> = T extends readonly unknown[]
  ? never
  : T extends object
    ? Extract<keyof { [K in keyof T as string extends K ? never : K]: T[K] }, string>
    : never;

/** Every column name of the realm tables, and every declared `jsonb` member as `column.member`. */
function realmFieldNames(members: JsonbMembers = REALM_JSONB_MEMBERS): string[] {
  const columns = REALM_TABLES.flatMap((table) =>
    Object.entries(getTableColumns(table)).flatMap(([key, column]) => [key, column.name])
  );
  const paths = Object.entries(members).flatMap(([column, names]) =>
    names.map((member) => `${column}.${member}`)
  );
  return [...columns, ...paths];
}

describe('admin events are always on', () => {
  it('lists every realm field that holds an event word, with its reason', () => {
    expect(findEventNames(realmFieldNames(), ALLOWED)).toEqual([]);
  });

  it('scans every column of the realm tables', () => {
    expect(REALM_TABLES.map((table) => getTableName(table))).toEqual(['realms', 'realm_hosts']);
    expect(realmFieldNames()).toEqual(expect.arrayContaining(['passwordPolicy', 'enabled']));
  });

  it('scans the members of every jsonb column, as their types declare them', () => {
    const jsonbColumns = REALM_TABLES.flatMap((table) =>
      Object.entries(getTableColumns(table))
        .filter(([, column]) => column.getSQLType() === 'jsonb')
        .map(([key]) => key)
    );
    expect(Object.keys(REALM_JSONB_MEMBERS).sort()).toEqual(jsonbColumns.sort());
    expect(realmFieldNames()).toEqual(
      expect.arrayContaining(['passwordPolicy.minLength', 'passwordPolicy.preventReuse'])
    );

    type Listed = {
      [C in keyof typeof REALM_JSONB_MEMBERS]: (typeof REALM_JSONB_MEMBERS)[C][number];
    };
    type Declared = {
      [C in keyof typeof REALM_JSONB_MEMBERS]: DeclaredMembers<NonNullable<RealmRow[C]>>;
    };
    expectTypeOf<Listed>().toEqualTypeOf<Declared>();
  });

  // The acceptance criterion of #827: a member named for events inside a
  // jsonb column fails the test, like a column would.
  it('fails on a jsonb member such as metadata.auditEnabled', () => {
    const members = { ...REALM_JSONB_MEMBERS, metadata: ['auditEnabled'] };
    expect(findEventNames(realmFieldNames(members), ALLOWED)).toEqual(['metadata.auditEnabled']);
  });
});

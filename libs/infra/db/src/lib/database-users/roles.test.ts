import { readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import { DATABASE_ROLES, DATABASE_USER_ENV, databaseUsersFromEnv, usersByRole } from './roles';

/** The `DB_USER_*` variables (issue #498). */

const ALL = {
  DB_USER_WEB: 'qauth_web',
  DB_USER_API: 'qauth_api',
  DB_USER_ADMIN: 'qauth_admin',
  DB_USER_SIGNER: 'qauth_signer',
  DB_USER_DELIVERY: 'qauth_delivery',
} as const;

describe('databaseUsersFromEnv', () => {
  it('names one variable per service role', () => {
    expect(DATABASE_ROLES).toEqual(['web', 'api', 'admin', 'signer', 'delivery']);
    expect(Object.values(DATABASE_USER_ENV)).toEqual(Object.keys(ALL));
  });

  it("names the auth server's service roles, read from their source", () => {
    // infra-db may not import the server's configuration, so the list is read
    // as text: a role added there must get a database user here.
    const source = readFileSync(
      path.resolve(__dirname, '../../../../../server/config/src/lib/schemas/service-roles.ts'),
      'utf8'
    );
    const declared = /export const SERVICE_ROLE_NAMES = \[([^\]]*)\] as const;/.exec(source);
    expect(declared).not.toBeNull();
    const names = [...(declared?.[1] ?? '').matchAll(/'([a-z]+)'/g)].map((match) => match[1]);
    expect(names).toEqual([...DATABASE_ROLES]);
  });

  it('reads a single deployment, with none set or all blank, as nothing to grant', () => {
    expect(databaseUsersFromEnv({})).toEqual({ configured: false });
    expect(
      databaseUsersFromEnv(Object.fromEntries(Object.keys(ALL).map((name) => [name, ' '])))
    ).toEqual({ configured: false });
  });

  it('reads a user for every role', () => {
    expect(databaseUsersFromEnv(ALL)).toEqual({
      configured: true,
      users: {
        web: 'qauth_web',
        api: 'qauth_api',
        admin: 'qauth_admin',
        signer: 'qauth_signer',
        delivery: 'qauth_delivery',
      },
    });
  });

  it('refuses a partial set, naming the roles left out', () => {
    const partial = {
      DB_USER_WEB: ALL.DB_USER_WEB,
      DB_USER_API: ALL.DB_USER_API,
      DB_USER_SIGNER: ALL.DB_USER_SIGNER,
    };
    const read = databaseUsersFromEnv(partial);
    expect(read.configured).toBe('invalid');
    expect(read).toMatchObject({
      problems: [expect.stringMatching(/^DB_USER_ADMIN, DB_USER_DELIVERY are not set/)],
    });
  });

  it.each([
    ['a NUL byte', 'qauth\0web'],
    ['a name over 63 bytes', 'u'.repeat(64)],
  ])('refuses %s, naming the variable', (_label, value) => {
    expect(databaseUsersFromEnv({ ...ALL, DB_USER_WEB: value })).toEqual({
      configured: 'invalid',
      problems: [expect.stringMatching(/^DB_USER_WEB is not a usable Postgres role name/)],
    });
  });
});

describe('usersByRole', () => {
  it('merges the roles that share a user, in role order', () => {
    const users = {
      web: 'qauth_front',
      api: 'qauth_front',
      admin: 'qauth_admin',
      signer: 'qauth_front',
      delivery: 'qauth_front',
    };
    expect([...usersByRole(users)]).toEqual([
      ['qauth_front', ['web', 'api', 'signer', 'delivery']],
      ['qauth_admin', ['admin']],
    ]);
  });
});

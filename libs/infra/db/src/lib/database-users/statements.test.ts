import { describe, expect, it } from 'vitest';

import type { DatabaseGrantsMap } from './grants-map';
import type { DatabaseUserAssignment } from './roles';
import { databaseUserGrantStatements, grantsOfUsers } from './statements';

/**
 * The statements that apply the grants map (issue #498), on a small map of
 * the test's own so the expected statements stay readable. The container
 * suite applies the real map.
 */

const MAP: DatabaseGrantsMap = {
  tables: {
    events: { web: ['INSERT'], delivery: ['SELECT', 'DELETE'] },
    realm_keys: { signer: ['SELECT', 'INSERT', 'UPDATE', 'DELETE'] },
    realms: { web: ['SELECT', 'INSERT', 'UPDATE'], signer: ['SELECT'] },
    roles: {},
  },
  columns: {
    realms: { delivery: ['issuer', 'id'], web: ['id'] },
  },
  functions: {
    '"events_own_row"(uuid)': ['web'],
    '"events_oldest_unread_time"()': ['web', 'delivery'],
  },
};

const SPLIT: DatabaseUserAssignment = {
  web: 'qauth_web',
  api: 'qauth_api',
  admin: 'qauth_admin',
  signer: 'qauth_signer',
  delivery: 'qauth_delivery',
};

/** The statements every user starts with: everything revoked, the journal granted. */
function prelude(user: string): string[] {
  return [
    `REVOKE ALL ON ALL TABLES IN SCHEMA "public" FROM "${user}"`,
    `REVOKE ALL ON ALL SEQUENCES IN SCHEMA "public" FROM "${user}"`,
    `REVOKE ALL ON ALL ROUTINES IN SCHEMA "public" FROM "${user}"`,
    `REVOKE CREATE ON SCHEMA "public" FROM "${user}"`,
    `GRANT USAGE ON SCHEMA "public" TO "${user}"`,
    `REVOKE ALL ON ALL TABLES IN SCHEMA "drizzle" FROM "${user}"`,
    `REVOKE ALL ON SCHEMA "drizzle" FROM "${user}"`,
    `GRANT USAGE ON SCHEMA "drizzle" TO "${user}"`,
    `GRANT SELECT ON TABLE "drizzle"."__drizzle_migrations" TO "${user}"`,
  ];
}

describe('databaseUserGrantStatements (#498)', () => {
  it("revokes everything each user held, then grants its role's tables, columns and functions", () => {
    expect(databaseUserGrantStatements(SPLIT, MAP)).toEqual([
      ...prelude('qauth_web'),
      'GRANT INSERT ON TABLE "events" TO "qauth_web"',
      'GRANT SELECT, INSERT, UPDATE ON TABLE "realms" TO "qauth_web"',
      'GRANT EXECUTE ON FUNCTION "events_oldest_unread_time"(), "events_own_row"(uuid) TO "qauth_web"',
      ...prelude('qauth_api'),
      ...prelude('qauth_admin'),
      ...prelude('qauth_signer'),
      'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE "realm_keys" TO "qauth_signer"',
      'GRANT SELECT ON TABLE "realms" TO "qauth_signer"',
      ...prelude('qauth_delivery'),
      'GRANT SELECT, DELETE ON TABLE "events" TO "qauth_delivery"',
      'GRANT SELECT ("id", "issuer") ON TABLE "realms" TO "qauth_delivery"',
      'GRANT EXECUTE ON FUNCTION "events_oldest_unread_time"() TO "qauth_delivery"',
    ]);
  });

  it('gives a user two roles share the grants of both, once', () => {
    const shared = { ...SPLIT, web: 'qauth_front', signer: 'qauth_front', delivery: 'qauth_front' };
    const [front] = grantsOfUsers(shared, MAP);
    expect(front?.user).toBe('qauth_front');
    expect(front?.roles).toEqual(['web', 'signer', 'delivery']);
    expect(Object.fromEntries(front?.tables ?? [])).toEqual({
      events: ['SELECT', 'INSERT', 'DELETE'],
      realm_keys: ['SELECT', 'INSERT', 'UPDATE', 'DELETE'],
      realms: ['SELECT', 'INSERT', 'UPDATE'],
    });
    // It reads the whole of realms, so no column grant is left.
    expect(front?.columns.size).toBe(0);
    expect(front?.functions).toEqual(['"events_oldest_unread_time"()', '"events_own_row"(uuid)']);
    expect(
      databaseUserGrantStatements(shared, MAP).filter((s) => s.includes('qauth_front'))
    ).toEqual([
      ...prelude('qauth_front'),
      'GRANT SELECT, INSERT, DELETE ON TABLE "events" TO "qauth_front"',
      'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE "realm_keys" TO "qauth_front"',
      'GRANT SELECT, INSERT, UPDATE ON TABLE "realms" TO "qauth_front"',
      'GRANT EXECUTE ON FUNCTION "events_oldest_unread_time"(), "events_own_row"(uuid) TO "qauth_front"',
    ]);
  });

  it('gives one user every role the union of the map', () => {
    const one = { web: 'u', api: 'u', admin: 'u', signer: 'u', delivery: 'u' };
    expect(grantsOfUsers(one, MAP)).toHaveLength(1);
  });

  it('quotes a user name as an identifier', () => {
    const odd = { ...SPLIT, web: 'odd"; DROP TABLE x; --' };
    expect(databaseUserGrantStatements(odd, MAP)[0]).toBe(
      'REVOKE ALL ON ALL TABLES IN SCHEMA "public" FROM "odd""; DROP TABLE x; --"'
    );
  });

  it('refuses a user name Postgres would truncate', () => {
    expect(() => databaseUserGrantStatements({ ...SPLIT, api: 'u'.repeat(64) }, MAP)).toThrow(
      TypeError
    );
  });
});

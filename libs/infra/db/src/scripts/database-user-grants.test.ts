import { describe, expect, it } from 'vitest';

import {
  DATABASE_USER_GRANTS_EXIT,
  DATABASE_USER_GRANTS_USAGE,
  parseDatabaseUserGrantsArgs,
  runDatabaseUserGrants,
} from './database-user-grants';

/**
 * The `db:grants` command without a database (issue #498). The container
 * suite, `database-users.integration.test.ts`, applies the grants to one.
 */

const argv = (...args: string[]) => ['node', 'grant-database-users.ts', ...args];

function capture() {
  const out: string[] = [];
  const err: string[] = [];
  return { out, err, io: { out: (l: string) => out.push(l), err: (l: string) => err.push(l) } };
}

const USERS = {
  DB_USER_WEB: 'qauth_web',
  DB_USER_API: 'qauth_api',
  DB_USER_ADMIN: 'qauth_admin',
  DB_USER_SIGNER: 'qauth_signer',
  DB_USER_DELIVERY: 'qauth_delivery',
};

describe('parseDatabaseUserGrantsArgs', () => {
  it('reads --check, --print and --help', () => {
    expect(parseDatabaseUserGrantsArgs(argv())).toEqual({
      check: false,
      print: false,
      help: false,
    });
    expect(parseDatabaseUserGrantsArgs(argv('--check'))?.check).toBe(true);
    expect(parseDatabaseUserGrantsArgs(argv('--print'))?.print).toBe(true);
    expect(parseDatabaseUserGrantsArgs(argv('-h'))?.help).toBe(true);
  });

  it('refuses an unknown flag, and --check with --print', () => {
    expect(parseDatabaseUserGrantsArgs(argv('--force'))).toBeNull();
    expect(parseDatabaseUserGrantsArgs(argv('--check', '--print'))).toBeNull();
  });
});

describe('runDatabaseUserGrants without a database', () => {
  it('prints the usage and exits 2 on an unknown flag', async () => {
    const { err, io } = capture();
    await expect(runDatabaseUserGrants(argv('--all'), {}, io)).resolves.toBe(
      DATABASE_USER_GRANTS_EXIT.usage
    );
    expect(err).toEqual([DATABASE_USER_GRANTS_USAGE]);
  });

  it('does nothing in a single deployment, without a database', async () => {
    const { out, err, io } = capture();
    await expect(runDatabaseUserGrants(argv(), {}, io)).resolves.toBe(
      DATABASE_USER_GRANTS_EXIT.done
    );
    expect(err).toEqual([]);
    expect(out).toHaveLength(1);
    expect(out[0]).toMatch(/^None of the DB_USER_\* variables is set: .*Nothing to do\.$/);
  });

  it('exits 2 when only some users are named, naming the missing ones', async () => {
    const { err, io } = capture();
    const env = { DB_USER_WEB: 'qauth_web', DATABASE_URL: 'postgresql://u:p@127.0.0.1:1/db' };
    await expect(runDatabaseUserGrants(argv(), env, io)).resolves.toBe(
      DATABASE_USER_GRANTS_EXIT.usage
    );
    expect(err[0]).toMatch(
      /^DB_USER_API, DB_USER_ADMIN, DB_USER_SIGNER, DB_USER_DELIVERY are not set/
    );
    expect(err.at(-1)).toBe('Nothing was granted.');
  });

  it('prints the statements with --print, connecting nowhere', async () => {
    const { out, io } = capture();
    await expect(runDatabaseUserGrants(argv('--print'), USERS, io)).resolves.toBe(
      DATABASE_USER_GRANTS_EXIT.done
    );
    expect(out[0]).toBe('REVOKE ALL ON ALL TABLES IN SCHEMA "public" FROM "qauth_web";');
    expect(out).toContain(
      'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE "realm_keys" TO "qauth_signer";'
    );
    expect(out.filter((line) => line.includes('"realm_keys"') && line.startsWith('GRANT'))).toEqual(
      ['GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE "realm_keys" TO "qauth_signer";']
    );
    for (const line of out) expect(line).toMatch(/^(REVOKE|GRANT) .*;$/);
  });

  it('exits 2 without DATABASE_URL, to apply or to check', async () => {
    for (const args of [argv(), argv('--check')]) {
      const { err, io } = capture();
      await expect(runDatabaseUserGrants(args, USERS, io)).resolves.toBe(
        DATABASE_USER_GRANTS_EXIT.usage
      );
      expect(err).toEqual([
        'DATABASE_URL must be set in the environment, to the owner of the tables.',
      ]);
    }
  });

  it('exits 3 when the database cannot be reached, having changed nothing', async () => {
    const env = { ...USERS, DATABASE_URL: 'postgresql://u:p@127.0.0.1:1/db' };
    const apply = capture();
    await expect(runDatabaseUserGrants(argv(), env, apply.io)).resolves.toBe(
      DATABASE_USER_GRANTS_EXIT.cannotRun
    );
    expect(apply.err.at(-1)).toMatch(/^Cannot apply the grants: .*Nothing was changed\.$/);
    const check = capture();
    await expect(runDatabaseUserGrants(argv('--check'), env, check.io)).resolves.toBe(
      DATABASE_USER_GRANTS_EXIT.cannotRun
    );
    expect(check.err.at(-1)).toMatch(/^Cannot check the grants: /);
  });
});

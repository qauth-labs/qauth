import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';

import { is } from 'drizzle-orm';
import { getTableConfig, PgTable } from 'drizzle-orm/pg-core';
import { describe, expect, it } from 'vitest';

import { ADMIN_AUDIT_LOG_WRITER_GRANTS } from '../admin-audit/grants';
import { EVENT_DELIVERY_COLUMNS, EVENT_DELIVERY_GRANTS } from '../events/delivery-grants';
import { EVENTS_WRITER_FUNCTIONS, EVENTS_WRITER_GRANTS } from '../events/grants';
import { EVENT_RETENTION_GRANTS, EVENT_RETENTION_REALM_COLUMNS } from '../events/retention-grants';
import type { TablePrivilege } from '../role-grants';
import * as schema from '../schema';
import { COLUMN_GRANTS, FUNCTION_GRANTS, TABLE_GRANTS } from './grants-map';
import { DATABASE_ROLES, type DatabaseRole } from './roles';

/**
 * The grants map (issue #498): its invariants, and its agreement with the
 * schema, the migrations and the grant builders of the areas that defined
 * their roles' grants first. The container suite applies it to Postgres.
 */

const DRIZZLE_DIR = path.resolve(__dirname, '..', '..', '..', 'drizzle');

/** Every table the schema defines, with its columns. */
const SCHEMA_TABLES = new Map(
  (Object.values(schema) as unknown[])
    .filter((value): value is PgTable => is(value, PgTable))
    .map((table) => {
      const config = getTableConfig(table);
      return [config.name, config.columns.map((column) => column.name)] as const;
    })
);

function privilegesOf(role: DatabaseRole, table: string): readonly TablePrivilege[] {
  return TABLE_GRANTS[table]?.[role] ?? [];
}

function tablesOf(role: DatabaseRole): string[] {
  return Object.keys(TABLE_GRANTS).filter((table) => privilegesOf(role, table).length > 0);
}

describe('the grants map (#498)', () => {
  it('names every table of the schema, and no other', () => {
    expect(Object.keys(TABLE_GRANTS).sort()).toEqual([...SCHEMA_TABLES.keys()].sort());
  });

  it('lists the tables in name order, with each privilege list in GRANT order', () => {
    const tables = Object.keys(TABLE_GRANTS);
    expect(tables).toEqual([...tables].sort());
    const order: readonly TablePrivilege[] = ['SELECT', 'INSERT', 'UPDATE', 'DELETE'];
    for (const [table, roles] of Object.entries(TABLE_GRANTS)) {
      for (const [role, privileges] of Object.entries(roles)) {
        expect(DATABASE_ROLES, `${table}: ${role}`).toContain(role);
        expect(privileges, `${table}: ${role}`).toEqual(
          order.filter((privilege) => privileges?.includes(privilege))
        );
        expect(privileges?.length, `${table}: ${role}`).toBeGreaterThan(0);
      }
    }
  });

  it("lets the sign-in engine and the password changes delete a user's required actions, and admin only add (#635, #1107)", () => {
    expect(TABLE_GRANTS['user_required_actions']).toEqual({
      web: ['SELECT', 'INSERT', 'DELETE'],
      api: ['SELECT', 'INSERT', 'DELETE'],
      admin: ['SELECT', 'INSERT'],
    });
  });

  it("lets the account page and the account API remove an account's credentials (#670, #844, #1108)", () => {
    expect(TABLE_GRANTS['user_credentials']).toEqual({
      web: ['SELECT', 'INSERT', 'UPDATE', 'DELETE'],
      api: ['SELECT', 'INSERT', 'UPDATE', 'DELETE'],
    });
  });

  it("lets web take and replace an account's recovery codes, and api count, delete, regenerate and confirm them (#649, #1107, #1108, #1109)", () => {
    expect(TABLE_GRANTS['user_recovery_codes']).toEqual({
      web: ['SELECT', 'INSERT', 'UPDATE', 'DELETE'],
      api: ['SELECT', 'INSERT', 'UPDATE', 'DELETE'],
    });
  });

  it('lets web alone read and advance the session epochs (#642)', () => {
    expect(TABLE_GRANTS['user_session_epochs']).toEqual({
      web: ['SELECT', 'INSERT', 'UPDATE'],
    });
  });

  it("lets web read the realm's upstream providers and admin manage them (#639)", () => {
    expect(TABLE_GRANTS['realm_upstream_providers']).toEqual({
      web: ['SELECT'],
      admin: ['SELECT', 'INSERT', 'UPDATE', 'DELETE'],
    });
  });

  it('gives realm_keys to the signer alone', () => {
    expect(TABLE_GRANTS['realm_keys']).toEqual({
      signer: ['SELECT', 'INSERT', 'UPDATE', 'DELETE'],
    });
    expect(COLUMN_GRANTS['realm_keys']).toBeUndefined();
  });

  it('lets every role read realm_public_keys and only the signer write it', () => {
    for (const role of DATABASE_ROLES) {
      expect(privilegesOf(role, 'realm_public_keys'), role).toContain('SELECT');
      if (role !== 'signer')
        expect(privilegesOf(role, 'realm_public_keys'), role).toEqual(['SELECT']);
    }
    expect(privilegesOf('signer', 'realm_public_keys')).toEqual(['SELECT', 'INSERT', 'UPDATE']);
  });

  it('gives audit_logs at most INSERT, to any role', () => {
    for (const role of DATABASE_ROLES) {
      expect(['INSERT']).toEqual(expect.arrayContaining([...privilegesOf(role, 'audit_logs')]));
    }
  });

  it('lets the event writers insert events and read none', () => {
    // `admin` writes the events of its operations (`user.verified`, #1052).
    for (const role of ['web', 'api', 'admin'] as const) {
      for (const [table, privileges] of Object.entries(EVENTS_WRITER_GRANTS)) {
        expect(privilegesOf(role, table), `${role}: ${table}`).toEqual(privileges);
      }
      for (const signature of EVENTS_WRITER_FUNCTIONS) {
        expect(FUNCTION_GRANTS[signature], signature).toContain(role);
      }
    }
    expect(privilegesOf('signer', 'events')).toEqual([]);
  });

  it("gives delivery its outbox and the retention job's tables, and nothing beyond them", () => {
    const expected = new Map<string, Set<TablePrivilege>>();
    for (const grants of [EVENT_DELIVERY_GRANTS, EVENT_RETENTION_GRANTS]) {
      for (const [table, privileges] of Object.entries(grants)) {
        const held = expected.get(table) ?? new Set<TablePrivilege>();
        privileges.forEach((privilege) => held.add(privilege));
        expected.set(table, held);
      }
    }
    expected.set('realm_public_keys', new Set<TablePrivilege>(['SELECT']));
    expect(tablesOf('delivery').sort()).toEqual([...expected.keys()].sort());
    for (const [table, privileges] of expected) {
      expect(new Set(privilegesOf('delivery', table)), table).toEqual(privileges);
    }
    const columns = Object.fromEntries(
      Object.entries(COLUMN_GRANTS).flatMap(([table, roles]) =>
        roles.delivery === undefined ? [] : [[table, [...roles.delivery].sort()]]
      )
    );
    expect(columns).toEqual({
      ...Object.fromEntries(
        Object.entries(EVENT_DELIVERY_COLUMNS).map(([table, names]) => [table, [...names].sort()])
      ),
      realms: [
        ...new Set([...(EVENT_DELIVERY_COLUMNS['realms'] ?? []), ...EVENT_RETENTION_REALM_COLUMNS]),
      ].sort(),
    });
    expect(FUNCTION_GRANTS['"events_oldest_unread_time"()']).toContain('delivery');
  });

  it("lets signer read whose client an upstream provider's assertions speak for, and no plugin config or secret (#1073)", () => {
    expect(privilegesOf('signer', 'realm_auth_method_plugins')).toEqual([]);
    expect(privilegesOf('signer', 'realm_upstream_providers')).toEqual([]);
    expect(COLUMN_GRANTS['realm_auth_method_plugins']?.signer).toEqual([
      'realm_id',
      'plugin_type',
      'enabled',
      'assertion_client_id',
      'assertion_issuer',
      'assertion_algorithm',
    ]);
    expect(COLUMN_GRANTS['realm_auth_method_plugins']?.signer).not.toContain('config');
    expect(COLUMN_GRANTS['realm_auth_method_plugins']?.signer).not.toContain('secrets');
    expect(COLUMN_GRANTS['realm_upstream_providers']?.signer).toEqual([
      'realm_id',
      'type',
      'enabled',
      'config',
    ]);
  });

  it("gives admin the admin audit log's writer grants", () => {
    for (const [table, privileges] of Object.entries(ADMIN_AUDIT_LOG_WRITER_GRANTS)) {
      expect(privilegesOf('admin', table), table).toEqual(privileges);
    }
  });

  it("gives admin users.verify's two functions, and no credential read nor account write of its own (#1052)", () => {
    expect(privilegesOf('admin', 'user_credentials')).toEqual([]);
    expect(privilegesOf('admin', 'users')).toEqual(['SELECT']);
    expect(FUNCTION_GRANTS['"user_credential_proofs"(uuid, uuid)']).toEqual(['admin']);
    expect(
      FUNCTION_GRANTS['"users_record_operator_verification"(uuid, uuid, uuid, bigint)']
    ).toEqual(['admin']);
  });

  it("lets admin manage any client of a realm and revoke a client's tokens, never issue one (#632)", () => {
    expect(privilegesOf('admin', 'oauth_clients')).toEqual([
      'SELECT',
      'INSERT',
      'UPDATE',
      'DELETE',
    ]);
    expect(privilegesOf('admin', 'refresh_tokens')).toEqual(['SELECT', 'UPDATE']);
  });

  it("lets web, api and admin move an account's security-change time through one function alone (#521)", () => {
    expect(FUNCTION_GRANTS['"admin_grants_record_security_change"(uuid, uuid)']).toEqual([
      'web',
      'api',
      'admin',
    ]);
  });

  it('lets no role write who administers, nor delete a realm or a user', () => {
    for (const role of DATABASE_ROLES) {
      for (const table of ['admin_grants', 'admin_roles']) {
        expect(privilegesOf(role, table), `${role}: ${table}`).not.toContain('INSERT');
        expect(privilegesOf(role, table), `${role}: ${table}`).not.toContain('UPDATE');
      }
      for (const table of ['realms', 'realm_hosts', 'users']) {
        expect(privilegesOf(role, table), `${role}: ${table}`).not.toContain('DELETE');
      }
    }
  });

  it('grants columns only where the role holds no SELECT on the whole table, and only columns that exist', () => {
    for (const [table, roles] of Object.entries(COLUMN_GRANTS)) {
      for (const [role, columns] of Object.entries(roles)) {
        expect(privilegesOf(role as DatabaseRole, table), `${role}: ${table}`).not.toContain(
          'SELECT'
        );
        for (const column of columns ?? []) {
          expect(SCHEMA_TABLES.get(table), `${table}.${column}`).toContain(column);
        }
      }
    }
  });

  it('grants EXECUTE only on functions a migration took from PUBLIC', () => {
    const migrations = readdirSync(DRIZZLE_DIR)
      .filter((file) => file.endsWith('.sql'))
      .map((file) => readFileSync(path.join(DRIZZLE_DIR, file), 'utf8'))
      .join('\n');
    for (const [signature, roles] of Object.entries(FUNCTION_GRANTS)) {
      expect(migrations, signature).toContain(`REVOKE ALL ON FUNCTION ${signature} FROM PUBLIC;`);
      for (const role of roles) expect(DATABASE_ROLES).toContain(role);
    }
  });
});

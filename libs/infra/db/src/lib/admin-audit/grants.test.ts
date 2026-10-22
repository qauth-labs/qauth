import { describe, expect, it } from 'vitest';

import { ADMIN_AUDIT_LOG_WRITER_GRANTS, adminAuditLogWriterGrantStatements } from './grants';

/**
 * The admin audit log grants (issue #448): a writing role holds INSERT and
 * SELECT on the log, SELECT on its checkpoints, and nothing on the prune
 * function. The container suite runs these statements against Postgres.
 */
describe('adminAuditLogWriterGrantStatements', () => {
  it('grants INSERT and SELECT on the log and SELECT on the checkpoints, nothing more', () => {
    expect(ADMIN_AUDIT_LOG_WRITER_GRANTS).toEqual({
      admin_audit_log: ['SELECT', 'INSERT'],
      admin_audit_log_checkpoints: ['SELECT'],
    });
    expect(adminAuditLogWriterGrantStatements('qauth_admin')).toEqual([
      'REVOKE ALL ON TABLE "admin_audit_log", "admin_audit_log_checkpoints" FROM "qauth_admin"',
      'REVOKE ALL ON FUNCTION "admin_audit_log_prune"(uuid, bigint) FROM "qauth_admin"',
      'GRANT SELECT, INSERT ON TABLE "admin_audit_log" TO "qauth_admin"',
      'GRANT SELECT ON TABLE "admin_audit_log_checkpoints" TO "qauth_admin"',
    ]);
  });

  it('quotes the role name as an identifier', () => {
    const [first] = adminAuditLogWriterGrantStatements('odd"; DROP TABLE x; --');
    expect(first).toBe(
      'REVOKE ALL ON TABLE "admin_audit_log", "admin_audit_log_checkpoints" FROM "odd""; DROP TABLE x; --"'
    );
  });

  it.each([
    ['an empty name', ''],
    ['a NUL byte', 'a\0b'],
    ['a name over 63 bytes', 'r'.repeat(64)],
  ])('refuses %s', (_label, role) => {
    expect(() => adminAuditLogWriterGrantStatements(role)).toThrow(TypeError);
  });
});

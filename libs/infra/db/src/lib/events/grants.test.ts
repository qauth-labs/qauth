import { describe, expect, it } from 'vitest';

import { EVENTS_WRITER_GRANTS, eventsWriterGrantStatements } from './grants';

/**
 * The event store's writer grants (issue #459): INSERT and SELECT on
 * `events`, nothing else. The container suite runs them against Postgres.
 */
describe('eventsWriterGrantStatements', () => {
  it('grants INSERT and SELECT on events, after revoking everything else', () => {
    expect(EVENTS_WRITER_GRANTS).toEqual({ events: ['SELECT', 'INSERT'] });
    expect(eventsWriterGrantStatements('qauth_app')).toEqual([
      'REVOKE ALL ON TABLE "events" FROM "qauth_app"',
      'GRANT SELECT, INSERT ON TABLE "events" TO "qauth_app"',
    ]);
  });

  it('quotes the role name as an identifier', () => {
    expect(eventsWriterGrantStatements('odd"; DROP TABLE x; --')[0]).toBe(
      'REVOKE ALL ON TABLE "events" FROM "odd""; DROP TABLE x; --"'
    );
  });

  it.each([
    ['an empty name', ''],
    ['a NUL byte', 'a\0b'],
    ['a name over 63 bytes', 'r'.repeat(64)],
  ])('refuses %s', (_label, role) => {
    expect(() => eventsWriterGrantStatements(role)).toThrow(TypeError);
  });
});

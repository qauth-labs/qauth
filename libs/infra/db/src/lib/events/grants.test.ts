import { describe, expect, it } from 'vitest';

import {
  EVENTS_WRITER_FUNCTIONS,
  EVENTS_WRITER_GRANTS,
  eventsWriterGrantStatements,
} from './grants';

/**
 * The event store's writer grants (issues #459 and #827): INSERT on
 * `events` and EXECUTE on the two functions an admin event reads through,
 * no SELECT. The container suite runs them against Postgres.
 */
describe('eventsWriterGrantStatements', () => {
  it('grants INSERT on events and EXECUTE on the two read functions, after revoking everything else', () => {
    expect(EVENTS_WRITER_GRANTS).toEqual({ events: ['INSERT'] });
    expect(EVENTS_WRITER_FUNCTIONS).toEqual([
      '"events_admin_chain_head"(uuid)',
      '"events_own_row"(uuid)',
    ]);
    expect(eventsWriterGrantStatements('qauth_app')).toEqual([
      'REVOKE ALL ON TABLE "events" FROM "qauth_app"',
      'GRANT INSERT ON TABLE "events" TO "qauth_app"',
      'GRANT EXECUTE ON FUNCTION "events_admin_chain_head"(uuid), "events_own_row"(uuid) TO "qauth_app"',
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

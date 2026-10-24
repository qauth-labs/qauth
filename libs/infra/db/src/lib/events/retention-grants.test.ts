import { describe, expect, it } from 'vitest';

import { EVENT_DELIVERY_GRANTS } from './delivery-grants';
import { EVENTS_WRITER_GRANTS } from './grants';
import { EVENT_RETENTION_GRANTS, eventRetentionGrantStatements } from './retention-grants';

/**
 * The retention role's grants (issue #536): it alone deletes from `events`.
 * The container suite runs them against Postgres.
 */
describe('eventRetentionGrantStatements', () => {
  it('deletes events, moves anchors and reads what the offered rule needs', () => {
    expect(EVENT_RETENTION_GRANTS).toEqual({
      events: ['SELECT', 'DELETE'],
      event_chain_anchors: ['SELECT', 'INSERT', 'UPDATE'],
      event_deliveries: ['SELECT'],
      event_delivery_positions: ['SELECT'],
    });
    expect(eventRetentionGrantStatements('qauth_retention')).toEqual([
      'REVOKE ALL ON TABLE "events" FROM "qauth_retention"',
      'REVOKE ALL ON TABLE "event_chain_anchors" FROM "qauth_retention"',
      'REVOKE ALL ON TABLE "event_deliveries" FROM "qauth_retention"',
      'REVOKE ALL ON TABLE "event_delivery_positions" FROM "qauth_retention"',
      'REVOKE ALL ON TABLE "realms" FROM "qauth_retention"',
      'GRANT SELECT, DELETE ON TABLE "events" TO "qauth_retention"',
      'GRANT SELECT, INSERT, UPDATE ON TABLE "event_chain_anchors" TO "qauth_retention"',
      'GRANT SELECT ON TABLE "event_deliveries" TO "qauth_retention"',
      'GRANT SELECT ON TABLE "event_delivery_positions" TO "qauth_retention"',
      'GRANT SELECT ("id", "user_event_retention_days", "admin_event_retention_days") ON TABLE "realms" TO "qauth_retention"',
    ]);
  });

  it('is the only grant set that deletes from events', () => {
    expect(EVENTS_WRITER_GRANTS['events']).not.toContain('DELETE');
    expect(EVENT_DELIVERY_GRANTS['events']).not.toContain('DELETE');
    expect(EVENT_RETENTION_GRANTS['events']).toContain('DELETE');
  });

  it('quotes the role name as an identifier', () => {
    expect(eventRetentionGrantStatements('odd"; DROP TABLE x; --')[0]).toBe(
      'REVOKE ALL ON TABLE "events" FROM "odd""; DROP TABLE x; --"'
    );
  });

  it.each([
    ['an empty name', ''],
    ['a NUL byte', 'a\0b'],
    ['a name over 63 bytes', 'r'.repeat(64)],
  ])('refuses %s', (_label, role) => {
    expect(() => eventRetentionGrantStatements(role)).toThrow(TypeError);
  });
});

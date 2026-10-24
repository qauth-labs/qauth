import { describe, expect, it } from 'vitest';

import { EVENT_DELIVERY_GRANTS, eventDeliveryGrantStatements } from './delivery-grants';

/**
 * The delivery role's grants (issue #460): it reads events, and reads and
 * writes only its own two tables. The container suite runs them against
 * Postgres.
 */
describe('eventDeliveryGrantStatements', () => {
  it('reads events and keeps its own queue, after revoking everything else', () => {
    expect(EVENT_DELIVERY_GRANTS).toEqual({
      events: ['SELECT'],
      event_deliveries: ['SELECT', 'INSERT', 'UPDATE'],
      event_delivery_positions: ['SELECT', 'INSERT', 'UPDATE', 'DELETE'],
    });
    expect(eventDeliveryGrantStatements('qauth_delivery')).toEqual([
      'REVOKE ALL ON TABLE "events" FROM "qauth_delivery"',
      'REVOKE ALL ON TABLE "event_deliveries" FROM "qauth_delivery"',
      'REVOKE ALL ON TABLE "event_delivery_positions" FROM "qauth_delivery"',
      'GRANT SELECT ON TABLE "events" TO "qauth_delivery"',
      'GRANT SELECT, INSERT, UPDATE ON TABLE "event_deliveries" TO "qauth_delivery"',
      'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE "event_delivery_positions" TO "qauth_delivery"',
    ]);
  });

  it('quotes the role name as an identifier', () => {
    expect(eventDeliveryGrantStatements('odd"; DROP TABLE x; --')[0]).toBe(
      'REVOKE ALL ON TABLE "events" FROM "odd""; DROP TABLE x; --"'
    );
  });

  it.each([
    ['an empty name', ''],
    ['a NUL byte', 'a\0b'],
    ['a name over 63 bytes', 'r'.repeat(64)],
  ])('refuses %s', (_label, role) => {
    expect(() => eventDeliveryGrantStatements(role)).toThrow(TypeError);
  });
});

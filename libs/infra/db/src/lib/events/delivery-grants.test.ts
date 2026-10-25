import { describe, expect, it } from 'vitest';

import {
  EVENT_DELIVERY_COLUMNS,
  EVENT_DELIVERY_GRANTS,
  eventDeliveryGrantStatements,
} from './delivery-grants';

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
      ssf_streams: ['SELECT'],
      ssf_stream_subjects: ['SELECT'],
    });
    expect(EVENT_DELIVERY_COLUMNS).toEqual({
      realms: ['id', 'ssf_transmitter_enabled'],
      oauth_clients: ['id', 'enabled', 'suspended', 'scopes'],
    });
    expect(eventDeliveryGrantStatements('qauth_delivery')).toEqual([
      'REVOKE ALL ON TABLE "events" FROM "qauth_delivery"',
      'REVOKE ALL ON TABLE "event_deliveries" FROM "qauth_delivery"',
      'REVOKE ALL ON TABLE "event_delivery_positions" FROM "qauth_delivery"',
      'REVOKE ALL ON TABLE "ssf_streams" FROM "qauth_delivery"',
      'REVOKE ALL ON TABLE "ssf_stream_subjects" FROM "qauth_delivery"',
      'REVOKE ALL ON TABLE "realms" FROM "qauth_delivery"',
      'REVOKE ALL ON TABLE "oauth_clients" FROM "qauth_delivery"',
      'GRANT SELECT ON TABLE "events" TO "qauth_delivery"',
      'GRANT SELECT, INSERT, UPDATE ON TABLE "event_deliveries" TO "qauth_delivery"',
      'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE "event_delivery_positions" TO "qauth_delivery"',
      'GRANT SELECT ON TABLE "ssf_streams" TO "qauth_delivery"',
      'GRANT SELECT ON TABLE "ssf_stream_subjects" TO "qauth_delivery"',
      'GRANT SELECT ("id", "ssf_transmitter_enabled") ON TABLE "realms" TO "qauth_delivery"',
      'GRANT SELECT ("id", "enabled", "suspended", "scopes") ON TABLE "oauth_clients" TO "qauth_delivery"',
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

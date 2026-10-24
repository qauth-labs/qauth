import { describe, expect, it } from 'vitest';

import { findEventSwitches, namesAnEventSwitch } from './always-on';

describe('namesAnEventSwitch', () => {
  it.each([
    'ADMIN_EVENTS_ENABLED',
    'EVENTS_DISABLED',
    'AUDIT_LOG_ENABLED',
    'adminEventsOff',
    'skipAuditEvents',
    'suppress_admin_events',
    'EVENT_OUTBOX_BYPASS',
  ])('reports %s', (name) => {
    expect(namesAnEventSwitch(name)).toBe(true);
  });

  it.each([
    'ADMIN_EVENT_RETENTION_DAYS',
    'USER_EVENT_RETENTION_DAYS',
    'FAILED_LOGIN_TRACKING_ENABLED',
    'WALLET_FEDERATION_ENABLED',
    'LOG_LEVEL',
    'eventTypes',
    'enabled',
  ])('passes %s', (name) => {
    expect(namesAnEventSwitch(name)).toBe(false);
  });

  it('lists the switches among names, in order', () => {
    expect(findEventSwitches(['A', 'EVENTS_OFF', 'B', 'auditDisabled'])).toEqual([
      'EVENTS_OFF',
      'auditDisabled',
    ]);
  });
});

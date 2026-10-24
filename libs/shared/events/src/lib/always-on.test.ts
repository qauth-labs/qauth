import { describe, expect, it } from 'vitest';

import { findEventNames, namesEvents } from './always-on';

describe('namesEvents', () => {
  // The names #827 found the switch-word check let through: a switch need
  // not say "enabled".
  it.each([
    'ADMIN_EVENTS',
    'EMIT_ADMIN_EVENTS',
    'AUDIT_LOG',
    'EVENT_STORE_MODE',
    'EVENTS_SINK',
    'ADMIN_EVENTS_ENABLED',
    'skipAuditEvents',
    'EVENT_OUTBOX_BYPASS',
    'metadata.auditEnabled',
    'eventTypes',
    'LOG_LEVEL',
    'AUDITING_ENABLED',
    'ADMIN_LOGGING',
    'EVENTSTORE_MODE',
    'AUDITLOG_ENABLED',
  ])('reports %s', (name) => {
    expect(namesEvents(name)).toBe(true);
  });

  it.each([
    'FAILED_LOGIN_TRACKING_ENABLED',
    'WALLET_FEDERATION_ENABLED',
    'loginWithEmailAllowed',
    'catalogUrl',
    'enabled',
    'passwordPolicy.preventReuse',
    'LOGIN_HINT',
    'logoUrl',
  ])('passes %s', (name) => {
    expect(namesEvents(name)).toBe(false);
  });
});

describe('findEventNames', () => {
  it('lists the names that name events and are not allowed, in order, each once', () => {
    expect(
      findEventNames(['A', 'EVENTS_SINK', 'LOG_LEVEL', 'B', 'auditLog', 'EVENTS_SINK'], {
        LOG_LEVEL: 'the process log, not events',
      })
    ).toEqual(['EVENTS_SINK', 'auditLog']);
  });

  it('refuses an allowed name without a reason', () => {
    expect(() => findEventNames([], { LOG_LEVEL: ' ' })).toThrow(/without a reason/);
  });
});

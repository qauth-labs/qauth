import { describe, expect, it, vi } from 'vitest';

vi.mock('../../config/env', () => ({ env: { NODE_ENV: 'test' } }));

import {
  isRegisteredSubject,
  type RegisteredSubject,
  subjectAuthTimeMs,
  subjectEnforcesDangerousStepUp,
  subjectGrant,
} from './authorization-subject';

/** Who an authorization request is decided for: a browser session, or a registration (#640). */

const SESSION = {
  realmId: 'realm-1',
  sid: 'sid-1',
  userId: 'user-1',
  authTime: 1_700_000_000_000,
  amr: ['pwd'],
  assuranceLevel: 'substantial',
  createdAt: 1_700_000_000_000,
  lastSeenAt: 1_700_000_000_000,
  expiresAt: 1_700_028_800_000,
  idleExpiresAt: null,
} as never;

const REGISTERED: RegisteredSubject = { registered: true, realmId: 'realm-1', userId: 'user-new' };

describe('the subject of an authorization request', () => {
  it('tells a registration from a browser session', () => {
    expect(isRegisteredSubject(REGISTERED)).toBe(true);
    expect(isRegisteredSubject(SESSION)).toBe(false);
  });

  it("compares a session's authentication time, and none for a registration", () => {
    expect(subjectAuthTimeMs(SESSION)).toBe(1_700_000_000_000);
    expect(subjectAuthTimeMs(REGISTERED)).toBe(Number.NEGATIVE_INFINITY);
  });

  it('holds the dangerous-scope step-up for a registration whatever the environment', () => {
    for (const agentStepUpEnforced of [true, false]) {
      expect(subjectEnforcesDangerousStepUp(REGISTERED, { agentStepUpEnforced })).toBe(true);
      expect(subjectEnforcesDangerousStepUp(SESSION, { agentStepUpEnforced })).toBe(
        agentStepUpEnforced
      );
    }
  });

  it("binds a session's auth_time, amr, acr, end and sid to the code", () => {
    expect(subjectGrant(SESSION)).toEqual({
      authTime: 1_700_000_000_000,
      amr: ['pwd'],
      assuranceLevel: 'substantial',
      sessionExpiresAt: 1_700_028_800_000,
      session: { realmId: 'realm-1', sid: 'sid-1' },
    });
  });

  it('binds no amr for a session that stored no method, and keeps its auth_time (#662)', () => {
    // A session created before sessions stored their methods, or by a sign-in
    // that proved none this server names: its tokens carry no `amr`.
    const unproved = { ...(SESSION as object), amr: [] } as never;

    expect(subjectGrant(unproved)).toMatchObject({ authTime: 1_700_000_000_000, amr: null });
  });

  it('binds none of them for a registration (ADR-017 Decision 10)', () => {
    expect(subjectGrant(REGISTERED)).toEqual({
      authTime: null,
      amr: null,
      assuranceLevel: null,
      sessionExpiresAt: null,
      session: null,
    });
  });
});

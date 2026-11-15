import { describe, expect, it, vi } from 'vitest';

vi.mock('../../config/env', () => ({ env: { NODE_ENV: 'test', SESSION_COOKIE_TTL: 86_400 } }));

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

const REGISTERED: RegisteredSubject = {
  registered: true,
  realmId: 'realm-1',
  userId: 'user-new',
  finishedBy: 'registration',
};

/** The realm and the request a registration's code is minted in (#1144). */
const CONTEXT = {
  realm: { ssoMaxLifespan: null },
  request: { ip: '192.0.2.7', headers: { 'user-agent': 'Firefox' } },
} as never;

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

  it('binds none of the authentication for a registration, and a logout-only session (#1144)', () => {
    vi.useFakeTimers({ now: 1_700_000_000_000 });
    try {
      // The realm sets no `sso_max_lifespan`: a browser session's lifetime.
      const end = 1_700_000_000_000 + 86_400_000;
      expect(subjectGrant(REGISTERED, CONTEXT)).toEqual({
        authTime: null,
        amr: null,
        assuranceLevel: null,
        sessionExpiresAt: end,
        session: {
          realmId: 'realm-1',
          logoutOnly: 'registration',
          expiresAt: end,
          ipAddress: '192.0.2.7',
          userAgent: 'Firefox',
        },
      });
      const reset = { ...REGISTERED, finishedBy: 'reset' } as const;
      const realm = { realm: { ssoMaxLifespan: 3600 }, request: { ip: '', headers: {} } } as never;
      expect(subjectGrant(reset, realm)).toMatchObject({
        sessionExpiresAt: 1_700_003_600_000,
        session: { logoutOnly: 'reset', expiresAt: 1_700_003_600_000, userAgent: null },
      });
    } finally {
      vi.useRealTimers();
    }
  });

  it('refuses a registration without the realm and request its session needs', () => {
    expect(() => subjectGrant(REGISTERED as never)).toThrow(/realm and request/);
  });
});

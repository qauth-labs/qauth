import { describe, expect, it } from 'vitest';

import {
  elevatedScopes,
  evaluateStepUp,
  isDangerousScope,
  parsePromptMode,
  type StepUpDecision,
  stepUpErrorForPromptNone,
  type StepUpInput,
} from './step-up';

describe('parsePromptMode', () => {
  it('accepts the known OIDC prompt values', () => {
    expect(parsePromptMode('login')).toBe('login');
    expect(parsePromptMode('consent')).toBe('consent');
    expect(parsePromptMode('none')).toBe('none');
  });

  it('returns null for absent / unknown values (fail-closed)', () => {
    expect(parsePromptMode(undefined)).toBeNull();
    expect(parsePromptMode('select_account')).toBeNull();
    expect(parsePromptMode('LOGIN')).toBeNull();
    expect(parsePromptMode('')).toBeNull();
  });
});

describe('isDangerousScope', () => {
  it('classifies write:* scopes as dangerous', () => {
    expect(isDangerousScope('write:files')).toBe(true);
    expect(isDangerousScope('write:anything')).toBe(true);
  });

  it('classifies the higher agent modes (admin/exec) as dangerous', () => {
    expect(isDangerousScope('agent:admin')).toBe(true);
    expect(isDangerousScope('agent:exec')).toBe(true);
  });

  it('does NOT classify read-only / readonly-mode scopes as dangerous', () => {
    expect(isDangerousScope('read:files')).toBe(false);
    expect(isDangerousScope('mcp:read')).toBe(false);
    expect(isDangerousScope('agent:readonly')).toBe(false);
    expect(isDangerousScope('openid')).toBe(false);
  });
});

describe('elevatedScopes', () => {
  it('returns scopes not covered by prior consent, deduped + order-preserving', () => {
    expect(elevatedScopes(['mcp:read', 'mcp:write', 'mcp:write'], ['mcp:read'])).toEqual([
      'mcp:write',
    ]);
  });

  it('returns empty when the request is fully within the prior grant', () => {
    expect(elevatedScopes(['mcp:read'], ['mcp:read', 'mcp:write'])).toEqual([]);
  });

  it('treats an empty prior consent as everything being elevated', () => {
    expect(elevatedScopes(['mcp:read', 'mcp:write'], [])).toEqual(['mcp:read', 'mcp:write']);
  });
});

describe('evaluateStepUp', () => {
  const NOW = 1_000_000_000_000;
  const base: StepUpInput = {
    requestedScopes: [],
    priorConsentScopes: [],
    prompt: null,
    maxAgeSeconds: null,
    authTimeMs: NOW, // fresh by default
    nowMs: NOW,
    freshAuthWindowMs: 120_000,
  };

  it('no elevation, no prompt, no dangerous scope ⇒ no step-up', () => {
    const d = evaluateStepUp({
      ...base,
      requestedScopes: ['mcp:read'],
      priorConsentScopes: ['mcp:read'],
    });
    expect(d.requiresFreshLogin).toBe(false);
    expect(d.requiresConsent).toBe(false);
    expect(d.elevated).toEqual([]);
  });

  it('widening the scope set requires consent (incremental consent), not silent widening', () => {
    const d = evaluateStepUp({
      ...base,
      requestedScopes: ['mcp:read', 'mcp:write'],
      priorConsentScopes: ['mcp:read'],
    });
    expect(d.requiresConsent).toBe(true);
    expect(d.elevated).toEqual(['mcp:write']);
    // mcp:write is not dangerous → fresh login not forced by danger; session is
    // fresh anyway.
    expect(d.requiresFreshLogin).toBe(false);
  });

  it('a dangerous elevated scope forces a fresh login when the session is stale', () => {
    const d = evaluateStepUp({
      ...base,
      requestedScopes: ['agent:exec'],
      priorConsentScopes: [],
      authTimeMs: NOW - 10 * 60 * 1000, // 10 min old, outside the 2 min window
    });
    expect(d.dangerous).toEqual(['agent:exec']);
    expect(d.requiresFreshLogin).toBe(true);
    expect(d.requiresConsent).toBe(true);
  });

  it('a dangerous scope ALREADY covered by prior consent still forces fresh auth (no elevation needed)', () => {
    // Should-fix #2: dangerous gating spans all requested scopes, not just the
    // elevated subset, so a "remembered" dangerous grant cannot be replayed off
    // a stale session without a fresh authentication.
    const d = evaluateStepUp({
      ...base,
      requestedScopes: ['write:files'],
      priorConsentScopes: ['write:files'], // already remembered → NOT elevated
      authTimeMs: NOW - 10 * 60 * 1000, // stale
    });
    expect(d.elevated).toEqual([]); // nothing newly requested
    expect(d.dangerous).toEqual(['write:files']); // but still dangerous
    expect(d.requiresFreshLogin).toBe(true); // and still gated
    // No elevation → no forced consent on its own (the danger drives login).
    expect(d.requiresConsent).toBe(false);
  });

  it('a dangerous elevated scope is satisfied by a recent (in-window) authentication', () => {
    const d = evaluateStepUp({
      ...base,
      requestedScopes: ['write:files'],
      priorConsentScopes: [],
      authTimeMs: NOW - 30 * 1000, // 30s old, inside the 2 min window
    });
    expect(d.dangerous).toEqual(['write:files']);
    // Re-auth just happened → not forced again (prevents the redirect loop).
    expect(d.requiresFreshLogin).toBe(false);
    // Still must be consented (it is an elevation).
    expect(d.requiresConsent).toBe(true);
  });

  it('prompt=login forces a fresh login only when auth is outside the window', () => {
    const stale = evaluateStepUp({
      ...base,
      prompt: 'login',
      authTimeMs: NOW - 10 * 60 * 1000,
    });
    expect(stale.requiresFreshLogin).toBe(true);

    const fresh = evaluateStepUp({ ...base, prompt: 'login', authTimeMs: NOW - 1000 });
    expect(fresh.requiresFreshLogin).toBe(false);
  });

  it('prompt=consent forces consent even with no elevation', () => {
    const d = evaluateStepUp({
      ...base,
      prompt: 'consent',
      requestedScopes: ['mcp:read'],
      priorConsentScopes: ['mcp:read'],
    });
    expect(d.requiresConsent).toBe(true);
    expect(d.elevated).toEqual([]);
  });

  // OIDC `auth_time` is second-granular: a just-completed login (sub-second
  // age) MUST satisfy max_age=0 so the authorize→login→authorize round-trip
  // terminates. A millisecond-precision comparison here would loop forever
  // (the prior bug this test now guards against).
  it('max_age=0 is satisfied by a sub-second-old authentication (no infinite loop)', () => {
    const justLoggedIn = evaluateStepUp({
      ...base,
      maxAgeSeconds: 0,
      authTimeMs: NOW - 40, // 40ms old — floor(0.04s) = 0, so 0 > 0 is false
    });
    expect(justLoggedIn.requiresFreshLogin).toBe(false);

    // But an authentication a full second or more old DOES exceed max_age=0.
    const oneSecondOld = evaluateStepUp({
      ...base,
      maxAgeSeconds: 0,
      authTimeMs: NOW - 1500, // floor(1.5s) = 1 > 0
    });
    expect(oneSecondOld.requiresFreshLogin).toBe(true);
  });

  it('max_age is enforced exactly against its own value, not widened by the window', () => {
    // 60s max_age, session 90s old → exceeded, even though the freshness window
    // (120s) would have accepted it for prompt=login purposes.
    const exceeded = evaluateStepUp({
      ...base,
      maxAgeSeconds: 60,
      authTimeMs: NOW - 90 * 1000,
    });
    expect(exceeded.requiresFreshLogin).toBe(true);

    const within = evaluateStepUp({ ...base, maxAgeSeconds: 60, authTimeMs: NOW - 30 * 1000 });
    expect(within.requiresFreshLogin).toBe(false);
  });
});

describe('stepUpErrorForPromptNone', () => {
  function decision(over: Partial<StepUpDecision>): StepUpDecision {
    return {
      elevated: [],
      dangerous: [],
      requiresFreshLogin: false,
      requiresConsent: false,
      ...over,
    };
  }

  it('returns login_required when a fresh login is needed (takes precedence)', () => {
    expect(
      stepUpErrorForPromptNone(decision({ requiresFreshLogin: true, requiresConsent: true }))
    ).toBe('login_required');
  });

  it('returns consent_required when only consent is needed', () => {
    expect(stepUpErrorForPromptNone(decision({ requiresConsent: true }))).toBe('consent_required');
  });

  it('returns null when no interaction is required (request may proceed)', () => {
    expect(stepUpErrorForPromptNone(decision({}))).toBeNull();
  });
});

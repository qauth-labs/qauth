import { describe, expect, it } from 'vitest';

import {
  AGENT_MODE_SCOPES,
  AGENT_MODES,
  agentModeForScope,
  findExceedingAgentScopes,
  isAgentModeScope,
  isModeWithinCap,
  parseAgentMode,
} from './scope-modes';

describe('scope-modes — taxonomy + reverse lookup', () => {
  it('exposes the three reserved scopes', () => {
    expect(AGENT_MODE_SCOPES).toEqual({
      readonly: 'agent:readonly',
      admin: 'agent:admin',
      exec: 'agent:exec',
    });
  });

  it('isAgentModeScope recognises only the reserved scopes', () => {
    expect(isAgentModeScope('agent:readonly')).toBe(true);
    expect(isAgentModeScope('agent:admin')).toBe(true);
    expect(isAgentModeScope('agent:exec')).toBe(true);
    // a plain scope, and an `agent:`-prefixed but non-reserved scope
    expect(isAgentModeScope('read:foo')).toBe(false);
    expect(isAgentModeScope('agent:superuser')).toBe(false);
    expect(isAgentModeScope('agent:')).toBe(false);
  });

  it('agentModeForScope maps reserved scopes to modes, null otherwise', () => {
    expect(agentModeForScope('agent:readonly')).toBe('readonly');
    expect(agentModeForScope('agent:admin')).toBe('admin');
    expect(agentModeForScope('agent:exec')).toBe('exec');
    expect(agentModeForScope('agent:other')).toBeNull();
    expect(agentModeForScope('email')).toBeNull();
  });
});

describe('parseAgentMode — fail-closed', () => {
  it('parses known modes', () => {
    for (const m of AGENT_MODES) {
      expect(parseAgentMode(m)).toBe(m);
    }
  });

  it('returns null for unknown / empty / non-string', () => {
    expect(parseAgentMode('superuser')).toBeNull();
    expect(parseAgentMode('')).toBeNull();
    expect(parseAgentMode(null)).toBeNull();
    expect(parseAgentMode(undefined)).toBeNull();
    // case-sensitive — `Admin` is NOT `admin`
    expect(parseAgentMode('Admin')).toBeNull();
  });
});

describe('isModeWithinCap — cap ordering (ReadOnly ⊂ Admin ⊂ Exec)', () => {
  it('permits a mode at or below the cap', () => {
    expect(isModeWithinCap('readonly', 'readonly')).toBe(true);
    expect(isModeWithinCap('readonly', 'admin')).toBe(true);
    expect(isModeWithinCap('readonly', 'exec')).toBe(true);
    expect(isModeWithinCap('admin', 'admin')).toBe(true);
    expect(isModeWithinCap('admin', 'exec')).toBe(true);
    expect(isModeWithinCap('exec', 'exec')).toBe(true);
  });

  it('rejects a mode above the cap', () => {
    expect(isModeWithinCap('admin', 'readonly')).toBe(false);
    expect(isModeWithinCap('exec', 'readonly')).toBe(false);
    expect(isModeWithinCap('exec', 'admin')).toBe(false);
  });

  it('a null cap denies every mode (default-deny)', () => {
    expect(isModeWithinCap('readonly', null)).toBe(false);
    expect(isModeWithinCap('admin', null)).toBe(false);
    expect(isModeWithinCap('exec', null)).toBe(false);
  });
});

describe('findExceedingAgentScopes — deny-by-default enforcement', () => {
  it('a verified agent within its cap has no exceeding scopes', () => {
    expect(findExceedingAgentScopes(['agent:readonly'], true, 'admin')).toEqual([]);
    expect(findExceedingAgentScopes(['agent:admin'], true, 'admin')).toEqual([]);
    // Exec cap permits all three (ReadOnly ⊂ Admin ⊂ Exec)
    expect(
      findExceedingAgentScopes(['agent:readonly', 'agent:admin', 'agent:exec'], true, 'exec')
    ).toEqual([]);
  });

  it('a capped agent cannot exceed its mode', () => {
    expect(findExceedingAgentScopes(['agent:exec'], true, 'readonly')).toEqual(['agent:exec']);
    expect(findExceedingAgentScopes(['agent:admin'], true, 'readonly')).toEqual(['agent:admin']);
    expect(findExceedingAgentScopes(['agent:exec'], true, 'admin')).toEqual(['agent:exec']);
  });

  it('a non-agent client can hold NO agent-mode scope, even with a cap (untrusted is_agent)', () => {
    // is_agent omitted/false ⇒ not an agent ⇒ every agent:* scope is rejected
    // regardless of the cap value.
    expect(findExceedingAgentScopes(['agent:readonly'], false, 'exec')).toEqual(['agent:readonly']);
    expect(findExceedingAgentScopes(['agent:admin'], false, 'admin')).toEqual(['agent:admin']);
  });

  it('an agent with no cap (null) can hold NO agent-mode scope (default-deny)', () => {
    expect(findExceedingAgentScopes(['agent:readonly'], true, null)).toEqual(['agent:readonly']);
    expect(findExceedingAgentScopes(['agent:exec'], true, null)).toEqual(['agent:exec']);
  });

  it('ignores non-reserved scopes — they are left to the ordinary allowlist', () => {
    expect(
      findExceedingAgentScopes(['read:foo', 'email', 'agent:other'], true, 'readonly')
    ).toEqual([]);
  });

  it('reports every exceeding scope in the request', () => {
    expect(findExceedingAgentScopes(['agent:admin', 'agent:exec'], true, 'readonly')).toEqual([
      'agent:admin',
      'agent:exec',
    ]);
  });
});

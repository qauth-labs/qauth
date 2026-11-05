import { describe, expect, it } from 'vitest';

import { clientAllowsHostedFlow, hostedFlowsOf, hostedFlowsSchema } from './hosted-flows';

describe('hostedFlowsSchema', () => {
  it('accepts the known flows and the empty list', () => {
    expect(hostedFlowsSchema.parse(['register'])).toEqual(['register']);
    expect(hostedFlowsSchema.parse([])).toEqual([]);
  });

  it('refuses an unknown flow and a repeat', () => {
    expect(hostedFlowsSchema.safeParse(['login']).success).toBe(false);
    expect(hostedFlowsSchema.safeParse(['register', 'register']).success).toBe(false);
  });
});

describe('hostedFlowsOf', () => {
  it('reads the stored list', () => {
    expect(hostedFlowsOf({ hostedFlows: ['register'] })).toEqual(['register']);
    expect(clientAllowsHostedFlow({ hostedFlows: ['register'] }, 'register')).toBe(true);
  });

  it('allows nothing for a NULL, absent or empty column', () => {
    expect(hostedFlowsOf({ hostedFlows: null })).toEqual([]);
    expect(hostedFlowsOf({})).toEqual([]);
    expect(hostedFlowsOf({ hostedFlows: [] })).toEqual([]);
    expect(clientAllowsHostedFlow({ hostedFlows: null }, 'register')).toBe(false);
  });

  it('fails closed on a value that is not a list of strings', () => {
    expect(hostedFlowsOf({ hostedFlows: 'register' })).toEqual([]);
    expect(hostedFlowsOf({ hostedFlows: { register: true } })).toEqual([]);
    expect(hostedFlowsOf({ hostedFlows: ['register', 1] })).toEqual([]);
  });

  it('ignores a member it does not know', () => {
    expect(hostedFlowsOf({ hostedFlows: ['reset', 'register'] })).toEqual(['register']);
    expect(hostedFlowsOf({ hostedFlows: ['Register'] })).toEqual([]);
  });
});

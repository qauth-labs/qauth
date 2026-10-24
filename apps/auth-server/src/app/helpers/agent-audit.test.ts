import type { ActClaim } from '@qauth-labs/fastify-plugin-jwt';
import { loadVectors } from '@qauth-labs/shared-test-vectors';
import { describe, expect, it } from 'vitest';

import {
  actDepth,
  delegationChainColumn,
  flattenActChain,
  MAX_DELEGATION_DEPTH,
} from './agent-audit';

describe('flattenActChain (ADR-007 §2, #186)', () => {
  it('returns [] for undefined', () => {
    expect(flattenActChain(undefined)).toEqual([]);
  });

  it('flattens a single actor', () => {
    expect(flattenActChain({ sub: 'agentA' })).toEqual(['agentA']);
  });

  it('flattens a nested chain, outermost (most recent) actor first', () => {
    const act: ActClaim = { sub: 'agentB', act: { sub: 'agentA' } };
    expect(flattenActChain(act)).toEqual(['agentB', 'agentA']);
  });

  it('takes ONLY the sub (public client_id) from each link', () => {
    // Even if extra claims were present, only `sub` is read — no token/secret
    // material can leak into the persisted chain.
    const act = { sub: 'agentB', extra: 'secret', act: { sub: 'agentA' } } as unknown as ActClaim;
    expect(flattenActChain(act)).toEqual(['agentB', 'agentA']);
  });

  it('skips links with a missing/empty sub without breaking the walk', () => {
    const act = { sub: '', act: { sub: 'agentA' } } as ActClaim;
    expect(flattenActChain(act)).toEqual(['agentA']);
  });

  it('is bounded by maxDepth against a hostile/over-deep chain', () => {
    let act: ActClaim = { sub: 'a0' };
    for (let i = 1; i <= 50; i++) act = { sub: `a${i}`, act };
    expect(flattenActChain(act, 4)).toHaveLength(4);
  });
});

describe('delegationChainColumn (ADR-007 §2, #186)', () => {
  it('returns null when there is no delegation (keeps the column NULL)', () => {
    expect(delegationChainColumn(undefined)).toBeNull();
  });

  it('returns the chain array when delegated', () => {
    expect(delegationChainColumn({ sub: 'agentB', act: { sub: 'agentA' } })).toEqual([
      'agentB',
      'agentA',
    ]);
  });
});

/**
 * The shared `act` chain vectors (`test-vectors/agent/act-chain.json`): the
 * flattened chain, the depth the minting gate counts, and the cap of 4. Each
 * case's whole `expected` object is rebuilt from these helpers, so a wrong
 * value anywhere in a case fails it.
 */
describe('agent/act-chain shared vectors (RFC 8693 §4.1, ADR-007 §2)', () => {
  const vectors = loadVectors<
    { act?: ActClaim },
    { chain: string[]; depth: number; within_cap: boolean }
  >('agent/act-chain');

  it.each(vectors.cases)('$id', ({ input, expected }) => {
    const depth = actDepth(input.act);
    expect({
      chain: flattenActChain(input.act),
      depth,
      within_cap: depth <= MAX_DELEGATION_DEPTH,
    }).toEqual(expected);
  });
});

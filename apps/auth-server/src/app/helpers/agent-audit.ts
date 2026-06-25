/**
 * Per-agent action audit helpers (ADR-007 §2, issue #186).
 *
 * Turns the RFC 8693 `act` (actor) delegation chain into an accountable,
 * queryable record on `audit_logs`. These helpers extract ONLY public client
 * identifiers from the chain — never any token, secret, or subject material —
 * so the resulting audit fields are safe to persist and to surface in a future
 * developer-portal "agent activity" view.
 */

import type { ActClaim } from '@qauth-labs/fastify-plugin-jwt';

/**
 * Flatten an RFC 8693 `act` delegation chain into the ordered list of actor
 * `client_id`s. Index 0 is the most recent (outermost) actor — the agent that
 * performed THIS action — and each following entry is a prior actor, walking
 * the nested `act` chain.
 *
 * Only the `sub` (the actor's `client_id`, a public identifier) is taken from
 * each link; no other claim is read. Returns an empty array for `undefined`.
 *
 * A defensive depth bound mirrors the minting-side `MAX_DELEGATION_DEPTH` so a
 * malformed or hostile chain cannot cause unbounded work here.
 *
 * @example
 * // { sub: 'agentB', act: { sub: 'agentA' } } → ['agentB', 'agentA']
 */
export function flattenActChain(act: ActClaim | undefined, maxDepth = 16): string[] {
  const chain: string[] = [];
  let cursor: ActClaim | undefined = act;
  while (cursor && chain.length < maxDepth) {
    if (typeof cursor.sub === 'string' && cursor.sub.length > 0) {
      chain.push(cursor.sub);
    }
    cursor = cursor.act;
  }
  return chain;
}

/**
 * Convenience: the flattened chain as an `audit_logs.delegation_chain` value —
 * the array when non-empty, or `null` when there was no delegation (keeps the
 * column NULL for ordinary, non-delegated entries rather than `[]`).
 */
export function delegationChainColumn(act: ActClaim | undefined): string[] | null {
  const chain = flattenActChain(act);
  return chain.length > 0 ? chain : null;
}

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
 * Maximum delegation depth (number of nested `act` actors) QAuth will mint —
 * the single source of truth shared by the token-exchange minting gate
 * (`token.ts`) and the audit-chain flattener below. Each re-exchange nests
 * another `act`, growing the JWT unboundedly; this cap bounds token size (DoS)
 * and keeps provenance legible. A chain that would exceed it is rejected at
 * mint time, so a *verified* QAuth token never carries more than this many
 * actors.
 */
export const MAX_DELEGATION_DEPTH = 4;

/**
 * Flatten an RFC 8693 `act` delegation chain into the ordered list of actor
 * `client_id`s. Index 0 is the most recent (outermost) actor — the agent that
 * performed THIS action — and each following entry is a prior actor, walking
 * the nested `act` chain.
 *
 * Only the `sub` (the actor's `client_id`, a public identifier) is taken from
 * each link; no other claim is read. Returns an empty array for `undefined`.
 *
 * The depth bound is {@link MAX_DELEGATION_DEPTH} — the same cap the minting
 * gate enforces — so a verified token's chain is never truncated, while a
 * malformed or hostile chain still cannot cause unbounded work here.
 *
 * @example
 * // { sub: 'agentB', act: { sub: 'agentA' } } → ['agentB', 'agentA']
 */
export function flattenActChain(
  act: ActClaim | undefined,
  maxDepth = MAX_DELEGATION_DEPTH
): string[] {
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

/**
 * Which act chains are an admin's (ADR-019 Decision 7, issue #523).
 *
 * Two kinds of token carry an RFC 8693 `act` claim. An agent's, from token
 * exchange, names each actor by its `client_id` as `sub` and nothing else. An
 * admin's act-chain token names the admin by its account id as `sub`, with
 * the admin's issuer (`iss`) and client (`client_id`), as RFC 8693 §4.1 lets
 * an actor carry identity claims. So an actor that names an `iss` or a
 * `client_id` is an admin, and the account API holds such a token to its
 * `admin_act_sessions` row on every call (`admin-access.ts`).
 */
import type { ActClaim } from '@qauth-labs/fastify-plugin-jwt';

/** How deep {@link isAdminActChain} looks: as deep as an agent chain may nest. */
const MAX_ACTORS = 16;

/**
 * Whether `act` is an admin's act chain: one of its actors names an `iss` or
 * a `client_id`. An actor beyond {@link MAX_ACTORS} counts as one, so a chain
 * too deep to read is never taken for an agent's.
 */
export function isAdminActChain(act: ActClaim | null | undefined): boolean {
  let cursor: unknown = act;
  for (let depth = 0; typeof cursor === 'object' && cursor !== null; depth += 1) {
    if (depth >= MAX_ACTORS) return true;
    if (Object.hasOwn(cursor, 'iss') || Object.hasOwn(cursor, 'client_id')) return true;
    cursor = (cursor as { act?: unknown }).act;
  }
  return false;
}

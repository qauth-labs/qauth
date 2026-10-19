/**
 * Whether a client may be used at all: enabled by its owner AND not suspended
 * by an operator. Every place that refuses a disabled client (authorize,
 * consent, each client-authentication path behind the token, introspection,
 * revocation and token-exchange endpoints, API keys) asks this, so a suspended
 * client is refused exactly where, and with exactly the error, a disabled one
 * is (ANT-2026-DR5XI3LV).
 *
 * `enabled` must be strictly true. `suspended` is NOT NULL in the database, so
 * every stored row carries it; an object without the field (a partial shape
 * in a caller that never read the column) reads as not suspended.
 */
export function isClientUsable(client: { enabled: boolean; suspended?: boolean | null }): boolean {
  return client.enabled === true && client.suspended !== true;
}

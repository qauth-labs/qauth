/** The longest `scope_id` that `realm_keys` holds. */
export const MAX_SCOPE_ID_LENGTH = 255;

/**
 * Whether `scopeId` can be stored as `realm_keys.scope_id`: a non-empty,
 * well-formed string of at most {@link MAX_SCOPE_ID_LENGTH} characters. A lone
 * surrogate and a NUL are refused: the associated-data encoder refuses the
 * first, and Postgres text the second.
 */
export function isScopeId(scopeId: unknown): scopeId is string {
  return (
    typeof scopeId === 'string' &&
    scopeId.length > 0 &&
    scopeId.length <= MAX_SCOPE_ID_LENGTH &&
    !scopeId.includes('\u0000') &&
    Buffer.from(scopeId, 'utf8').toString('utf8') === scopeId
  );
}

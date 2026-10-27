/**
 * Who set the destination of an egress call (ADR-019 Decision 8). Every call
 * names it; it decides whether the deployment allowlist may apply.
 *
 * - `operator`: the deployment's own configuration, such as a trusted ID-JAG
 *   issuer's discovery URL.
 * - `admin`: a realm admin, such as a back-channel logout URI an admin sets on
 *   a client.
 * - `client`: an OAuth client, such as a CIMD `client_id`, a registered
 *   `jwks_uri` or an SSF receiver's push endpoint.
 * - `end_user`: an end user.
 * - `remote_document`: a document the server fetched, such as the `jwks_uri`
 *   an issuer's discovery document names.
 */
export const EGRESS_SOURCES = [
  'operator',
  'admin',
  'client',
  'end_user',
  'remote_document',
] as const;
export type EgressSource = (typeof EGRESS_SOURCES)[number];

/**
 * The sources an allowlist entry may apply to. A destination that a client,
 * an end user or a remote document supplies never uses the allowlist.
 */
const ALLOWLIST_SOURCES: ReadonlySet<EgressSource> = new Set<EgressSource>(['operator', 'admin']);

/** Whether the allowlist may apply to a destination of `source`. */
export function allowlistApplies(source: EgressSource): boolean {
  return ALLOWLIST_SOURCES.has(source);
}

/** `source`, when it is one of {@link EGRESS_SOURCES}; a `TypeError` otherwise. */
export function checkSource(source: unknown): EgressSource {
  if (typeof source !== 'string' || !(EGRESS_SOURCES as readonly string[]).includes(source)) {
    throw new TypeError(`egress source must be one of ${EGRESS_SOURCES.join(', ')}`);
  }
  return source as EgressSource;
}

/** `realm`, when it is absent or a realm name; a `TypeError` otherwise. */
export function checkRealm(realm: unknown): string | undefined {
  if (realm === undefined) return undefined;
  if (typeof realm !== 'string' || realm === '') {
    throw new TypeError('egress realm must be a realm name');
  }
  return realm;
}

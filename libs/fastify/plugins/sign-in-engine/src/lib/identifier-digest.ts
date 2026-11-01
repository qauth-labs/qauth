import { createHmac, hkdfSync } from 'node:crypto';

import type { IdentifierDigest } from '@qauth-labs/server-sign-in-engine';

/** The signer's cookie HMAC secrets, by shape (`Signer.getCookieSecrets` of `@qauth-labs/server-keys`). */
export interface CookieSecretSource {
  getCookieSecrets(
    caller: 'web' | 'local',
    realmId: string
  ): Promise<{
    readonly current: { readonly kid: string; readonly secret: Buffer };
    readonly previous: { readonly kid: string; readonly secret: Buffer } | null;
  }>;
}

/**
 * What the identifier key is derived for: a QAuth-defined label, the `info`
 * of an HKDF derivation (RFC 5869), so the key is not any value the cookie
 * secret signs and a digest of an identifier never equals a cookie signature.
 */
export const IDENTIFIER_HMAC_LABEL = 'urn:qauth:key-use:identifier-hmac:v1-rc.0';

/**
 * What the end-user IP key is derived for (#615): the failure ladder keeps the
 * IPs known to an account as their keyed HMACs under this label, so no Redis
 * key or value holds an address, and an IP's digest never equals an
 * identifier's.
 */
export const END_USER_IP_HMAC_LABEL = 'urn:qauth:key-use:end-user-ip-hmac:v1-rc.0';

/**
 * The identifier's keyed HMAC (ADR-017 Decision 7): HMAC-SHA-256 under a key
 * derived from the realm's active cookie HMAC secret with HKDF-SHA-256
 * (RFC 5869, the label as `info`), over the realm id and the normalised
 * identifier, base64url without padding.
 *
 * The key comes from the key custody that exists (ADR-019 Decision 9) and
 * adds no secret: the realm's `cookie_hmac` key, which the `web` role may
 * read, with {@link IDENTIFIER_HMAC_LABEL} for domain separation. A rotation
 * of that key changes every digest, so audit records before and after it no
 * longer correlate, and the failure ladder (#615), which keys its counters and
 * known IPs on these digests, starts every account afresh: no counted failure
 * and no known IP survives it. A process that holds the `signer` role reads
 * the secret as `local`, so the `api` role's login route keys the same
 * counters as the `web` role's.
 *
 * @param caller - how the signer is called: `web` across the role boundary, `local` in its process
 * @param label - the derivation's label: {@link IDENTIFIER_HMAC_LABEL}, or
 *   {@link END_USER_IP_HMAC_LABEL} for the end-user IPs the ladder keeps known
 */
export function createCookieSecretIdentifierDigest(
  signer: CookieSecretSource,
  caller: 'web' | 'local' = 'web',
  label: string = IDENTIFIER_HMAC_LABEL
): IdentifierDigest {
  return async ({ realmId, identifier }) => {
    const { current, previous } = await signer.getCookieSecrets(caller, realmId);
    previous?.secret.fill(0);
    let key: Buffer | undefined;
    try {
      key = Buffer.from(hkdfSync('sha256', current.secret, Buffer.alloc(0), label, 32));
      return createHmac('sha256', key).update(`${realmId}\u0000${identifier}`).digest('base64url');
    } finally {
      current.secret.fill(0);
      key?.fill(0);
    }
  };
}

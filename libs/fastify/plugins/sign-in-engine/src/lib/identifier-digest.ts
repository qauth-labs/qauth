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
 * The identifier's keyed HMAC (ADR-017 Decision 7): HMAC-SHA-256 under a key
 * derived from the realm's active cookie HMAC secret with HKDF-SHA-256
 * (RFC 5869, the label as `info`), over the realm id and the normalised
 * identifier, base64url without padding.
 *
 * The key comes from the key custody that exists (ADR-019 Decision 9) and
 * adds no secret: the realm's `cookie_hmac` key, which the `web` role may
 * read, with {@link IDENTIFIER_HMAC_LABEL} for domain separation. A rotation
 * of that key changes every digest, so audit records before and after it no
 * longer correlate. The per-account ladder (#615), which keys its counters on
 * this digest, decides whether the identifier needs a key of its own that the
 * `api` role (the FiPA endpoint) may use too.
 */
export function createCookieSecretIdentifierDigest(
  signer: CookieSecretSource,
  caller: 'web' | 'local' = 'web'
): IdentifierDigest {
  return async ({ realmId, identifier }) => {
    const { current, previous } = await signer.getCookieSecrets(caller, realmId);
    previous?.secret.fill(0);
    const key = Buffer.from(
      hkdfSync('sha256', current.secret, Buffer.alloc(0), IDENTIFIER_HMAC_LABEL, 32)
    );
    current.secret.fill(0);
    const digest = createHmac('sha256', key)
      .update(`${realmId}\u0000${identifier}`)
      .digest('base64url');
    key.fill(0);
    return digest;
  };
}

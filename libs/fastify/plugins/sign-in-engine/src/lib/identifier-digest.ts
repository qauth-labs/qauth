import { createHmac } from 'node:crypto';

import type { IdentifierDigest } from '@qauth-labs/server-sign-in-engine';

/** The signer's cookie HMAC secrets, by shape (`Signer.getCookieSecrets` of `@qauth-labs/server-keys`). */
export interface CookieSecretSource {
  getCookieSecrets(
    caller: 'web' | 'local',
    realmId: string
  ): Promise<{ readonly current: { readonly kid: string; readonly secret: Buffer } }>;
}

/**
 * What the identifier key is derived for: a QAuth-defined label, so a digest
 * of an identifier can never equal a cookie signature under the same secret.
 */
export const IDENTIFIER_HMAC_LABEL = 'urn:qauth:key-use:identifier-hmac:v1-rc.0';

/**
 * The identifier's keyed HMAC (ADR-017 Decision 7): HMAC-SHA-256 under a key
 * derived from the realm's active cookie HMAC secret, over the realm id and
 * the normalised identifier, base64url without padding.
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
    const { current } = await signer.getCookieSecrets(caller, realmId);
    const key = createHmac('sha256', current.secret).update(IDENTIFIER_HMAC_LABEL).digest();
    current.secret.fill(0);
    return createHmac('sha256', key).update(`${realmId}\u0000${identifier}`).digest('base64url');
  };
}

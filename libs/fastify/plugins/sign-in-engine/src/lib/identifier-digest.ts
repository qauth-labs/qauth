import { createHmac, hkdfSync } from 'node:crypto';

import type { EmailCodeDigest, IdentifierDigest } from '@qauth-labs/server-sign-in-engine';

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
 * What the email-code key is derived for (#638): the sign-in transaction
 * holds an emailed code only as its keyed HMAC under this label, so the
 * stored form is no value the cookie secret signs and no identifier's digest.
 */
export const EMAIL_CODE_HMAC_LABEL = 'urn:qauth:key-use:email-code-hmac:v1-rc.0';

/** HMAC-SHA-256 of `message` under the HKDF of the realm's current cookie secret for `label`. */
async function cookieSecretHmac(
  signer: CookieSecretSource,
  caller: 'web' | 'local',
  label: string,
  realmId: string,
  message: string
): Promise<string> {
  const { current, previous } = await signer.getCookieSecrets(caller, realmId);
  previous?.secret.fill(0);
  let key: Buffer | undefined;
  try {
    key = Buffer.from(hkdfSync('sha256', current.secret, Buffer.alloc(0), label, 32));
    return createHmac('sha256', key).update(message).digest('base64url');
  } finally {
    current.secret.fill(0);
    key?.fill(0);
  }
}

/**
 * An emailed code's keyed HMAC (#638): HMAC-SHA-256 under a key derived from
 * the realm's active cookie HMAC secret with HKDF-SHA-256 and
 * {@link EMAIL_CODE_HMAC_LABEL}, over the realm id, the code's own salt and
 * the code, base64url without padding. The transaction holds this and the
 * salt, never the code, so a reader of the interaction store must still
 * guess the code against the server's key.
 *
 * A rotation of the cookie key changes every digest: a code mailed before it
 * is answered as a wrong one once, and a resend mails one that works. The
 * transaction keeps its count of wrong answers across it.
 *
 * @param caller - how the signer is called: `web` across the role boundary, `local` in its process
 */
export function createCookieSecretEmailCodeDigest(
  signer: CookieSecretSource,
  caller: 'web' | 'local' = 'web'
): EmailCodeDigest {
  return ({ realmId, salt, code }) =>
    cookieSecretHmac(
      signer,
      caller,
      EMAIL_CODE_HMAC_LABEL,
      realmId,
      `${realmId}\u0000${salt}\u0000${code}`
    );
}

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
  return ({ realmId, identifier }) =>
    cookieSecretHmac(signer, caller, label, realmId, `${realmId}\u0000${identifier}`);
}

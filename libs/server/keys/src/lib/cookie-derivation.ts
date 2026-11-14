import { hkdfSync } from 'node:crypto';

/**
 * WHAT A REALM'S COOKIE KEY GIVES A ROLE THAT DOES NOT HOLD IT (ADR-019
 * Decision 9, ADR-017 Decision 7, issue #497).
 *
 * The signer hands the realm's cookie HMAC secrets to the browser-facing role
 * only (`getCookieSecrets`): whoever holds them can make a session cookie. Two
 * things other roles need of that key go through the signer instead:
 *
 * - **A derived key** (`getCookieDerivedKey`): HKDF-SHA-256 (RFC 5869) of the
 *   realm's active cookie secret, with no salt and a label of
 *   {@link COOKIE_DERIVED_KEY_LABELS} as its `info`, 32 bytes. The failure
 *   ladder's identifier and end-user IP digests and the emailed code's digest
 *   are HMACs under such keys, so every process of a realm keys an account
 *   the same way, while the derived key makes no cookie: HKDF is one-way, and
 *   a cookie's MAC is made with the secret itself.
 * - **A cookie's MAC, checked** (`verifyCookieMac`): the signer computes it
 *   over {@link cookieMacInput} and compares it in constant time, so the role
 *   learns whether a cookie is the realm's without the key that made it.
 *
 * The labels are QAuth-defined identifiers of a pre-1.0 format, versioned as
 * release candidates (ADR-018 §5); a new use of the key adds a label here.
 */

/** The labels a key may be derived for from a realm's cookie secret. */
export const COOKIE_DERIVED_KEY_LABELS = Object.freeze([
  // The identifier's keyed HMAC: the failure ladder's and the send caps' account key.
  'urn:qauth:key-use:identifier-hmac:v1-rc.0',
  // The end-user IP's keyed HMAC: the IPs the failure ladder keeps known.
  'urn:qauth:key-use:end-user-ip-hmac:v1-rc.0',
  // An emailed code's keyed HMAC, as the sign-in transaction holds it.
  'urn:qauth:key-use:email-code-hmac:v1-rc.0',
] as const);

/** A label of {@link COOKIE_DERIVED_KEY_LABELS}. */
export type CookieDerivedKeyLabel = (typeof COOKIE_DERIVED_KEY_LABELS)[number];

/** Whether `value` is a label of {@link COOKIE_DERIVED_KEY_LABELS}. */
export function isCookieDerivedKeyLabel(value: unknown): value is CookieDerivedKeyLabel {
  return (
    typeof value === 'string' && (COOKIE_DERIVED_KEY_LABELS as readonly string[]).includes(value)
  );
}

/** The length of a derived key, in bytes. */
export const COOKIE_DERIVED_KEY_BYTES = 32;

/**
 * The key derived from `secret` for `label`: HKDF-SHA-256 with no salt and the
 * label as `info`. A fresh buffer, which belongs to the caller.
 */
export function deriveCookieKey(secret: Uint8Array, label: string): Buffer {
  return Buffer.from(hkdfSync('sha256', secret, Buffer.alloc(0), label, COOKIE_DERIVED_KEY_BYTES));
}

/** The format of a cookie's MAC input, first in it, so another use of the key cannot collide. */
export const COOKIE_MAC_LABEL = 'qauth-cookie/1-rc.0';

/** What a signed cookie's MAC covers, besides the format's label. */
export interface CookieMacFields {
  /** The cookie's name, so one cookie cannot pass for another. */
  readonly cookieName: string;
  /** The realm the cookie belongs to. */
  readonly realmId: string;
  /** The cookie key that signs it. */
  readonly kid: string;
  /** The cookie's content. */
  readonly payload: string;
}

/**
 * The text a signed cookie's MAC is made over (#493): {@link COOKIE_MAC_LABEL},
 * the cookie's name, the realm id, the `kid` and the payload, NUL-separated.
 * None of them holds a NUL: the realm id is a UUID, a `kid` and a cookie name
 * are tokens, and a payload comes from a cookie value.
 */
export function cookieMacInput(fields: CookieMacFields): string {
  return [COOKIE_MAC_LABEL, fields.cookieName, fields.realmId, fields.kid, fields.payload].join(
    '\u0000'
  );
}

/** A `kid` a signed cookie carries: base64url, as every generated and imported cookie key's. */
export const COOKIE_KID_PATTERN = /^[A-Za-z0-9_-]{1,255}$/;

/** A cookie's name: an RFC 6265 token. */
export const COOKIE_NAME_PATTERN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$/;

/** A cookie's MAC: base64url HMAC-SHA-256, 32 bytes as 43 characters without padding. */
export const COOKIE_MAC_PATTERN = /^[A-Za-z0-9_-]{43}$/;

/** The longest payload `verifyCookieMac` checks: a cookie is at most 4096 bytes. */
export const MAX_COOKIE_PAYLOAD_LENGTH = 4096;

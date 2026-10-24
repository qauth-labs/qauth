/**
 * WebAuthn origins and relying-party IDs (ADR-017 Decision 14, ADR-019
 * Decision 2, issue #467).
 *
 * A passkey ceremony is accepted only from an origin the realm expects. Two
 * kinds of origin reach QAuth:
 *
 * - a web origin, `https://host[:port]`, for the hosted pages and for a
 *   first-party web front-end. Its host must be the relying-party ID (RP ID) or
 *   a name under it (WebAuthn Level 3 §5.1.4.1 step 7: the RP ID is a
 *   registrable domain suffix of, or equal to, the origin's effective domain).
 *   Plain `http` is accepted on `localhost` and names under it only, which
 *   browsers treat as a secure context, for development;
 * - an Android app origin, `android:apk-key-hash:<hash>`, where `<hash>` is the
 *   base64url SHA-256 of the app's signing certificate. Android's Credential
 *   Manager sends it in `clientDataJSON.origin` for a native app. An iOS app
 *   sends the `https` origin of the RP ID instead, so it needs no entry.
 *
 * The same rules serve the database layer (the operator-set per-client origins
 * of the seed manifest) and the WebAuthn provider, so they live here.
 */
import { InvalidRealmHostError, normaliseRealmHost } from './realm-host';

/** The scheme-like prefix Android's Credential Manager puts before an app's key hash. */
export const ANDROID_APK_KEY_HASH_ORIGIN_PREFIX = 'android:apk-key-hash:';

/** Base64url of a SHA-256 digest: 32 bytes, 43 characters, no padding. */
const SHA256_BASE64URL = /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/;

/** Longest origin accepted: a scheme, a 253-character host and a port. */
export const WEBAUTHN_ORIGIN_MAX_LENGTH = 300;

/**
 * Why {@link normaliseWebAuthnOrigin} refused a value.
 *
 * - `malformed` — not a URL origin and not an Android key-hash origin.
 * - `scheme` — a URL whose scheme is not `https` (or `http` on localhost).
 * - `not_origin` — a URL with a path, query, fragment or userinfo.
 * - `ip_literal` — an IP address as the host; no RP ID can cover one.
 * - `android_hash` — an Android origin whose hash is not a base64url SHA-256.
 */
export type InvalidWebAuthnOriginReason =
  | 'malformed'
  | 'scheme'
  | 'not_origin'
  | 'ip_literal'
  | 'android_hash';

/**
 * Thrown by {@link normaliseWebAuthnOrigin}. The message is fixed text and
 * never repeats the value; the value is on {@link input} for an operator log.
 */
export class InvalidWebAuthnOriginError extends Error {
  readonly statusCode = 400;
  readonly code = 'INVALID_WEBAUTHN_ORIGIN';

  constructor(
    public readonly reason: InvalidWebAuthnOriginReason,
    message: string,
    public readonly input: string
  ) {
    super(message);
    this.name = 'InvalidWebAuthnOriginError';
    Object.setPrototypeOf(this, InvalidWebAuthnOriginError.prototype);
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, InvalidWebAuthnOriginError);
    }
  }
}

/** `localhost` or a name under it (RFC 6761 §6.3). */
const isLocalhost = (host: string): boolean => host === 'localhost' || host.endsWith('.localhost');

/**
 * Normalise a WebAuthn origin to the form a browser writes in
 * `clientDataJSON.origin`, so a stored origin compares by plain equality.
 *
 * A web origin comes out as `scheme://host[:port]`: lower case, punycode for an
 * internationalised name, the default port dropped. An Android origin comes out
 * unchanged after its hash is checked.
 *
 * @throws InvalidWebAuthnOriginError when the value is neither kind of origin.
 *
 * @example
 * ```typescript
 * normaliseWebAuthnOrigin('https://Auth.Example.com:443'); // 'https://auth.example.com'
 * normaliseWebAuthnOrigin('http://localhost:5173');        // 'http://localhost:5173'
 * normaliseWebAuthnOrigin('https://auth.example.com/ui');  // throws (not_origin)
 * ```
 */
export function normaliseWebAuthnOrigin(input: string): string {
  if (
    typeof input !== 'string' ||
    input.length === 0 ||
    input.length > WEBAUTHN_ORIGIN_MAX_LENGTH
  ) {
    throw new InvalidWebAuthnOriginError(
      'malformed',
      'WebAuthn origin is empty or too long',
      String(input)
    );
  }

  if (input.startsWith(ANDROID_APK_KEY_HASH_ORIGIN_PREFIX)) {
    const hash = input.slice(ANDROID_APK_KEY_HASH_ORIGIN_PREFIX.length);
    if (!SHA256_BASE64URL.test(hash)) {
      throw new InvalidWebAuthnOriginError(
        'android_hash',
        'Android origin must carry the base64url SHA-256 of the signing certificate (43 characters, no padding)',
        input
      );
    }
    return input;
  }

  if (/\s/u.test(input)) {
    throw new InvalidWebAuthnOriginError(
      'malformed',
      'WebAuthn origin contains white space',
      input
    );
  }

  let url: URL;
  try {
    url = new URL(input);
  } catch {
    throw new InvalidWebAuthnOriginError('malformed', 'WebAuthn origin is not a URL', input);
  }

  // A browser writes an origin with no path, not even `/`, so neither may this.
  const afterScheme = input.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '');
  if (
    url.username !== '' ||
    url.password !== '' ||
    url.search !== '' ||
    url.hash !== '' ||
    /[/?#@\\]/.test(afterScheme)
  ) {
    throw new InvalidWebAuthnOriginError(
      'not_origin',
      'WebAuthn origin must be scheme, host and port only',
      input
    );
  }

  let host: string;
  try {
    host = normaliseRealmHost(url.host, 'primary');
  } catch (error) {
    if (!(error instanceof InvalidRealmHostError)) throw error;
    throw new InvalidWebAuthnOriginError(
      error.reason === 'ip_literal' ? 'ip_literal' : 'malformed',
      error.reason === 'ip_literal'
        ? 'WebAuthn origin host is an IP address, which no RP ID can cover'
        : 'WebAuthn origin host is not a valid host name',
      input
    );
  }

  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && isLocalhost(host))) {
    throw new InvalidWebAuthnOriginError(
      'scheme',
      'WebAuthn origin must use https; plain http is for localhost only',
      input
    );
  }

  return url.port === '' ? `${url.protocol}//${host}` : `${url.protocol}//${host}:${url.port}`;
}

/** Whether `origin` is an Android app origin (`android:apk-key-hash:…`). */
export function isAndroidAppOrigin(origin: string): boolean {
  return origin.startsWith(ANDROID_APK_KEY_HASH_ORIGIN_PREFIX);
}

/**
 * Whether the RP ID `rpId` covers `host`: the host is the RP ID or a name under
 * it, compared label by label. Both must already be normalised
 * (`normaliseRealmHost`). `example.com` covers `auth.example.com`; it does not
 * cover `badexample.com`.
 */
export function rpIdCoversHost(rpId: string, host: string): boolean {
  return host === rpId || host.endsWith(`.${rpId}`);
}

/**
 * Whether a normalised origin may take part in a ceremony for `rpId`. An
 * Android app origin is not tied to a host; the app's link to the RP ID is the
 * association file the RP ID serves, which the platform checks.
 */
export function isWebAuthnOriginForRpId(origin: string, rpId: string): boolean {
  if (isAndroidAppOrigin(origin)) return true;
  let url: URL;
  try {
    url = new URL(origin);
  } catch {
    return false;
  }
  return rpIdCoversHost(rpId, url.hostname);
}

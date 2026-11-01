import { timingSafeEqual } from 'node:crypto';

import {
  decodeProtectedHeader,
  errors as joseErrors,
  importJWK,
  type JWK,
  jwtVerify,
  type ProtectedHeaderParameters,
} from 'jose';

import type { UpstreamIdTokenAlgorithm } from './config';
import { invalidResponse } from './errors';

/**
 * ID token validation (OpenID Connect Core 1.0 §3.1.3.7): the signature
 * against the provider's key set, an allowlist of algorithms, `iss`, `aud`,
 * `azp`, `exp`, `iat` and `nonce`.
 */

/** How far the provider's clock may differ from this server's, in seconds. */
export const ID_TOKEN_CLOCK_TOLERANCE_SECONDS = 30;

/**
 * How old an ID token may be when it arrives, in seconds, by its `iat`. A
 * token comes from the code exchange that has just run, so an old one is a
 * replay or a broken clock.
 */
export const ID_TOKEN_MAX_AGE_SECONDS = 600;

/** The longest ID token the client reads, in characters. */
export const MAX_ID_TOKEN_LENGTH = 16 * 1024;

/** The longest `sub` (OpenID Connect Core 1.0 §2). */
const MAX_SUB_LENGTH = 255;

/** A C0 or C1 control character, or DEL. */
// eslint-disable-next-line no-control-regex -- matching control characters is the point
const CONTROL_CHARACTER = /[\u0000-\u001f\u007f-\u009f]/;

/** What the ID token must say. */
export interface IdTokenExpectations {
  /** The configured issuer: `iss`, byte for byte. */
  readonly issuer: string;
  /** QAuth's client id at the provider: in `aud`, and `azp` when present. */
  readonly clientId: string;
  /** The `nonce` the authorization request sent. */
  readonly nonce: string;
  /** The algorithms the token may be signed with: never `none` or `HS*`. */
  readonly algorithms: readonly UpstreamIdTokenAlgorithm[];
}

/** The keys that may verify a token of `algorithm` with `kid`. */
export type IdTokenKeys = (
  algorithm: UpstreamIdTokenAlgorithm,
  kid: string | undefined
) => Promise<readonly JWK[]>;

/**
 * Validate an ID token and return its claims.
 *
 * - The header's `alg` must be in `expected.algorithms`, checked before any
 *   key is looked up: `none` and `HS*` never are, so neither an unsigned
 *   token nor one MACed with the client secret gets that far.
 * - The signature must verify under a key of the provider's key set that
 *   fits the algorithm (and the header's `kid` when it names one).
 * - `iss` equals the configured issuer; `aud` holds the client id; a token
 *   with more than one audience carries `azp`, and `azp`, when present,
 *   is the client id; `exp` has not passed; `iat` is at most
 *   {@link ID_TOKEN_MAX_AGE_SECONDS} old and not in the future; `nbf`, when
 *   present, has passed; all within {@link ID_TOKEN_CLOCK_TOLERANCE_SECONDS}.
 * - `nonce` equals the authorization request's, compared in constant time.
 * - `sub` is 1 to 255 characters of well-formed text with no control
 *   character.
 *
 * @throws UpstreamOidcError `invalid_response` when a check fails; the
 *   message names the check, never the token
 */
export async function validateIdToken(
  token: unknown,
  expected: IdTokenExpectations,
  keys: IdTokenKeys
): Promise<Record<string, unknown>> {
  if (typeof token !== 'string' || token.length === 0 || token.length > MAX_ID_TOKEN_LENGTH) {
    throw invalidResponse('id_token: missing, or longer than the client reads');
  }
  let header: ProtectedHeaderParameters;
  try {
    header = decodeProtectedHeader(token);
  } catch (cause) {
    throw invalidResponse('id_token: not a JWS', { cause });
  }
  const algorithm = header.alg;
  if (
    typeof algorithm !== 'string' ||
    !(expected.algorithms as readonly string[]).includes(algorithm)
  ) {
    throw invalidResponse('id_token: signed with an algorithm the config does not allow');
  }
  const kid = header.kid;
  if (kid !== undefined && typeof kid !== 'string') {
    throw invalidResponse('id_token: the kid is not a string');
  }
  const candidates = await keys(algorithm as UpstreamIdTokenAlgorithm, kid);
  if (candidates.length === 0) {
    throw invalidResponse("id_token: no key of the provider's key set fits it");
  }

  let payload: Record<string, unknown> | undefined;
  for (const candidate of candidates) {
    let key: Awaited<ReturnType<typeof importJWK>>;
    try {
      key = await importJWK({ ...candidate }, algorithm);
    } catch {
      continue;
    }
    try {
      const verified = await jwtVerify(token, key, {
        algorithms: [algorithm],
        issuer: expected.issuer,
        audience: expected.clientId,
        clockTolerance: ID_TOKEN_CLOCK_TOLERANCE_SECONDS,
        maxTokenAge: ID_TOKEN_MAX_AGE_SECONDS,
        requiredClaims: ['iss', 'sub', 'aud', 'exp', 'iat'],
      });
      payload = verified.payload as Record<string, unknown>;
      break;
    } catch (error) {
      // Another key of the set may have signed it; any other failure is final.
      if (error instanceof joseErrors.JWSSignatureVerificationFailed) continue;
      throw invalidResponse(`id_token: ${claimProblem(error)}`, { cause: error });
    }
  }
  if (payload === undefined) {
    throw invalidResponse("id_token: the signature does not verify under the provider's keys");
  }

  const { sub, aud, azp, nonce } = payload;
  if (
    typeof sub !== 'string' ||
    sub.length === 0 ||
    sub.length > MAX_SUB_LENGTH ||
    CONTROL_CHARACTER.test(sub) ||
    !isWellFormed(sub)
  ) {
    throw invalidResponse('id_token: the sub is not 1 to 255 characters of plain text');
  }
  if (Array.isArray(aud) && aud.length > 1 && azp === undefined) {
    throw invalidResponse('id_token: more than one audience and no azp');
  }
  if (azp !== undefined && azp !== expected.clientId) {
    throw invalidResponse('id_token: the azp is not the client id');
  }
  if (typeof nonce !== 'string' || !sameText(nonce, expected.nonce)) {
    throw invalidResponse("id_token: the nonce is not the authorization request's");
  }
  return payload;
}

/** Which check a jose error failed, without the token's content. */
function claimProblem(error: unknown): string {
  if (error instanceof joseErrors.JWTExpired) return `the ${error.claim} check failed (expired)`;
  if (error instanceof joseErrors.JWTClaimValidationFailed) {
    return `the ${error.claim} check failed`;
  }
  if (error instanceof joseErrors.JOSEError) return error.code;
  return 'not a valid JWT';
}

/** Whether two strings are equal, compared in constant time over their bytes. */
export function sameText(presented: string, expected: string): boolean {
  const a = Buffer.from(presented, 'utf8');
  const b = Buffer.from(expected, 'utf8');
  return a.length === b.length && timingSafeEqual(a, b);
}

/** `String.prototype.isWellFormed` (ES2024; the workspace's lib is ES2022). */
function isWellFormed(value: string): boolean {
  return (String.prototype as unknown as { isWellFormed(this: string): boolean }).isWellFormed.call(
    value
  );
}

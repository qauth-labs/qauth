import {
  createRemoteJWKSet,
  decodeProtectedHeader,
  type JWTPayload,
  jwtVerify,
  type JWTVerifyGetKey,
  type ProtectedHeaderParameters,
} from 'jose';

export interface VerifiedJwt {
  readonly header: ProtectedHeaderParameters;
  readonly payload: JWTPayload;
}

export interface VerifyOptions {
  /** The `iss` the token must carry: the base URL of the server under test. */
  readonly issuer: string;
  /** When set, `aud` must contain it. */
  readonly audience?: string | string[];
  /** The JOSE `typ` header the token must carry, e.g. `at+jwt` (RFC 9068 §2.1). */
  readonly typ?: string;
}

const remoteKeySets = new Map<string, JWTVerifyGetKey>();

/**
 * The key set published at `jwksUri`, fetched over HTTP and cached per URI for
 * the life of the test worker. jose refetches it when a token names a `kid`
 * the cached set does not have.
 */
export function remoteKeySet(jwksUri: string): JWTVerifyGetKey {
  let keySet = remoteKeySets.get(jwksUri);
  if (!keySet) {
    keySet = createRemoteJWKSet(new URL(jwksUri));
    remoteKeySets.set(jwksUri, keySet);
  }
  return keySet;
}

/**
 * Verify a compact JWS against a key set and return its header and claims.
 *
 * The signature, `iss`, `exp` and `nbf` are always checked; `aud` and `typ`
 * when the caller names them. The accepted algorithm is whatever the selected
 * key allows, so a token signed with an algorithm the published key does not
 * carry is refused.
 *
 * @throws a jose error naming the failed check
 */
export async function verifyJwt(
  token: string,
  keySet: JWTVerifyGetKey,
  options: VerifyOptions
): Promise<VerifiedJwt> {
  const { payload, protectedHeader } = await jwtVerify(token, keySet, {
    issuer: options.issuer,
    ...(options.audience !== undefined ? { audience: options.audience } : {}),
    ...(options.typ !== undefined ? { typ: options.typ } : {}),
  });
  return { header: protectedHeader, payload };
}

/** The protected header of a compact JWS, without verifying anything. */
export function peekHeader(token: string): ProtectedHeaderParameters {
  return decodeProtectedHeader(token);
}

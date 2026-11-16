import { randomUUID } from 'node:crypto';

import { type CryptoKey, exportJWK, generateKeyPair, type JWK, SignJWT } from 'jose';

/**
 * TEST SUPPORT — `private_key_jwt` client authentication (RFC 7523 §2.2).
 *
 * Only a client that authenticates with `private_key_jwt` may hold the admin
 * API's audience (#522), so a suite whose client gets an admin token gives
 * that client a key with {@link clientAssertionKey}, lists its public half in
 * the client's `jwks`, and authenticates each token request with
 * {@link clientAssertionFields} instead of a secret.
 */

/** The `client_assertion_type` of a JWT client assertion (RFC 7523 §2.2). */
export const CLIENT_ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

/** A client's signing key: the private key, and the public JWK its `jwks` lists. */
export interface ClientAssertionKey {
  readonly privateKey: CryptoKey;
  readonly jwk: JWK;
}

/** A fresh ES256 client key, its public JWK named `kid`. */
export async function clientAssertionKey(kid = 'client-key-1'): Promise<ClientAssertionKey> {
  const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
  return { privateKey, jwk: { ...(await exportJWK(publicKey)), kid } };
}

/** The `jwks` column of a client that signs its assertions with `key`. */
export function clientJwks(key: ClientAssertionKey): { keys: Record<string, unknown>[] } {
  return { keys: [key.jwk as Record<string, unknown>] };
}

/**
 * A client assertion of `clientId`, signed with `key`, for the realm whose
 * issuer is `issuer` (the only audience the server accepts), with a fresh
 * `jti` and a minute of life.
 */
export async function signClientAssertion(
  key: ClientAssertionKey,
  clientId: string,
  issuer: string
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({})
    .setProtectedHeader({ alg: 'ES256', kid: key.jwk.kid ?? 'client-key-1' })
    .setIssuer(clientId)
    .setSubject(clientId)
    .setAudience(issuer)
    .setJti(randomUUID())
    .setIssuedAt(now)
    .setExpirationTime(now + 60)
    .sign(key.privateKey);
}

/** The members of a token request that authenticate `clientId` with an assertion of `key`. */
export async function clientAssertionFields(
  key: ClientAssertionKey,
  clientId: string,
  issuer: string
): Promise<{ client_assertion_type: string; client_assertion: string }> {
  return {
    client_assertion_type: CLIENT_ASSERTION_TYPE,
    client_assertion: await signClientAssertion(key, clientId, issuer),
  };
}

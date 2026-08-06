import { InvalidClientError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import type { JSONWebKeySet, JWK } from 'jose';
import { z } from 'zod';

import { env } from '../../config/env';
import { REDIS_KEYS } from '../constants/redis-keys';
import type { OAuthClientLike } from './client-auth';
import { SsrfBlockedError, ssrfSafeGet } from './ssrf-safe-fetch';

/**
 * Client JWK Set handling — RFC 7591 §2 `jwks` / `jwks_uri` (#384).
 *
 * A client registered for `private_key_jwt` proves possession of a private key
 * whose PUBLIC half the authorization server holds, either inline
 * (`oauth_clients.jwks`) or by reference (`oauth_clients.jwks_uri`). This
 * module owns everything about that key set: what shape is acceptable, how a
 * remote one is fetched, and how the two forms are kept mutually exclusive.
 *
 * It sits below both `cimd.ts` (which accepts a key set from a metadata
 * document) and `client-assertion.ts` (which verifies signatures against one),
 * so the validation bar is defined once and cannot drift between the
 * registration path and the authentication path.
 */

/** Maximum number of keys accepted in a client JWK Set. Matches the seed-manifest cap. */
const CLIENT_JWKS_MAX_KEYS = 20;

/** Maximum accepted `jwks_uri` length, in characters. */
export const CLIENT_JWKS_URI_MAX_LENGTH = 2048;

/** Per-request timeout for a `jwks_uri` fetch, in milliseconds. */
const CLIENT_JWKS_FETCH_TIMEOUT_MS = 5000;

/** Maximum `jwks_uri` document size, in bytes. */
const CLIENT_JWKS_MAX_DOCUMENT_BYTES = 65536;

/** Bounded cache TTL for a fetched `jwks_uri` document, in seconds. */
const CLIENT_JWKS_CACHE_TTL_SECONDS = 300;

/**
 * A single client JWK. Deliberately permissive about the parameters it carries
 * (RFC 7517 leaves the set open) and strict about what matters:
 *
 *   - a `kty` must be present, so key selection is never left ambiguous;
 *   - no PRIVATE component may be present. The AS never needs a client's
 *     private key, so accepting one is pure liability — a `d` (RSA/EC/OKP
 *     private exponent) or `k` (symmetric key value) member rejects the whole
 *     set. The seed manifest applies the same rule at provisioning time; this
 *     is the defence-in-depth re-check on read that the schema column asks for.
 *   - `kty: 'oct'` is rejected. A symmetric key can only be used with a MAC
 *     algorithm, and none of those are in the permitted assertion algorithm
 *     list — rejecting it here states that intent instead of relying on `jose`
 *     to fail later for a reason nobody reads.
 */
const clientJwkSchema = z
  .object({ kty: z.string().min(1).max(16) })
  .catchall(z.unknown())
  .refine((jwk) => !('d' in jwk) && !('k' in jwk), {
    message: 'jwks must contain PUBLIC keys only (a "d" or "k" member was present)',
  })
  .refine((jwk) => jwk.kty !== 'oct', {
    message: 'jwks must not contain symmetric ("oct") keys',
  });

/** RFC 7517 §5 JWK Set as registered on a client. */
export const clientJwkSetSchema = z.object({
  keys: z.array(clientJwkSchema).min(1).max(CLIENT_JWKS_MAX_KEYS),
});

export type ClientJwkSet = z.infer<typeof clientJwkSetSchema>;

/**
 * Validate an untrusted value as a client JWK Set usable for signature
 * verification. The persisted column, a freshly fetched `jwks_uri` document and
 * a registration payload are all the same RFC 7517 structure, and all three
 * must clear the same bar.
 *
 * Throws {@link InvalidClientError} on anything that does not parse; the
 * message is for the caller's audit log, never for the client.
 */
export function parseClientJwkSet(value: unknown, source: string): JSONWebKeySet {
  const parsed = clientJwkSetSchema.safeParse(value);
  if (!parsed.success) {
    throw new InvalidClientError(`${source} is not a valid public JWK Set`);
  }
  // The shape was just validated, and `jose` re-checks every parameter it
  // actually consumes when it imports the key.
  return { keys: parsed.data.keys.map((key) => key as unknown as JWK) };
}

/**
 * RFC 7591 §2: "The `jwks_uri` and `jwks` parameters MUST NOT both be present
 * in the same request or response." Enforced at the validation layer rather
 * than as a DB CHECK so the offending parameter can be named.
 *
 * Fail-closed: a record carrying both is ambiguous about which key set is
 * authoritative, so it authenticates nothing at all.
 */
export function assertJwksMutuallyExclusive(jwks: unknown, jwksUri: unknown, source: string): void {
  if (jwks != null && jwksUri != null) {
    throw new InvalidClientError(
      `${source}: jwks and jwks_uri are mutually exclusive (RFC 7591 §2)`
    );
  }
}

/**
 * Fetch a client's `jwks_uri` through the SSRF-guarded path and cache the
 * validated document for a bounded TTL.
 *
 * The URL is registration-supplied and dereferenced by the server, so it gets
 * exactly the treatment a CIMD document gets: https-only, no redirect
 * following, DNS-pinned IP validation, byte cap, timeout, non-200 rejection.
 * A private / loopback / link-local target is refused — the check that stops a
 * `jwks_uri` from being turned into a cloud-metadata read primitive.
 */
export async function fetchClientJwkSet(
  fastify: FastifyInstance,
  jwksUri: string
): Promise<JSONWebKeySet> {
  const cacheKey = REDIS_KEYS.CLIENT_JWKS(jwksUri);

  try {
    const cached = await fastify.redis.get(cacheKey);
    if (cached) {
      const parsed = clientJwkSetSchema.safeParse(JSON.parse(cached));
      if (parsed.success) {
        return { keys: parsed.data.keys.map((key) => key as unknown as JWK) };
      }
    }
  } catch {
    // Best-effort cache: a miss or a malformed entry simply re-fetches.
  }

  let result;
  try {
    result = await ssrfSafeGet(jwksUri, {
      timeoutMs: CLIENT_JWKS_FETCH_TIMEOUT_MS,
      maxBytes: CLIENT_JWKS_MAX_DOCUMENT_BYTES,
      // Reuses the CIMD escape hatch: both settings gate exactly the same thing
      // (a registration-supplied URL the AS dereferences) and #384 introduced no
      // configuration surface of its own. Defaults to false.
      allowPrivateAddresses: env.CIMD_ALLOW_PRIVATE_ADDRESSES,
    });
  } catch (err) {
    if (err instanceof SsrfBlockedError) {
      throw new InvalidClientError(`client jwks_uri fetch blocked: ${err.message}`);
    }
    throw new InvalidClientError('client jwks_uri fetch failed');
  }

  if (result.status !== 200) {
    throw new InvalidClientError(`client jwks_uri fetch returned ${result.status}`);
  }

  let json: unknown;
  try {
    json = JSON.parse(result.body);
  } catch {
    throw new InvalidClientError('client jwks_uri document is not valid JSON');
  }

  const keySet = parseClientJwkSet(json, 'client jwks_uri document');

  try {
    await fastify.redis.set(cacheKey, JSON.stringify(keySet), 'EX', CLIENT_JWKS_CACHE_TTL_SECONDS);
  } catch {
    // Best-effort cache; a write failure must not fail the request.
  }

  return keySet;
}

/**
 * Resolve the JWK Set a client's assertions must verify against.
 *
 * Exactly one source may be registered (RFC 7591 §2). A client with neither
 * cannot be authenticated by assertion at all — the fail-closed outcome for a
 * half-provisioned `private_key_jwt` client.
 */
export async function resolveClientKeySet(
  fastify: FastifyInstance,
  client: OAuthClientLike
): Promise<JSONWebKeySet> {
  assertJwksMutuallyExclusive(client.jwks, client.jwksUri, 'registered client');

  if (client.jwks != null) {
    return parseClientJwkSet(client.jwks, 'registered client jwks');
  }
  if (typeof client.jwksUri === 'string' && client.jwksUri.length > 0) {
    return fetchClientJwkSet(fastify, client.jwksUri);
  }
  throw new InvalidClientError('client has no registered jwks or jwks_uri');
}

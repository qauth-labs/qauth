import { InvalidClientError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { createLocalJWKSet, decodeJwt, decodeProtectedHeader, jwtVerify } from 'jose';

import { REDIS_KEYS } from '../constants/redis-keys';
import {
  ASSERTION_SIGNING_ALG_VALUES_SUPPORTED,
  CLIENT_ASSERTION_TYPE_JWT_BEARER,
} from '../schemas/oauth';
import { isCimdClientId } from './cimd';
import type { OAuthClientLike } from './client-auth';
import { resolveClientKeySet } from './client-jwks';
import { resolveClient } from './client-resolution';
import { resolveIssuerIdentifier } from './discovery';

/**
 * `private_key_jwt` client authentication — RFC 7523 §2.2 + RFC 7521 §6.
 *
 * A confidential client authenticates at the token endpoint by presenting a
 * short-lived JWT it signed with a private key whose PUBLIC half the
 * authorization server already holds (`oauth_clients.jwks` inline, or
 * `oauth_clients.jwks_uri` by reference — RFC 7591 §2). No shared secret ever
 * crosses the wire, which is what makes this usable by a client the AS never
 * issued a secret to: a CIMD client identified by an https URL (CIMD §6.2),
 * which is the practical motivation for #384.
 *
 * ## Trust boundary
 *
 * The assertion is entirely attacker-controlled text until its signature
 * verifies. Every claim read before verification (`iss`, `sub`, the header
 * `alg`) is used ONLY to look up which registered key set to verify against —
 * never as an established fact. In particular:
 *
 *   - Key material carried BY the assertion (`jwk`, `jku`, `x5u` headers) is
 *     rejected outright. Honouring it would let anyone sign their own
 *     credential and hand us the key to check it with.
 *   - `alg` is intersected with {@link ASSERTION_SIGNING_ALG_VALUES_SUPPORTED},
 *     the same list discovery advertises. That list is asymmetric-only, so
 *     `none` and every `HS*` MAC algorithm are impossible: an HS256 assertion
 *     verified against a public JWK is the classic algorithm-confusion attack,
 *     where the "signature" is an HMAC over a key the attacker can also read.
 *   - The client's registered `token_endpoint_auth_method` MUST be exactly
 *     `private_key_jwt`. A client provisioned for `client_secret_*` cannot be
 *     authenticated by assertion, and (enforced in `client-auth.ts`) a
 *     `private_key_jwt` client cannot fall back to its secret. Seeded clients
 *     carry a real `client_secret_hash` regardless of method, so this pairing
 *     check is what keeps the two methods from being interchangeable.
 *
 * ## Replay
 *
 * A bearer assertion that can be replayed is a bearer credential. RFC 7523 §3
 * therefore lets the AS require `jti`; we require it unconditionally and burn
 * it in Redis with `SET NX` for the remainder of the assertion's validity
 * window. Redis being unreachable FAILS THE REQUEST rather than skipping the
 * check — this is a security control, not a cache.
 */

/* -------------------------------------------------------------------------- */
/*                                   Bounds                                   */
/* -------------------------------------------------------------------------- */

/**
 * Clock-skew tolerance, in seconds, applied to the assertion's `exp` / `nbf` /
 * `iat`. Matches the ID-JAG default (`ID_JAG_CLOCK_SKEW_LEEWAY`) so the two
 * assertion verifiers behave identically, but is deliberately a constant rather
 * than that setting: tuning ID-JAG must not silently loosen client
 * authentication for every client on the deployment.
 */
export const CLIENT_ASSERTION_CLOCK_SKEW_LEEWAY_SECONDS = 60;

/**
 * Maximum permitted `exp - iat` of a client assertion, in seconds. RFC 7523 §3
 * requires `exp` but sets no ceiling; an assertion valid for a day is a
 * long-lived bearer credential in all but name. Bounding the lifetime also
 * bounds how long the `jti` replay entry must be retained.
 */
export const CLIENT_ASSERTION_MAX_LIFETIME_SECONDS = 300;

/** Maximum `jti` length accepted, in characters (bounds the hashed cache key input). */
const CLIENT_ASSERTION_MAX_JTI_LENGTH = 255;

/** Maximum `iss` / `sub` length accepted — a CIMD client_id is an URL, so this matches that cap. */
const CLIENT_ASSERTION_MAX_ISSUER_LENGTH = 2048;

/* -------------------------------------------------------------------------- */
/*                             Assertion verification                         */
/* -------------------------------------------------------------------------- */

/**
 * The `aud` values a client assertion may name, per RFC 7523 §3: "The JWT MUST
 * contain an `aud` claim containing a value that identifies the authorization
 * server as an intended audience." Deployments differ on whether that means
 * the issuer identifier or the concrete token endpoint URL, and the RFC
 * explicitly permits either, so both are accepted and NOTHING else is.
 */
export function acceptedClientAssertionAudiences(fastify: FastifyInstance): string[] {
  const issuer = resolveIssuerIdentifier(fastify.jwtUtils.getIssuer());
  return [issuer, `${issuer}/oauth/token`];
}

function isPermittedAlg(alg: string | undefined): boolean {
  return (
    typeof alg === 'string' &&
    (ASSERTION_SIGNING_ALG_VALUES_SUPPORTED as readonly string[]).includes(alg)
  );
}

/**
 * The unverified `iss` of a client assertion, used ONLY to look up the client
 * record. Returns null when the assertion is not a decodable JWT or its
 * `iss`/`sub` do not both name the same client.
 *
 * RFC 7523 §3 requires `iss` to be the issuer of the assertion and, for client
 * authentication (§2.2 / RFC 7521 §6.1), `sub` to be the client_id. When the
 * client authenticates itself the two are the same principal, so a mismatch
 * means the assertion is either malformed or an attempt to have one client's
 * key vouch for another client's identity.
 */
function readAssertionSubject(assertion: string): string | null {
  let payload;
  try {
    payload = decodeJwt(assertion);
  } catch {
    return null;
  }
  const iss = payload.iss;
  const sub = payload.sub;
  if (typeof iss !== 'string' || typeof sub !== 'string') return null;
  if (iss.length === 0 || iss.length > CLIENT_ASSERTION_MAX_ISSUER_LENGTH) return null;
  if (iss !== sub) return null;
  return iss;
}

/**
 * Look up the client an assertion claims to come from, materialising a CIMD
 * client on the way when the `client_id` is an https URL that has not been
 * resolved before (CIMD §6.2 — the case #384 exists to serve).
 *
 * Returns null for an unknown or disabled client. The caller maps that to the
 * same `invalid_client` every other failure produces, so this never becomes a
 * client-existence oracle.
 */
async function findAssertionClient(
  fastify: FastifyInstance,
  realmId: string,
  clientId: string
): Promise<OAuthClientLike | null> {
  let row = await fastify.repositories.oauthClients.findByClientId(realmId, clientId);
  if (!row && isCimdClientId(clientId)) {
    // Materialise the CIMD client, then re-read so the persisted row (which
    // carries the jwks / jwks_uri columns) is what we authenticate against.
    const { client: resolved } = await resolveClient(fastify, realmId, clientId);
    if (resolved) {
      row = await fastify.repositories.oauthClients.findByClientId(realmId, clientId);
    }
  }
  if (!row || !row.enabled) return null;
  return row;
}

/**
 * Burn the assertion's `jti` so the same assertion cannot be presented twice.
 *
 * Runs AFTER signature verification on purpose: consuming a `jti` before the
 * signature is known good would let an unauthenticated caller invalidate
 * assertions a legitimate client is about to send.
 *
 * `SET NX` is the atomic primitive — a write that finds the key present means
 * this exact assertion was already accepted. Any Redis error rejects the
 * request: without a working store there is no replay protection, and silently
 * degrading to "accept" would turn every assertion into a reusable bearer
 * credential.
 */
async function consumeAssertionJti(
  fastify: FastifyInstance,
  clientId: string,
  jti: string,
  expSeconds: number
): Promise<void> {
  const nowSeconds = Math.floor(Date.now() / 1000);
  const remaining = expSeconds - nowSeconds;
  const ttlSeconds = Math.min(
    Math.max(remaining, 1) + CLIENT_ASSERTION_CLOCK_SKEW_LEEWAY_SECONDS,
    CLIENT_ASSERTION_MAX_LIFETIME_SECONDS + CLIENT_ASSERTION_CLOCK_SKEW_LEEWAY_SECONDS
  );

  const key = REDIS_KEYS.CLIENT_ASSERTION_JTI(clientId, jti);

  let stored: string | null;
  try {
    stored = await fastify.redis.set(key, '1', 'EX', ttlSeconds, 'NX');
  } catch {
    throw new InvalidClientError('client_assertion replay protection is unavailable');
  }
  if (stored !== 'OK') {
    throw new InvalidClientError('client_assertion jti has already been used');
  }
}

/** Parameters carried by an RFC 7523 §2.2 client-authentication request. */
export interface ClientAssertionCredentials {
  /** RFC 7521 §4.2 — `client_id` MAY be omitted when an assertion is present. */
  clientId?: string;
  assertionType: string;
  assertion: string;
  method: 'private_key_jwt';
}

/**
 * Authenticate a client from an RFC 7523 §2.2 `client_assertion`.
 *
 * Every failure surfaces as {@link InvalidClientError} (RFC 6749 §5.2
 * `invalid_client`) with a reason attached for the caller's audit log — the
 * client itself learns only that authentication failed, so this cannot be used
 * to enumerate clients, key sets or registered auth methods.
 *
 * Order of checks is deliberate: everything cheap and purely structural runs
 * before the first database read, and the database read runs before the first
 * signature verification, so a forged-assertion flood costs an attacker more
 * than it costs the server.
 */
export async function authenticateClientAssertion(
  fastify: FastifyInstance,
  realmId: string,
  creds: ClientAssertionCredentials
): Promise<OAuthClientLike> {
  // 1. The assertion type URN. Exact match only — `...:grant-type:jwt-bearer`
  //    differs from `...:client-assertion-type:jwt-bearer` by one path segment
  //    and MUST NOT be accepted here.
  if (creds.assertionType !== CLIENT_ASSERTION_TYPE_JWT_BEARER) {
    throw new InvalidClientError('unsupported client_assertion_type');
  }

  // 2. Protected header. Pin the algorithm to the advertised asymmetric set
  //    (rejects `none` and every `HS*`) and refuse an assertion that tries to
  //    supply its own verification key.
  let header;
  try {
    header = decodeProtectedHeader(creds.assertion);
  } catch {
    throw new InvalidClientError('client_assertion header is not decodable');
  }
  if (!isPermittedAlg(header.alg)) {
    throw new InvalidClientError('client_assertion alg is not permitted');
  }
  if (header.jwk !== undefined || header.jku !== undefined || header.x5u !== undefined) {
    throw new InvalidClientError('client_assertion must not carry its own key material');
  }

  // 3. Which client does it claim to be? Unverified — used only for lookup.
  const claimedClientId = readAssertionSubject(creds.assertion);
  if (claimedClientId === null) {
    throw new InvalidClientError('client_assertion iss and sub must both be the client_id');
  }
  // RFC 7521 §4.2: when `client_id` is also sent it MUST identify the same
  // client. A disagreement is a mix-up attempt, not a tolerable redundancy.
  if (creds.clientId !== undefined && creds.clientId !== claimedClientId) {
    throw new InvalidClientError('client_id does not match the client_assertion subject');
  }

  // 4. Resolve the registered client and confirm it is provisioned for this
  //    authentication method. A `client_secret_*` client MUST NOT be
  //    authenticable by assertion.
  const client = await findAssertionClient(fastify, realmId, claimedClientId);
  if (!client) {
    throw new InvalidClientError();
  }
  if (client.tokenEndpointAuthMethod !== 'private_key_jwt') {
    throw new InvalidClientError('client is not registered for private_key_jwt');
  }

  // 5. Verify the signature against the client's REGISTERED keys.
  const keySet = await resolveClientKeySet(fastify, client);
  const localJwks = createLocalJWKSet(keySet);

  let verified;
  try {
    verified = await jwtVerify(creds.assertion, localJwks, {
      algorithms: [...ASSERTION_SIGNING_ALG_VALUES_SUPPORTED],
      issuer: claimedClientId,
      subject: claimedClientId,
      audience: acceptedClientAssertionAudiences(fastify),
      clockTolerance: CLIENT_ASSERTION_CLOCK_SKEW_LEEWAY_SECONDS,
      requiredClaims: ['iss', 'sub', 'aud', 'exp', 'jti'],
    });
  } catch {
    throw new InvalidClientError('client_assertion signature or claims are invalid');
  }

  const { exp, iat, jti } = verified.payload;
  if (typeof exp !== 'number') {
    throw new InvalidClientError('client_assertion exp is missing');
  }

  // 6. Bound the assertion's lifetime. `jose` has already enforced `exp` and
  //    `nbf` with the skew leeway; what it cannot know is our ceiling on how
  //    long a client assertion may live, or that an `iat` far in the future is
  //    a malformed assertion rather than a valid one.
  const nowSeconds = Math.floor(Date.now() / 1000);
  const issuedAt = typeof iat === 'number' ? iat : nowSeconds;
  if (typeof iat === 'number' && iat > nowSeconds + CLIENT_ASSERTION_CLOCK_SKEW_LEEWAY_SECONDS) {
    throw new InvalidClientError('client_assertion iat is in the future');
  }
  if (exp - issuedAt > CLIENT_ASSERTION_MAX_LIFETIME_SECONDS) {
    throw new InvalidClientError('client_assertion lifetime exceeds the permitted maximum');
  }

  // 7. Single use.
  if (typeof jti !== 'string' || jti.length === 0 || jti.length > CLIENT_ASSERTION_MAX_JTI_LENGTH) {
    throw new InvalidClientError('client_assertion jti is missing or malformed');
  }
  await consumeAssertionJti(fastify, client.clientId, jti, exp);

  return client;
}

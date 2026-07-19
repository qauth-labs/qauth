import { PQC_HEADER_ALG_MEMBER } from '@qauth-labs/core-crypto';
import type { HybridSignedToken } from '@qauth-labs/fastify-plugin-jwt';
import type { FastifyInstance } from 'fastify';

import { REDIS_KEYS } from '../constants/redis-keys';

/**
 * Live hybrid (Ed25519 + ML-DSA-65) access-token issuance and PQC-material
 * delivery (ADR-005, #275; folds in #247 reference delivery).
 *
 * ## Why the PQC signature is stored, not returned
 *
 * A hybrid token's detached ML-DSA-65 signature is a fixed ~4412 base64url
 * bytes — over a 4 KB cookie and a 2 KB URL budget on its own. So the bearer
 * token handed to a client stays the plain ~716 B Ed25519 compact JWS
 * (`HybridSignedToken.token`), and the PQC component is parked server-side
 * keyed by the token's `jti`. A resource server retrieves it out-of-band from
 * RFC 7662 introspection, whose POST body has no header/cookie ceiling. This is
 * `PQC_TOKEN_DELIVERY='reference'`, the fail-safe default.
 *
 * The store entry carries the SAME TTL as the token, so it self-evicts on
 * expiry and can never outlive the credential it describes.
 */

/**
 * Sign an access token, choosing the hybrid or classical signer according to
 * the server's `HYBRID_SIGNING_ENABLED` posture, and return the compact JWS to
 * put on the wire.
 *
 * The returned string is byte-shaped identically in both modes — a hybrid
 * bearer IS an ordinary Ed25519 JWS — so every caller and every existing client
 * integration is unaffected by the flag. When hybrid is on, the detached PQC
 * signature is persisted for introspection-time delivery as a side effect.
 *
 * A store failure is deliberately NOT swallowed: issuing a token whose PQC
 * component is unretrievable would silently downgrade the deployment's posture
 * to classical-only, which is exactly what #248 F1 exists to prevent.
 *
 * @param fastify - Server instance (jwtUtils + redis).
 * @param payload - Access-token claims, as accepted by `signAccessToken`.
 * @returns The compact Ed25519 JWS to return as `access_token`.
 */
export async function issueAccessToken(
  fastify: FastifyInstance,
  payload: Parameters<FastifyInstance['jwtUtils']['signAccessToken']>[0]
): Promise<string> {
  if (!fastify.jwtUtils.isHybridSigningEnabled()) {
    return fastify.jwtUtils.signAccessToken(payload);
  }

  const hybrid = await fastify.jwtUtils.signHybridAccessToken(payload);
  await storePqcSignature(fastify, hybrid);
  return hybrid.token;
}

/**
 * Persist the detached PQC signature of a freshly minted hybrid token, keyed by
 * its `jti`, with a TTL matching the token's remaining lifetime.
 *
 * `jti`/`exp` are read via an unverified decode, which is safe here and ONLY
 * here: the token was produced by this process microseconds earlier, so there
 * is no untrusted input to validate. Nothing on the verification path ever
 * decodes unverified.
 */
async function storePqcSignature(
  fastify: FastifyInstance,
  hybrid: HybridSignedToken
): Promise<void> {
  const { jti, exp } = fastify.jwtUtils.decodeTokenUnsafe(hybrid.token);
  // #248 F1 made a signed `pqc_alg` binding, so a hybrid token whose detached
  // signature was never stored is not a degraded token — it is an UNVERIFIABLE
  // one at every PQC-aware verifier. Both branches below therefore throw rather
  // than return: handing back a token we know cannot be verified is the silent
  // downgrade this module exists to prevent.
  if (!jti) {
    throw new Error(
      'storePqcSignature: hybrid token has no jti — refusing to issue a token whose PQC signature cannot be retrieved.'
    );
  }

  const ttlSeconds =
    exp !== undefined
      ? Math.ceil(exp - Date.now() / 1000)
      : fastify.jwtUtils.getAccessTokenLifespan();
  if (ttlSeconds <= 0) {
    throw new Error('storePqcSignature: hybrid token is already expired — refusing to issue it.');
  }

  await fastify.redis.setex(
    REDIS_KEYS.PQC_SIGNATURE(jti),
    ttlSeconds,
    JSON.stringify({ pqcSignature: hybrid.pqcSignature, pqcAlg: hybrid.pqcAlg })
  );
}

/**
 * Whether a token's protected header carries a `pqc_alg` member.
 *
 * Only ever called on a token that already passed Ed25519 verification, so the
 * header is authenticated: a `pqc_alg` present here was put there by this
 * issuer. Malformed input simply answers `false`.
 */
function advertisesPqc(compactJws: string): boolean {
  try {
    const [encodedHeader] = compactJws.split('.');
    if (!encodedHeader) return false;
    const header: unknown = JSON.parse(Buffer.from(encodedHeader, 'base64url').toString('utf-8'));
    return typeof header === 'object' && header !== null && PQC_HEADER_ALG_MEMBER in header;
  } catch {
    return false;
  }
}

/** The PQC material returned alongside an introspection response. */
export interface StoredPqcSignature {
  /** base64url detached ML-DSA-65 signature over the token's JWS signing-input. */
  pqcSignature: string;
  /** The parallel PQC algorithm. Authoritative copy is the signed `pqc_alg` header. */
  pqcAlg: string;
}

/**
 * Look up the detached PQC signature for a verified token's `jti`.
 *
 * Returns `undefined` when the token predates hybrid issuance, the entry has
 * expired, or the stored value is unparseable. The caller then simply omits the
 * PQC fields — introspection of the classical component is unaffected, so a
 * lookup miss degrades availability of the PQC material, never the correctness
 * of the `active` decision.
 *
 * ## Retrieval is deliberately NOT gated on `isHybridSigningEnabled()`
 *
 * Gating lookup on the current issuance posture turns `HYBRID_SIGNING_ENABLED`
 * into a one-way door. Since #248 F1 a signed `pqc_alg` is BINDING, so every
 * still-valid token minted while the flag was on would start failing at every
 * PQC-aware verifier the instant the flag flipped off — a hard outage lasting a
 * full access-token lifetime, not a graceful degradation to classical-only.
 *
 * Serving whatever is stored keeps rollback safe: the store is TTL-bounded, so
 * it self-drains one token lifetime after issuance stops, and a deployment that
 * never issued hybrid tokens simply has no entries to serve.
 *
 * The lookup is instead gated on the TOKEN itself: only a token whose (already
 * Ed25519-verified) protected header advertises `pqc_alg` can have stored PQC
 * material, so a classical token costs no store round-trip. That gate is a
 * per-token fact, not a per-deployment posture, which is what makes it safe
 * across a flag flip.
 *
 * @param verifiedToken - The compact JWS that ALREADY passed
 *   `verifyAccessToken`. Its header is read only after that verification, so
 *   this is authenticated input, not an unsafe decode of attacker-controlled
 *   data.
 */
export async function getPqcSignature(
  fastify: FastifyInstance,
  jti: string | undefined,
  verifiedToken: string
): Promise<StoredPqcSignature | undefined> {
  if (!jti) return undefined;
  if (!advertisesPqc(verifiedToken)) return undefined;

  const raw = await fastify.redis.get(REDIS_KEYS.PQC_SIGNATURE(jti));
  if (!raw) return undefined;

  try {
    const parsed: unknown = JSON.parse(raw);
    if (
      typeof parsed === 'object' &&
      parsed !== null &&
      'pqcSignature' in parsed &&
      typeof (parsed as StoredPqcSignature).pqcSignature === 'string' &&
      'pqcAlg' in parsed &&
      typeof (parsed as StoredPqcSignature).pqcAlg === 'string'
    ) {
      return parsed as StoredPqcSignature;
    }
  } catch {
    // Corrupt entry — treat exactly as a miss.
  }
  return undefined;
}

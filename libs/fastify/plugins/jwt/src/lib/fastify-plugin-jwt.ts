import {
  getSignatureBackend,
  importPublicSigningJwk,
  type MlDsaKey,
  PQC_ALG_ML_DSA_65,
  type PqcBackendSelection,
  type SigningKey,
} from '@qauth-labs/core-crypto';
import {
  ACCESS_TOKEN_TYP,
  buildAccessTokenClaims,
  buildIdTokenClaims,
  decodeJwtUnsafe,
  decodeProtectedHeaderUnsafe,
  extractAccessTokenCredential,
  extractJWTFromHeader,
  generateRefreshToken,
  hashRefreshToken,
  ID_TOKEN_TYP,
  verifyAccessToken,
  verifyHybridAccessToken,
} from '@qauth-labs/server-jwt';
import type { VerificationKey } from '@qauth-labs/server-keys';
import {
  JWTExpiredError,
  JWTInvalidError,
  MissingAccessTokenError,
} from '@qauth-labs/shared-errors';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import fp from 'fastify-plugin';

import packageJson from '../../package.json';
import type {
  AccessTokenCheckPolicy,
  JWTPayload,
  JwtPluginOptions,
  JwtUtils,
  TokenRealm,
} from '../types';

declare module 'fastify' {
  interface FastifyInstance {
    jwtUtils: JwtUtils;
    requireJwt: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
    /**
     * Verify the access token of a request's `Authorization` header and return
     * its claims, as `requireJwt` does, under a route's own
     * {@link AccessTokenCheckPolicy} (#509). It does not set
     * `request.jwtPayload`: the caller does, once its own checks pass.
     */
    verifyRequestAccessToken: (
      request: FastifyRequest,
      policy?: AccessTokenCheckPolicy
    ) => Promise<JWTPayload>;
  }

  interface FastifyRequest {
    jwtPayload?: JWTPayload;
  }
}

/**
 * Refuse a DPoP-bound access token presented as a Bearer token (RFC 9449
 * §7.2). Its `cnf.jkt` names the one key whose proofs may accompany it, so
 * accepting it without a proof would let anyone who copied it use it.
 *
 * Applied whether or not this server verifies DPoP proofs: a token minted while
 * `DPOP_ENABLED` was on stays bound after the switch goes off. `requireJwt`
 * calls it for every Bearer credential; a route that reads a Bearer token by
 * hand calls it after verification.
 *
 * @throws JWTInvalidError when the claims carry `cnf`
 */
export function refuseBoundTokenAsBearer(claims: { cnf?: unknown }): void {
  if (claims.cnf !== undefined) {
    throw new JWTInvalidError('A DPoP-bound access token cannot be used as a Bearer token');
  }
}

/**
 * The role the plugin names on each signer call. In a single deployment every
 * role shares the signer's process (ADR-019 Decision 9); the remote signer
 * (#497) takes the caller's role from its client certificate instead.
 */
const SIGNER_CALLER = 'local';

/** The most imported public keys the plugin keeps, across realms. */
const MAX_IMPORTED_KEYS = 256;

/** The algorithm every access token is signed with. */
const ACCESS_TOKEN_ALGORITHM = 'EdDSA';

/** The registered claims the plugin adds to a token's claims: `aud`, `iat` and `exp`. */
function withLifetime(
  claims: Record<string, unknown>,
  audience: string | string[],
  expiresIn: number
): Record<string, unknown> {
  const issuedAt = Math.floor(Date.now() / 1000);
  return { ...claims, aud: audience, iat: issuedAt, exp: issuedAt + expiresIn };
}

/**
 * Fastify plugin for JWT operations
 * Decorates fastify instance with jwtUtils
 *
 * The plugin holds no key (ADR-019 Decision 9, #491). Every token is signed
 * through the signer for its realm, which sets `iss` from the realm row and
 * `kid` from the realm's active key; every token is verified with the realm's
 * published keys, which the signer lists. So a realm's tokens verify only with
 * that realm's keys and only under its issuer.
 *
 * @example
 * ```typescript
 * await fastify.register(jwtPlugin, {
 *   signer: fastify.signer,
 *   requestRealm: (request) => tokenRealm(requestRealm(request)),
 *   accessTokenLifespan: env.ACCESS_TOKEN_LIFESPAN,
 *   refreshTokenLifespan: env.REFRESH_TOKEN_LIFESPAN,
 * });
 *
 * // Use in routes. email/email_verified MUST come from the trust-ordered
 * // resolver (ADR-002/#229) — never from the users row — and only under the
 * // `email` scope; both are omitted entirely without it, or when the user has
 * // no verified email.
 * const token = await fastify.jwtUtils.signAccessToken(requestRealm(request), {
 *   sub: user.id,
 *   ...(await resolveEmailClaimsForScopes(fastify, user, grantedScopes)),
 * });
 * ```
 */
export const jwtPlugin = fp<JwtPluginOptions>(
  async (fastify: FastifyInstance, options: JwtPluginOptions) => {
    const { signer } = options;

    // Hybrid issuance needs the operator to have enabled ML-DSA-65, or the
    // server could sign hybrid tokens it cannot verify. Fail fast: a
    // half-configured hybrid deployment must never silently fall back to
    // classical-only issuance. The realm's pair itself is the key boot step's
    // to check, which refuses to start with half a pair.
    const hybridSigningEnabled = options.hybridSigningEnabled === true;
    // #248 F7/F11: the ML-DSA backend is resolved through the OPERATOR's
    // allowlist, never a literal. Without one that enables ML-DSA-65, no hybrid
    // token verifies here.
    const pqcBackend: PqcBackendSelection | undefined =
      options.enabledSignatureAlgorithms?.includes(PQC_ALG_ML_DSA_65) === true
        ? { enabledSignatureAlgorithms: options.enabledSignatureAlgorithms }
        : undefined;
    if (hybridSigningEnabled && pqcBackend === undefined) {
      throw new Error(
        "jwtPlugin: hybridSigningEnabled requires enabledSignatureAlgorithms with ML-DSA-65 (SIGNING_ALGORITHM_MODE='ed25519+ml-dsa-65')."
      );
    }

    /**
     * The public keys imported for verification, by realm and key. Public
     * material only, and bounded: the oldest entry goes first.
     */
    const importedKeys = new Map<string, Promise<SigningKey>>();

    function importEdKey(realmId: string, key: VerificationKey): Promise<SigningKey> {
      const cacheKey = `${realmId}\u0000${key.kid}\u0000${JSON.stringify(key.publicJwk)}`;
      let imported = importedKeys.get(cacheKey);
      if (imported === undefined) {
        imported = importPublicSigningJwk(key.publicJwk, ACCESS_TOKEN_ALGORITHM);
        // A failed import is not kept, so a later call tries again.
        imported.catch(() => importedKeys.delete(cacheKey));
        if (importedKeys.size >= MAX_IMPORTED_KEYS) {
          const [oldest] = importedKeys.keys();
          importedKeys.delete(oldest);
        }
        importedKeys.set(cacheKey, imported);
      }
      return imported;
    }

    /**
     * The realm's EdDSA keys that may have signed `token`: the one its `kid`
     * names or, for a token issued before tokens named their key (#491), every
     * EdDSA verification key of the realm. The header is read unverified, only
     * to pick the key; the signature check with that key comes next.
     *
     * @throws JWTInvalidError when the token is malformed, is not EdDSA, or
     *   names a key the realm does not publish for verification
     */
    async function accessTokenKeys(
      realm: Pick<TokenRealm, 'id'>,
      token: string
    ): Promise<{ keys: SigningKey[]; verificationKeys: readonly VerificationKey[] }> {
      const header = decodeProtectedHeaderUnsafe(token);
      if (header['alg'] !== ACCESS_TOKEN_ALGORITHM) {
        throw new JWTInvalidError('Invalid JWT token: an access token is signed with EdDSA');
      }
      const kid = header['kid'];
      if (kid !== undefined && typeof kid !== 'string') {
        throw new JWTInvalidError('Invalid JWT token: kid is not a string');
      }
      const verificationKeys = await signer.getVerificationKeys(
        SIGNER_CALLER,
        realm.id,
        'token_signing'
      );
      const candidates = verificationKeys.filter(
        (key) =>
          key.algorithm === ACCESS_TOKEN_ALGORITHM &&
          key.publicJwk.kty === 'OKP' &&
          (kid === undefined || key.kid === kid)
      );
      if (candidates.length === 0) {
        throw new JWTInvalidError('Invalid JWT token: no key of this realm verifies it');
      }
      return {
        keys: await Promise.all(candidates.map((key) => importEdKey(realm.id, key))),
        verificationKeys,
      };
    }

    /**
     * Run `verify` with each key that may have signed the token, and return
     * the first answer. Only the key that made the signature gets past it to
     * the expiry check, so an expiry is that key's answer and ends the search.
     */
    async function withEachKey<T>(
      keys: readonly SigningKey[],
      verify: (key: SigningKey) => Promise<T>
    ): Promise<T> {
      let failure: unknown;
      for (const key of keys) {
        try {
          return await verify(key);
        } catch (error) {
          if (error instanceof JWTExpiredError) throw error;
          failure ??= error;
        }
      }
      throw failure;
    }

    /** Verify an access token of `realm`: its keys, its issuer unless `pinIssuer` is false. */
    async function verifyRealmAccessToken(
      realm: TokenRealm,
      token: string,
      verifyOptions: { audience?: string | string[]; pinIssuer: boolean; requireTyp: boolean }
    ): Promise<JWTPayload> {
      const { keys } = await accessTokenKeys(realm, token);
      return withEachKey(keys, (key) =>
        verifyAccessToken(token, key, {
          ...(verifyOptions.pinIssuer ? { issuer: realm.issuer } : {}),
          ...(verifyOptions.audience !== undefined ? { audience: verifyOptions.audience } : {}),
          requireTyp: verifyOptions.requireTyp,
        })
      );
    }

    /** The algorithms of the realm's active `token_signing` keys. */
    async function activeTokenAlgorithms(realm: Pick<TokenRealm, 'id'>): Promise<Set<string>> {
      const keys = await signer.getVerificationKeys(SIGNER_CALLER, realm.id, 'token_signing');
      return new Set(keys.filter((key) => key.status === 'active').map((key) => key.algorithm));
    }

    const jwtUtils: JwtUtils = {
      async signAccessToken(realm, payload) {
        // `expiresInOverride` lets callers shorten a token below the configured
        // lifespan (e.g. RFC 8693 token-exchange clamps to the subject token's
        // remaining lifetime). It can only narrow — the value is passed through
        // verbatim and callers compute the clamped seconds. Never widens here.
        const { expiresInOverride, ...fields } = payload;
        const { claims, audience } = buildAccessTokenClaims(fields);
        return signer.signJws(SIGNER_CALLER, {
          realmId: realm.id,
          purpose: 'token_signing',
          typ: ACCESS_TOKEN_TYP,
          claims: withLifetime(claims, audience, expiresInOverride ?? options.accessTokenLifespan),
        });
      },
      isHybridSigningEnabled() {
        return hybridSigningEnabled;
      },
      async signHybridAccessToken(realm, payload) {
        if (!hybridSigningEnabled) {
          throw new Error('Hybrid signing is not enabled on this server.');
        }
        // Same lifespan semantics as the classical signer: `expiresInOverride`
        // may only NARROW the configured lifespan (RFC 8693 clamping). The
        // claims are shaped by the same `buildAccessTokenClaims`, so the bearer
        // token is indistinguishable from a classical one.
        const { expiresInOverride, ...fields } = payload;
        const { claims, audience } = buildAccessTokenClaims(fields);
        return signer.signHybrid(SIGNER_CALLER, {
          realmId: realm.id,
          typ: ACCESS_TOKEN_TYP,
          claims: withLifetime(claims, audience, expiresInOverride ?? options.accessTokenLifespan),
        });
      },
      async verifyHybridAccessToken(realm, hybrid, verifyOptions) {
        if (pqcBackend === undefined) {
          throw new JWTInvalidError('PQC verification is not configured on this server');
        }
        const { keys, verificationKeys } = await accessTokenKeys(realm, hybrid.token);
        const mlDsaKeys = verificationKeys.filter((key) => key.algorithm === PQC_ALG_ML_DSA_65);
        // The ML-DSA key is resolved from the Ed25519-SIGNED `pqc_kid` (#248
        // F5): a kid this realm does not publish resolves to nothing and
        // verification fails closed. A token without one, from before the
        // ML-DSA key had a configured kid, takes the realm's only ML-DSA key.
        const mlDsa = (signedPqcKid: string | undefined): MlDsaKey | undefined => {
          const key =
            signedPqcKid === undefined
              ? mlDsaKeys.length === 1
                ? mlDsaKeys[0]
                : undefined
              : mlDsaKeys.find((candidate) => candidate.kid === signedPqcKid);
          const pub = key?.publicJwk['pub'];
          if (typeof pub !== 'string') return undefined;
          return getSignatureBackend(
            PQC_ALG_ML_DSA_65,
            pqcBackend.enabledSignatureAlgorithms
          ).importKey(pub, 'public');
        };
        // `requirePqc` is a FLOOR, not the downgrade control: verifyHybrid
        // treats the issuer-signed `pqc_alg` as binding on its own (#248 F1).
        const claims = await withEachKey(keys, (ed) =>
          verifyHybridAccessToken(
            hybrid,
            { ed, mlDsa },
            {
              issuer: realm.issuer,
              requirePqc: verifyOptions.requirePqc,
              ...(verifyOptions.audience !== undefined ? { audience: verifyOptions.audience } : {}),
              ...pqcBackend,
            }
          )
        );
        return claims as unknown as JWTPayload;
      },
      async signIdToken(realm, payload) {
        // OIDC ID tokens share the lifespan of access tokens. `aud` is the
        // client_id; identity claims + nonce are passed through verbatim.
        //
        // #309: a realm with an active RS256 key signs its ID tokens with
        // RS256 (what the OIDC Basic/Config certification suite, #286,
        // requires to verify); otherwise with its EdDSA key. Access tokens
        // always stay EdDSA. Either way the signer stamps the key's `kid`, so
        // the ID token resolves unambiguously against the realm's JWKS.
        const { claims, audience } = buildIdTokenClaims(payload);
        const algorithm = (await activeTokenAlgorithms(realm)).has('RS256') ? 'RS256' : 'EdDSA';
        return signer.signJws(SIGNER_CALLER, {
          realmId: realm.id,
          purpose: 'token_signing',
          typ: ID_TOKEN_TYP,
          algorithm,
          claims: withLifetime(claims, audience, options.accessTokenLifespan),
        });
      },
      generateRefreshToken() {
        return generateRefreshToken();
      },
      hashRefreshToken(token) {
        return hashRefreshToken(token);
      },
      async verifyAccessToken(realm, token, verifyOptions = {}) {
        return verifyRealmAccessToken(realm, token, {
          ...(verifyOptions.audience !== undefined ? { audience: verifyOptions.audience } : {}),
          pinIssuer: true,
          // #283: the operator's rollout switch is applied HERE, not left to
          // each call site, so no route can accidentally verify with a weaker
          // `typ` policy than the deployment was configured for.
          requireTyp: options.requireAccessTokenTyp === true,
        });
      },
      extractFromHeader(authHeader) {
        return extractJWTFromHeader(authHeader);
      },
      extractCredentialFromHeader(authHeader) {
        return extractAccessTokenCredential(authHeader, {
          allowDpop: options.verifyDpopProof !== undefined,
        });
      },
      decodeTokenUnsafe(token) {
        return decodeJwtUnsafe(token);
      },
      getAccessTokenLifespan() {
        return options.accessTokenLifespan;
      },
      getRefreshTokenLifespan() {
        return options.refreshTokenLifespan;
      },
      async getIdTokenSigningAlgValuesSupported(realm) {
        // #309: RS256 is advertised FIRST and is the default ID-token signature
        // when the realm has an RS256 key (what OIDC Basic/Config
        // certification, #286, requires). EdDSA stays advertised so existing
        // RPs keep working.
        const algorithms = await activeTokenAlgorithms(realm);
        return algorithms.has('RS256') ? ['RS256', 'EdDSA'] : ['EdDSA'];
      },
      async getJwks(realm) {
        // The realm's published `token_signing` keys in their window: the
        // active keys, `next` keys before they sign, and retired keys that may
        // still verify, each under its own `kid`, in a fixed order. ML-DSA
        // `AKP` entries sit beside the `OKP` and `RSA` ones (#246); classical
        // verifiers ignore the key types they do not understand.
        return signer.getJwks(SIGNER_CALLER, realm.id);
      },
    };

    fastify.decorate('jwtUtils', jwtUtils);

    /**
     * The checks every bearer-protected route shares: the credential, the
     * signature and expiry, the issuer, revocation and the DPoP binding.
     * `policy` changes only what it names; with none, this is `requireJwt`.
     */
    async function verifyRequestAccessToken(
      request: FastifyRequest,
      policy: AccessTokenCheckPolicy = {}
    ): Promise<JWTPayload> {
      // `Bearer`, or `DPoP` only when the host app verifies DPoP proofs: without
      // `verifyDpopProof` a `DPoP` header is no credential, as before DPoP.
      const credential = jwtUtils.extractCredentialFromHeader(request.headers.authorization);
      if (!credential) {
        // No credential at all, an empty token or a scheme this server does
        // not take: the request "lacks any authentication information" (RFC
        // 6750 §3.1), which is not a refused token.
        throw new MissingAccessTokenError('Missing or malformed Authorization header');
      }
      const { scheme, token } = credential;
      const { acceptIssuer } = policy;
      // RFC 9700 mix-up defence: every bearer-protected route MUST only accept
      // tokens its realm issued. The token verifies only with the keys of the
      // request's realm (ADR-019 Decision 1, #491), and its issuer is pinned
      // to that realm's here, so a token minted in another realm is refused
      // outright. A route with its own issuer rule (#509) decides after the
      // signature check instead, below. `requireTyp` can only tighten the
      // operator's rollout switch (#283), never loosen it.
      const payload = await verifyRealmAccessToken(options.requestRealm(request), token, {
        pinIssuer: acceptIssuer === undefined,
        requireTyp: options.requireAccessTokenTyp === true || policy.requireTyp === true,
      });
      if (acceptIssuer !== undefined) {
        // A token that names no issuer is refused before the rule sees it.
        if (payload.iss === undefined || !(await acceptIssuer(payload.iss, request))) {
          throw new JWTInvalidError('Access token issuer is not accepted here');
        }
      }

      // RFC 7009 revocation: reject a signature-valid but explicitly revoked
      // token. The denylist check runs only AFTER verification (so an attacker
      // cannot probe the store with unsigned tokens) and only when the host app
      // wired a denylist; otherwise behaviour is unchanged.
      if (options.isTokenRevoked && (await options.isTokenRevoked(payload.jti))) {
        throw new JWTInvalidError('Token has been revoked');
      }

      if (scheme === 'DPoP' && options.verifyDpopProof !== undefined) {
        // RFC 9449 §7.1: the DPoP scheme carries a DPoP-bound token, checked
        // against the proof's key. A token bound to no key has nothing to
        // check the proof against.
        if (payload.cnf === undefined) {
          throw new JWTInvalidError('The access token is not bound to a DPoP key');
        }
        await options.verifyDpopProof(request, token, payload);
      } else {
        refuseBoundTokenAsBearer(payload);
      }

      return payload;
    }

    fastify.decorate('verifyRequestAccessToken', verifyRequestAccessToken);

    async function requireJwt(request: FastifyRequest): Promise<void> {
      request.jwtPayload = await verifyRequestAccessToken(request);
    }

    fastify.decorate('requireJwt', requireJwt);

    fastify.log.debug('JWT plugin registered');
  },
  {
    name: packageJson.name,
  }
);

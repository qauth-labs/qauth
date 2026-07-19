import { deriveMlDsaPublicKeyAndZeroize, getSignatureBackend } from '@qauth-labs/core-crypto';
import {
  type AkpJwk,
  assertDistinctJwksKeyIds,
  decodeJwtUnsafe,
  exportMlDsaPublicJwk,
  exportPublicJwk,
  exportPublicKeyPem,
  extractJWTFromHeader,
  generateRefreshToken,
  hashRefreshToken,
  importPrivateKey,
  importPublicKey,
  type PublicJwk,
  signAccessToken,
  signIdToken,
  verifyAccessToken,
} from '@qauth-labs/server-jwt';
import { JWTInvalidError } from '@qauth-labs/shared-errors';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import fp from 'fastify-plugin';

import packageJson from '../../package.json';
import type { JWTPayload, JwtPluginOptions, JwtUtils } from '../types';

declare module 'fastify' {
  interface FastifyInstance {
    jwtUtils: JwtUtils;
    requireJwt: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
  }

  interface FastifyRequest {
    jwtPayload?: JWTPayload;
  }
}

/**
 * Fastify plugin for JWT operations
 * Decorates fastify instance with jwtUtils
 *
 * @example
 * ```typescript
 * await fastify.register(jwtPlugin, {
 *   privateKey: env.JWT_PRIVATE_KEY,
 *   issuer: env.JWT_ISSUER,
 *   accessTokenLifespan: env.ACCESS_TOKEN_LIFESPAN,
 *   refreshTokenLifespan: env.REFRESH_TOKEN_LIFESPAN,
 * });
 *
 * // Use in routes. email/email_verified MUST come from the trust-ordered
 * // resolver (resolveEmailClaims, ADR-002/#229) — never from the users row;
 * // both are omitted entirely when the user has no verified email.
 * const token = await fastify.jwtUtils.signAccessToken({
 *   sub: user.id,
 *   ...(await resolveEmailClaims(fastify, user.id)),
 * });
 * ```
 */
export const jwtPlugin = fp<JwtPluginOptions>(
  async (fastify: FastifyInstance, options: JwtPluginOptions) => {
    // Import private key once at plugin registration
    const privateKey = await importPrivateKey(options.privateKey);

    // Import or derive public key for verification
    let publicKey: Awaited<ReturnType<typeof importPublicKey>>;
    if (options.publicKey) {
      // Use provided public key
      publicKey = await importPublicKey(options.publicKey);
    } else {
      // Derive public key from private key
      // For EdDSA keys, we can export the public key from the private key
      // Note: This requires the key to be extractable, which imported keys are by default in jose
      try {
        const publicKeyPem = await exportPublicKeyPem(privateKey);
        publicKey = await importPublicKey(publicKeyPem);
      } catch {
        throw new Error(
          'Failed to derive public key from private key. Please provide JWT_PUBLIC_KEY in environment variables.'
        );
      }
    }

    // ML-DSA JWKS entries (#246), including retired keys for rotation (#248 F9).
    // Built ONCE at boot: the configured seed is expanded, the public half is
    // derived, and the transient private key is zeroized immediately (#248 F10)
    // — nothing but public material survives this block. Absent → JWKS stays
    // EdDSA-only.
    const mlDsaJwks: AkpJwk[] = [];
    if (options.mlDsaSeed) {
      // #248 F7/F11: gate on the OPERATOR's enabled set, never a hardcoded
      // literal, so `SIGNING_ALGORITHM_MODE` is authoritative and a registered
      // native backend (#244) is selectable here. Defaulting the option would
      // reintroduce the bypass, so an absent set is a boot failure.
      if (!options.enabledSignatureAlgorithms) {
        throw new Error(
          'jwtPlugin: `enabledSignatureAlgorithms` is required when `mlDsaSeed` is set. ' +
            'Pass cryptoEnv.enabledSignatureAlgorithms so SIGNING_ALGORITHM_MODE gates the ML-DSA backend.'
        );
      }
      const backend = getSignatureBackend('ML-DSA-65', options.enabledSignatureAlgorithms);
      mlDsaJwks.push(
        exportMlDsaPublicJwk(
          deriveMlDsaPublicKeyAndZeroize(backend.importKey(options.mlDsaSeed, 'private')),
          options.mlDsaKeyId
        )
      );
      // Retired ML-DSA keys are published under their OWN kid so tokens signed
      // before a rotation keep verifying. Public material only — a retired key
      // is configured as a public key, never as a seed.
      for (const retired of options.retiredMlDsaPublicKeys ?? []) {
        mlDsaJwks.push(
          exportMlDsaPublicJwk(backend.importKey(retired.publicKey, 'public'), retired.keyId)
        );
      }
    }

    // Retired Ed25519 keys, each under its own kid (#248 F9).
    const retiredEdJwks: PublicJwk[] = [];
    for (const retired of options.retiredKeys ?? []) {
      retiredEdJwks.push(
        await exportPublicJwk(await importPublicKey(retired.publicKey), retired.keyId)
      );
    }

    const jwtUtils: JwtUtils = {
      async signAccessToken(payload) {
        // `expiresInOverride` lets callers shorten a token below the configured
        // lifespan (e.g. RFC 8693 token-exchange clamps to the subject token's
        // remaining lifetime). It can only narrow — the value is passed through
        // verbatim and callers compute the clamped seconds. Never widens here.
        const { expiresInOverride, ...claims } = payload;
        const expiresIn = expiresInOverride ?? options.accessTokenLifespan;
        return signAccessToken(claims, privateKey, options.issuer, expiresIn);
      },
      async signIdToken(payload) {
        // OIDC ID tokens share the access-token signing key (one JWKS verifies
        // both) and lifespan. `aud` is the client_id; identity claims + nonce
        // are passed through verbatim. Crypto stays in the plugin, never the
        // route, per the project's security-first plugin boundary.
        return signIdToken(payload, privateKey, options.issuer, options.accessTokenLifespan);
      },
      generateRefreshToken() {
        return generateRefreshToken();
      },
      hashRefreshToken(token) {
        return hashRefreshToken(token);
      },
      async verifyAccessToken(token, options) {
        return verifyAccessToken(token, publicKey, options);
      },
      extractFromHeader(authHeader) {
        return extractJWTFromHeader(authHeader);
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
      getIssuer() {
        return options.issuer;
      },
      async getJwks() {
        // Active Ed25519 key, then retired Ed25519 keys under their own kids so
        // in-flight tokens keep verifying across a rotation (#248 F9), then the
        // ML-DSA AKP entries (#246 — classical verifiers ignore the `kty: 'AKP'`
        // entries they don't understand; PQC verifiers resolve them by
        // `(kid, alg)`, see `selectJwksKey`).
        const keys: (PublicJwk | AkpJwk)[] = [
          await exportPublicJwk(publicKey, options.keyId),
          ...retiredEdJwks,
          ...mlDsaJwks,
        ];
        // Every kid must be distinct across OKP/AKP and active/retired, or a
        // verifier resolving by kid can land on the wrong algorithm's key.
        // Serving an ambiguous JWKS is worse than serving none.
        assertDistinctJwksKeyIds(keys);
        return { keys };
      },
    };

    fastify.decorate('jwtUtils', jwtUtils);

    async function requireJwt(request: FastifyRequest): Promise<void> {
      const token = jwtUtils.extractFromHeader(request.headers.authorization);
      if (!token) {
        throw new JWTInvalidError('Missing or malformed Authorization header');
      }
      // RFC 9700 mix-up defence: every bearer-protected route MUST only accept
      // tokens this server issued. Pin the issuer here so the shared preHandler
      // rejects a foreign-issuer token even if it verifies under the same key.
      const payload = await jwtUtils.verifyAccessToken(token, {
        issuer: options.issuer,
      });

      // RFC 7009 revocation: reject a signature-valid but explicitly revoked
      // token. The denylist check runs only AFTER verification (so an attacker
      // cannot probe the store with unsigned tokens) and only when the host app
      // wired a denylist; otherwise behaviour is unchanged.
      if (options.isTokenRevoked && (await options.isTokenRevoked(payload.jti))) {
        throw new JWTInvalidError('Token has been revoked');
      }

      request.jwtPayload = payload;
    }

    fastify.decorate('requireJwt', requireJwt);

    fastify.log.debug('JWT plugin registered');
  },
  {
    name: packageJson.name,
  }
);

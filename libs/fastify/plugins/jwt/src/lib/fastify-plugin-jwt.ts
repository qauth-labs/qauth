import {
  decodeJwtUnsafe,
  exportPublicJwk,
  exportPublicKeyPem,
  extractJWTFromHeader,
  generateRefreshToken,
  hashRefreshToken,
  importPrivateKey,
  importPublicKey,
  signAccessToken,
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
 * // Use in routes
 * const token = await fastify.jwtUtils.signAccessToken({
 *   sub: user.id,
 *   email: user.email,
 *   email_verified: user.emailVerified,
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

    const jwtUtils: JwtUtils = {
      async signAccessToken(payload) {
        return signAccessToken(payload, privateKey, options.issuer, options.accessTokenLifespan);
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
        // Single active key for now. When we add rotation, push retired keys
        // with their own `kid` here so in-flight tokens keep verifying.
        const jwk = await exportPublicJwk(publicKey, options.keyId);
        return { keys: [jwk] };
      },
    };

    fastify.decorate('jwtUtils', jwtUtils);

    async function requireJwt(request: FastifyRequest): Promise<void> {
      const token = jwtUtils.extractFromHeader(request.headers.authorization);
      if (!token) {
        throw new JWTInvalidError('Missing or malformed Authorization header');
      }
      request.jwtPayload = await jwtUtils.verifyAccessToken(token);
    }

    fastify.decorate('requireJwt', requireJwt);

    fastify.log.debug('JWT plugin registered');
  },
  {
    name: packageJson.name,
  }
);

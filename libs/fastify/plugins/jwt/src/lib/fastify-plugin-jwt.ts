import {
  generateRefreshToken,
  hashRefreshToken,
  importPrivateKey,
  signAccessToken,
} from '@qauth/server-jwt';
import type { FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';

import type { JwtPluginOptions, JwtUtils } from '../types';

declare module 'fastify' {
  interface FastifyInstance {
    jwtUtils: JwtUtils;
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
      getAccessTokenLifespan() {
        return options.accessTokenLifespan;
      },
      getRefreshTokenLifespan() {
        return options.refreshTokenLifespan;
      },
    };

    fastify.decorate('jwtUtils', jwtUtils);

    fastify.log.debug('JWT plugin registered');
  },
  {
    name: '@qauth/fastify-plugin-jwt',
  }
);

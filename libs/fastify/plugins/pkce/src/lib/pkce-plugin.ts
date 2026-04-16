import {
  generateCodeChallenge,
  generateCodeVerifier,
  generatePkcePair,
  isValidCodeVerifierFormat,
  verifyCodeChallenge,
} from '@qauth-labs/server-pkce';
import type { FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';

import packageJson from '../../package.json';

/**
 * PKCE utilities interface exposed on Fastify instance
 */
export interface PkceUtils {
  generateCodeVerifier: typeof generateCodeVerifier;
  generateCodeChallenge: typeof generateCodeChallenge;
  generatePkcePair: typeof generatePkcePair;
  isValidCodeVerifierFormat: typeof isValidCodeVerifierFormat;
  verifyCodeChallenge: typeof verifyCodeChallenge;
}

declare module 'fastify' {
  interface FastifyInstance {
    pkceUtils: PkceUtils;
  }
}

/**
 * Fastify plugin for PKCE (Proof Key for Code Exchange) utilities.
 * Decorates fastify instance with pkceUtils for OAuth 2.1 PKCE operations.
 *
 * @example
 * ```typescript
 * await fastify.register(pkcePlugin);
 *
 * // Use in routes
 * const isValid = fastify.pkceUtils.verifyCodeChallenge(verifier, challenge);
 * const pair = fastify.pkceUtils.generatePkcePair();
 * ```
 */
export const pkcePlugin = fp(
  async (fastify: FastifyInstance) => {
    const pkceUtils: PkceUtils = {
      generateCodeVerifier,
      generateCodeChallenge,
      generatePkcePair,
      isValidCodeVerifierFormat,
      verifyCodeChallenge,
    };

    fastify.decorate('pkceUtils', pkceUtils);

    fastify.log.debug('PKCE plugin registered');
  },
  {
    name: packageJson.name,
  }
);

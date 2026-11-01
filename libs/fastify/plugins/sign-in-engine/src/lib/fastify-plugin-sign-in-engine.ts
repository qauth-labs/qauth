import {
  createSignInEngine,
  type SignInEngine,
  type SignInEngineDependencies,
} from '@qauth-labs/server-sign-in-engine';
import type { FastifyInstance, FastifyPluginOptions } from 'fastify';
import fp from 'fastify-plugin';

import packageJson from '../../package.json';

declare module 'fastify' {
  interface FastifyInstance {
    /**
     * The sign-in engine (#614, ADR-017 Decision 4): every transport that
     * signs a person in calls its `advance` once per round.
     */
    signInEngine: SignInEngine;
  }
}

/** Options for {@link signInEnginePlugin}: the engine's ports, built from the server's own. */
export type SignInEnginePluginOptions = FastifyPluginOptions &
  SignInEngineDependencies & {
    /**
     * Whether the server runs in production. Defaults to
     * `NODE_ENV === 'production'`. In production the engine is built only
     * with a `ladder` hook.
     */
    readonly production?: boolean;
  };

export const SIGN_IN_ENGINE_PLUGIN_NAME = packageJson.name;

/**
 * Decorate the server with one sign-in engine built from `options`. The
 * transports (the Interaction API's answer route, #616; the FiPA endpoint,
 * #646) register it with the adapters of this library over the server's
 * repositories, password hasher and signer.
 *
 * In production it refuses to register without a `ladder` hook: the
 * engine's default ladder counts nothing, so a password could be guessed
 * without limit until the per-account ladder (#615) is passed in.
 *
 * @throws Error in production when `hooks.ladder` is absent
 */
export const signInEnginePlugin = fp(
  async (fastify: FastifyInstance, options: SignInEnginePluginOptions) => {
    const { production = process.env['NODE_ENV'] === 'production', ...dependencies } = options;
    if (production && dependencies.hooks?.ladder === undefined) {
      throw new Error(
        'sign-in engine: a production server needs a ladder hook (#615); without one a ' +
          'password could be guessed without limit'
      );
    }
    fastify.decorate('signInEngine', createSignInEngine(dependencies));
  },
  { name: SIGN_IN_ENGINE_PLUGIN_NAME, fastify: '5.x' }
);

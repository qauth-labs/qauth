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
     * with a `ladder` hook and a `passwordHardAction`.
     */
    readonly production?: boolean;
  };

export const SIGN_IN_ENGINE_PLUGIN_NAME = packageJson.name;

/**
 * Build one sign-in engine from `options`, with the checks of
 * {@link signInEnginePlugin}: a transport that needs more than one engine,
 * such as the Interaction API's answer route with one per verified-account
 * policy (#616), builds each here.
 *
 * In production it refuses an engine without a `ladder` hook (the
 * per-account ladder of `createRedisFailureLadder`, #615): the engine's
 * default ladder counts nothing, so a password could be guessed without
 * limit. It refuses one without a `passwordHardAction` too: the default never
 * disables a password at the ladder's hard ceiling, whatever arms it.
 *
 * @throws Error in production when `hooks.ladder` or `passwordHardAction` is absent
 */
export function createCheckedSignInEngine(options: SignInEnginePluginOptions): SignInEngine {
  const { production = process.env['NODE_ENV'] === 'production', ...dependencies } = options;
  if (production && dependencies.hooks?.ladder === undefined) {
    throw new Error(
      'sign-in engine: a production server needs a ladder hook (#615); without one a ' +
        'password could be guessed without limit'
    );
  }
  if (production && dependencies.passwordHardAction === undefined) {
    throw new Error(
      'sign-in engine: a production server needs the password hard action (#615); without ' +
        'it the ladder never disables a password at its hard ceiling'
    );
  }
  return createSignInEngine(dependencies);
}

/**
 * Decorate the server with one sign-in engine built from `options`, by
 * {@link createCheckedSignInEngine}. The transports (the Interaction API's
 * answer route, #616; the FiPA endpoint, #646) register it with the adapters
 * of this library over the server's repositories, password hasher and signer.
 *
 * @throws Error in production when `hooks.ladder` or `passwordHardAction` is absent
 */
export const signInEnginePlugin = fp(
  async (fastify: FastifyInstance, options: SignInEnginePluginOptions) => {
    fastify.decorate('signInEngine', createCheckedSignInEngine(options));
  },
  { name: SIGN_IN_ENGINE_PLUGIN_NAME, fastify: '5.x' }
);

import {
  AUTH_METHOD_CONTRACT,
  type AuthMethod,
  type ImportAuthMethodPlugin,
  UPSTREAM_STEP_URN,
} from '@qauth-labs/fastify-plugin-federation';
import { z } from 'zod';

/**
 * TEST SUPPORT — fixture AuthMethod plugins (#600), for the plugin runtime's
 * unit and container tests. A fixture is a minimal method on the contract,
 * with a config whose `clientSecret` is a secret member; its callback hands
 * back nothing a real sign-in could use.
 */

/** The config of a fixture plugin. */
export const fixturePluginConfigSchema = z.object({
  issuer: z.url(),
  clientId: z.string().min(1).max(64),
  clientSecret: z.string().min(1).max(256).meta({ writeOnly: true }),
});

/** Options of {@link fixturePluginMethod}. */
export interface FixturePluginOptions {
  /** The method's `type`, its route segment. */
  readonly type: string;
  /** The method's `id`; its type by default. */
  readonly id?: string;
  /** The contract it declares; this server's by default. */
  readonly contract?: string;
}

/** A fixture method: a callback under `/callback`, and a bounce from a POST to it. */
export function fixturePluginMethod(options: FixturePluginOptions): AuthMethod {
  return {
    contract: (options.contract ?? AUTH_METHOD_CONTRACT) as typeof AUTH_METHOD_CONTRACT,
    type: options.type,
    id: options.id ?? options.type,
    display: { name: 'Fixture provider' },
    configSchema: fixturePluginConfigSchema,
    steps: [UPSTREAM_STEP_URN],
    routes: [
      {
        kind: 'callback',
        method: 'GET',
        path: '/callback',
        handle: async () => ({ kind: 'failed', reason: 'invalid_response' }),
      },
      {
        kind: 'bounce',
        method: 'POST',
        path: '/callback',
        handle: async (request) => {
          const state = request.form['state'];
          const query: Record<string, string> = typeof state === 'string' ? { state } : {};
          return { to: '/callback', query };
        },
      },
    ],
    start: async () => ({
      redirectTo: 'https://provider.example/authorize',
      transaction: {},
      binding: 'fixture-binding-0123456789',
    }),
    verify: async () => Promise.reject(new Error('the fixture verifies nothing')),
    extractAttributes: () => [],
  };
}

/**
 * An importer over named fixture modules, as the loader's test support takes
 * it: a name it does not hold is "not installed", as Node answers.
 */
export function fixturePluginImporter(
  modules: Readonly<Record<string, unknown>>
): ImportAuthMethodPlugin {
  return async (name) => {
    if (Object.hasOwn(modules, name)) return modules[name];
    const error = new Error(`Cannot find package '${name}' imported from /app/main.js`);
    (error as NodeJS.ErrnoException).code = 'ERR_MODULE_NOT_FOUND';
    throw error;
  };
}

import { z } from 'zod';

import { MAX_UPSTREAM_CLIENT_ID_LENGTH, MAX_UPSTREAM_CLIENT_SECRET_LENGTH } from '../lib/config';
import { createUpstreamOidcPresetMethod } from '../lib/upstream-oidc-preset';

/**
 * TEST SUPPORT — a preset plugin on the generic upstream OpenID Connect
 * client (#951), shaped as the first-party presets of #671 will be: its own
 * id, type and config, a fixed provider, and its client secret inside a
 * discriminated union of client authentication methods. The provider is the
 * fake one (`createFakeProvider({ issuer: EXAMPLE_PRESET_ISSUER })`).
 */

/** The package name a test loads the preset under. */
export const EXAMPLE_PRESET_PACKAGE = '@qauth-labs/plugin-example-idp';

/** The preset's AuthMethod id. */
export const EXAMPLE_PRESET_ID = 'example-idp';

/** The preset's AuthMethod type: its callback is `/upstream/example_idp/callback`. */
export const EXAMPLE_PRESET_TYPE = 'example_idp';

/** The preset's provider: its issuer, and the one origin it answers on. */
export const EXAMPLE_PRESET_ISSUER = 'https://idp.example.com';

/** Where the preset's secret member sits. */
export const EXAMPLE_PRESET_SECRET_PATH = 'clientAuthentication.clientSecret';

const clientSecret = z
  .string()
  .min(1)
  .max(MAX_UPSTREAM_CLIENT_SECRET_LENGTH)
  .meta({ writeOnly: true });

/** The preset's config: what an admin sets for a realm. No URL among it. */
export const examplePresetConfigSchema = z.strictObject({
  clientId: z.string().min(1).max(MAX_UPSTREAM_CLIENT_ID_LENGTH),
  clientAuthentication: z.discriminatedUnion('method', [
    z.strictObject({ method: z.literal('client_secret_basic'), clientSecret }),
    z.strictObject({ method: z.literal('client_secret_post'), clientSecret }),
    z.strictObject({ method: z.literal('private_key_jwt') }),
  ]),
  /** Whether the provider answers by `form_post`. */
  formPost: z.boolean().default(false),
});

export type ExamplePresetConfig = z.output<typeof examplePresetConfigSchema>;

/** A fresh method of the preset. */
export function examplePresetMethod() {
  return createUpstreamOidcPresetMethod({
    id: EXAMPLE_PRESET_ID,
    type: EXAMPLE_PRESET_TYPE,
    display: { name: 'Example IdP' },
    origins: [EXAMPLE_PRESET_ISSUER],
    configSchema: examplePresetConfigSchema,
    upstreamConfig: (config: ExamplePresetConfig) => ({
      issuer: EXAMPLE_PRESET_ISSUER,
      clientId: config.clientId,
      clientAuthentication:
        config.clientAuthentication.method === 'private_key_jwt'
          ? { method: 'private_key_jwt', signingAlgorithm: 'RS256' }
          : config.clientAuthentication,
      responseMode: config.formPost ? 'form_post' : 'query',
    }),
  });
}

/** The preset's package, as `import()` answers it: its method under `authMethod`. */
export function examplePresetPackage(): {
  readonly authMethod: ReturnType<typeof examplePresetMethod>;
} {
  return Object.freeze({ authMethod: examplePresetMethod() });
}

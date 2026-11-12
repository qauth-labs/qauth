import { z } from 'zod';

import { MAX_UPSTREAM_CLIENT_ID_LENGTH, MAX_UPSTREAM_CLIENT_SECRET_LENGTH } from '../lib/config';
import { createUpstreamOidcPresetMethod } from '../lib/upstream-oidc-preset';

/**
 * TEST SUPPORT — a preset plugin on the generic upstream OpenID Connect
 * client (#951), shaped as a provider preset in its own repository is (#671):
 * its own id, type and config, a fixed provider, and its client secret inside a
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

/**
 * The package name a test loads the tenant preset under (#1031): a preset
 * whose issuer a member of its config shapes, as a multi-tenant provider's
 * does.
 */
export const EXAMPLE_TENANT_PRESET_PACKAGE = '@qauth-labs/plugin-example-tenant-idp';

/** The tenant preset's AuthMethod id. */
export const EXAMPLE_TENANT_PRESET_ID = 'example-tenant-idp';

/** The tenant preset's AuthMethod type. */
export const EXAMPLE_TENANT_PRESET_TYPE = 'example_tenant_idp';

/** Where the tenant preset's secret member sits. */
export const EXAMPLE_TENANT_PRESET_SECRET_PATH = 'clientSecret';

/**
 * The tenant preset's config: the tenant, which is no URL and shapes the
 * issuer's path (`https://idp.example.com/<tenant>`), and a token endpoint an
 * admin may set by hand on the provider's origin.
 */
export const exampleTenantPresetConfigSchema = z.strictObject({
  tenant: z.string().regex(/^[a-z0-9][a-z0-9-]{0,62}$/),
  clientId: z.string().min(1).max(MAX_UPSTREAM_CLIENT_ID_LENGTH),
  clientSecret,
  /** The tenant's token endpoint, set by hand; discovered when absent. */
  tokenEndpoint: z.url().max(2048).optional(),
});

export type ExampleTenantPresetConfig = z.output<typeof exampleTenantPresetConfigSchema>;

/** The tenant's issuer: a path of the provider's one origin. */
export function exampleTenantIssuer(tenant: string): string {
  return `${EXAMPLE_PRESET_ISSUER}/${tenant}`;
}

/** A fresh method of the tenant preset. */
export function exampleTenantPresetMethod() {
  return createUpstreamOidcPresetMethod({
    id: EXAMPLE_TENANT_PRESET_ID,
    type: EXAMPLE_TENANT_PRESET_TYPE,
    display: { name: 'Example Tenant IdP' },
    origins: [EXAMPLE_PRESET_ISSUER],
    configSchema: exampleTenantPresetConfigSchema,
    upstreamConfig: (config: ExampleTenantPresetConfig) => {
      const issuer = exampleTenantIssuer(config.tenant);
      return {
        issuer,
        clientId: config.clientId,
        clientAuthentication: {
          method: 'client_secret_basic',
          clientSecret: config.clientSecret,
        },
        ...(config.tokenEndpoint === undefined
          ? {}
          : {
              endpoints: {
                authorization: `${issuer}/authorize`,
                token: config.tokenEndpoint,
                jwks: `${issuer}/jwks`,
              },
            }),
      };
    },
  });
}

/** The tenant preset's package, as `import()` answers it. */
export function exampleTenantPresetPackage(): {
  readonly authMethod: ReturnType<typeof exampleTenantPresetMethod>;
} {
  return Object.freeze({ authMethod: exampleTenantPresetMethod() });
}

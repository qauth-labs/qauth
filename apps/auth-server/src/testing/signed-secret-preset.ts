import { AUTH_METHOD_CONTRACT } from '@qauth-labs/fastify-plugin-federation';
import { z } from 'zod';

/**
 * TEST SUPPORT — an upstream OpenID Connect preset package whose client
 * authenticates with a client secret the signer role signs, as Sign in with
 * Apple's does (#671, #1073): the provider issued the key, the client id is
 * a Services ID, and the signed secret's `iss` is a Team ID the realm's admin
 * sets. A config that carries a `clientSecret` authenticates with it
 * instead, so the signer signs nothing for it.
 *
 * The package exports the preset as `upstreamOidcPreset`, the shape the
 * plugin SDK's `defineUpstreamOidcPreset` makes, so the loader builds its
 * method on the server's own client.
 */

/** The package's npm name, the value `AUTH_METHOD_PLUGINS` lists. */
export const SIGNED_SECRET_PRESET_PACKAGE = '@example/qauth-plugin-signed-secret-idp';

/** The preset's AuthMethod id, the admin API's name for it. */
export const SIGNED_SECRET_PRESET_ID = 'signed-secret-idp';

/** The preset's AuthMethod type: the provider id its client assertions are signed under. */
export const SIGNED_SECRET_PRESET_TYPE = 'signed_secret_idp';

/** The provider's issuer and one origin. */
export const SIGNED_SECRET_PRESET_ISSUER = 'https://appleid.signed-secret.example';

/** The preset's config: what an admin sets for a realm. */
export const signedSecretPresetConfigSchema = z.strictObject({
  servicesId: z.string().min(1).max(255),
  teamId: z
    .string()
    .regex(/^[A-Z0-9]{10}$/)
    .optional(),
  clientSecret: z.string().min(1).max(1024).meta({ writeOnly: true }).optional(),
});

export type SignedSecretPresetConfig = z.output<typeof signedSecretPresetConfigSchema>;

/** The preset, as the package exports it. */
export function signedSecretPreset() {
  return Object.freeze({
    contract: AUTH_METHOD_CONTRACT,
    id: SIGNED_SECRET_PRESET_ID,
    type: SIGNED_SECRET_PRESET_TYPE,
    display: { name: 'Signed secret IdP' },
    origins: [SIGNED_SECRET_PRESET_ISSUER],
    configSchema: signedSecretPresetConfigSchema,
    upstreamConfig: (config: SignedSecretPresetConfig) => ({
      issuer: SIGNED_SECRET_PRESET_ISSUER,
      clientId: config.servicesId,
      clientAuthentication:
        config.clientSecret === undefined
          ? {
              method: 'signed_client_secret',
              signingAlgorithm: 'ES256',
              ...(config.teamId === undefined ? {} : { assertionIssuer: config.teamId }),
            }
          : { method: 'client_secret_post', clientSecret: config.clientSecret },
      responseMode: 'form_post',
    }),
  });
}

/** The preset's package, as `import()` answers it. */
export function signedSecretPresetPackage(): { readonly upstreamOidcPreset: unknown } {
  return Object.freeze({ upstreamOidcPreset: signedSecretPreset() });
}

import {
  createUpstreamOidcPresetMethod,
  MAX_UPSTREAM_CLIENT_ID_LENGTH,
  MAX_UPSTREAM_CLIENT_SECRET_LENGTH,
  type UpstreamClaimAttribute,
  upstreamClaimIsTrue,
  upstreamOidcRedirectUri,
} from '@qauth-labs/server-upstream-oidc';
import { z } from 'zod';

/**
 * The Google sign-in plugin (#671): a preset on the generic upstream OpenID
 * Connect client for Google's OpenID Provider, `https://accounts.google.com`.
 * A realm's admin sets the OAuth client id and secret of a web application
 * registered at Google, nothing else: the issuer, the endpoints, the scopes
 * and the claim mapping are the plugin's.
 *
 * EXPERIMENTAL, like the AuthMethod contract it implements.
 *
 * @experimental
 */

/** The plugin's AuthMethod id: its name in the admin API. */
export const GOOGLE_PLUGIN_ID = 'google';

/** The plugin's AuthMethod type: its callback is `/upstream/google/callback`. */
export const GOOGLE_PLUGIN_TYPE = 'google';

/** Google's issuer identifier, which its ID tokens carry as `iss`. */
export const GOOGLE_ISSUER = 'https://accounts.google.com';

/**
 * The origins Google's OpenID Provider answers on: the issuer and the
 * authorization endpoint, the token endpoint, the key set and userinfo, as
 * its discovery document names them. No call goes to another host.
 */
export const GOOGLE_ORIGINS: readonly string[] = Object.freeze([
  'https://accounts.google.com',
  'https://oauth2.googleapis.com',
  'https://www.googleapis.com',
  'https://openidconnect.googleapis.com',
]);

/** The scopes the plugin asks for. */
export const GOOGLE_SCOPES: readonly string[] = Object.freeze(['openid', 'email', 'profile']);

/** The plugin's config for one realm: the web application's OAuth client at Google. */
export const googleConfigSchema = z.strictObject({
  /** The OAuth client id, such as `1234-abc.apps.googleusercontent.com`. */
  clientId: z.string().min(1).max(MAX_UPSTREAM_CLIENT_ID_LENGTH),
  /** The client secret: write-only, stored encrypted under the plugin's own context. */
  clientSecret: z.string().min(1).max(MAX_UPSTREAM_CLIENT_SECRET_LENGTH).meta({ writeOnly: true }),
});

/** The plugin's config, parsed. */
export type GoogleConfig = z.output<typeof googleConfigSchema>;

/**
 * The attributes a Google sign-in maps to. `email` is verified only when the
 * ID token's `email_verified` is the boolean `true`. `hd`, the Google
 * Workspace domain, is kept as an attribute that is never verified: it says
 * which domain the account belongs to, and the plugin makes no decision on it.
 */
export const GOOGLE_ATTRIBUTES: readonly UpstreamClaimAttribute[] = Object.freeze([
  { claim: 'email', verified: (claims) => upstreamClaimIsTrue(claims, 'email_verified') },
  { claim: 'name' },
  { claim: 'given_name' },
  { claim: 'family_name' },
  { claim: 'locale' },
  { claim: 'hd' },
]);

/**
 * A fresh method of the plugin: its own discovery documents, key sets and
 * results. The package exports one as `authMethod`.
 *
 * @experimental
 */
export function createGoogleMethod() {
  return createUpstreamOidcPresetMethod({
    id: GOOGLE_PLUGIN_ID,
    type: GOOGLE_PLUGIN_TYPE,
    display: { name: 'Google' },
    origins: GOOGLE_ORIGINS,
    configSchema: googleConfigSchema,
    upstreamConfig: (config: GoogleConfig) => ({
      issuer: GOOGLE_ISSUER,
      clientId: config.clientId,
      clientAuthentication: { method: 'client_secret_post', clientSecret: config.clientSecret },
      scopes: [...GOOGLE_SCOPES],
      idTokenSigningAlgorithms: ['RS256'],
    }),
    attributes: GOOGLE_ATTRIBUTES,
  });
}

/**
 * The redirect URI to register for the OAuth client at Google, for a realm
 * served at `realmOrigin`: `<realm origin>/upstream/google/callback`.
 *
 * @throws TypeError when `realmOrigin` is not a bare origin
 */
export function googleRedirectUri(realmOrigin: string): string {
  return upstreamOidcRedirectUri(realmOrigin, GOOGLE_PLUGIN_TYPE);
}

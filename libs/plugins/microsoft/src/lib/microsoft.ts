import {
  createUpstreamOidcPresetMethod,
  MAX_UPSTREAM_CLIENT_ID_LENGTH,
  MAX_UPSTREAM_CLIENT_SECRET_LENGTH,
  UPSTREAM_TENANT_PLACEHOLDER,
  type UpstreamClaimAttribute,
  upstreamClaimIsTrue,
  upstreamOidcRedirectUri,
} from '@qauth-labs/server-upstream-oidc';
import { z } from 'zod';

/**
 * The Microsoft sign-in plugin (#671): a preset on the generic upstream
 * OpenID Connect client for the Microsoft identity platform's v2.0
 * endpoints. A realm's admin sets the application's client id and secret
 * and the tenant to sign in through:
 *
 * - **a tenant id** (a GUID): only that tenant's accounts sign in. The
 *   issuer is `https://login.microsoftonline.com/<tenant id>/v2.0`, and an
 *   ID token another tenant issued is refused;
 * - **`organizations`** or **`common`**: the multi-tenant endpoints, through
 *   which work or school accounts of any tenant (and, for `common`, personal
 *   accounts) sign in. Their discovery document names the issuer template
 *   `https://login.microsoftonline.com/{tenantid}/v2.0`, and an ID token is
 *   accepted only when its `iss` is the template with the token's own `tid`
 *   in place.
 *
 * EXPERIMENTAL, like the AuthMethod contract it implements.
 *
 * @experimental
 */

/** The plugin's AuthMethod id: its name in the admin API. */
export const MICROSOFT_PLUGIN_ID = 'microsoft';

/** The plugin's AuthMethod type: its callback is `/upstream/microsoft/callback`. */
export const MICROSOFT_PLUGIN_TYPE = 'microsoft';

/** The origin of the Microsoft identity platform's endpoints. */
export const MICROSOFT_LOGIN_ORIGIN = 'https://login.microsoftonline.com';

/**
 * The origins the provider answers on: the login endpoints (the issuer, the
 * authorization and token endpoints, the key set) and Microsoft Graph, which
 * serves userinfo. No call goes to another host.
 */
export const MICROSOFT_ORIGINS: readonly string[] = Object.freeze([
  MICROSOFT_LOGIN_ORIGIN,
  'https://graph.microsoft.com',
]);

/** The multi-tenant endpoints the config may name in place of a tenant id. */
export const MICROSOFT_MULTI_TENANT_ENDPOINTS = Object.freeze(['common', 'organizations'] as const);

/** A tenant id, as the v2.0 issuer spells it: a GUID in lower case. */
export const MICROSOFT_TENANT_ID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** The issuer template of the multi-tenant endpoints. */
export const MICROSOFT_ISSUER_TEMPLATE = `${MICROSOFT_LOGIN_ORIGIN}/${UPSTREAM_TENANT_PLACEHOLDER}/v2.0`;

/** The scopes the plugin asks for. */
export const MICROSOFT_SCOPES: readonly string[] = Object.freeze(['openid', 'email', 'profile']);

/** The v2.0 issuer of a tenant id, or the discovery base of a multi-tenant endpoint. */
export function microsoftIssuer(tenant: string): string {
  return `${MICROSOFT_LOGIN_ORIGIN}/${tenant}/v2.0`;
}

/** The plugin's config for one realm: the application's registration and the tenant. */
export const microsoftConfigSchema = z.strictObject({
  /**
   * The tenant id (a lower-case GUID) whose accounts sign in, or a
   * multi-tenant endpoint: `organizations` (work or school accounts of any
   * tenant) or `common` (those and personal accounts).
   */
  tenant: z.union([
    z.enum(MICROSOFT_MULTI_TENANT_ENDPOINTS),
    z.string().regex(MICROSOFT_TENANT_ID_PATTERN),
  ]),
  /** The application (client) id of the app registration. */
  clientId: z.string().min(1).max(MAX_UPSTREAM_CLIENT_ID_LENGTH),
  /** A client secret of the app registration: write-only, stored encrypted. */
  clientSecret: z.string().min(1).max(MAX_UPSTREAM_CLIENT_SECRET_LENGTH).meta({ writeOnly: true }),
});

/** The plugin's config, parsed. */
export type MicrosoftConfig = z.output<typeof microsoftConfigSchema>;

/**
 * The attributes a Microsoft sign-in maps to. `email` is verified only when
 * the ID token carries `xms_edov` (email domain owner verified) as the
 * boolean `true`, an optional claim the app registration must ask for: the
 * `email` claim alone is a mutable property of the account that any tenant
 * may set, so it is unverified by default. `email_verified` is not read.
 * `preferred_username` and `tid` (the account's tenant) are kept, never
 * verified.
 */
export const MICROSOFT_ATTRIBUTES: readonly UpstreamClaimAttribute[] = Object.freeze([
  { claim: 'email', verified: (claims) => upstreamClaimIsTrue(claims, 'xms_edov') },
  { claim: 'name' },
  { claim: 'given_name' },
  { claim: 'family_name' },
  { claim: 'preferred_username' },
  { claim: 'tid' },
]);

/** Whether the config names a multi-tenant endpoint. */
function isMultiTenant(tenant: string): boolean {
  return (MICROSOFT_MULTI_TENANT_ENDPOINTS as readonly string[]).includes(tenant);
}

/**
 * A fresh method of the plugin: its own discovery documents, key sets and
 * results. The package exports one as `authMethod`.
 *
 * @experimental
 */
export function createMicrosoftMethod() {
  return createUpstreamOidcPresetMethod({
    id: MICROSOFT_PLUGIN_ID,
    type: MICROSOFT_PLUGIN_TYPE,
    display: { name: 'Microsoft' },
    origins: MICROSOFT_ORIGINS,
    configSchema: microsoftConfigSchema,
    upstreamConfig: (config: MicrosoftConfig) => ({
      issuer: microsoftIssuer(config.tenant),
      ...(isMultiTenant(config.tenant)
        ? { tenantIssuer: { template: MICROSOFT_ISSUER_TEMPLATE, tenantClaim: 'tid' } }
        : {}),
      clientId: config.clientId,
      clientAuthentication: { method: 'client_secret_post', clientSecret: config.clientSecret },
      scopes: [...MICROSOFT_SCOPES],
      idTokenSigningAlgorithms: ['RS256'],
    }),
    attributes: MICROSOFT_ATTRIBUTES,
  });
}

/**
 * The redirect URI to register for the app registration, for a realm served
 * at `realmOrigin`: `<realm origin>/upstream/microsoft/callback`.
 *
 * @throws TypeError when `realmOrigin` is not a bare origin
 */
export function microsoftRedirectUri(realmOrigin: string): string {
  return upstreamOidcRedirectUri(realmOrigin, MICROSOFT_PLUGIN_TYPE);
}

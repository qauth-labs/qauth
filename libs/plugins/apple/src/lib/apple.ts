import {
  createUpstreamOidcPresetMethod,
  MAX_UPSTREAM_CLIENT_ID_LENGTH,
  type UpstreamClaimAttribute,
  upstreamOidcRedirectUri,
} from '@qauth-labs/server-upstream-oidc';
import { z } from 'zod';

/**
 * The Sign in with Apple plugin (#671): a preset on the generic upstream
 * OpenID Connect client for Apple's provider, `https://appleid.apple.com`.
 *
 * What Apple does differently, and what the plugin does about it:
 *
 * - **The client secret is a JWT**, signed with a key registered at Apple.
 *   The plugin holds no key: the signer role signs it, for each token
 *   request, with the realm's `upstream_client_assertion` key for the
 *   plugin's type (ADR-019 Decision 9), ES256, valid 60 seconds. Its `iss`
 *   is the developer team's Team ID and its `sub` the Services ID, both from
 *   the signer's configuration of the provider, and its `aud` Apple's issuer.
 * - **The response arrives as `form_post`**, a cross-site POST, which the
 *   callback bounces to its GET route so the browser brings the flow cookie.
 * - **The person's name arrives once**, in the `user` member of the first
 *   authorization's response, never in the ID token. The bounce carries only
 *   the first and last name on, and they become the new account's
 *   `given_name` and `family_name`, unverified. A later sign-in, which
 *   carries no name, never changes them: the sign-in flow stores a
 *   provider's attributes when it creates the account.
 * - **A private relay address** (`is_private_email`, or an address at
 *   `privaterelay.appleid.com`) forwards mail only from senders the
 *   developer team registered with Apple. Unless the realm's config says it
 *   did (`privateRelayReceivesMail`), the address is kept as the
 *   `private_relay_email` attribute in place of `email`, so it is never the
 *   address QAuth mails.
 *
 * EXPERIMENTAL, like the AuthMethod contract it implements.
 *
 * @experimental
 */

/** The plugin's AuthMethod id: its name in the admin API. */
export const APPLE_PLUGIN_ID = 'apple';

/** The plugin's AuthMethod type: its callback is `/upstream/apple/callback`. */
export const APPLE_PLUGIN_TYPE = 'apple';

/** Apple's issuer identifier: the ID tokens' `iss` and the client secret's `aud`. */
export const APPLE_ISSUER = 'https://appleid.apple.com';

/** The origins Apple's provider answers on: all its endpoints are on its issuer's. */
export const APPLE_ORIGINS: readonly string[] = Object.freeze([APPLE_ISSUER]);

/** The scopes the plugin asks for: Apple's `name` and `email`. */
export const APPLE_SCOPES: readonly string[] = Object.freeze(['openid', 'name', 'email']);

/** The domain of Apple's private relay addresses. */
export const APPLE_PRIVATE_RELAY_DOMAIN = 'privaterelay.appleid.com';

/** The longest first or last name the plugin keeps, in characters. */
export const MAX_APPLE_NAME_LENGTH = 256;

/** The plugin's config for one realm. */
export const appleConfigSchema = z.strictObject({
  /**
   * The Services ID registered at Apple, such as `com.example.signin`: the
   * `client_id` of every request and the ID tokens' audience.
   */
  clientId: z.string().min(1).max(MAX_UPSTREAM_CLIENT_ID_LENGTH),
  /**
   * Whether the developer team registered this realm's mail domains with
   * Apple's private email relay service, so a private relay address receives
   * QAuth's mail: then it is kept as `email`. Off by default.
   */
  privateRelayReceivesMail: z.boolean().default(false),
});

/** The plugin's config, parsed. */
export type AppleConfig = z.output<typeof appleConfigSchema>;

/** Whether Apple's `true` is in `value`: it sends some flags as the string `"true"`. */
function appleTrue(value: unknown): boolean {
  return value === true || value === 'true';
}

/**
 * The attributes a Sign in with Apple sign-in maps to. `email` is verified
 * only when `email_verified` is `true` (or Apple's `"true"`). A private
 * relay address the realm does not take as mail, the first and last name
 * from the `user` member, are kept unverified.
 */
export const APPLE_ATTRIBUTES: readonly UpstreamClaimAttribute[] = Object.freeze([
  {
    claim: 'email',
    verified: (claims) =>
      Object.hasOwn(claims, 'email_verified') && appleTrue(claims['email_verified']),
  },
  { claim: 'private_relay_email' },
  { claim: 'given_name' },
  { claim: 'family_name' },
]);

/** A name part as the plugin keeps it: a non-blank string, trimmed, of plain text. */
function namePart(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length > MAX_APPLE_NAME_LENGTH) return undefined;
  // eslint-disable-next-line no-control-regex -- matching control characters is the point
  if (/[\u0000-\u001f\u007f-\u009f]/.test(trimmed)) return undefined;
  return trimmed;
}

/** The name Apple's `user` member gives, or `undefined` for one with no name part. */
export function appleUserName(
  value: string
): { readonly firstName?: string; readonly lastName?: string } | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    return undefined;
  }
  const name =
    typeof parsed === 'object' && parsed !== null && Object.hasOwn(parsed, 'name')
      ? (parsed as { name: unknown }).name
      : undefined;
  if (typeof name !== 'object' || name === null) return undefined;
  const parts = name as Record<string, unknown>;
  const firstName = namePart(Object.hasOwn(parts, 'firstName') ? parts['firstName'] : undefined);
  const lastName = namePart(Object.hasOwn(parts, 'lastName') ? parts['lastName'] : undefined);
  if (firstName === undefined && lastName === undefined) return undefined;
  return {
    ...(firstName === undefined ? {} : { firstName }),
    ...(lastName === undefined ? {} : { lastName }),
  };
}

/**
 * The `user` member as the bounce carries it on: only the name, so the
 * address Apple repeats there never rides in a URL (the ID token's is the
 * one the plugin reads), or nothing when it holds no name.
 */
function carriedUser(value: string): string | undefined {
  const name = appleUserName(value);
  return name === undefined ? undefined : JSON.stringify({ name });
}

/** Whether the ID token's address is one of Apple's private relay addresses. */
export function isApplePrivateRelay(claims: Readonly<Record<string, unknown>>): boolean {
  const email = Object.hasOwn(claims, 'email') ? claims['email'] : undefined;
  return (
    (Object.hasOwn(claims, 'is_private_email') && appleTrue(claims['is_private_email'])) ||
    (typeof email === 'string' && email.toLowerCase().endsWith(`@${APPLE_PRIVATE_RELAY_DOMAIN}`))
  );
}

/**
 * A fresh method of the plugin: its own discovery documents, key sets and
 * results. The package exports one as `authMethod`.
 *
 * @experimental
 */
export function createAppleMethod() {
  return createUpstreamOidcPresetMethod({
    id: APPLE_PLUGIN_ID,
    type: APPLE_PLUGIN_TYPE,
    display: { name: 'Apple' },
    origins: APPLE_ORIGINS,
    configSchema: appleConfigSchema,
    upstreamConfig: (config: AppleConfig) => ({
      issuer: APPLE_ISSUER,
      clientId: config.clientId,
      clientAuthentication: { method: 'signed_client_secret', signingAlgorithm: 'ES256' },
      scopes: [...APPLE_SCOPES],
      // Apple asks for form_post whenever the scopes name `name` or `email`.
      responseMode: 'form_post',
      idTokenSigningAlgorithms: ['RS256'],
    }),
    responseMembers: { user: carriedUser },
    identityClaims: ({ claims, response, config }) => {
      const extra: Record<string, unknown> = {};
      const user = Object.hasOwn(response, 'user') ? response['user'] : undefined;
      const name = user === undefined ? undefined : appleUserName(user);
      // The ID token's own, should it ever carry them, win.
      if (name?.firstName !== undefined && !Object.hasOwn(claims, 'given_name')) {
        extra['given_name'] = name.firstName;
      }
      if (name?.lastName !== undefined && !Object.hasOwn(claims, 'family_name')) {
        extra['family_name'] = name.lastName;
      }
      if (!config.privateRelayReceivesMail && isApplePrivateRelay(claims)) {
        extra['private_relay_email'] = claims['email'];
        extra['email'] = undefined;
        extra['email_verified'] = undefined;
      }
      return extra;
    },
    attributes: APPLE_ATTRIBUTES,
  });
}

/**
 * The return URL to register for the Services ID at Apple, for a realm
 * served at `realmOrigin`: `<realm origin>/upstream/apple/callback`.
 *
 * @throws TypeError when `realmOrigin` is not a bare origin
 */
export function appleRedirectUri(realmOrigin: string): string {
  return upstreamOidcRedirectUri(realmOrigin, APPLE_PLUGIN_TYPE);
}

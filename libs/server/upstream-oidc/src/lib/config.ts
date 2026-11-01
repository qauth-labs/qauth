import { z } from 'zod';

/**
 * The config of one upstream OpenID Connect provider in one realm (#601):
 * what an admin sets, parsed by the method's `configSchema`.
 *
 * Two ways to name the provider's endpoints:
 *
 * - **Discovery** (no `endpoints`): the client reads
 *   `<issuer>/.well-known/openid-configuration` (OpenID Connect Discovery 1.0
 *   §4). The document's `issuer` must equal the configured one, and every URL
 *   it names is a `remote_document` destination: the deployment's egress
 *   allowlist never applies to it, so a discovered endpoint never reaches a
 *   private or loopback address (ADR-019 Decision 8).
 * - **By hand** (`endpoints`): for a provider on a private address. The
 *   endpoints are `admin` destinations, which an allowlist entry that names
 *   the realm may open. No discovery document is read.
 */

/** The longest URL the config or a discovery document may name. */
export const MAX_UPSTREAM_URL_LENGTH = 2048;

/** The longest client id. */
export const MAX_UPSTREAM_CLIENT_ID_LENGTH = 255;

/** The longest client secret. */
export const MAX_UPSTREAM_CLIENT_SECRET_LENGTH = 1024;

/**
 * How QAuth authenticates to the provider's token endpoint (OpenID Connect
 * Core 1.0 §9).
 *
 * - `client_secret_basic`: HTTP Basic with the client id and secret, each
 *   form-urlencoded first (RFC 6749 §2.3.1);
 * - `client_secret_post`: the client id and secret in the form body;
 * - `private_key_jwt`: a client assertion (RFC 7523) the signer role signs
 *   with the realm's `upstream_client_assertion` key for this provider
 *   (ADR-019 Decision 9). The library never holds that key.
 *
 * `none` is not offered: QAuth is a confidential client.
 */
export const UPSTREAM_CLIENT_AUTHENTICATION_METHODS = Object.freeze([
  'client_secret_basic',
  'client_secret_post',
  'private_key_jwt',
] as const);

export type UpstreamClientAuthenticationMethod =
  (typeof UPSTREAM_CLIENT_AUTHENTICATION_METHODS)[number];

/**
 * The algorithms an ID token may be signed with: asymmetric JWS algorithms
 * only. `none` and every MAC algorithm (`HS*`) are absent by construction: a
 * MAC would be checked with the client secret, which the provider also holds,
 * so it proves nothing about who signed.
 */
export const UPSTREAM_ID_TOKEN_ALGORITHMS = Object.freeze([
  'RS256',
  'RS384',
  'RS512',
  'PS256',
  'PS384',
  'PS512',
  'ES256',
  'ES384',
  'ES512',
  'EdDSA',
] as const);

export type UpstreamIdTokenAlgorithm = (typeof UPSTREAM_ID_TOKEN_ALGORITHMS)[number];

/** The ID token algorithms a provider's config allows unless it names its own. */
export const DEFAULT_UPSTREAM_ID_TOKEN_ALGORITHMS: readonly UpstreamIdTokenAlgorithm[] =
  Object.freeze(['RS256', 'PS256', 'ES256', 'EdDSA']);

/** The algorithms the signer signs a client assertion with. */
export const UPSTREAM_ASSERTION_ALGORITHMS = Object.freeze(['RS256', 'ES256', 'EdDSA'] as const);

/** The scopes an authorization request asks for unless the config names its own. */
export const DEFAULT_UPSTREAM_SCOPES: readonly string[] = Object.freeze([
  'openid',
  'email',
  'profile',
]);

/** A scope token (RFC 6749 §3.3): printable ASCII but space, `"` and `\`. */
const SCOPE_TOKEN = /^[\x21\x23-\x5b\x5d-\x7e]{1,128}$/;

/**
 * Why `value` cannot be an endpoint URL, or `undefined` when it can: an
 * absolute `https` URL with a host, no credentials and no fragment, at most
 * {@link MAX_UPSTREAM_URL_LENGTH} characters. A query is allowed (RFC 6749
 * §3.1 and §3.2).
 */
export function upstreamUrlProblem(value: unknown): string | undefined {
  if (typeof value !== 'string') return 'is not a string';
  if (value.length > MAX_UPSTREAM_URL_LENGTH) {
    return `is longer than ${MAX_UPSTREAM_URL_LENGTH} characters`;
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return 'is not an absolute URL';
  }
  if (url.protocol !== 'https:') return 'is not https';
  if (url.hostname === '') return 'has no host';
  if (url.username !== '' || url.password !== '') return 'carries credentials';
  if (value.includes('#')) return 'has a fragment';
  return undefined;
}

/**
 * Why `value` cannot be an issuer identifier, or `undefined` when it can: an
 * endpoint URL ({@link upstreamUrlProblem}) with no query either (OpenID
 * Connect Discovery 1.0 §2, RFC 8414 §2).
 */
export function upstreamIssuerProblem(value: unknown): string | undefined {
  const problem = upstreamUrlProblem(value);
  if (problem !== undefined) return problem;
  if ((value as string).includes('?')) return 'has a query';
  return undefined;
}

const endpointUrl = z.string().superRefine((value, context) => {
  const problem = upstreamUrlProblem(value);
  if (problem !== undefined) context.addIssue({ code: 'custom', message: `the URL ${problem}` });
});

const issuerUrl = z.string().superRefine((value, context) => {
  const problem = upstreamIssuerProblem(value);
  if (problem !== undefined) context.addIssue({ code: 'custom', message: `the issuer ${problem}` });
});

/** A client secret: write-only, so an admin API never returns it. */
const clientSecret = z
  .string()
  .min(1)
  .max(MAX_UPSTREAM_CLIENT_SECRET_LENGTH)
  .meta({ writeOnly: true });

/** How the client authenticates at the token endpoint. */
export const upstreamClientAuthenticationSchema = z.discriminatedUnion('method', [
  z.strictObject({ method: z.literal('client_secret_basic'), clientSecret }),
  z.strictObject({ method: z.literal('client_secret_post'), clientSecret }),
  z.strictObject({
    method: z.literal('private_key_jwt'),
    /** The algorithm of the key registered with the provider. */
    signingAlgorithm: z.enum(UPSTREAM_ASSERTION_ALGORITHMS).default('RS256'),
  }),
]);

/** The provider's endpoints, set by hand: no discovery document is read. */
export const upstreamEndpointsSchema = z.strictObject({
  authorization: endpointUrl,
  token: endpointUrl,
  jwks: endpointUrl,
  userinfo: endpointUrl.optional(),
  /**
   * Whether the provider sends `iss` in its authorization response
   * (RFC 9207), as `authorization_response_iss_parameter_supported` says in
   * a discovery document. When `true`, a response without it is refused.
   */
  issParameterSupported: z.boolean().default(false),
});

/** The config's members, each checked on its own. */
const upstreamOidcConfigMembers = z.strictObject({
  /** The provider's issuer identifier, compared byte for byte. */
  issuer: issuerUrl,
  /** The client id QAuth is registered under at the provider. */
  clientId: z.string().min(1).max(MAX_UPSTREAM_CLIENT_ID_LENGTH),
  clientAuthentication: upstreamClientAuthenticationSchema,
  /** The scopes to ask for; `openid` among them. */
  scopes: z
    .array(z.string().regex(SCOPE_TOKEN))
    .min(1)
    .max(32)
    .default([...DEFAULT_UPSTREAM_SCOPES])
    .refine((scopes) => scopes.includes('openid'), { message: 'scopes must include openid' })
    .refine((scopes) => new Set(scopes).size === scopes.length, {
      message: 'scopes must not repeat',
    }),
  /** The endpoints by hand; without them, discovery. */
  endpoints: upstreamEndpointsSchema.optional(),
  /**
   * How the provider returns the authorization response: `query` (a `GET` to
   * the callback) or `form_post` (a cross-site `POST`, which the method
   * bounces to the `GET` callback so the browser brings the flow cookie).
   */
  responseMode: z.enum(['query', 'form_post']).default('query'),
  /** The algorithms an ID token may be signed with. Never `none` or `HS*`. */
  idTokenSigningAlgorithms: z
    .array(z.enum(UPSTREAM_ID_TOKEN_ALGORITHMS))
    .min(1)
    .max(UPSTREAM_ID_TOKEN_ALGORITHMS.length)
    .default([...DEFAULT_UPSTREAM_ID_TOKEN_ALGORITHMS])
    .refine((algorithms) => new Set(algorithms).size === algorithms.length, {
      message: 'algorithms must not repeat',
    }),
  /** Whether to read the userinfo endpoint after the code exchange. */
  fetchUserinfo: z.boolean().default(false),
});

/**
 * The config schema of the generic upstream OIDC client. A config that could
 * never sign anyone in is refused here, so the registration check reports it
 * as `invalid_config` rather than each `start()` failing: userinfo reads
 * with endpoints set by hand that name no userinfo endpoint.
 */
export const upstreamOidcConfigSchema = upstreamOidcConfigMembers.superRefine((config, context) => {
  if (
    config.fetchUserinfo &&
    config.endpoints !== undefined &&
    config.endpoints.userinfo === undefined
  ) {
    context.addIssue({
      code: 'custom',
      path: ['endpoints', 'userinfo'],
      message: 'fetchUserinfo needs a userinfo endpoint among the endpoints set by hand',
    });
  }
});

/** A provider's config as the method reads it, after parsing. */
export type UpstreamOidcConfig = z.output<typeof upstreamOidcConfigSchema>;

/** A provider's config as an admin writes it, before parsing. */
export type UpstreamOidcConfigInput = z.input<typeof upstreamOidcConfigSchema>;

/**
 * The discovery document URL of an issuer: the issuer with a terminating `/`
 * removed, then `/.well-known/openid-configuration` (OpenID Connect
 * Discovery 1.0 §4).
 */
export function discoveryUrl(issuer: string): string {
  return `${issuer.endsWith('/') ? issuer.slice(0, -1) : issuer}/.well-known/openid-configuration`;
}

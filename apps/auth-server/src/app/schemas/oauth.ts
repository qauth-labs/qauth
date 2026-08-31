import { z } from 'zod';

import { OAUTH_OPAQUE_PARAM_MAX_LENGTH, OAUTH_SCOPE_PARAM_MAX_LENGTH } from '../constants';

/**
 * RFC 8707 §2: `resource` is an absolute URI without fragment, identifying
 * the protected resource the access token is intended for. Clients MAY
 * include multiple values (one per resource). We accept either a single
 * string or an array; the route normalizes to an array.
 *
 * Coerced to string[] so downstream code (authorize/token routes, DB
 * repositories, `resolveAudience`) can treat all cases uniformly.
 */
const resourceEntrySchema = z
  .url()
  .max(2048)
  .refine((v) => !v.includes('#'), { message: 'resource must not contain a fragment' });

export const resourceParamSchema = z
  .union([resourceEntrySchema, z.array(resourceEntrySchema).max(10)])
  .optional()
  .transform((v) => (v === undefined ? undefined : Array.isArray(v) ? v : [v]));

/* -------------------------------------------------------------------------- */
/*        Grant-type, token-type and client-assertion URNs (one place)        */
/* -------------------------------------------------------------------------- */

/**
 * RFC 8693 OAuth 2.0 Token Exchange grant + token-type URIs.
 *
 * QAuth's agent-native on-behalf-of delegation (ADR-007 §2): an agent client
 * exchanges a user's `subject_token` (and optionally an `actor_token`) for a
 * delegated access token whose `sub` is the user and whose `act` claim
 * identifies the agent. This is an MCP auth *extension* (ext-auth), not core.
 */
export const TOKEN_EXCHANGE_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:token-exchange';
export const TOKEN_TYPE_ACCESS_TOKEN = 'urn:ietf:params:oauth:token-type:access_token';
export const TOKEN_TYPE_REFRESH_TOKEN = 'urn:ietf:params:oauth:token-type:refresh_token';
export const TOKEN_TYPE_JWT = 'urn:ietf:params:oauth:token-type:jwt';

/**
 * RFC 8693 §3 ID Token token-type URN. Note the underscore (`id_token`), which
 * differs from the hyphenated `id-jag` below — they are distinct registry
 * entries and neither spelling is interchangeable.
 *
 * Used as a `subject_token_type` on the ID-JAG minting path: an enterprise
 * client presents the OIDC ID token QAuth already issued it as proof of the
 * end-user's authenticated identity, and exchanges it for an ID-JAG targeted
 * at a third-party MCP server's authorization server.
 */
export const TOKEN_TYPE_ID_TOKEN = 'urn:ietf:params:oauth:token-type:id_token';

/**
 * Identity Assertion Authorization Grant (ID-JAG) token-type URN — the
 * Enterprise-Managed Agents (EMA) cross-domain credential (ADR-011).
 *
 * An ID-JAG is NOT a bearer access token. It is a short-lived, single-use,
 * audience-restricted assertion that says "this enterprise IdP asserts that
 * user U authorized client C to obtain access to resource R". The holder
 * presents it to R's OWN authorization server, which exchanges it for an
 * access token. Consequently an ID-JAG response MUST report
 * `token_type: "N_A"` (RFC 8693 §2.2.1) — see {@link idJagTokenResponseSchema}.
 */
export const TOKEN_TYPE_ID_JAG = 'urn:ietf:params:oauth:token-type:id-jag';

/**
 * RFC 7523 §2.1 JWT assertion authorization grant. QAuth's CONSUME side of
 * ID-JAG (ADR-011): a client presents an ID-JAG minted by a trusted enterprise
 * IdP in the `assertion` parameter and receives an access token restricted to
 * the audience named by the assertion's `resource` claim.
 *
 * FAIL-CLOSED: the grant is rejected with `unsupported_grant_type` unless
 * `ID_JAG_ENABLED=true`, and every assertion is rejected unless its `iss` is
 * byte-equal to an entry in `ID_JAG_TRUSTED_ISSUERS` (empty by default).
 */
export const JWT_BEARER_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:jwt-bearer';

/**
 * RFC 7523 §2.2 client-assertion type URN — the only value QAuth accepts for
 * `client_assertion_type`. It selects `private_key_jwt` client authentication
 * (#384): the client proves possession of the private key matching a JWK in
 * its registered `jwks` / `jwks_uri`.
 *
 * NOTE the URN is `client-assertion-type`, NOT the `grant-type` URN above.
 * They differ by one path segment and are frequently confused; a request that
 * swaps them MUST be rejected, never leniently accepted.
 */
export const CLIENT_ASSERTION_TYPE_JWT_BEARER =
  'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

/**
 * Authorization-grant profile URN advertised in discovery when ID-JAG is
 * enabled (`authorization_grant_profiles_supported`).
 */
export const ID_JAG_GRANT_PROFILE = 'urn:ietf:params:oauth:grant-profile:id-jag';

/* -------------------------------------------------------------------------- */
/*                   Assertion bounds and accepted algorithms                 */
/* -------------------------------------------------------------------------- */

/**
 * Maximum length of any assertion JWT accepted at the token endpoint — both
 * the RFC 7523 §2.1 `assertion` (an ID-JAG) and the §2.2 `client_assertion`
 * (private_key_jwt). Matches the existing `subject_token` / `actor_token`
 * ceiling so every JWT-shaped token-endpoint parameter is bounded identically.
 *
 * These are UNAUTHENTICATED inputs — the assertion is what establishes the
 * caller's identity, so the bound is applied before any signature work and
 * caps the cost of a forged-signature flood.
 */
export const ASSERTION_MAX_LENGTH = 8192;

/** Maximum length of an assertion *type* URN parameter. */
export const ASSERTION_TYPE_MAX_LENGTH = 256;

/**
 * The JWS algorithms QAuth will verify an assertion with — RFC 7523 client
 * assertions (`private_key_jwt`) and ID-JAG assertions from a trusted issuer
 * alike.
 *
 * THIS IS THE SINGLE SOURCE OF TRUTH. `discovery.ts` publishes it as
 * `token_endpoint_auth_signing_alg_values_supported`, and the verifiers MUST
 * pass this exact list to `jose`'s `algorithms` option. Advertising an
 * algorithm the verifier rejects — or accepting one that is not advertised —
 * is a conformance failure, so neither side may hard-code its own copy.
 *
 * ASYMMETRIC ONLY, and `alg: none` is impossible by construction. `HS*` is
 * deliberately ABSENT: an HMAC assertion is verified with the shared client
 * secret (that is `client_secret_jwt`, a different auth method QAuth does not
 * implement), and allowing it here would let a client that only knows a secret
 * authenticate through the private-key path.
 */
export const ASSERTION_SIGNING_ALG_VALUES_SUPPORTED = [
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
] as const;

export type AssertionSigningAlg = (typeof ASSERTION_SIGNING_ALG_VALUES_SUPPORTED)[number];

/* -------------------------------------------------------------------------- */
/*                    Shared client-authentication parameters                 */
/* -------------------------------------------------------------------------- */

/**
 * The client-authentication parameters every token-endpoint grant accepts,
 * spread into each grant body so the surface can never drift between grants.
 *
 * All four are optional at the SCHEMA level and the actual requirement is
 * decided by the handler, which knows the client's registered
 * `token_endpoint_auth_method`. That split is deliberate: an authentication
 * failure must surface as RFC 6749 §5.2 `invalid_client` (401 with
 * `WWW-Authenticate`), never as a generic Zod 400.
 *
 * - `client_id` / `client_secret` — `client_secret_post`; `client_secret_basic`
 *   supplies the same pair via the `Authorization` header instead.
 * - `client_assertion_type` / `client_assertion` — RFC 7523 §2.2
 *   `private_key_jwt` (#384). Per RFC 7521 §4.2 `client_id` MAY be omitted when
 *   an assertion is present, since the assertion's `sub` names the client.
 *
 * SECURITY (for the #384 implementer): presenting MORE than one authentication
 * method in a single request MUST be rejected (`invalid_client`), per RFC 6749
 * §2.3 — never "try each until one passes". A client registered for
 * `private_key_jwt` MUST NOT be allowed to fall back to a secret, and a client
 * registered for a secret MUST NOT be allowed to authenticate with an
 * assertion. Adding these fields must not make any EXISTING client's
 * authentication easier to satisfy.
 */
const clientAuthenticationFields = {
  client_id: z.string().min(1).optional(),
  client_secret: z.string().min(1).optional(),
  client_assertion_type: z.string().min(1).max(ASSERTION_TYPE_MAX_LENGTH).optional(),
  client_assertion: z.string().min(1).max(ASSERTION_MAX_LENGTH).optional(),
} as const;

/**
 * OAuth 2.1 authorize query parameters (GET /oauth/authorize).
 * RFC 6749 4.1.1, RFC 7636 PKCE, RFC 8707 Resource Indicators.
 */
export const authorizeQuerySchema = z.object({
  response_type: z.literal('code'),
  client_id: z.string().min(1),
  redirect_uri: z.url(),
  code_challenge: z
    .string()
    .min(43)
    .max(128)
    .regex(/^[A-Za-z0-9._~-]+$/),
  code_challenge_method: z.literal('S256'),
  // `state` / `nonce` are opaque, client-owned, round-tripped params. Bound
  // centrally (OAUTH_OPAQUE_PARAM_MAX_LENGTH) so this schema and its
  // /ui/consent form mirror can never drift apart again.
  state: z.string().max(OAUTH_OPAQUE_PARAM_MAX_LENGTH).optional(),
  // Bounded for the same reason (#316 follow-up): every parameter that
  // round-trips through the login bounce is written to the pending-authorization
  // stash BEFORE the user authenticates, so an unbounded one is an
  // unauthenticated Redis write primitive. See OAUTH_SCOPE_PARAM_MAX_LENGTH.
  scope: z.string().max(OAUTH_SCOPE_PARAM_MAX_LENGTH).optional(),
  nonce: z.string().max(OAUTH_OPAQUE_PARAM_MAX_LENGTH).optional(),
  // OIDC Core §3.1.2.1 step-up parameters (ADR-007 §2, #185). `prompt` forces
  // a fresh authentication (`login`) or re-consent (`consent`); `max_age`
  // bounds, in seconds, how old the existing authentication may be before a
  // re-authentication is required (`0` ⇒ always re-authenticate). Only the
  // values QAuth acts on are accepted; anything else is rejected at the edge.
  prompt: z.enum(['none', 'login', 'consent']).optional(),
  max_age: z.coerce.number().int().min(0).max(315360000).optional(),
  resource: resourceParamSchema,
});

export type AuthorizeQuery = z.infer<typeof authorizeQuerySchema>;

/**
 * OAuth 2.1 token exchange body (POST /oauth/token, authorization_code grant).
 * RFC 6749 4.1.3, RFC 7636 PKCE. client_secret_post (MVP).
 *
 * Client authentication comes from {@link clientAuthenticationFields}: the
 * `client_id` / `client_secret` pair (also expressible as
 * `client_secret_basic` via the HTTP `Authorization: Basic ...` header) or an
 * RFC 7523 §2.2 `client_assertion`. The route handler enforces that exactly
 * one method is used and that it matches the client's registered method.
 */
export const tokenExchangeAuthCodeBodySchema = z.object({
  grant_type: z.literal('authorization_code'),
  code: z.string().min(1),
  redirect_uri: z.string().min(1),
  code_verifier: z
    .string()
    .min(43)
    .max(128)
    .regex(/^[A-Za-z0-9._~-]+$/),
  // RFC 8707 §2: when present, MUST match the resource set bound to the
  // authorization code. Enforced in the handler, not the schema.
  resource: resourceParamSchema,
  ...clientAuthenticationFields,
});

/**
 * OAuth 2.1 client credentials grant body (POST /oauth/token).
 * RFC 6749 4.4. Used for machine-to-machine authentication.
 * `scope` is optional and space-separated.
 */
export const tokenExchangeClientCredsBodySchema = z.object({
  grant_type: z.literal('client_credentials'),
  scope: z.string().optional(),
  // RFC 8707 §2: machine clients request a resource at mint time; handler
  // uses it as the token `aud` (overrides client.audience when present).
  resource: resourceParamSchema,
  ...clientAuthenticationFields,
});

/**
 * OAuth 2.1 refresh_token grant body (POST /oauth/token).
 * RFC 6749 §6. Supports rotation and optional scope down-scoping.
 *
 * `client_id` / `client_secret` remain optional here — confidential
 * clients authenticate via `client_secret_basic` or `client_secret_post`;
 * public clients (PKCE, `token_endpoint_auth_method: none`) present only
 * their `client_id` and rely on refresh-token ownership for binding.
 *
 * The refresh-token format is the hex pair produced by
 * `jwtUtils.generateRefreshToken()` (64-char lowercase hex). Strict
 * validation keeps malformed tokens out of DB lookups.
 */
export const tokenExchangeRefreshBodySchema = z.object({
  grant_type: z.literal('refresh_token'),
  refresh_token: z
    .string()
    .length(64, 'refresh_token must be exactly 64 characters')
    .regex(/^[0-9a-fA-F]{64}$/, 'refresh_token must be a valid hex string'),
  scope: z.string().optional(),
  // RFC 8707 §2: on refresh, resource MUST be a subset of the one bound
  // to the original authorization code. Enforced in the handler.
  resource: resourceParamSchema,
  ...clientAuthenticationFields,
});

/**
 * OAuth 2.0 Token Exchange body (POST /oauth/token, RFC 8693 §2.1).
 *
 * - `subject_token` / `subject_token_type` (REQUIRED): the token representing
 *   the party on whose behalf the request is made (the end-user).
 * - `actor_token` / `actor_token_type` (OPTIONAL): the token representing the
 *   acting party. `actor_token_type` is REQUIRED when `actor_token` is present
 *   (enforced in the handler so we can return a structured OAuth error).
 * - `scope` / `resource` / `audience` (OPTIONAL): requested down-scoping /
 *   audience targeting. Scope and audience are preserved or NARROWED, never
 *   widened (handler-enforced).
 * - `requested_token_type` (OPTIONAL): the desired issued-token type. Two
 *   values are meaningful: `...:token-type:access_token` (the delegated
 *   access token, the default when omitted) and — only when `ID_JAG_ENABLED`
 *   — {@link TOKEN_TYPE_ID_JAG}, which asks QAuth to MINT an ID-JAG for the
 *   third-party resource AS named by `audience` (ADR-011).
 *
 * Token-type *values* are validated in the handler (not the schema) so an
 * unsupported type surfaces as RFC 6749 §5.2 `invalid_request` rather than a
 * generic Zod validation error, per RFC 8693 §2.2.2. The existing
 * access_token-only gate in `token.ts` therefore still stands and must be
 * relaxed DELIBERATELY, one URN at a time, by the ID-JAG implementation —
 * this schema does not and must not do it implicitly.
 *
 * Client authentication comes from {@link clientAuthenticationFields}. The
 * handler authenticates the client and gates the grant on the agent
 * classification (default-deny).
 */
export const tokenExchangeTokenExchangeBodySchema = z.object({
  grant_type: z.literal(TOKEN_EXCHANGE_GRANT_TYPE),
  subject_token: z.string().min(1).max(ASSERTION_MAX_LENGTH),
  subject_token_type: z.string().min(1).max(ASSERTION_TYPE_MAX_LENGTH),
  actor_token: z.string().min(1).max(ASSERTION_MAX_LENGTH).optional(),
  actor_token_type: z.string().min(1).max(ASSERTION_TYPE_MAX_LENGTH).optional(),
  requested_token_type: z.string().min(1).max(ASSERTION_TYPE_MAX_LENGTH).optional(),
  scope: z.string().max(OAUTH_SCOPE_PARAM_MAX_LENGTH).optional(),
  // RFC 8693 §2.1 `audience` — logical target name(s). Accepted as string or
  // array; the handler treats it together with `resource` for aud narrowing.
  //
  // ID-JAG MINT (ADR-011): on a `requested_token_type=...:id-jag` request this
  // carries the ISSUER IDENTIFIER of the target resource's authorization
  // server, and becomes the minted assertion's `aud`. Exactly one value is
  // meaningful there — an assertion cannot be audience-restricted to two
  // authorization servers at once — so the handler MUST reject a multi-valued
  // `audience` on that path rather than silently picking the first.
  audience: z
    .union([z.string().min(1).max(2048), z.array(z.string().min(1).max(2048)).max(10)])
    .optional()
    .transform((v) => (v === undefined ? undefined : Array.isArray(v) ? v : [v])),
  // RFC 8707 §2: resource indicators; MUST be a subset of the subject token's
  // audience. Enforced in the handler. On the ID-JAG mint path this is the MCP
  // server the assertion authorizes access to (the assertion's `resource`).
  resource: resourceParamSchema,
  ...clientAuthenticationFields,
});

/**
 * RFC 7523 §2.1 JWT-assertion grant body (POST /oauth/token) — QAuth's CONSUME
 * side of ID-JAG (ADR-011).
 *
 * The client presents an ID-JAG minted by a trusted enterprise IdP and gets
 * back an access token restricted to the MCP server the assertion names.
 *
 * - `assertion` (REQUIRED): the ID-JAG, a compact-serialized JWS.
 * - `scope` (OPTIONAL): requested down-scoping. The assertion's own `scope`
 *   claim is the CEILING — the granted scope is the intersection, never a
 *   union, and never wider than what the enterprise IdP authorized.
 * - `resource` (OPTIONAL, RFC 8707 §2): when present it MUST be consistent
 *   with the assertion's `resource` claim. The CLAIM is authoritative; this
 *   parameter can only narrow, and a mismatch is a rejection, not a merge.
 *
 * Everything that decides trust lives in the assertion's signature and the
 * operator allowlist — never in these parameters. In particular there is no
 * issuer/JWKS parameter here BY DESIGN: keys are resolved by OIDC discovery
 * against an issuer already present in `ID_JAG_TRUSTED_ISSUERS`.
 */
export const tokenExchangeJwtBearerBodySchema = z.object({
  grant_type: z.literal(JWT_BEARER_GRANT_TYPE),
  assertion: z.string().min(1).max(ASSERTION_MAX_LENGTH),
  scope: z.string().max(OAUTH_SCOPE_PARAM_MAX_LENGTH).optional(),
  resource: resourceParamSchema,
  ...clientAuthenticationFields,
});

/**
 * Discriminated union of supported token grant bodies.
 */
export const tokenExchangeBodySchema = z.discriminatedUnion('grant_type', [
  tokenExchangeAuthCodeBodySchema,
  tokenExchangeClientCredsBodySchema,
  tokenExchangeRefreshBodySchema,
  tokenExchangeTokenExchangeBodySchema,
  tokenExchangeJwtBearerBodySchema,
]);

export type TokenExchangeAuthCodeBody = z.infer<typeof tokenExchangeAuthCodeBodySchema>;
export type TokenExchangeClientCredsBody = z.infer<typeof tokenExchangeClientCredsBodySchema>;
export type TokenExchangeRefreshBody = z.infer<typeof tokenExchangeRefreshBodySchema>;
export type TokenExchangeTokenExchangeBody = z.infer<typeof tokenExchangeTokenExchangeBodySchema>;
export type TokenExchangeJwtBearerBody = z.infer<typeof tokenExchangeJwtBearerBodySchema>;
export type TokenExchangeBody = z.infer<typeof tokenExchangeBodySchema>;

/**
 * OAuth token response.
 * RFC 6749 5.1. `refresh_token` and `scope` are optional (client_credentials
 * grants MUST NOT include refresh_token per RFC 6749 4.4.3).
 *
 * `issued_token_type` (RFC 8693 §2.2.1) is REQUIRED in a token-exchange
 * response and absent for the other grants; we always emit
 * `...:access_token` for the delegated token-exchange path.
 *
 * `id_token` (OIDC Core §3.1.3.3) is present only on an authorization_code
 * exchange whose granted scope includes `openid`. It is a signed JWT (EdDSA)
 * asserting the end-user's authentication to the client; absent otherwise.
 */
export const tokenExchangeResponseSchema = z.object({
  access_token: z.string(),
  refresh_token: z.string().optional(),
  expires_in: z.number(),
  token_type: z.literal('Bearer'),
  scope: z.string().optional(),
  issued_token_type: z.string().optional(),
  id_token: z.string().optional(),
});

export type TokenExchangeResponse = z.infer<typeof tokenExchangeResponseSchema>;

/**
 * Response returned when QAuth MINTS an Identity Assertion Authorization Grant
 * (ID-JAG) via RFC 8693 token exchange (ADR-011).
 *
 * Structurally an RFC 8693 §2.2.1 token-exchange response, but with two
 * differences from {@link tokenExchangeResponseSchema} that make it a separate
 * schema rather than a widening of that one:
 *
 *  1. `token_type` is `"N_A"`, not `"Bearer"`. RFC 8693 §2.2.1 requires exactly
 *     this when the issued token is not usable as a bearer access token, and an
 *     ID-JAG is not: it is presented to the target resource's OWN authorization
 *     server to be exchanged, never sent to a protected resource. Emitting
 *     `"Bearer"` here would invite clients to use it as an access token.
 *  2. `issued_token_type` is REQUIRED and pinned to {@link TOKEN_TYPE_ID_JAG},
 *     so a client can never mistake a minted assertion for an access token.
 *
 * There is deliberately NO `refresh_token`: an ID-JAG is a short-lived,
 * single-use hand-off credential (`ID_JAG_ISSUED_LIFETIME`, default 5 min), and
 * a refreshable one would defeat that. `access_token` carries the assertion
 * because RFC 8693 names the field that way regardless of issued token type.
 */
export const idJagTokenResponseSchema = z.object({
  /** The minted ID-JAG (compact JWS). Named `access_token` per RFC 8693 §2.2.1. */
  access_token: z.string(),
  issued_token_type: z.literal(TOKEN_TYPE_ID_JAG),
  token_type: z.literal('N_A'),
  expires_in: z.number(),
  scope: z.string().optional(),
});

export type IdJagTokenResponse = z.infer<typeof idJagTokenResponseSchema>;

/**
 * The full 200 response surface of `POST /oauth/token`.
 *
 * Use THIS as the route's `response: { 200: ... }` schema once ID-JAG minting
 * lands — `tokenExchangeResponseSchema` alone pins `token_type: 'Bearer'` and
 * would strip or reject a valid `N_A` ID-JAG response at serialization time.
 * Order matters: the ID-JAG variant is listed first so a response carrying
 * `token_type: 'N_A'` matches it instead of failing the Bearer literal.
 */
export const tokenEndpointResponseSchema = z.union([
  idJagTokenResponseSchema,
  tokenExchangeResponseSchema,
]);

export type TokenEndpointResponse = z.infer<typeof tokenEndpointResponseSchema>;

/**
 * Token introspection request body (POST /oauth/introspect).
 * RFC 7662 2.1. Uses application/x-www-form-urlencoded in transport.
 *
 * `client_id` / `client_secret` are optional because clients may also
 * authenticate with `client_secret_basic` via the HTTP `Authorization`
 * header. The route handler enforces that at least one auth method is used.
 */
export const introspectRequestSchema = z.object({
  token: z.string().min(1),
  token_type_hint: z.string().max(64).optional(),
  client_id: z.string().min(1).optional(),
  client_secret: z.string().min(1).optional(),
});

export type IntrospectRequest = z.infer<typeof introspectRequestSchema>;

/**
 * Token revocation request body (POST /oauth/revoke).
 * RFC 7009 §2.1. The client authenticates with `client_secret_post` (body) or
 * `client_secret_basic` (Authorization header); the route enforces that at
 * least one auth method is used. `token_type_hint` is advisory only (§2.1):
 * the server still determines the actual token type.
 */
export const revokeRequestSchema = z.object({
  token: z.string().min(1),
  token_type_hint: z.enum(['access_token', 'refresh_token']).optional(),
  client_id: z.string().min(1).optional(),
  client_secret: z.string().min(1).optional(),
});

export type RevokeRequest = z.infer<typeof revokeRequestSchema>;

/**
 * Token introspection response body.
 * RFC 7662 2.2.
 */
export const introspectResponseSchema = z.object({
  active: z.boolean(),
  sub: z.string().optional(),
  client_id: z.string().optional(),
  exp: z.number().optional(),
  iat: z.number().optional(),
  iss: z.string().optional(),
  aud: z.union([z.string(), z.array(z.string())]).optional(),
  scope: z.string().optional(),
  token_type: z.literal('Bearer').optional(),
  /**
   * ADR-005 / #275 — reference delivery of the post-quantum component.
   *
   * When the server issues hybrid (Ed25519 + ML-DSA-65) tokens, the bearer
   * itself stays a small Ed25519 compact JWS and the ~4.4 KB detached ML-DSA-65
   * signature is delivered HERE, in the introspection body (no header/cookie
   * ceiling). A PQC-capable resource server verifies it over the token's JWS
   * signing-input using the `AKP` key published in JWKS.
   *
   * Present only for `active: true` hybrid tokens; omitted entirely on a
   * classical deployment, so existing RFC 7662 consumers are unaffected.
   *
   * SECURITY: `pqc_alg` here is informational. The authoritative algorithm and
   * key id are the `pqc_alg` / `pqc_kid` members of the token's Ed25519-SIGNED
   * protected header (#248 F1/F5) — a verifier MUST negotiate and resolve keys
   * from those, never from this body.
   */
  pqc_signature: z.string().optional(),
  pqc_alg: z.string().optional(),
});

export type IntrospectResponse = z.infer<typeof introspectResponseSchema>;

/**
 * Dynamic Client Registration request body (POST /oauth/register).
 * RFC 7591 §2. Accepts the common subset of client metadata fields; any
 * unknown keys are allowed and echoed back per §3.2.1 (server MAY omit,
 * but we round-trip recognized fields only to keep DB shape bounded).
 *
 * Policy notes:
 *   - `token_endpoint_auth_method=none` marks the client as public
 *     (PKCE required).
 *   - Grant/response type consistency is enforced in the route handler,
 *     not in the schema, so we can surface a structured OAuth error.
 *   - `scope` is space-separated per RFC 7591 §2 / RFC 6749 §3.3.
 *   - RFC 7591 §3.2 requires servers to ignore unrecognized metadata fields,
 *     so this schema uses Zod's default strip behaviour (no `.strict()`).
 *
 * DELIBERATE OMISSIONS — do not "complete" these without an explicit maintainer
 * decision:
 *   - `jwks` / `jwks_uri` and `token_endpoint_auth_method: 'private_key_jwt'`
 *     (#384). A client MUST NOT be able to self-register the keys that
 *     authenticate it, nor hand the AS a URL to dereference, through an
 *     unauthenticated endpoint. `private_key_jwt` is provisioned by an
 *     operator (`db:seed-oauth-clients` manifest / admin), exactly like
 *     `max_agent_mode` and `environment`.
 *   - `urn:ietf:params:oauth:grant-type:jwt-bearer` in `grant_types`
 *     (ADR-011). ID-JAG consumption depends on an operator-configured issuer
 *     allowlist; letting a client add the grant to itself would suggest a
 *     capability it cannot actually reach and muddies the trust boundary.
 * Since Zod strips unknown keys here, a registration request carrying any of
 * them is silently ignored rather than honoured — which is the fail-closed
 * outcome, but callers should not rely on it as the enforcement mechanism.
 *
 * ADMITTED, and why it differs from `jwt-bearer` above (#381):
 * `urn:ietf:params:oauth:grant-type:token-exchange` IS accepted here. Note the
 * asymmetry is deliberate. `jwt-bearer` is excluded because a self-registered
 * client could not reach the capability at all — the issuer allowlist is
 * operator-set, so advertising it to the client would be a lie. Token exchange
 * is the opposite: the capability IS reachable, and reaching it confers nothing
 * the client did not already hold. `handleTokenExchange` requires a
 * cryptographically valid subject token the client must already possess, and
 * preserves-or-narrows its scope and audience (GATE 4) — the delegated token is
 * never wider than the one presented. The one axis where a grant could add
 * authority, the reserved `agent:*` scope modes, is clamped to the OPERATOR-set
 * `max_agent_mode` (GATE 4c), which self-registration deliberately never sets,
 * so it stays NULL and yields no agent mode at all. What the exchange does add
 * is an `act` claim naming the agent — strictly more auditable, not less.
 *
 * Refusing it here instead would have meant withdrawing the grant from
 * `grant_types_supported` (`helpers/discovery.ts`) and from ADR-007 §2's
 * agent-native surface, i.e. deleting a shipped feature rather than finishing
 * its provisioning.
 */
export const dynamicClientRegistrationRequestSchema = z.object({
  client_name: z.string().min(1).max(255).optional(),
  redirect_uris: z.array(z.string().min(1).max(2048)).max(20).optional(),
  grant_types: z
    .array(
      z.enum([
        'authorization_code',
        'refresh_token',
        'client_credentials',
        TOKEN_EXCHANGE_GRANT_TYPE,
      ])
    )
    .max(8)
    .optional(),
  response_types: z
    .array(z.enum(['code']))
    .max(4)
    .optional(),
  token_endpoint_auth_method: z
    .enum(['none', 'client_secret_basic', 'client_secret_post'])
    .optional(),
  scope: z.string().max(2048).optional(),
  client_uri: z.url().max(2048).optional(),
  logo_uri: z.url().max(2048).optional(),
  tos_uri: z.url().max(2048).optional(),
  policy_uri: z.url().max(2048).optional(),
  contacts: z.array(z.email().max(255)).max(10).optional(),
  software_id: z.string().max(255).optional(),
  software_version: z.string().max(64).optional(),
  /**
   * QAuth extension metadata (ADR-007 §2): marks the client as an autonomous
   * AI agent. RFC 7591 §2 permits a server to define additional client
   * metadata; this QAuth-specific flag is a plain boolean and defaults to a
   * standard (non-agent) client when omitted. Persisted as
   * `oauth_clients.is_agent` and echoed back per §3.2.1. Nothing is gated on
   * it yet — delegation / scope modes / step-up are later ADR-007 §2 issues.
   *
   * TRUST: this is self-asserted, unverified client input — the client sets
   * it in its own registration request. Later gating must treat it as
   * untrusted (verify, don't trust) and default-deny, since a client can
   * also *omit* it to dodge agent-specific controls.
   */
  is_agent: z.boolean().optional(),
});

export type DynamicClientRegistrationRequest = z.infer<
  typeof dynamicClientRegistrationRequestSchema
>;

/**
 * Dynamic Client Registration response body.
 * RFC 7591 §3.2.1. `client_secret` is omitted for public clients.
 * `client_id_issued_at` / `client_secret_expires_at` are seconds-since-epoch
 * (not milliseconds).
 */
export const dynamicClientRegistrationResponseSchema = z.object({
  client_id: z.string(),
  client_secret: z.string().optional(),
  client_id_issued_at: z.number().int().nonnegative(),
  // RFC 7591: 0 means "does not expire". We emit 0 for non-expiring secrets.
  client_secret_expires_at: z.number().int().nonnegative().optional(),
  client_name: z.string().optional(),
  redirect_uris: z.array(z.string()).optional(),
  grant_types: z.array(z.string()),
  response_types: z.array(z.string()),
  token_endpoint_auth_method: z.string(),
  scope: z.string().optional(),
  client_uri: z.string().optional(),
  logo_uri: z.string().optional(),
  tos_uri: z.string().optional(),
  policy_uri: z.string().optional(),
  contacts: z.array(z.string()).optional(),
  software_id: z.string().optional(),
  software_version: z.string().optional(),
  /** QAuth extension: echoed back when the client was registered as an agent. */
  is_agent: z.boolean().optional(),
});

export type DynamicClientRegistrationResponse = z.infer<
  typeof dynamicClientRegistrationResponseSchema
>;

/**
 * OIDC userinfo response schema (GET /userinfo).
 * Returns selected claims for the authenticated end-user.
 *
 * Claims kept consistent with the ID token and discovery `claims_supported`
 * (OIDC Core §5.3 / §5.1): `sub` always; `email`, `email_verified`, `name`
 * when available.
 */
export const userinfoResponseSchema = z.object({
  sub: z.string().min(1),
  email: z.email().optional(),
  email_verified: z.boolean().optional(),
  name: z.string().optional(),
});

export type UserinfoResponse = z.infer<typeof userinfoResponseSchema>;

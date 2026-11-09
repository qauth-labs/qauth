import type { z } from 'zod';

import type { AuthMethodDisplay } from './auth-method.js';
import {
  AUTH_METHOD_ATTRIBUTE_KEY_PATTERN,
  AUTH_METHOD_CONTRACT,
  AUTH_METHOD_ID_PATTERN,
  UPSTREAM_OIDC_METHOD_ID,
  UPSTREAM_OIDC_TYPE_PATTERN,
} from './contract.js';
import { AuthMethodContractError } from './errors.js';
import { authMethodTypeProblems, contractProblems, displayProblems } from './validate.js';

/**
 * A PRESET PLUGIN on QAuth's generic upstream OpenID Connect client (#951,
 * #671): the facts of one named provider and its claim rules, which the
 * server's own client runs. A plugin that signs people in at an OpenID
 * Provider is written as one, in its own repository, against this package
 * alone.
 *
 * The protocol stays in the server: discovery, PKCE with S256, `state` and
 * `nonce`, the ID token and key set checks, the token request and the signer
 * call. So a fix to that code reaches every preset with a server release, and
 * no plugin carries its own copy of it. A preset package exports its preset
 * as {@link UPSTREAM_OIDC_PRESET_EXPORT}, made with
 * {@link defineUpstreamOidcPreset}; the server's plugin loader builds the
 * method from it, then holds the method to the whole AuthMethod contract as
 * it holds a plugin that exports an `authMethod`.
 *
 * A preset has:
 *
 * - **its own id and type**, outside the generic client's (never `oidc`,
 *   never `oidc_<alias>`): its realm state and admin API name are its own,
 *   and its callback is `/upstream/<type>/callback` on the realm host;
 * - **its own config**, the members an admin sets for a realm (a client id,
 *   a client secret, a tenant), which `upstreamConfig` turns into the
 *   client's provider config at every use. A client secret is a member the
 *   preset's schema marks `.meta({ writeOnly: true })`, so the server keeps it
 *   write-only and stores it encrypted;
 * - **its provider's origins**: the issuer and every endpoint the client
 *   calls, the discovered ones included, must be on one of them, so a client
 *   secret goes to that provider and to no other host;
 * - what the provider needs beyond the generic client, which only a preset
 *   sets, never a realm's admin: a client secret the signer role signs
 *   (`signed_client_secret`), an issuer template for a multi-tenant provider
 *   (`tenantIssuer`), response members its callback reads
 *   (`responseMembers`), claims from them and its config (`identityClaims`)
 *   and its own attribute rules (`attributes`).
 *
 * EXPERIMENTAL, like the contract. The test kit's `checkUpstreamOidcPreset`
 * (`@qauth-labs/plugin-sdk/testing`) checks a preset without the server.
 *
 * @packageDocumentation
 */

/**
 * The export a preset package names its preset by: `upstreamOidcPreset`, the
 * value {@link defineUpstreamOidcPreset} returns. A package exports either a
 * preset or an `authMethod`, never both. A CommonJS package may put it under
 * `default`.
 *
 * ```ts
 * // index.ts of @example/qauth-plugin-example-idp
 * export const upstreamOidcPreset = defineUpstreamOidcPreset({ … });
 * ```
 *
 * @experimental
 */
export const UPSTREAM_OIDC_PRESET_EXPORT = 'upstreamOidcPreset';

/**
 * The client authentication whose client secret the signer role signs for
 * each token request: a JWT sent as `client_secret` in the form body, for a
 * provider that takes no static secret. Its claims are a client assertion's
 * (`iss`, `sub`, `aud`, `iat`, `exp`, `jti`); the signer signs it with the
 * realm's `upstream_client_assertion` key for the preset's type, so no secret
 * is stored and the plugin holds no key. Offered to presets only: the generic
 * client's config, which a realm's admin writes, has no such method.
 *
 * @experimental
 */
export const UPSTREAM_SIGNED_CLIENT_SECRET = 'signed_client_secret';

/**
 * How a preset's client authenticates at the token endpoint (OpenID Connect
 * Core 1.0 §9): HTTP Basic or the form body with a client secret, a client
 * assertion the signer role signs (`private_key_jwt`, RFC 7523), or
 * {@link UPSTREAM_SIGNED_CLIENT_SECRET}. `none` is not offered: QAuth is a
 * confidential client.
 *
 * @experimental
 */
export const UPSTREAM_PRESET_CLIENT_AUTHENTICATION_METHODS = Object.freeze([
  'client_secret_basic',
  'client_secret_post',
  'private_key_jwt',
  UPSTREAM_SIGNED_CLIENT_SECRET,
] as const);

/**
 * The algorithms an ID token may be signed with: asymmetric JWS algorithms
 * only. `none` and every MAC algorithm (`HS*`) are absent by construction: a
 * MAC would be checked with the client secret, which the provider also holds,
 * so it proves nothing about who signed.
 *
 * @experimental
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

/**
 * An algorithm an ID token may be signed with.
 *
 * @experimental
 */
export type UpstreamIdTokenAlgorithm = (typeof UPSTREAM_ID_TOKEN_ALGORITHMS)[number];

/**
 * The algorithms the signer role signs a client assertion, or a signed
 * client secret, with.
 *
 * @experimental
 */
export const UPSTREAM_ASSERTION_ALGORITHMS = Object.freeze(['RS256', 'ES256', 'EdDSA'] as const);

/**
 * An algorithm the signer role signs a client assertion with.
 *
 * @experimental
 */
export type UpstreamAssertionAlgorithm = (typeof UPSTREAM_ASSERTION_ALGORITHMS)[number];

/**
 * The placeholder an issuer template holds for the tenant id:
 * `https://idp.example.com/{tenantid}/v2.0`.
 *
 * @experimental
 */
export const UPSTREAM_TENANT_PLACEHOLDER = '{tenantid}';

/**
 * The most origins a preset may name.
 *
 * @experimental
 */
export const MAX_UPSTREAM_OIDC_PRESET_ORIGINS = 8;

/**
 * The most response members a preset reads.
 *
 * @experimental
 */
export const MAX_UPSTREAM_RESPONSE_MEMBERS = 4;

/**
 * The longest value of a response member the `form_post` bounce carries on and
 * the callback reads, in characters: it rides in the callback's URL.
 *
 * @experimental
 */
export const MAX_UPSTREAM_RESPONSE_MEMBER_LENGTH = 1024;

/**
 * The name of a response member a preset reads: lower case, as a form
 * member's, at most 32 characters.
 *
 * @experimental
 */
export const UPSTREAM_RESPONSE_MEMBER_NAME_PATTERN = /^[a-z][a-z0-9_]{0,31}$/;

/**
 * The authorization response's own parameters, which the client reads itself
 * and no response member may be.
 *
 * @experimental
 */
export const UPSTREAM_RESPONSE_PARAMETERS: readonly string[] = Object.freeze([
  'code',
  'state',
  'iss',
  'error',
  'error_description',
  'error_uri',
]);

/**
 * The claims only the ID token may carry: its own validity (`iss`, `aud`,
 * `azp`, `exp`, `iat`, `nbf`, `jti`, `nonce`, the hashes) and the facts of
 * the authentication (`acr`, `amr`, `auth_time`, `sid`, `cnf`). They stay the
 * validated ones: neither a userinfo answer nor a preset's `identityClaims`
 * sets one. Nor does either set `sub`.
 *
 * @experimental
 */
export const UPSTREAM_ID_TOKEN_ONLY_CLAIMS: readonly string[] = Object.freeze([
  'iss',
  'aud',
  'azp',
  'exp',
  'iat',
  'nbf',
  'jti',
  'nonce',
  'at_hash',
  'c_hash',
  's_hash',
  'acr',
  'amr',
  'auth_time',
  'sid',
  'cnf',
]);

/**
 * Claims whose truth another claim of the same source vouches for: a value
 * and its `*_verified` flag (OpenID Connect Core 1.0 §5.1). A preset's
 * `identityClaims` may remove either, never set one: a value a preset makes up
 * is never taken as one the provider verified.
 *
 * @experimental
 */
export const UPSTREAM_VERIFIED_CLAIM_PAIRS: readonly (readonly [value: string, flag: string])[] =
  Object.freeze([
    Object.freeze(['email', 'email_verified'] as const),
    Object.freeze(['phone_number', 'phone_number_verified'] as const),
  ]);

/**
 * How a preset's client authenticates at the token endpoint
 * ({@link UPSTREAM_PRESET_CLIENT_AUTHENTICATION_METHODS}). A `clientSecret`
 * must be the value of a config member the preset's schema marks
 * `writeOnly`, so the server stores it encrypted.
 *
 * @experimental
 */
export type UpstreamOidcClientAuthentication =
  | { method: 'client_secret_basic'; clientSecret: string }
  | { method: 'client_secret_post'; clientSecret: string }
  | {
      method: 'private_key_jwt';
      /** The algorithm of the key registered with the provider; `RS256` unless set. */
      signingAlgorithm?: UpstreamAssertionAlgorithm | undefined;
    }
  | {
      method: typeof UPSTREAM_SIGNED_CLIENT_SECRET;
      /** The algorithm of the key registered with the provider; `ES256` unless set. */
      signingAlgorithm?: UpstreamAssertionAlgorithm | undefined;
    };

/**
 * A provider's endpoints, set by hand: no discovery document is read. Each an
 * `https` URL on one of the preset's origins.
 *
 * @experimental
 */
export interface UpstreamOidcEndpoints {
  authorization: string;
  token: string;
  jwks: string;
  userinfo?: string | undefined;
  /**
   * Whether the provider sends `iss` in its authorization response
   * (RFC 9207); a response without it is then refused. `false` unless set.
   */
  issParameterSupported?: boolean | undefined;
}

/**
 * The issuer of a multi-tenant provider, whose shared endpoints serve many
 * tenants. The discovery document names the template, and each ID token the
 * template with its own tenant id, the value of its `tenantClaim`, in place of
 * {@link UPSTREAM_TENANT_PLACEHOLDER}. A token is accepted only when its `iss`
 * is the template with that tenant id in place.
 *
 * @experimental
 */
export interface UpstreamOidcTenantIssuer {
  /**
   * The issuer with {@link UPSTREAM_TENANT_PLACEHOLDER} once, in its path:
   * `https://idp.example.com/{tenantid}/v2.0`.
   */
  template: string;
  /** The ID token claim that names the tenant, such as `tid`. */
  tenantClaim: string;
}

/**
 * The provider config a preset's `upstreamConfig` makes: what the server's
 * client runs on. The server parses it at every use and refuses a config
 * whose URLs are off the preset's origins.
 *
 * @experimental
 */
export interface UpstreamOidcProviderConfig {
  /** The provider's issuer identifier, compared byte for byte. */
  issuer: string;
  /** The client id QAuth is registered under at the provider. */
  clientId: string;
  clientAuthentication: UpstreamOidcClientAuthentication;
  /** The scopes to ask for, `openid` among them; `openid email profile` unless set. */
  scopes?: string[] | undefined;
  /** The endpoints by hand; without them, discovery. */
  endpoints?: UpstreamOidcEndpoints | undefined;
  /**
   * How the provider returns the authorization response: `query` (a `GET`
   * to the callback, the default) or `form_post` (a cross-site `POST`, which
   * the client bounces to the `GET` callback so the browser brings the flow
   * cookie).
   */
  responseMode?: 'query' | 'form_post' | undefined;
  /** The algorithms an ID token may be signed with; `RS256 PS256 ES256 EdDSA` unless set. */
  idTokenSigningAlgorithms?: UpstreamIdTokenAlgorithm[] | undefined;
  /** Whether to read the userinfo endpoint after the code exchange; `false` unless set. */
  fetchUserinfo?: boolean | undefined;
  /** A multi-tenant provider's issuer template. */
  tenantIssuer?: UpstreamOidcTenantIssuer | undefined;
}

/**
 * Members of the authorization response besides the protocol's own that a
 * preset's callback reads, by name: each maps the value the provider sent to
 * the value the `form_post` bounce carries on in the callback's URL, at most
 * {@link MAX_UPSTREAM_RESPONSE_MEMBER_LENGTH} characters, or `undefined` to
 * drop it. The callback reads the value the bounce carried and maps it again,
 * so a map must give its own output back unchanged. The value is the
 * browser's to choose, never signed by the provider: whatever the callback
 * makes of it is only ever an unverified claim.
 *
 * @experimental
 */
export type UpstreamResponseMembers = Readonly<
  Record<string, (value: string) => string | undefined>
>;

/**
 * The claims a preset's identity gets besides the provider's: from the
 * response members it reads and the preset's config. The result's members are
 * set over the provider's claims, and one set to `undefined` removes a claim.
 * `sub` and the claims only the ID token may carry
 * ({@link UPSTREAM_ID_TOKEN_ONLY_CLAIMS}) stay the validated ones. A claim the
 * provider vouches for ({@link UPSTREAM_VERIFIED_CLAIM_PAIRS}) and its
 * `*_verified` flag may be removed, never set.
 *
 * @experimental
 */
export type UpstreamIdentityClaims<TConfig> = (input: {
  /** The provider's claims, validated: the ID token's over userinfo's. */
  readonly claims: Readonly<Record<string, unknown>>;
  /** The preset's response members the response carried, each a single value. */
  readonly response: Readonly<Record<string, string>>;
  /** The preset's config, parsed. */
  readonly config: TConfig;
}) => Readonly<Record<string, unknown>>;

/**
 * One attribute a provider's claims map to.
 *
 * @experimental
 */
export interface UpstreamClaimAttribute {
  /** The claim the value is read from: a string claim, or the attribute is left out. */
  readonly claim: string;
  /** The attribute's key: the claim's name unless set. */
  readonly attribute?: string;
  /**
   * Whether the provider vouches for the value, read from the identity's
   * claims: `verified` only when this returns the boolean `true`. Without it
   * the attribute is never verified.
   */
  readonly verified?: (claims: Readonly<Record<string, unknown>>) => boolean;
}

/**
 * Whether `claims[name]` is the boolean `true`: the test of a `*_verified`
 * flag, for a {@link UpstreamClaimAttribute}'s `verified`.
 *
 * @experimental
 */
export function upstreamClaimIsTrue(
  claims: Readonly<Record<string, unknown>>,
  name: string
): boolean {
  return Object.hasOwn(claims, name) && claims[name] === true;
}

/**
 * The generic client's attributes, which a preset gets unless it sets its
 * own: the standard profile claims of OpenID Connect Core 1.0 §5.1 that are
 * plain text, `email` and `phone_number` verified by their `*_verified` claim.
 *
 * @experimental
 */
export const UPSTREAM_STANDARD_ATTRIBUTES: readonly UpstreamClaimAttribute[] = Object.freeze([
  { claim: 'email', verified: (claims) => upstreamClaimIsTrue(claims, 'email_verified') },
  {
    claim: 'phone_number',
    verified: (claims) => upstreamClaimIsTrue(claims, 'phone_number_verified'),
  },
  { claim: 'name' },
  { claim: 'given_name' },
  { claim: 'family_name' },
  { claim: 'middle_name' },
  { claim: 'nickname' },
  { claim: 'preferred_username' },
  { claim: 'locale' },
  { claim: 'zoneinfo' },
]);

/**
 * What a preset author writes ({@link defineUpstreamOidcPreset}).
 *
 * @typeParam TConfig - the preset's parsed config, the output of `configSchema`
 * @experimental
 */
export interface UpstreamOidcPresetOptions<TConfig> {
  /**
   * The plugin's AuthMethod id, such as `example-idp`: its name in the admin
   * API and its realm state. Never `oidc`, the generic client's.
   */
  readonly id: string;
  /**
   * The plugin's AuthMethod type, such as `example_idp`: its registry key, its
   * route segment, the credential type it writes and the source of the
   * attributes it writes. Never `oidc_<alias>`, the generic client's
   * namespace.
   */
  readonly type: string;
  /** What the sign-in page shows. */
  readonly display: AuthMethodDisplay;
  /**
   * The `https` origins the provider answers on, such as
   * `https://idp.example.com`: bare origins, at most
   * {@link MAX_UPSTREAM_OIDC_PRESET_ORIGINS}. The issuer and every endpoint
   * the client calls must be on one of them, those the discovery document
   * names included: a provider whose token endpoint or key set is on another
   * host lists that host's origin too.
   */
  readonly origins: readonly string[];
  /**
   * The preset's config for one realm: a Zod object schema, its client
   * secret a string member marked `.meta({ writeOnly: true })` (inside a
   * discriminated union of client authentication methods too).
   */
  readonly configSchema: z.ZodType<TConfig>;
  /**
   * The provider config for a config `configSchema` parsed: the issuer (or
   * the endpoints) of the provider, and the client id and client
   * authentication, the secret passed on as the preset's secret member holds
   * it. Called at every use; it must not throw for a parsed config.
   */
  upstreamConfig(config: TConfig): UpstreamOidcProviderConfig;
  /**
   * Members of the authorization response besides the protocol's own that the
   * callback reads: at most {@link MAX_UPSTREAM_RESPONSE_MEMBERS}
   * ({@link UpstreamResponseMembers}).
   */
  readonly responseMembers?: UpstreamResponseMembers;
  /**
   * The claims the identity gets besides the provider's, from the response
   * members and the config ({@link UpstreamIdentityClaims}).
   */
  readonly identityClaims?: UpstreamIdentityClaims<TConfig>;
  /** The attributes the claims map to; {@link UPSTREAM_STANDARD_ATTRIBUTES} unless set. */
  readonly attributes?: readonly UpstreamClaimAttribute[];
}

/**
 * A preset, as a package exports it ({@link UPSTREAM_OIDC_PRESET_EXPORT}):
 * its options, frozen, and the contract it is written against, which the
 * server's loader checks first.
 *
 * @typeParam TConfig - the preset's parsed config
 * @experimental
 */
export interface UpstreamOidcPreset<TConfig = unknown> extends UpstreamOidcPresetOptions<TConfig> {
  readonly contract: typeof AUTH_METHOD_CONTRACT;
}

/**
 * Define a preset: its options checked ({@link upstreamOidcPresetProblems})
 * and frozen, with the contract it is written against.
 *
 * ```ts
 * import { defineUpstreamOidcPreset } from '@qauth-labs/plugin-sdk';
 * import { z } from 'zod';
 *
 * export const upstreamOidcPreset = defineUpstreamOidcPreset({
 *   id: 'example-idp',
 *   type: 'example_idp',
 *   display: { name: 'Example IdP' },
 *   origins: ['https://idp.example.com'],
 *   configSchema: z.strictObject({
 *     clientId: z.string().min(1).max(255),
 *     clientSecret: z.string().min(1).max(1024).meta({ writeOnly: true }),
 *   }),
 *   upstreamConfig: (config) => ({
 *     issuer: 'https://idp.example.com',
 *     clientId: config.clientId,
 *     clientAuthentication: { method: 'client_secret_basic', clientSecret: config.clientSecret },
 *   }),
 * });
 * ```
 *
 * @throws AuthMethodContractError listing every problem of the options
 * @experimental
 */
export function defineUpstreamOidcPreset<TConfig>(
  options: UpstreamOidcPresetOptions<TConfig>
): UpstreamOidcPreset<TConfig> {
  const candidate = {
    ...options,
    contract: AUTH_METHOD_CONTRACT,
  };
  const problems = upstreamOidcPresetProblems(candidate);
  if (problems.length > 0) {
    throw new AuthMethodContractError(describePreset(options), problems);
  }
  return Object.freeze({
    ...candidate,
    origins: Object.freeze([...options.origins]),
    ...(options.responseMembers === undefined
      ? {}
      : { responseMembers: Object.freeze({ ...options.responseMembers }) }),
    ...(options.attributes === undefined
      ? {}
      : { attributes: Object.freeze([...options.attributes]) }),
  }) as UpstreamOidcPreset<TConfig>;
}

/**
 * Whether `value` is a preset that meets the static checks.
 *
 * @experimental
 */
export function isUpstreamOidcPreset(value: unknown): value is UpstreamOidcPreset {
  return upstreamOidcPresetProblems(value).length === 0;
}

/**
 * The problems of `value` as a preset, one sentence each; none for a preset
 * the server's loader builds: the contract version, its id and type (never
 * the generic client's), its display data, its origins (one to
 * {@link MAX_UPSTREAM_OIDC_PRESET_ORIGINS} bare `https` origins), a Zod config
 * schema, `upstreamConfig` and `identityClaims` functions, its response
 * members (one to {@link MAX_UPSTREAM_RESPONSE_MEMBERS} lower-case names,
 * none a protocol parameter, each a function) and its attribute rules.
 *
 * These checks need no server. What only the server can check, the provider
 * config `upstreamConfig` makes for a config, it checks where it parses the
 * config, and the test kit's `checkUpstreamOidcPreset` checks on sample
 * configs.
 *
 * @experimental
 */
export function upstreamOidcPresetProblems(value: unknown): string[] {
  if (typeof value !== 'object' || value === null) return ['it is not an object'];
  const preset = value as Record<string, unknown>;
  const problems: string[] = [];

  problems.push(...contractProblems(preset['contract']));

  const id = preset['id'];
  if (typeof id !== 'string' || !AUTH_METHOD_ID_PATTERN.test(id)) {
    problems.push(`id must match ${AUTH_METHOD_ID_PATTERN.source}`);
  } else if (id === UPSTREAM_OIDC_METHOD_ID) {
    problems.push(
      `id ${id} is the generic upstream OpenID Connect client's, which no preset may take`
    );
  }
  const typeProblems = authMethodTypeProblems(preset['type']);
  problems.push(...typeProblems);
  if (typeProblems.length === 0 && UPSTREAM_OIDC_TYPE_PATTERN.test(preset['type'] as string)) {
    problems.push(
      `type ${String(preset['type'])} is in the generic upstream OpenID Connect client's namespace (oidc_<alias>), which no preset may take`
    );
  }

  problems.push(...displayProblems(preset['display']));
  problems.push(...originProblems(preset['origins']));

  const schema = preset['configSchema'];
  if (
    typeof schema !== 'object' ||
    schema === null ||
    typeof (schema as Record<string, unknown>)['safeParse'] !== 'function'
  ) {
    problems.push('configSchema must be a Zod schema');
  }
  if (typeof preset['upstreamConfig'] !== 'function') {
    problems.push('upstreamConfig must be a function of the parsed config');
  }
  if (preset['identityClaims'] !== undefined && typeof preset['identityClaims'] !== 'function') {
    problems.push('identityClaims must be a function when the preset has it');
  }
  problems.push(...responseMemberProblems(preset['responseMembers']));
  problems.push(...attributeRuleProblems(preset['attributes']));
  return problems;
}

/** The problems of a preset's origins: one to eight bare `https` origins. */
function originProblems(origins: unknown): string[] {
  if (
    !Array.isArray(origins) ||
    origins.length === 0 ||
    origins.length > MAX_UPSTREAM_OIDC_PRESET_ORIGINS
  ) {
    return [
      `origins must list the provider's https origins, at least one and at most ${MAX_UPSTREAM_OIDC_PRESET_ORIGINS}`,
    ];
  }
  const problems: string[] = [];
  origins.forEach((origin: unknown, index) => {
    if (!isBareHttpsOrigin(origin)) {
      problems.push(
        `origins[${index}] must be a bare https origin, such as https://idp.example.com`
      );
    }
  });
  if (new Set(origins).size !== origins.length) problems.push('origins must not repeat');
  return problems;
}

/** Whether `value` is an `https` origin and nothing more: no path, query or credentials. */
function isBareHttpsOrigin(value: unknown): boolean {
  if (typeof value !== 'string') return false;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && url.origin === value;
  } catch {
    return false;
  }
}

/** The problems of a preset's response members. */
function responseMemberProblems(members: unknown): string[] {
  if (members === undefined) return [];
  if (typeof members !== 'object' || members === null || Array.isArray(members)) {
    return ['responseMembers must be an object of member names and functions'];
  }
  const entries = Object.entries(members);
  const problems: string[] = [];
  if (entries.length === 0 || entries.length > MAX_UPSTREAM_RESPONSE_MEMBERS) {
    problems.push(`responseMembers must name one to ${MAX_UPSTREAM_RESPONSE_MEMBERS} members`);
  }
  for (const [name, map] of entries) {
    if (!UPSTREAM_RESPONSE_MEMBER_NAME_PATTERN.test(name)) {
      problems.push(
        `responseMembers names ${JSON.stringify(name.slice(0, 64))}, which is not a lower-case member name (${UPSTREAM_RESPONSE_MEMBER_NAME_PATTERN.source})`
      );
    } else if (UPSTREAM_RESPONSE_PARAMETERS.includes(name)) {
      problems.push(
        `responseMembers names ${name}, a parameter of the protocol, which the client reads itself`
      );
    }
    if (typeof map !== 'function')
      problems.push(`responseMembers.${name.slice(0, 64)} must be a function`);
  }
  return problems;
}

/** The problems of a preset's attribute rules. */
function attributeRuleProblems(rules: unknown): string[] {
  if (rules === undefined) return [];
  if (!Array.isArray(rules)) return ['attributes must be a list of claim attribute rules'];
  const problems: string[] = [];
  rules.forEach((rule: unknown, index) => {
    const at = `attributes[${index}]`;
    if (typeof rule !== 'object' || rule === null) {
      problems.push(`${at} must be an object`);
      return;
    }
    const { claim, attribute, verified } = rule as Record<string, unknown>;
    if (typeof claim !== 'string' || claim.length === 0) {
      problems.push(`${at}.claim must name a claim`);
    }
    const key = attribute ?? claim;
    if (typeof key !== 'string' || !AUTH_METHOD_ATTRIBUTE_KEY_PATTERN.test(key)) {
      problems.push(
        `${at} must map to an attribute key that matches ${AUTH_METHOD_ATTRIBUTE_KEY_PATTERN.source}`
      );
    }
    if (verified !== undefined && typeof verified !== 'function') {
      problems.push(`${at}.verified must be a function when the rule has it`);
    }
  });
  return problems;
}

/** How a preset is named in an error: its type, when it has a usable one. */
function describePreset(value: { readonly type?: unknown }): string {
  return typeof value.type === 'string' && authMethodTypeProblems(value.type).length === 0
    ? `The upstream OpenID Connect preset ${value.type}`
    : 'An upstream OpenID Connect preset';
}

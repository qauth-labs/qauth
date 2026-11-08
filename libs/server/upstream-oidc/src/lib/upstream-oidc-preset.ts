import {
  AUTH_METHOD_ID_PATTERN,
  AUTH_METHOD_TYPE_PATTERN,
  type AuthMethod,
  type AuthMethodDisplay,
  authMethodSecretPaths,
  configMemberAt,
  UPSTREAM_OIDC_METHOD_ID,
  UPSTREAM_OIDC_TYPE_PATTERN,
} from '@qauth-labs/server-federation';
import type { z } from 'zod';

import type { UpstreamClaimAttribute } from './attributes';
import {
  UPSTREAM_TENANT_PLACEHOLDER,
  type UpstreamOidcClientConfig,
  type UpstreamOidcClientConfigInput,
  upstreamOidcClientConfigSchema,
} from './config';
import { upstreamClientSecretDestination } from './stored-config';
import {
  type UpstreamIdentityClaims,
  upstreamOidcClientMethod,
  type UpstreamOidcTransaction,
  type UpstreamResponseMembers,
} from './upstream-oidc-method';

/**
 * A PRESET PLUGIN on the generic upstream OpenID Connect client (#951): an
 * AuthMethod for one named provider (the first-party presets of #671), which
 * the plugin runtime (#600) loads as any plugin, from its package's
 * `authMethod` export.
 *
 * The generic client (`createUpstreamOidcMethod`) is one method per provider
 * a realm configures, every one with the id `oidc` and a type `oidc_<alias>`,
 * both reserved for it; the realm's provider rows run it (#639, #714). A
 * preset is a plugin instead, so it has what the plugin loader asks of one:
 *
 * - **its own id and type**, outside the generic client's (never `oidc`,
 *   never `oidc_<alias>`): its realm state and admin API name are its own,
 *   and its callback is `/upstream/<type>/callback` on the realm host;
 * - **its own config**, the members an admin sets for a realm (a client id,
 *   a client secret, a tenant), which `upstreamConfig` turns into the
 *   generic client's config, the issuer and endpoints among them, at every
 *   use. Its client secret is a member the preset's schema marks
 *   `.meta({ writeOnly: true })`, so the plugin runtime keeps it write-only
 *   and stores it encrypted under the plugin's own context;
 * - **its provider's origins**, which bind the secret to its provider.
 *   The generic client binds its stored secret to the issuer and the token
 *   endpoint it was entered for; a plugin's secret is bound to the plugin.
 *   So a preset names the `https` origins its provider answers on, and the
 *   issuer and every endpoint the client calls must be on one of them: the
 *   ones `upstreamConfig` makes for a config, checked when the config is
 *   parsed, and the ones the discovery document names, checked at every
 *   use. Whatever a realm's admin configures, the secret goes to that
 *   provider's origins and to no other host. A provider whose host an admin
 *   chooses is the generic client's, not a preset's;
 * - **its destination** (#1031): within those origins, the method's
 *   `secretDestination` names the issuer and the token endpoint set by hand
 *   that `upstreamConfig` makes for a config, as the digest the generic
 *   client binds its secret to (`upstreamClientSecretDestination`). The admin
 *   API compares it for the stored config and the new one at each
 *   configure, on top of its own URL-origin rule, so a configure that
 *   changes either (a member that shapes the issuer's path, such as a tenant
 *   or a region, or a token endpoint's path) must send the secret again, as
 *   the generic client asks for it again. The plugin secret's context does
 *   not name the destination, as the generic client's does.
 *
 * What it adds to the generic client, it checks when the config is parsed,
 * so the admin API refuses such a config at the configure: a config whose
 * provider config does not parse, names a URL off the preset's origins,
 * sends a client secret that is not the value of one of the preset's secret
 * members (a secret taken from a plain member would be stored in the clear),
 * or carries a secret member's value anywhere but in the client secret (a
 * client id, a scope or a URL goes out, and is logged, in the clear).
 * Everything else is the generic client's, unchanged: discovery, PKCE with
 * S256, `state` and `nonce`, the ID token checks, the callback and its
 * `form_post` bounce, `verify()` and the attributes, under the preset's type.
 *
 * What a named provider needs beyond that, a preset sets in its options
 * (#671), never a realm's admin: a client secret the signer role signs
 * (`signed_client_secret`, Sign in with Apple's), an issuer template for a
 * multi-tenant provider (`tenantIssuer`, e.g. Microsoft's `common` and
 * `organizations` endpoints), response members its callback reads (Apple's `user`),
 * claims from them and its config (`identityClaims`) and its own attribute
 * rules (`attributes`).
 *
 * Every call the client makes goes as a `remote_document` destination unless
 * the preset's own config names its origin (the context's rule), so the
 * deployment's egress allowlist never opens a private address for a preset.
 *
 * EXPERIMENTAL, like the contract it implements.
 *
 * @experimental
 */

/**
 * Options of {@link createUpstreamOidcPresetMethod}.
 *
 * @typeParam TConfig - the preset's parsed config, the output of `configSchema`
 * @experimental
 */
export interface UpstreamOidcPresetOptions<TConfig> {
  /**
   * The plugin's AuthMethod id, such as `example-idp`: its name in the admin API
   * and its realm state. Never `oidc`, the generic client's.
   */
  readonly id: string;
  /**
   * The plugin's AuthMethod type, such as `example_idp`: its registry key, its
   * route segment and the credential type it writes. Never `oidc_<alias>`,
   * the generic client's namespace.
   */
  readonly type: string;
  /** What the sign-in page shows. */
  readonly display: AuthMethodDisplay;
  /**
   * The `https` origins the provider answers on, such as
   * `https://idp.example.com`: bare origins, at most eight. The issuer
   * and every endpoint the client calls must be on one of them, those the
   * discovery document names included: a provider whose token endpoint or
   * key set is on another host lists that host's origin too.
   */
  readonly origins: readonly string[];
  /**
   * The preset's config for one realm: a Zod object schema, its client
   * secret a string member marked `.meta({ writeOnly: true })` (inside a
   * discriminated union of client authentication methods too).
   */
  readonly configSchema: z.ZodType<TConfig>;
  /**
   * The generic client's config for a config `configSchema` parsed: the
   * issuer (or the endpoints) of the provider, and the client id and client
   * authentication, the secret passed on as the preset's secret member
   * holds it. Called at every use; it must not throw for a parsed config.
   *
   * Beyond the generic client's members, a preset's config may name a
   * `signed_client_secret` client authentication, and a `tenantIssuer`
   * whose template, as the issuer, is on the preset's origins.
   */
  upstreamConfig(config: TConfig): UpstreamOidcClientConfigInput;
  /**
   * Members of the authorization response besides the protocol's own that
   * the callback reads, such as Sign in with Apple's `user`: at most four,
   * each mapped to the value the `form_post` bounce carries on in the
   * callback's URL, at most 1024 characters. A member's value is the
   * browser's to choose: whatever is made of it is an unverified claim.
   */
  readonly responseMembers?: UpstreamResponseMembers;
  /**
   * The claims the identity gets besides the provider's, from the response
   * members and the config: never `sub` or a claim only the ID token may
   * carry.
   */
  readonly identityClaims?: UpstreamIdentityClaims<TConfig>;
  /** The attributes the claims map to; the generic client's standard ones unless set. */
  readonly attributes?: readonly UpstreamClaimAttribute[];
}

/**
 * The most origins a preset may name.
 *
 * @experimental
 */
export const MAX_UPSTREAM_OIDC_PRESET_ORIGINS = 8;

/** Where the generic client's config holds the client secret. */
const CLIENT_SECRET_PATH = 'clientAuthentication.clientSecret';

/** The preset's origins, checked: each a bare `https` origin. */
function presetOrigins(origins: unknown): ReadonlySet<string> {
  if (
    !Array.isArray(origins) ||
    origins.length === 0 ||
    origins.length > MAX_UPSTREAM_OIDC_PRESET_ORIGINS
  ) {
    throw new TypeError(
      `origins must list the provider's https origins, at least one and at most ${MAX_UPSTREAM_OIDC_PRESET_ORIGINS}`
    );
  }
  for (const origin of origins) {
    let url: URL | undefined;
    try {
      url = typeof origin === 'string' ? new URL(origin) : undefined;
    } catch {
      url = undefined;
    }
    if (url === undefined || url.protocol !== 'https:' || url.origin !== origin) {
      throw new TypeError(
        'each of origins must be a bare https origin, such as https://idp.example.com'
      );
    }
  }
  return new Set(origins as string[]);
}

/** The origin of `value`, or `undefined` for a value that is no URL. */
function originOf(value: string): string | undefined {
  try {
    return new URL(value).origin;
  } catch {
    return undefined;
  }
}

/**
 * The URLs of a provider config the preset's origins must hold: its issuer,
 * its issuer template (with a tenant id in place) and its endpoints.
 */
function providerUrls(config: UpstreamOidcClientConfig): [name: string, url: string][] {
  const urls: [string, string][] = [['issuer', config.issuer]];
  if (config.tenantIssuer !== undefined) {
    urls.push([
      'tenantIssuer.template',
      config.tenantIssuer.template.replace(UPSTREAM_TENANT_PLACEHOLDER, 'tenant'),
    ]);
  }
  for (const [name, url] of Object.entries(config.endpoints ?? {})) {
    if (typeof url === 'string') urls.push([`endpoints.${name}`, url]);
  }
  return urls;
}

/** Every string of a provider config but its client secret, each with its path. */
function providerStrings(
  value: unknown,
  path: readonly string[] = []
): [path: string, value: string][] {
  if (typeof value === 'string') {
    const name = path.join('.');
    return name === CLIENT_SECRET_PATH ? [] : [[name, value]];
  }
  if (value !== null && typeof value === 'object') {
    return Object.entries(value).flatMap(([key, member]) =>
      providerStrings(member, [...path, key])
    );
  }
  return [];
}

/**
 * Create a preset plugin's method on the generic upstream OpenID Connect
 * client (#951). A preset package exports it as `authMethod`.
 *
 * ```ts
 * export const authMethod = createUpstreamOidcPresetMethod({
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
 * @throws TypeError when `id` is `oidc` or no AuthMethod id, `type` is in
 *   the generic client's namespace or no AuthMethod type, `origins` is not a
 *   list of bare `https` origins, `upstreamConfig` or `identityClaims` is
 *   not a function, `responseMembers` names a protocol parameter or more
 *   than four members, or `attributes` is not a list of rules
 * @experimental
 */
export function createUpstreamOidcPresetMethod<TConfig>(
  options: UpstreamOidcPresetOptions<TConfig>
): AuthMethod<TConfig, UpstreamOidcTransaction> {
  const { id, type, display, configSchema, upstreamConfig } = options;
  if (
    typeof id !== 'string' ||
    !AUTH_METHOD_ID_PATTERN.test(id) ||
    id === UPSTREAM_OIDC_METHOD_ID
  ) {
    throw new TypeError(
      `id must be the preset's own AuthMethod id, such as example-idp: never ${UPSTREAM_OIDC_METHOD_ID}, the generic client's`
    );
  }
  if (
    typeof type !== 'string' ||
    !AUTH_METHOD_TYPE_PATTERN.test(type) ||
    UPSTREAM_OIDC_TYPE_PATTERN.test(type)
  ) {
    throw new TypeError(
      "type must be the preset's own AuthMethod type, such as example_idp: never oidc_<alias>, the generic client's namespace"
    );
  }
  const origins = presetOrigins(options.origins);
  if (typeof upstreamConfig !== 'function') {
    throw new TypeError('upstreamConfig must be a function of the parsed config');
  }
  if (options.identityClaims !== undefined && typeof options.identityClaims !== 'function') {
    throw new TypeError('identityClaims must be a function');
  }
  if (
    options.attributes !== undefined &&
    (!Array.isArray(options.attributes) ||
      !options.attributes.every(
        (rule) =>
          typeof rule === 'object' &&
          rule !== null &&
          typeof rule.claim === 'string' &&
          (rule.attribute === undefined || typeof rule.attribute === 'string') &&
          (rule.verified === undefined || typeof rule.verified === 'function')
      ))
  ) {
    throw new TypeError('attributes must be a list of claim attribute rules');
  }

  // The preset's secret members, read once from its schema. A schema the
  // reader refuses fails the plugin loader too; here it means no member is
  // secret, so a config that sends a client secret is refused.
  let secretPaths: readonly string[] | undefined;
  const presetSecretPaths = (): readonly string[] => {
    if (secretPaths === undefined) {
      try {
        secretPaths = Object.freeze(authMethodSecretPaths({ type, configSchema }));
      } catch {
        secretPaths = Object.freeze([]);
      }
    }
    return secretPaths;
  };

  /** The provider config of a parsed preset config, or the problems with it. */
  const resolve = (
    config: TConfig
  ): { readonly config: UpstreamOidcClientConfig } | { readonly problems: readonly string[] } => {
    let input: unknown;
    try {
      input = upstreamConfig(config);
    } catch {
      return { problems: ['upstreamConfig threw for the config'] };
    }
    const parsed = upstreamOidcClientConfigSchema.safeParse(input);
    if (!parsed.success) {
      return {
        problems: parsed.error.issues.map(
          (issue) =>
            `the provider config it makes does not parse at ${issue.path.join('.') || '(root)'}: ${issue.code}`
        ),
      };
    }
    const problems = providerUrls(parsed.data)
      .filter(([, url]) => !origins.has(originOf(url) ?? ''))
      .map(([name]) => `the provider config names its ${name} off the preset's origins`);
    const authentication = parsed.data.clientAuthentication;
    if (
      'clientSecret' in authentication &&
      !presetSecretPaths().some(
        (path) => configMemberAt(config, path) === authentication.clientSecret
      )
    ) {
      problems.push(
        "the client secret is not the value of one of the preset's secret members, so it would be stored in the clear"
      );
    }
    // A secret member's value anywhere else, in part too (a URL's path, a
    // scope), would go out and be logged in the clear.
    const secretValues = presetSecretPaths()
      .map((path) => configMemberAt(config, path))
      .filter((value): value is string => typeof value === 'string' && value.length > 0);
    for (const [name, value] of providerStrings(parsed.data)) {
      if (secretValues.some((secret) => value.includes(secret))) {
        problems.push(
          `the provider config carries the value of a secret member at ${name}, which would be sent in the clear`
        );
      }
    }
    return problems.length > 0 ? { problems } : { config: parsed.data };
  };

  const method = upstreamOidcClientMethod({
    id,
    type,
    display,
    // The preset's own schema, with the checks above: a config that fails
    // them is refused where the host parses it, at the admin API's configure
    // and at every context. The issues name no value.
    configSchema: configSchema.superRefine((config, context) => {
      const resolved = resolve(config);
      if ('problems' in resolved) {
        for (const message of resolved.problems) context.addIssue({ code: 'custom', message });
      }
    }),
    // Discovered endpoints too: the document is the provider's, but a path
    // of its origin an admin's config points the issuer at may serve one.
    endpointOrigins: origins,
    ...(options.responseMembers === undefined ? {} : { responseMembers: options.responseMembers }),
    ...(options.identityClaims === undefined ? {} : { identityClaims: options.identityClaims }),
    ...(options.attributes === undefined
      ? {}
      : { attributes: Object.freeze([...options.attributes]) }),
    providerConfig(config) {
      const resolved = resolve(config);
      if ('problems' in resolved) {
        // The host parsed the config with the schema above, which runs the
        // same checks: reaching this is a preset whose mapping is not pure.
        throw new Error(`The preset ${type} made a provider config that fails its checks`);
      }
      return resolved.config;
    },
  });
  return Object.freeze({
    ...method,
    // Where the client secret goes (#1031): the issuer and the token
    // endpoint set by hand that the config makes, as the generic client's
    // stored secret is bound to them. A discovered token endpoint is not part
    // of it: discovery reads the issuer's own document, on the origins.
    secretDestination(config: TConfig): string {
      const resolved = resolve(config);
      if ('problems' in resolved) {
        // As in providerConfig: the host passes only a config the schema
        // above parsed. The host counts a throw as a new destination.
        throw new Error(`The preset ${type} made a provider config that fails its checks`);
      }
      return upstreamClientSecretDestination(resolved.config);
    },
  });
}

import {
  AUTH_METHOD_CONTRACT,
  type AuthMethod,
  authMethodSecretPaths,
  configMemberAt,
  UPSTREAM_TENANT_PLACEHOLDER,
  type UpstreamOidcPresetOptions,
  upstreamOidcPresetProblems,
} from '@qauth-labs/server-federation';

import { type UpstreamOidcClientConfig, upstreamOidcClientConfigSchema } from './config';
import { upstreamClientSecretDestination } from './stored-config';
import { upstreamOidcClientMethod, type UpstreamOidcTransaction } from './upstream-oidc-method';

export type { UpstreamOidcPresetOptions };
export { MAX_UPSTREAM_OIDC_PRESET_ORIGINS } from '@qauth-labs/server-federation';

/**
 * A PRESET PLUGIN on the generic upstream OpenID Connect client (#951, #671):
 * an AuthMethod for one named provider, which the plugin runtime (#600)
 * builds from its package's `upstreamOidcPreset` export. The preset's shape,
 * `UpstreamOidcPresetOptions`, is the plugin SDK's (`@qauth-labs/plugin-sdk`),
 * so a preset written in its own repository against the SDK alone is what
 * this function builds; this library declares none of it again.
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
 * (`signed_client_secret`), an issuer template for a multi-tenant provider
 * whose shared endpoints serve many tenants (`tenantIssuer`), response
 * members its callback reads, claims from them and its config
 * (`identityClaims`) and its own attribute rules (`attributes`).
 *
 * Every call the client makes goes as a `remote_document` destination unless
 * the preset's own config names its origin (the context's rule), so the
 * deployment's egress allowlist never opens a private address for a preset.
 *
 * EXPERIMENTAL, like the contract it implements.
 *
 * @experimental
 */

/** Where the generic client's config holds the client secret. */
const CLIENT_SECRET_PATH = 'clientAuthentication.clientSecret';

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
 * client (#951). The plugin loader calls it for a package that exports an
 * `upstreamOidcPreset` (`defineUpstreamOidcPreset` of the plugin SDK, #671);
 * the server's own tests call it on options too.
 *
 * ```ts
 * const method = createUpstreamOidcPresetMethod({
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
 * @throws TypeError listing the problems `upstreamOidcPresetProblems` of the
 *   plugin SDK finds: `id` is `oidc` or no AuthMethod id, `type` is in the
 *   generic client's namespace or no AuthMethod type, `origins` is not a
 *   list of bare `https` origins, `upstreamConfig` or `identityClaims` is
 *   not a function, `responseMembers` names a protocol parameter or more
 *   than four members, or `attributes` is not a list of rules
 * @experimental
 */
export function createUpstreamOidcPresetMethod<TConfig>(
  options: UpstreamOidcPresetOptions<TConfig>
): AuthMethod<TConfig, UpstreamOidcTransaction> {
  // The SDK's static checks, the ones the plugin loader runs on a package's
  // preset: one implementation for the loader, the test kit and this.
  const problems = upstreamOidcPresetProblems({ ...options, contract: AUTH_METHOD_CONTRACT });
  if (problems.length > 0) {
    throw new TypeError(`The preset cannot be built:\n- ${problems.join('\n- ')}`);
  }
  const { id, type, display, configSchema, upstreamConfig } = options;
  const origins: ReadonlySet<string> = new Set(options.origins);

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

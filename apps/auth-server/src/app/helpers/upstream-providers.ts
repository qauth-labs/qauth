import type { RealmUpstreamProvider } from '@qauth-labs/fastify-plugin-db';
import {
  type AuthMethod,
  type AuthMethodContext,
  createAuthMethodContext,
  createUpstreamOidcMethod,
  openUpstreamOidcConfig,
  UPSTREAM_OIDC_TYPE_PATTERN,
} from '@qauth-labs/fastify-plugin-federation';
import type {
  UpstreamProviderDirectory,
  UpstreamProviderEntry,
} from '@qauth-labs/fastify-plugin-sign-in-engine';
import { DISPLAY_TEXT_PATTERN } from '@qauth-labs/shared-interaction-contract';
import type { FastifyInstance, FastifyRequest } from 'fastify';

import {
  AUTH_METHOD_PLUGIN_SIGNER_CALLER,
  authMethodPluginContext,
  authMethodPluginEnabledIn,
  type AuthMethodPluginRuntime,
} from './auth-method-plugins';
import { realmIssuer } from './realm-url';
import { requestRealm } from './request-realm';

/**
 * THE REALM'S UPSTREAM IDENTITY PROVIDERS (#639): who a person may sign in
 * through, as the `upstream` step lists them and the routing parameter
 * (`qauth_upstream`) names them.
 *
 * - A generic OpenID Connect provider (#601) is a row of
 *   `realm_upstream_providers`: its `oidc_<alias>` type, the name and order
 *   of its button, whether the sign-in page hides it, whether it is on, and
 *   whether an account it creates counts as verified (`marks_verified`). Its
 *   method is built per type, and its config opened with the signer at each
 *   use, its client secret included.
 * - An AuthMethod plugin (#600) the realm has enabled is a provider too,
 *   after the OpenID Connect ones: never hidden, and an account it creates
 *   counts as verified.
 *
 * A hidden provider is never listed; only the routing parameter reaches it.
 * A provider that is off is neither listed nor reachable.
 */

/** The most providers the `upstream` step lists: its schema's bound. */
export const MAX_OFFERED_UPSTREAM_PROVIDERS = 16;

/** A provider name the `upstream` step can carry: its schema's pattern. */
const STEP_PROVIDER_PATTERN = /^[a-z][a-z0-9_]{0,62}$/;

/** The longest button name the `upstream` step carries. */
const MAX_PROVIDER_NAME_LENGTH = 64;

/** A button name the `upstream` step can show: the contract's display text. */
const DISPLAY_TEXT = new RegExp(DISPLAY_TEXT_PATTERN, 'u');

/** One provider of a realm, as the flow starts and completes it. */
export interface RealmUpstreamProviderOf {
  /** What the step lists of it. */
  readonly entry: UpstreamProviderEntry;
  /** Its AuthMethod: the generic OpenID Connect client's for its type, or the plugin's. */
  readonly method: AuthMethod;
  /** Whether the sign-in page leaves it out: only the routing parameter reaches it. */
  readonly hidden: boolean;
  /**
   * Whether an account it creates counts as verified, and its verified
   * `email` attribute with it (the per-provider verified switch).
   */
  readonly marksVerified: boolean;
  /** Its context for the request's realm: config, egress, signer, logger. */
  context(request: FastifyRequest): Promise<AuthMethodContext>;
}

/** What the catalog reads: the repositories, the plugins, the signer and the egress client. */
export type UpstreamProviderServer = Pick<
  FastifyInstance,
  'repositories' | 'authMethodPlugins' | 'signer' | 'egress'
>;

/** The realm's providers: the listed ones, and any one by its type. */
export interface UpstreamProviderCatalog {
  /** The providers the step lists, in order: the OpenID Connect ones, then the plugins. */
  offered(realmId: string): Promise<UpstreamProviderEntry[]>;
  /** The provider of `type`, hidden or not, while it is on; `undefined` otherwise. */
  find(realmId: string, type: string): Promise<RealmUpstreamProviderOf | undefined>;
}

/**
 * The generic OpenID Connect methods of this process, one per type: a
 * method keeps the provider's discovery document and keys (per realm host
 * and issuer), so one per type serves every realm.
 */
const oidcMethods = new Map<string, AuthMethod>();

/** The generic OpenID Connect method of `type` (`oidc_<alias>`). */
export function upstreamOidcMethod(type: string): AuthMethod {
  let method = oidcMethods.get(type);
  if (method === undefined) {
    // The button's name is the realm's row's, never the method's.
    method = createUpstreamOidcMethod({ type, display: { name: type } }) as unknown as AuthMethod;
    oidcMethods.set(type, method);
  }
  return method;
}

/**
 * The routes every generic OpenID Connect provider declares (the callback
 * and its `form_post` bounce), for the family mount under `/upstream/:type`:
 * each request runs the routes of its own provider's method.
 */
export function upstreamOidcRoutes(): AuthMethod['routes'] {
  return createUpstreamOidcMethod({ type: 'oidc_routes', display: { name: 'routes' } })
    .routes as AuthMethod['routes'];
}

/** A button name the step can carry, from what an operator or a plugin set. */
function buttonName(name: string): string {
  return name.trim().slice(0, MAX_PROVIDER_NAME_LENGTH).trim();
}

/** Whether the step can show `name` as a button: one it cannot is left out of the list. */
function showable(name: string): boolean {
  return name.length > 0 && DISPLAY_TEXT.test(name);
}

/**
 * The context of a generic OpenID Connect provider for the request's realm:
 * its stored config opened with the signer as `api`, as the plugin runtime
 * opens a plugin's secrets (#600), its client secret kept out of the egress
 * labels and the log lines.
 */
async function oidcContext(
  fastify: UpstreamProviderServer,
  request: FastifyRequest,
  method: AuthMethod,
  row: RealmUpstreamProvider
): Promise<AuthMethodContext> {
  const realm = requestRealm(request);
  if (row.realmId !== realm.id) {
    throw new Error('an upstream provider of another realm');
  }
  const config = await openUpstreamOidcConfig(
    fastify.signer,
    { realmId: realm.id, providerId: row.type, caller: AUTH_METHOD_PLUGIN_SIGNER_CALLER },
    row.config
  );
  const secrets = new Map<string, string>();
  const authentication = config.clientAuthentication;
  if ('clientSecret' in authentication) {
    secrets.set('clientAuthentication.clientSecret', authentication.clientSecret);
  }
  return createAuthMethodContext(method, {
    config,
    secrets,
    // The callback answers on the realm's host, at its root.
    origin: new URL(realmIssuer(realm)).origin,
    realmName: realm.name,
    realmId: realm.id,
    providerId: row.type,
    signerCaller: AUTH_METHOD_PLUGIN_SIGNER_CALLER,
    egress: fastify.egress,
    signer: fastify.signer,
    log: request.log.child({ upstreamProvider: row.type }),
  });
}

/** The AuthMethod plugins this process loaded; none on a process that loads none. */
function installedPlugins(fastify: UpstreamProviderServer): AuthMethodPluginRuntime['installed'] {
  return (fastify.authMethodPlugins as AuthMethodPluginRuntime | undefined)?.installed ?? [];
}

/** The realm's upstream providers over the server's repositories and plugins. */
export function upstreamProviderCatalog(fastify: UpstreamProviderServer): UpstreamProviderCatalog {
  return Object.freeze({
    async offered(realmId: string): Promise<UpstreamProviderEntry[]> {
      const entries: UpstreamProviderEntry[] = [];
      const rows = await fastify.repositories.realmUpstreamProviders.listByRealm(realmId);
      for (const row of rows) {
        if (!row.enabled || row.hidden || !UPSTREAM_OIDC_TYPE_PATTERN.test(row.type)) continue;
        const name = buttonName(row.displayName);
        if (showable(name)) entries.push({ provider: row.type, name });
      }
      for (const plugin of installedPlugins(fastify)) {
        if (
          !STEP_PROVIDER_PATTERN.test(plugin.type) ||
          UPSTREAM_OIDC_TYPE_PATTERN.test(plugin.type) ||
          !(await authMethodPluginEnabledIn(fastify, realmId, plugin))
        ) {
          continue;
        }
        const name = buttonName(plugin.method.display.name);
        if (showable(name)) entries.push({ provider: plugin.type, name });
      }
      return entries.slice(0, MAX_OFFERED_UPSTREAM_PROVIDERS);
    },

    async find(realmId: string, type: string): Promise<RealmUpstreamProviderOf | undefined> {
      if (UPSTREAM_OIDC_TYPE_PATTERN.test(type)) {
        const row = await fastify.repositories.realmUpstreamProviders.find(realmId, type);
        if (row === undefined || !row.enabled) return undefined;
        const method = upstreamOidcMethod(type);
        return Object.freeze({
          entry: Object.freeze({ provider: type, name: buttonName(row.displayName) }),
          method,
          hidden: row.hidden,
          marksVerified: row.marksVerified,
          context: (request: FastifyRequest) => oidcContext(fastify, request, method, row),
        });
      }
      if (!STEP_PROVIDER_PATTERN.test(type)) return undefined;
      const plugin = installedPlugins(fastify).find((installed) => installed.type === type);
      if (plugin === undefined || !(await authMethodPluginEnabledIn(fastify, realmId, plugin))) {
        return undefined;
      }
      return Object.freeze({
        entry: Object.freeze({ provider: type, name: buttonName(plugin.method.display.name) }),
        method: plugin.method,
        hidden: false,
        marksVerified: true,
        context: (request: FastifyRequest) =>
          authMethodPluginContext(fastify, request, plugin.method),
      });
    },
  });
}

/** The sign-in engine's provider directory (#639): the realm's listed providers. */
export function upstreamProviderDirectory(
  fastify: UpstreamProviderServer
): UpstreamProviderDirectory {
  const catalog = upstreamProviderCatalog(fastify);
  const directory: UpstreamProviderDirectory = {
    offered: ({ realmId }) => catalog.offered(realmId),
  };
  return Object.freeze(directory);
}

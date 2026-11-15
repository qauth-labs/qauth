import { DISPLAY_TEXT_PATTERN } from '@qauth-labs/shared-interaction-contract';
import { consentTextFor, PROTECTED_RESOURCE_LIMITS } from '@qauth-labs/shared-validation';
import type { FastifyInstance } from 'fastify';

/**
 * THE SCOPES OF A REGISTERED PROTECTED RESOURCE (#1087).
 *
 * A realm registers protected resources (`protected_resources`): a resource
 * indicator (RFC 8707), the scopes it defines with their consent texts, and
 * who may ask for them, every client of the realm or the listed
 * `client_id`s. A scope a registered resource defines is bound to it:
 *
 * - it is granted only when the authorization request names that resource
 *   (`resource`), and then to any client the resource is open to, a CIMD or
 *   dynamically registered client included, whatever the client's own
 *   `scopes` list holds. The user's consent is still required, and it is
 *   recorded per resource (`oauth_consents.resource_scopes`);
 * - asked for without its resource, or with another, it is dropped, so a
 *   token's `aud` and the resource scopes it carries always agree. A client
 *   the resource is not open to gets none of its scopes, its own list
 *   notwithstanding;
 * - a request that names several resources gets it only when each of them is
 *   a registered resource that defines it and is open to the client. A token
 *   is one credential for every audience it names, so a scope one of them
 *   granted would otherwise reach another that never did: one that defines a
 *   scope of the same name but is closed to the client, or one QAuth does not
 *   know.
 *
 * Every other scope keeps the client's own `scopes` list as its ceiling. With
 * no registered resource, the rule is the client list alone, as before.
 *
 * The code grant applies the rule again to a code's scopes at the resources
 * the token is issued for, and the refresh grant to the family's at the
 * resources of the refresh, so a narrowed audience drops the scopes of the
 * resources it no longer names, and a resource closed since drops its own.
 */

/** A scope a registered resource defines, as the rule reads it. */
export interface RegisteredResourceScope {
  readonly scope: string;
  /** The consent text by BCP 47 locale; English is always among them. */
  readonly text: Readonly<Record<string, string>>;
  readonly sensitive: boolean;
}

/**
 * A registered protected resource, as the rule reads it: the shape of a
 * `protected_resources` row it needs. Kept local, as `consent.ts` keeps its
 * client view: the app does not import the database library's types.
 */
export interface RegisteredResource {
  readonly resource: string;
  readonly scopes: readonly RegisteredResourceScope[];
  readonly anyClient: boolean;
  readonly clientIds: readonly string[];
}

/** The client the rule asks about: its `client_id` and its own scope list. */
export interface ScopeRuleClient {
  readonly clientId: string;
  readonly scopes: readonly string[];
}

/** A realm's registered resources, read once per request. */
export type RegisteredResources = readonly RegisteredResource[];

/**
 * The realm's registered protected resources, read in `tx` when given.
 * Every path that grants a user's scopes reads them first.
 */
export async function registeredResourcesOf(
  fastify: Pick<FastifyInstance, 'repositories'>,
  realmId: string,
  tx?: Parameters<FastifyInstance['repositories']['protectedResources']['listByRealm']>[1]
): Promise<RegisteredResources> {
  return fastify.repositories.protectedResources.listByRealm(realmId, tx);
}

/** Whether the resource is open to the client: every client, or one it lists. */
function openTo(resource: RegisteredResource, clientId: string): boolean {
  return resource.anyClient || resource.clientIds.includes(clientId);
}

/** Whether some registered resource defines `scope`. */
export function isResourceBoundScope(scope: string, registered: RegisteredResources): boolean {
  return registered.some((resource) => resource.scopes.some((entry) => entry.scope === scope));
}

/**
 * The entry of `scope` that grants it to this request, or `undefined`. It is
 * granted only when the request names at least one resource and every one of
 * them is a registered resource that defines the scope and is open to the
 * client; the entry is the first named resource's, whose consent text the
 * consent step shows.
 */
export function grantingEntry(
  scope: string,
  client: Pick<ScopeRuleClient, 'clientId'>,
  resources: readonly string[],
  registered: RegisteredResources
): RegisteredResourceScope | undefined {
  let granting: RegisteredResourceScope | undefined;
  for (const indicator of resources) {
    const resource = registered.find((candidate) => candidate.resource === indicator);
    if (resource === undefined || !openTo(resource, client.clientId)) return undefined;
    const entry = resource.scopes.find((candidate) => candidate.scope === scope);
    if (entry === undefined) return undefined;
    granting ??= entry;
  }
  return granting;
}

/**
 * Whether the rule grants `scope` to the client for a request that names
 * `resources`: when a registered resource defines the scope, by the
 * registrations of the resources the request names ({@link grantingEntry}),
 * by the client's own list otherwise.
 */
export function isScopeGrantable(
  scope: string,
  client: ScopeRuleClient,
  resources: readonly string[],
  registered: RegisteredResources
): boolean {
  if (isResourceBoundScope(scope, registered)) {
    return grantingEntry(scope, client, resources, registered) !== undefined;
  }
  return client.scopes.includes(scope);
}

/**
 * The requested scopes (space-delimited) the rule grants the client for a
 * request that names `resources`, in the request's order, each once. Every
 * other requested scope is dropped silently, the deny-by-default behaviour of
 * `/oauth/authorize`: a client with no scope list and no open resource gets
 * nothing.
 *
 * With no registered resource it is the client's allowlist alone
 * (`filterRequestedScopes` in `consent.ts`).
 */
export function grantRequestedScopes(
  requestedRaw: string | undefined,
  client: ScopeRuleClient,
  resources: readonly string[],
  registered: RegisteredResources
): string[] {
  const requested = (requestedRaw ?? '').split(/\s+/).filter((s) => s.length > 0);
  const out: string[] = [];
  const seen = new Set<string>();
  for (const scope of requested) {
    if (seen.has(scope)) continue;
    seen.add(scope);
    if (isScopeGrantable(scope, client, resources, registered)) out.push(scope);
  }
  return out;
}

/**
 * `scopes` without the resource-bound ones the rule does not grant the client
 * at `resources`, in their order: what the token endpoint issues from a
 * code's or a refresh token's scopes. A scope no registered resource defines
 * is kept: the grant applies its own ceiling to it.
 */
export function withoutUngrantedResourceScopes(
  scopes: readonly string[],
  client: Pick<ScopeRuleClient, 'clientId'>,
  resources: readonly string[],
  registered: RegisteredResources
): string[] {
  return scopes.filter(
    (scope) =>
      !isResourceBoundScope(scope, registered) ||
      grantingEntry(scope, client, resources, registered) !== undefined
  );
}

/**
 * The granted `scopes` the client gets through a registered resource alone,
 * which its own list does not hold. No operator vouched for this client
 * having them, so a first-party client's administrative consent does not
 * cover them: only the user's consent does.
 */
export function scopesOnlyAResourceGrants(
  scopes: readonly string[],
  client: ScopeRuleClient,
  registered: RegisteredResources
): string[] {
  return scopes.filter(
    (scope) => isResourceBoundScope(scope, registered) && !client.scopes.includes(scope)
  );
}

/**
 * The client's scope ceiling at `resources`: its own list without the scopes a
 * registered resource defines, and with those the rule grants it there. The
 * refresh grant checks the family's scopes against it.
 */
export function scopeCeilingAt(
  client: ScopeRuleClient,
  resources: readonly string[],
  registered: RegisteredResources
): string[] {
  const ceiling = new Set(
    client.scopes.filter((scope) => !isResourceBoundScope(scope, registered))
  );
  // Only a scope the first named resource defines can be granted at all.
  const first = registered.find((resource) => resource.resource === resources[0]);
  for (const entry of first?.scopes ?? []) {
    if (grantingEntry(entry.scope, client, resources, registered) !== undefined) {
      ceiling.add(entry.scope);
    }
  }
  return [...ceiling];
}

/**
 * What the consent step shows for a resource-bound scope the request was
 * granted: the resource's own text in the first of `locales` it holds, else
 * English, and whether the realm flags it as sensitive. `undefined` for a
 * scope no registration grants this request.
 */
export function resourceScopeDisplay(
  scope: string,
  client: Pick<ScopeRuleClient, 'clientId'>,
  resources: readonly string[],
  registered: RegisteredResources,
  locales: readonly string[]
): { readonly text: string | undefined; readonly sensitive: boolean } | undefined {
  const entry = grantingEntry(scope, client, resources, registered);
  if (entry === undefined) return undefined;
  const text = consentTextFor(entry.text, locales);
  return {
    text: text !== undefined && isShowable(text) ? text : undefined,
    sensitive: entry.sensitive === true,
  };
}

const DISPLAY_TEXT = new RegExp(DISPLAY_TEXT_PATTERN, 'u');

/**
 * Whether a stored text is one the consent step can show. The admin API and
 * the seed manifest store no other, but a row written by hand is read too:
 * such a text is left out, and the step shows the scope's value, rather than
 * the step refusing to render.
 */
function isShowable(text: string): boolean {
  return (
    typeof text === 'string' &&
    text.length <= PROTECTED_RESOURCE_LIMITS.textMaxLength &&
    DISPLAY_TEXT.test(text)
  );
}

/** The most `ui_locales` tags the consent step reads. */
const UI_LOCALES_MAX = 8;

/** A BCP 47 language tag, as the Interaction API's `uiLocales` carries one. */
const LOCALE_TAG = /^[a-z]{2,3}(?:-[A-Za-z0-9]{1,8})*$/i;

/**
 * The tags of an authorization request's `ui_locales` (OpenID Connect Core
 * 1.0 §3.1.2.1, space-separated, preferred first) the consent texts are
 * picked by: the well-formed ones, in order, at most eight. A malformed tag is
 * skipped, as an unsupported one would be.
 */
export function uiLocalesOf(raw: string | undefined): string[] {
  if (raw === undefined) return [];
  return raw
    .split(' ')
    .filter((tag) => tag.length > 0 && tag.length <= 35 && LOCALE_TAG.test(tag))
    .slice(0, UI_LOCALES_MAX);
}

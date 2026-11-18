import { isDeepStrictEqual } from 'node:util';

import type { RealmFileClient } from '@qauth-labs/realm-file';
import {
  ADMIN_API_AUDIENCE,
  firstPartyPolicySchema,
  type SecurityEffect,
} from '@qauth-labs/shared-validation';

import type { Classification } from '../../helpers/admin-operations';
import { ENVIRONMENTS } from '../../helpers/environment-policy';
import { AGENT_MODES } from '../../helpers/scope-modes';
import type { ChangeDirection } from '../change-preview';
import {
  classificationOfClientChange,
  type ClientFieldName,
  holdsAdminScope,
  listDirection,
} from '../clients/fields';
import { type AdminClient, shownFirstPartyPolicy } from '../clients/representation';

/**
 * THE FIELDS OF A `clients` ENTRY, AS AN IMPORT COMPARES THEM (ADR-019
 * Decision 11, issue #518): every member of a realm file's client but its
 * natural key, `client_id`, with the value it stores, which way a change of
 * it moves, and what the change needs.
 *
 * - **What it stores.** A member the entry leaves out stores what the seed
 *   manifest stores for it (`buildInsert` in `infra-db`'s
 *   `seed-clients.ts`): an entry is the whole client, as a manifest's is.
 *   Every list that is a set is compared as one, sorted (RFC 8785's order).
 * - **What a change needs.** Each change is authorized as the single
 *   operation it equals (ADR-019 Decision 11): a member the admin API's
 *   client representation holds is classified as `clients.update` classifies
 *   its change (`classificationOfClientChange`, the client field table of
 *   #632, with its rules for a scope that widens `client_credentials` and a
 *   client that holds an admin scope). A member no admin operation writes
 *   yet (the audience, the ID-JAG targets, the passkey origins, the hosted
 *   flows, the registration challenge) fails closed: every change of it is a
 *   security change with the effect `token-content`, needing
 *   `clients.security`.
 * - **Which way it moves.** The directions of #518's table: a list tightens
 *   with fewer entries and loosens with one added; a requirement tightens
 *   when it is switched on; how the client authenticates ranks
 *   `private_key_jwt`, then the two secret methods, then `none`; being an
 *   agent and the agent mode loosen as they rise; an environment loosens
 *   toward `development`; a key set, a key set's URL and the first-party and
 *   domain fields have no known direction, so any change loosens; the name
 *   and the description are neutral.
 *
 * {@link IMPORT_CLIENT_FIELDS} is typed by the realm file's client, so a
 * member the seed manifest adds fails the build until it has an entry here.
 */

/** A member of a `clients` entry an import compares: every one but its natural key. */
export type ImportClientFieldName = Exclude<keyof RealmFileClient, 'client_id'>;

/** One member and how an import judges a change of it. */
export interface ImportClientField {
  /**
   * The member of the admin API's client representation it is, whose change
   * `clients.update` classifies; absent for a member no admin operation
   * writes yet, every change of which is a security change.
   */
  readonly admin?: ClientFieldName;
  /** The value an entry stores for it: the seed manifest's default when the entry leaves it out. */
  readonly stored: (entry: RealmFileClient) => unknown;
  /** Which way a change from `before` to `after`, two stored values, moves. */
  readonly direction: (before: unknown, after: unknown) => ChangeDirection;
  /**
   * Whether a change describes the environment the client runs in, which a
   * sandbox promotion leaves out unless it is selected (ADR-019 Decision 11).
   */
  readonly environmentBound?: (before: unknown, after: unknown) => boolean;
}

/** Strings in UTF-16 code unit order, as RFC 8785 orders object members. */
const byCodeUnit = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

/** A list that is a set: each value once, sorted. */
export const sortedSet = (values: readonly string[]): string[] =>
  [...new Set(values)].sort(byCodeUnit);

/** A list a member may leave out, stored as the empty list. */
const listOrEmpty = (values: readonly string[] | null | undefined): string[] =>
  sortedSet(values ?? []);

/**
 * A key set with each key's members in code unit order and the keys as
 * written: the order the realm file's canonical form keeps (#515).
 */
function canonicalKeySet(jwks: { readonly keys: readonly Record<string, unknown>[] }): unknown {
  return {
    keys: jwks.keys.map((key) =>
      Object.fromEntries(
        Object.keys(key)
          .sort(byCodeUnit)
          .map((member) => [member, structuredClone(key[member])])
      )
    ),
  };
}

/** The first-party policy a `native_backend` entry stores: its own, or the defaults. */
function storedFirstPartyPolicyOf(entry: RealmFileClient): unknown {
  if (entry.first_party_profile !== 'native_backend') return null;
  const policy = entry.first_party_policy ?? firstPartyPolicySchema.parse({});
  return { ...policy, flows: sortedSet(policy.flows) };
}

/** No change moves. */
const neutral = (): ChangeDirection => 'neutral';

/** A change whose direction is not known: it counts as loosening. */
const unknownDirection = (before: unknown, after: unknown): ChangeDirection =>
  isDeepStrictEqual(before, after) ? 'neutral' : 'loosening';

/** A list of entries, `null` for none: fewer tighten, one added loosens. */
function entriesDirection(before: unknown, after: unknown): ChangeDirection {
  const was = new Set(Array.isArray(before) ? before.map(String) : []);
  const now = new Set(Array.isArray(after) ? after.map(String) : []);
  if ([...now].some((value) => !was.has(value))) return 'loosening';
  return [...was].some((value) => !now.has(value)) ? 'tightening' : 'neutral';
}

/**
 * Which way a value moves on a scale from the laxest to the strictest. An
 * unknown value ranks -1, below every known one, so moving to it loosens,
 * and so does a move between two unknown values; two known values of one
 * rank (the two secret methods) are as strict as each other.
 */
const rankedDirection =
  (rank: (value: unknown) => number) =>
  (before: unknown, after: unknown): ChangeDirection => {
    const was = rank(before);
    const now = rank(after);
    if (now === was) {
      return now === -1 && !isDeepStrictEqual(before, after) ? 'loosening' : 'neutral';
    }
    return now > was ? 'tightening' : 'loosening';
  };

/** A requirement: on is the stricter. */
const requirementDirection = rankedDirection((value) =>
  value === true ? 1 : value === false ? 0 : -1
);

/** A capability: off is the stricter. */
const capabilityDirection = rankedDirection((value) =>
  value === false ? 1 : value === true ? 0 : -1
);

/** How a client authenticates, by strictness: `private_key_jwt`, then a secret, then `none`. */
const AUTH_METHOD_RANK: Readonly<Record<string, number>> = Object.freeze({
  none: 0,
  client_secret_basic: 1,
  client_secret_post: 1,
  private_key_jwt: 2,
});

const authMethodDirection = rankedDirection((value) =>
  typeof value === 'string' && Object.hasOwn(AUTH_METHOD_RANK, value) ? AUTH_METHOD_RANK[value] : -1
);

/** The agent mode, by strictness: no mode (deny) the strictest, `exec` the laxest. */
const agentModeDirection = rankedDirection((value) => {
  if (value === null) return AGENT_MODES.length;
  const index = AGENT_MODES.indexOf(value as (typeof AGENT_MODES)[number]);
  return index === -1 ? -1 : AGENT_MODES.length - 1 - index;
});

/** The environment, by strictness (ADR-008): `development` the laxest. */
const environmentDirection = rankedDirection((value) =>
  ENVIRONMENTS.indexOf(value as (typeof ENVIRONMENTS)[number])
);

/** Setting or changing where logout tokens go loosens; removing it tightens. */
const destinationDirection = (before: unknown, after: unknown): ChangeDirection => {
  if (isDeepStrictEqual(before, after)) return 'neutral';
  return after === null ? 'tightening' : 'loosening';
};

/** Whether a list of URIs holds an `http` one: a loopback URI, which only a local app has. */
const holdsHttpUri = (value: unknown): boolean =>
  Array.isArray(value) && value.some((uri) => typeof uri === 'string' && /^http:/i.test(uri));

const httpUriBound = (before: unknown, after: unknown): boolean =>
  holdsHttpUri(before) || holdsHttpUri(after);

const alwaysBound = (): boolean => true;

/**
 * Every member of a `clients` entry but `client_id`, in the order of the
 * seed manifest's schema. The order is the plan's: an update lists its
 * changes in it.
 */
export const IMPORT_CLIENT_FIELDS = Object.freeze({
  name: { admin: 'name', stored: (entry) => entry.name, direction: neutral },
  description: {
    admin: 'description',
    stored: (entry) => entry.description ?? null,
    direction: neutral,
  },
  grant_types: {
    admin: 'grantTypes',
    stored: (entry) => sortedSet(entry.grant_types),
    direction: listDirection,
  },
  response_types: {
    admin: 'responseTypes',
    stored: (entry) => sortedSet(entry.response_types ?? ['code']),
    direction: listDirection,
  },
  scopes: {
    admin: 'scopes',
    stored: (entry) => listOrEmpty(entry.scopes),
    direction: listDirection,
  },
  client_credentials_scopes: {
    admin: 'clientCredentialsScopes',
    // Left out, the grant may issue any scope of `scopes`: `null`, every value.
    stored: (entry) =>
      entry.client_credentials_scopes === undefined
        ? null
        : sortedSet(entry.client_credentials_scopes),
    direction: listDirection,
  },
  audience: {
    // An empty list or none: the token endpoint names the client itself.
    stored: (entry) =>
      entry.audience === undefined || entry.audience === null || entry.audience.length === 0
        ? null
        : sortedSet(entry.audience),
    direction: entriesDirection,
  },
  redirect_uris: {
    admin: 'redirectUris',
    stored: (entry) => listOrEmpty(entry.redirect_uris),
    direction: listDirection,
    environmentBound: httpUriBound,
  },
  post_logout_redirect_uris: {
    admin: 'postLogoutRedirectUris',
    stored: (entry) => listOrEmpty(entry.post_logout_redirect_uris),
    direction: listDirection,
    environmentBound: httpUriBound,
  },
  backchannel_logout_uri: {
    admin: 'backchannelLogoutUri',
    stored: (entry) => entry.backchannel_logout_uri ?? null,
    direction: destinationDirection,
    environmentBound: alwaysBound,
  },
  backchannel_logout_session_required: {
    admin: 'backchannelLogoutSessionRequired',
    stored: (entry) => entry.backchannel_logout_session_required ?? false,
    direction: neutral,
  },
  require_pkce: {
    admin: 'requirePkce',
    stored: (entry) => entry.require_pkce ?? true,
    direction: requirementDirection,
  },
  token_endpoint_auth_method: {
    admin: 'tokenEndpointAuthMethod',
    stored: (entry) => entry.token_endpoint_auth_method ?? 'client_secret_basic',
    direction: authMethodDirection,
  },
  is_agent: {
    admin: 'isAgent',
    stored: (entry) => entry.is_agent ?? false,
    direction: capabilityDirection,
  },
  max_agent_mode: {
    admin: 'maxAgentMode',
    stored: (entry) => entry.max_agent_mode ?? null,
    direction: agentModeDirection,
  },
  id_jag_targets: {
    stored: (entry) => listOrEmpty(entry.id_jag_targets),
    direction: entriesDirection,
  },
  jwks: {
    admin: 'jwks',
    stored: (entry) => (entry.jwks === undefined ? null : canonicalKeySet(entry.jwks)),
    direction: unknownDirection,
  },
  jwks_uri: {
    admin: 'jwksUri',
    stored: (entry) => entry.jwks_uri ?? null,
    direction: unknownDirection,
  },
  webauthn_allowed_origins: {
    stored: (entry) => listOrEmpty(entry.webauthn_allowed_origins),
    direction: entriesDirection,
  },
  dpop_bound_access_tokens: {
    admin: 'dpopBoundAccessTokens',
    stored: (entry) => entry.dpop_bound_access_tokens ?? false,
    direction: requirementDirection,
  },
  verified_domain: {
    admin: 'verifiedDomain',
    stored: (entry) => entry.verified_domain ?? null,
    direction: unknownDirection,
  },
  first_party_profile: {
    admin: 'firstPartyProfile',
    stored: (entry) => entry.first_party_profile ?? null,
    direction: unknownDirection,
  },
  first_party_policy: {
    admin: 'firstPartyPolicy',
    stored: storedFirstPartyPolicyOf,
    direction: unknownDirection,
  },
  first_party_reason: {
    admin: 'firstPartyReason',
    stored: (entry) =>
      entry.first_party_profile === undefined ? null : (entry.first_party_reason ?? null),
    direction: unknownDirection,
  },
  hosted_flows: {
    stored: (entry) =>
      entry.hosted_flows === undefined || entry.hosted_flows.length === 0
        ? null
        : sortedSet(entry.hosted_flows),
    direction: entriesDirection,
  },
  registration_challenge: {
    stored: (entry) => entry.registration_challenge === true,
    direction: requirementDirection,
  },
  environment: {
    admin: 'environment',
    stored: (entry) => entry.environment ?? 'production',
    direction: environmentDirection,
    environmentBound: alwaysBound,
  },
} satisfies Record<ImportClientFieldName, ImportClientField>);

/** The members, in table order. */
export const IMPORT_CLIENT_FIELD_NAMES: readonly ImportClientFieldName[] = Object.freeze(
  Object.keys(IMPORT_CLIENT_FIELDS) as ImportClientFieldName[]
);

/** An entry as it stores: every member of the table with its value. */
export type StoredClient = Readonly<Record<ImportClientFieldName, unknown>> & {
  readonly client_id: string;
};

/** What `entry` stores, member by member. */
export function storedClientOf(entry: RealmFileClient): StoredClient {
  const stored: Record<string, unknown> = { client_id: entry.client_id };
  for (const name of IMPORT_CLIENT_FIELD_NAMES) {
    stored[name] = (IMPORT_CLIENT_FIELDS[name] as ImportClientField).stored(entry);
  }
  return stored as StoredClient;
}

/**
 * The admin API's client representation of a stored entry, as far as the
 * client field table reads it: every member the table maps, the first-party
 * policy in the representation's member names. The read-only members, which
 * no change touches, are left at placeholders.
 */
function adminViewOf(client: StoredClient): AdminClient {
  const view: Record<string, unknown> = {
    id: '00000000-0000-0000-0000-000000000000',
    client_id: client.client_id,
    developerId: null,
    provisionedByOperator: true,
    dynamicallyRegistered: false,
    metadataDocument: null,
    enabled: true,
    suspended: false,
    suspendedAt: null,
    backchannelLogoutUriSource: client.backchannel_logout_uri === null ? null : 'admin',
    accessTokenLifespanSeconds: null,
    refreshTokenLifespanSeconds: null,
    createdAt: '1970-01-01T00:00:00.000Z',
    updatedAt: '1970-01-01T00:00:00.000Z',
    lastUsedAt: null,
  };
  for (const name of IMPORT_CLIENT_FIELD_NAMES) {
    const admin = (IMPORT_CLIENT_FIELDS[name] as ImportClientField).admin;
    if (admin === undefined) continue;
    view[admin] =
      name === 'first_party_policy' ? shownFirstPartyPolicy(client[name]) : client[name];
  }
  return view as AdminClient;
}

/** What a change of a member no admin operation writes needs: a security change, failed closed. */
function unmappedClassification(
  name: ImportClientFieldName,
  before: StoredClient,
  after: StoredClient
): Classification {
  const effects: SecurityEffect[] = ['token-content'];
  const namesAdminAudience = (client: StoredClient) =>
    Array.isArray(client.audience) && client.audience.includes(ADMIN_API_AUDIENCE);
  if (
    holdsAdminScope({ scopes: before.scopes as string[] }) ||
    holdsAdminScope({ scopes: after.scopes as string[] }) ||
    (name === 'audience' && (namesAdminAudience(before) || namesAdminAudience(after)))
  ) {
    effects.push('administration');
  }
  return { class: 'security', effects, permissions: ['clients.security'] };
}

/** One changed member of a client the file and the realm both hold. */
export interface ClientFieldChange {
  readonly name: ImportClientFieldName;
  readonly before: unknown;
  readonly after: unknown;
  readonly direction: ChangeDirection;
  readonly classification: Classification;
  readonly environmentBound: boolean;
}

/**
 * The members `after` stores differently from `before`, in table order, each
 * with its direction and the classification of the single operation it
 * equals.
 */
export function clientFieldChanges(before: StoredClient, after: StoredClient): ClientFieldChange[] {
  const state = adminViewOf(before);
  const client = adminViewOf(after);
  const changes: ClientFieldChange[] = [];
  for (const name of IMPORT_CLIENT_FIELD_NAMES) {
    const field: ImportClientField = IMPORT_CLIENT_FIELDS[name];
    const was = before[name];
    const now = after[name];
    if (isDeepStrictEqual(was, now)) continue;
    changes.push({
      name,
      before: was,
      after: now,
      direction: field.direction(was, now),
      classification:
        field.admin === undefined
          ? unmappedClassification(name, before, after)
          : classificationOfClientChange(field.admin, state, client),
      environmentBound: field.environmentBound?.(was, now) ?? false,
    });
  }
  return changes;
}

/** Whether a stored client describes the environment it runs in (ADR-019 Decision 11). */
export function isEnvironmentBoundClient(client: StoredClient): boolean {
  return (
    client.environment !== 'production' ||
    client.backchannel_logout_uri !== null ||
    holdsHttpUri(client.redirect_uris) ||
    holdsHttpUri(client.post_logout_redirect_uris)
  );
}

/** The ways a client authenticates with a secret, which the realm keeps and a file never holds. */
const SECRET_METHODS: ReadonlySet<unknown> = new Set(['client_secret_basic', 'client_secret_post']);

/** Whether a stored client authenticates with a client secret. */
export const authenticatesWithSecret = (client: StoredClient): boolean =>
  SECRET_METHODS.has(client.token_endpoint_auth_method);

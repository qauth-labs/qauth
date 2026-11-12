import { isDeepStrictEqual } from 'node:util';

import {
  firstPartyPolicySchema,
  isReservedQauthScope,
  normaliseVerifiedDomain,
  type SecurityEffect,
} from '@qauth-labs/shared-validation';

// Values from the classification module, never from the registry, which
// imports this one: see `helpers/admin-classification.ts`.
import {
  classifyByField,
  type FieldRule,
  mergeClassifications,
  mergePatchLeafPaths,
} from '../../helpers/admin-classification';
import type { Classification, ClassifyInput } from '../../helpers/admin-operations';
import { ADMIN_SCOPE_LIST } from '../../helpers/admin-scopes';
import { ENVIRONMENTS } from '../../helpers/environment-policy';
import { AGENT_MODES } from '../../helpers/scope-modes';
import type { ChangeDirection } from '../change-preview';
import { type AdminClient, shownFirstPartyPolicy, storedFirstPartyPolicy } from './representation';

/**
 * THE FIELD TABLE OF A CLIENT (ADR-020 §3 and its Appendix, ADR-019 Decision
 * 7, issue #632): every member of the client representation with its class,
 * and the classification of a client update built from it.
 *
 * - `read-only`: no operation's body takes it: what the server keeps, and
 *   what `clients.enable` and `clients.disable` switch.
 * - `write`: every change is a write, `qauth:admin:write`.
 * - `security`: every change is a security change, `qauth:admin:security`
 *   and an approval, with the field's effects: the redirect URIs, the
 *   post-logout redirect URIs, how the client authenticates and its keys,
 *   first-party trust, the verified domain, the agent-type fields and the
 *   grant and response types a client may add.
 * - `security-when`: a change is a security change when the field's own
 *   rule says (`securityWhen`), and a write otherwise: switching PKCE or
 *   DPoP off, a looser environment, a longer token lifetime, a wider
 *   `client_credentials` list, a back-channel logout URI set, a `qauth:`
 *   scope added. Tightening each is a write.
 *
 * {@link CLIENT_FIELDS} is typed by the representation's keys, so a member
 * added to the representation without an entry fails the build, and a unit
 * test holds the table to the schema's keys too.
 */

/** The class of a client field. */
export type ClientFieldClass = 'read-only' | 'write' | 'security' | 'security-when';

/** One member of the client representation and what a change of it needs. */
export interface ClientField {
  readonly class: ClientFieldClass;
  /** The effects of a security change of the field; empty for `read-only` and `write`. */
  readonly effects: readonly SecurityEffect[];
  /** With `security-when`: whether a change from `before` to `after` is a security change. */
  readonly securityWhen?: (before: unknown, after: unknown) => boolean;
  /** Which way a change moves. Absent: `neutral` for a write, `loosening` for a security field. */
  readonly direction?: (before: unknown, after: unknown) => ChangeDirection;
  /** What the class rests on, in one sentence, for the docs and the approver. */
  readonly rule: string;
}

/** The members of a string list, or `undefined` when `value` is not one. */
function setOf(value: unknown): Set<string> | undefined {
  return Array.isArray(value) ? new Set(value.map(String)) : undefined;
}

/**
 * Which way a list moves as a set: only removals tighten, only additions
 * loosen, both loosen (a direction that is not known counts as loosening).
 * `null` stands for every value: a list in its place tightens.
 */
export function listDirection(before: unknown, after: unknown): ChangeDirection {
  if (before === null && after === null) return 'neutral';
  if (after === null) return 'loosening';
  if (before === null) return 'tightening';
  const was = setOf(before) ?? new Set<string>();
  const now = setOf(after) ?? new Set<string>();
  const added = [...now].some((value) => !was.has(value));
  const removed = [...was].some((value) => !now.has(value));
  if (added) return 'loosening';
  return removed ? 'tightening' : 'neutral';
}

/** Which way a requirement moves: `true` is the stricter. */
function requirementDirection(before: unknown, after: unknown): ChangeDirection {
  if (before === after) return 'neutral';
  return after === true ? 'tightening' : 'loosening';
}

/** A token lifetime in seconds, `null` (the realm's) as the longest. */
const lifetimeOf = (value: unknown): number =>
  typeof value === 'number' ? value : Number.POSITIVE_INFINITY;

function lifetimeDirection(before: unknown, after: unknown): ChangeDirection {
  const was = lifetimeOf(before);
  const now = lifetimeOf(after);
  if (now === was) return 'neutral';
  return now > was ? 'loosening' : 'tightening';
}

/** How strict an environment is (ADR-008): `development` the laxest. */
const environmentRank = (value: unknown): number =>
  ENVIRONMENTS.indexOf(value as (typeof ENVIRONMENTS)[number]);

function environmentDirection(before: unknown, after: unknown): ChangeDirection {
  const was = environmentRank(before);
  const now = environmentRank(after);
  if (now === was) return 'neutral';
  // An unknown value ranks -1: the laxest.
  return now < was ? 'loosening' : 'tightening';
}

/** How much an agent may do: no mode (deny) the least. */
const agentModeRank = (value: unknown): number =>
  value === null ? -1 : AGENT_MODES.indexOf(value as (typeof AGENT_MODES)[number]);

function agentModeDirection(before: unknown, after: unknown): ChangeDirection {
  const was = agentModeRank(before);
  const now = agentModeRank(after);
  if (now === was) return 'neutral';
  return now > was ? 'loosening' : 'tightening';
}

const loosens =
  (direction: (before: unknown, after: unknown) => ChangeDirection) =>
  (before: unknown, after: unknown): boolean =>
    direction(before, after) === 'loosening';

const READ_ONLY = (rule: string): ClientField => ({ class: 'read-only', effects: [], rule });
const WRITE_FIELD = (rule: string, direction?: ClientField['direction']): ClientField => ({
  class: 'write',
  effects: [],
  rule,
  ...(direction === undefined ? {} : { direction }),
});
const SECURITY_FIELD = (
  effects: readonly SecurityEffect[],
  rule: string,
  direction?: ClientField['direction']
): ClientField => ({
  class: 'security',
  effects,
  rule,
  ...(direction === undefined ? {} : { direction }),
});
const SECURITY_WHEN = (
  effects: readonly SecurityEffect[],
  rule: string,
  direction: NonNullable<ClientField['direction']>,
  securityWhen: (before: unknown, after: unknown) => boolean = loosens(direction)
): ClientField => ({ class: 'security-when', effects, rule, direction, securityWhen });

/**
 * Every member of the client representation, with its class. The order is
 * the representation's, and a preview lists its changes in it.
 */
export const CLIENT_FIELDS = Object.freeze({
  id: READ_ONLY('The id the server gave the client.'),
  client_id: READ_ONLY('The OAuth client_id, which tokens and grants name: never changed.'),
  name: WRITE_FIELD('The name the client is shown under: display data.'),
  description: WRITE_FIELD('A description for admins: display data.'),
  developerId: READ_ONLY('Who owns the client: the developer API keeps it (ADR-012).'),
  provisionedByOperator: READ_ONLY('Set when an operator or an admin registers the client.'),
  dynamicallyRegistered: READ_ONLY('Set by RFC 7591 registration.'),
  metadataDocument: READ_ONLY('A CIMD client’s document, which no admin changes.'),
  enabled: READ_ONLY('The owner’s switch; clients.enable turns it on for a client with no owner.'),
  suspended: READ_ONLY('Switched by clients.disable and clients.enable.'),
  suspendedAt: READ_ONLY('Set with the suspension.'),
  redirectUris: SECURITY_FIELD(
    ['token-content'],
    'Where authorization codes are sent: every change decides who receives a code.',
    listDirection
  ),
  postLogoutRedirectUris: SECURITY_FIELD(
    ['posture-loosening'],
    'Where the end-session route may send the browser (#675): every change is a security change.',
    listDirection
  ),
  backchannelLogoutUri: SECURITY_WHEN(
    ['token-content'],
    'Where logout tokens naming the user and the session go (#624): setting or changing it is a security change, removing it a write.',
    (before, after) => (before === after ? 'neutral' : after === null ? 'tightening' : 'loosening')
  ),
  backchannelLogoutUriSource: READ_ONLY('Set with the back-channel logout URI: admin.'),
  backchannelLogoutSessionRequired: WRITE_FIELD(
    'Whether the client needs sid in a logout token; QAuth sends one in every token.'
  ),
  scopes: SECURITY_WHEN(
    ['token-content'],
    'The scopes the client may request: a write, but adding a scope of the reserved qauth: namespace is a security change.',
    listDirection,
    (before, after) => {
      const was = setOf(before) ?? new Set<string>();
      return [...(setOf(after) ?? [])].some(
        (scope) => isReservedQauthScope(scope) && !was.has(scope)
      );
    }
  ),
  clientCredentialsScopes: SECURITY_WHEN(
    ['token-content'],
    'The scopes a token naming no user may carry (#891): lifting or widening the list is a security change, narrowing it a write.',
    listDirection
  ),
  grantTypes: SECURITY_WHEN(
    ['token-content'],
    'How the client may obtain tokens: adding a grant type is a security change, removing one a write.',
    listDirection
  ),
  responseTypes: SECURITY_WHEN(
    ['token-content'],
    'The response types of the authorization endpoint: adding one is a security change, removing one a write.',
    listDirection
  ),
  tokenEndpointAuthMethod: SECURITY_FIELD(
    ['token-content'],
    'How the client authenticates: every change decides who can obtain its tokens.'
  ),
  jwks: SECURITY_FIELD(
    ['token-content'],
    'The keys a private_key_jwt client authenticates with: every change decides who can obtain its tokens.'
  ),
  jwksUri: SECURITY_FIELD(
    ['token-content'],
    'Where the keys of a private_key_jwt client are fetched from: every change decides who can obtain its tokens.'
  ),
  requirePkce: SECURITY_WHEN(
    ['posture-loosening'],
    'Switching PKCE off is a security change; switching it on a write.',
    requirementDirection
  ),
  dpopBoundAccessTokens: SECURITY_WHEN(
    ['posture-loosening'],
    'Switching DPoP binding off is a security change (RFC 9449); switching it on a write.',
    requirementDirection
  ),
  environment: SECURITY_WHEN(
    ['posture-loosening'],
    'A laxer environment is a security change (ADR-008); a stricter one a write.',
    environmentDirection
  ),
  isAgent: SECURITY_FIELD(
    ['token-content'],
    'Whether the client is an agent (ADR-007 §2): every change changes what its tokens assert.',
    requirementDirection
  ),
  maxAgentMode: SECURITY_FIELD(
    ['token-content'],
    'The most an agent may do: every change changes what its tokens may carry.',
    agentModeDirection
  ),
  verifiedDomain: SECURITY_FIELD(
    ['token-content'],
    'The domain every screen shows first for the client (ADR-019 Decision 6): every change is a security change.'
  ),
  firstPartyProfile: SECURITY_FIELD(
    ['token-content'],
    'First-party trust (ADR-017 Decision 2): every change, its removal included, is a security change.'
  ),
  firstPartyPolicy: SECURITY_FIELD(
    ['token-content'],
    'A native_backend client’s policy: every change is a security change.'
  ),
  firstPartyReason: SECURITY_FIELD(
    ['token-content'],
    'The written reason for first-party trust: every change is a security change.'
  ),
  accessTokenLifespanSeconds: SECURITY_WHEN(
    ['posture-loosening'],
    'The client’s own access token lifetime, at most the realm’s: shortening it is a write, lengthening it or giving it back to the realm’s a security change.',
    lifetimeDirection
  ),
  refreshTokenLifespanSeconds: SECURITY_WHEN(
    ['posture-loosening'],
    'The client’s own refresh token lifetime, at most the realm’s: shortening it is a write, lengthening it or giving it back to the realm’s a security change.',
    lifetimeDirection
  ),
  createdAt: READ_ONLY('Set by the server.'),
  updatedAt: READ_ONLY('Set by the server.'),
  lastUsedAt: READ_ONLY('Set when the client obtains a token.'),
} satisfies Record<keyof AdminClient, ClientField>);

/** A member of the representation. */
export type ClientFieldName = keyof AdminClient;

/** The members an update and a create take: every field that is not read-only. */
export const PATCHABLE_CLIENT_FIELDS: readonly ClientFieldName[] = Object.freeze(
  (Object.keys(CLIENT_FIELDS) as ClientFieldName[]).filter(
    (name) => CLIENT_FIELDS[name].class !== 'read-only'
  )
);

/** A patchable member. */
export type PatchableClientField = Exclude<
  ClientFieldName,
  | 'id'
  | 'client_id'
  | 'developerId'
  | 'provisionedByOperator'
  | 'dynamicallyRegistered'
  | 'metadataDocument'
  | 'enabled'
  | 'suspended'
  | 'suspendedAt'
  | 'backchannelLogoutUriSource'
  | 'createdAt'
  | 'updatedAt'
  | 'lastUsedAt'
>;

/**
 * What a member set to `null` takes: the value a create gives it when it is
 * left out. A member with no default (`name`, `tokenEndpointAuthMethod`,
 * `grantTypes`) takes no `null`: a patch that sends one is refused (422).
 */
export const CLIENT_FIELD_DEFAULTS: Readonly<Partial<Record<PatchableClientField, unknown>>> =
  Object.freeze({
    description: null,
    redirectUris: [],
    postLogoutRedirectUris: [],
    backchannelLogoutUri: null,
    backchannelLogoutSessionRequired: false,
    scopes: [],
    clientCredentialsScopes: null,
    responseTypes: ['code'],
    jwks: null,
    jwksUri: null,
    requirePkce: true,
    dpopBoundAccessTokens: false,
    environment: 'production',
    isAgent: false,
    maxAgentMode: null,
    verifiedDomain: null,
    firstPartyProfile: null,
    firstPartyPolicy: null,
    firstPartyReason: null,
    accessTokenLifespanSeconds: null,
    refreshTokenLifespanSeconds: null,
  });

/** One member a request got wrong: a JSON Pointer and a message. */
export interface ClientFieldProblem {
  readonly pointer: string;
  readonly message: string;
}

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' &&
  value !== null &&
  !Array.isArray(value) &&
  (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);

/** RFC 7396 §2: `patch` applied to `target`. Copies; changes neither. */
export function mergePatch(target: unknown, patch: unknown): unknown {
  if (!isPlainObject(patch)) return structuredClone(patch);
  const result: Record<string, unknown> = isPlainObject(target) ? structuredClone(target) : {};
  for (const [key, value] of Object.entries(patch)) {
    if (value === null) delete result[key];
    else result[key] = mergePatch(result[key], value);
  }
  return result;
}

/** A client once a patch is applied, and what the patch named. */
export interface AppliedClientPatch {
  /** The client the patch makes, normalised as it would be stored. */
  readonly client: AdminClient;
  /** The members the patch names, by name. */
  readonly named: ReadonlySet<string>;
  /** Members the patch sets to `null` that have no default. */
  readonly problems: readonly ClientFieldProblem[];
}

/**
 * The client `body`, a JSON Merge Patch (RFC 7396), makes of `state`, as it
 * would be stored. Pure: the classification, the preview, the approval's
 * rendering and the handler each compute it alike.
 *
 * - Each patchable member the body names is merged; `null` gives it its
 *   default ({@link CLIENT_FIELD_DEFAULTS}), and a member with none keeps
 *   its value and is reported in `problems`. A member that is not patchable
 *   is ignored here: the body schema refuses it, and the classification
 *   fails such a request closed.
 * - A list the patch names drops repeats; a verified domain it names takes
 *   its stored form when it has one. A member it does not name stays as
 *   stored.
 * - When the patch names a member of first-party trust, the three stay
 *   consistent (ADR-017 Decision 2): removing the
 *   profile removes its policy and its reason, and `web_redirect` drops a
 *   policy, unless the patch names them (the check then refuses them);
 *   `native_backend` takes its policy with every member, the defaults
 *   filled in.
 * - The back-channel logout URI says who set it: `admin`.
 */
export function applyClientPatch(state: AdminClient, body: unknown): AppliedClientPatch {
  const patch = isPlainObject(body) ? body : {};
  const named = new Set(Object.keys(patch));
  const client = structuredClone(state) as Record<string, unknown>;
  const problems: ClientFieldProblem[] = [];
  for (const name of PATCHABLE_CLIENT_FIELDS) {
    if (!Object.hasOwn(patch, name)) continue;
    const value = patch[name];
    if (value === null) {
      if (Object.hasOwn(CLIENT_FIELD_DEFAULTS, name)) {
        client[name] = structuredClone(CLIENT_FIELD_DEFAULTS[name as PatchableClientField]);
      } else {
        problems.push({ pointer: `/${name}`, message: `${name} is required and has no default` });
      }
      continue;
    }
    client[name] = mergePatch(client[name], value);
  }

  // Only what the patch names is normalised: a member it leaves alone is
  // stored as it was, whatever an older path wrote.
  for (const list of [
    'redirectUris',
    'postLogoutRedirectUris',
    'scopes',
    'grantTypes',
    'clientCredentialsScopes',
  ]) {
    if (named.has(list) && Array.isArray(client[list])) {
      client[list] = [...new Set(client[list] as unknown[])];
    }
  }
  if (named.has('verifiedDomain') && typeof client['verifiedDomain'] === 'string') {
    try {
      client['verifiedDomain'] = normaliseVerifiedDomain(client['verifiedDomain']);
    } catch {
      // Kept as sent: the check refuses it, naming the field.
    }
  }

  // A policy or a reason the patch itself names is kept as sent, so the
  // check refuses one that the profile does not take. A patch that names no
  // member of first-party trust leaves all three as stored.
  const profile = client['firstPartyProfile'];
  const namesTrust = ['firstPartyProfile', 'firstPartyPolicy', 'firstPartyReason'].some((name) =>
    named.has(name)
  );
  if (namesTrust && profile === null) {
    if (!named.has('firstPartyPolicy')) client['firstPartyPolicy'] = null;
    if (!named.has('firstPartyReason')) client['firstPartyReason'] = null;
  } else if (namesTrust && profile === 'web_redirect' && !named.has('firstPartyPolicy')) {
    client['firstPartyPolicy'] = null;
  } else if (namesTrust && profile === 'native_backend') {
    const policy = firstPartyPolicySchema.safeParse(
      storedFirstPartyPolicy(client['firstPartyPolicy'] ?? {})
    );
    // A policy that does not parse is kept as sent: the check refuses it.
    if (policy.success) client['firstPartyPolicy'] = shownFirstPartyPolicy(policy.data);
  }

  if (client['backchannelLogoutUri'] !== state.backchannelLogoutUri) {
    client['backchannelLogoutUriSource'] = client['backchannelLogoutUri'] === null ? null : 'admin';
  }
  return { client: client as AdminClient, named, problems };
}

/** The fields whose value differs between `before` and `after`, in table order. */
export function changedClientFields(before: AdminClient, after: AdminClient): ClientFieldName[] {
  return (Object.keys(CLIENT_FIELDS) as ClientFieldName[]).filter(
    (name) =>
      CLIENT_FIELDS[name].class !== 'read-only' && !isDeepStrictEqual(before[name], after[name])
  );
}

/** What a request that changes nothing, or a change that is a write, needs. */
const WRITE: Classification = Object.freeze({
  class: 'write',
  effects: Object.freeze([]),
  permissions: Object.freeze(['clients.write']),
});

/**
 * What every update needs besides its change: reading the client, since it
 * answers the client's representation. Without it a token with
 * `qauth:admin:write` alone would read any client through a patch that
 * changes nothing.
 */
const READ: Classification = Object.freeze({
  class: 'read',
  effects: Object.freeze([]),
  permissions: Object.freeze(['clients.read']),
});

/** What a change of one field needs, by its entry. */
export function classificationOfClientField(
  name: ClientFieldName,
  before: unknown,
  after: unknown
): Classification {
  const field: ClientField = CLIENT_FIELDS[name];
  if (isDeepStrictEqual(before, after)) return WRITE;
  const security: Classification = {
    class: 'security',
    effects: [...field.effects],
    permissions: ['clients.security'],
  };
  switch (field.class) {
    case 'write':
      return WRITE;
    case 'security':
      return security;
    case 'security-when':
      return field.securityWhen?.(before, after) === false ? WRITE : security;
    case 'read-only':
      // No body takes it; should one, the request fails closed.
      return security;
  }
}

/** The admin API's own scopes, which only an admin token carries. */
const ADMIN_SCOPES: ReadonlySet<string> = new Set(ADMIN_SCOPE_LIST);

/**
 * Whether a client may obtain admin tokens: it holds a scope of the admin
 * API (`qauth:admin:*`). Every change of one changes who can administer, a
 * narrowing too: a write that took `qauth:admin:security` from the admin
 * console's client, suspended it or cut its token lifetime to a second
 * would leave no token able to undo it.
 */
export function holdsAdminScope(client: Pick<AdminClient, 'scopes'>): boolean {
  return client.scopes.some((scope) => ADMIN_SCOPES.has(scope));
}

/**
 * Whether a change of `scopes` gives a client a scope it may obtain as
 * itself: it has the `client_credentials` grant and no
 * `clientCredentialsScopes` list, so every scope of `scopes` is issued to
 * it without a user and without consent (#891).
 */
function widensClientCredentials(state: AdminClient, client: AdminClient): boolean {
  return (
    (client.grantTypes as readonly string[]).includes('client_credentials') &&
    client.clientCredentialsScopes === null &&
    client.scopes.some((scope) => !state.scopes.includes(scope))
  );
}

/** `classification` as a security change, with `effect` among its effects. */
function asSecurity(classification: Classification, effect: SecurityEffect): Classification {
  const effects = classification.class === 'security' ? [...classification.effects] : [];
  return {
    class: 'security',
    effects: effects.includes(effect) ? effects : [...effects, effect],
    permissions: ['clients.security'],
  };
}

/**
 * What the change of one field from `state` to `client` needs: its entry in
 * the field table ({@link classificationOfClientField}), and two rules that
 * read the rest of the client. A scope added to a `client_credentials`
 * client without a list is a security change (`token-content`), and every
 * change of a client that holds an admin scope, or gets one, is a security
 * change with the effect `administration` ({@link holdsAdminScope}).
 */
export function classificationOfClientChange(
  name: ClientFieldName,
  state: AdminClient,
  client: AdminClient
): Classification {
  const before = state[name];
  const after = client[name];
  let classification = classificationOfClientField(name, before, after);
  if (isDeepStrictEqual(before, after)) return classification;
  if (name === 'scopes' && widensClientCredentials(state, client)) {
    classification = asSecurity(classification, 'token-content');
  }
  if (holdsAdminScope(state) || holdsAdminScope(client)) {
    classification = asSecurity(classification, 'administration');
  }
  return classification;
}

/** Which way a change of one field moves, by its entry. */
export function directionOfClientField(
  name: ClientFieldName,
  before: unknown,
  after: unknown
): ChangeDirection {
  if (isDeepStrictEqual(before, after)) return 'neutral';
  const field: ClientField = CLIENT_FIELDS[name];
  if (field.direction !== undefined) return field.direction(before, after);
  return field.class === 'write' ? 'neutral' : 'loosening';
}

/** A JSON Pointer's first token, unescaped (RFC 6901): the member of the representation it names. */
function memberOf(pointer: string): string {
  const token = pointer.split('/')[1] ?? '';
  return token.replace(/~1/g, '/').replace(/~0/g, '~');
}

/**
 * The classification of a client update (API-03): the leaf paths of its body
 * (`mergePatchLeafPaths`), each mapped to the member of the representation it
 * is in, so a member the table does not hold, a read-only one included,
 * fails the request closed (`classifyByField`), and every member the patched
 * client holds differently besides, which the patch did not name but its
 * rules changed; each member is classified by its change on the patched
 * client ({@link classificationOfClientChange}), and the update always needs
 * `clients.read` too: it answers the client.
 */
export function classifyClientPatch(request: ClassifyInput, state: AdminClient): Classification {
  const { client } = applyClientPatch(state, request.body);
  const fields: Record<string, FieldRule<AdminClient>> = {};
  for (const name of PATCHABLE_CLIENT_FIELDS) {
    fields[name] = () => classificationOfClientChange(name, state, client);
  }
  const members = new Set([
    ...mergePatchLeafPaths(request.body).map(memberOf),
    ...changedClientFields(state, client),
  ]);
  return mergeClassifications([
    READ,
    classifyByField<AdminClient>({ changedFields: () => members, fields, unchanged: WRITE })(
      request,
      state
    ),
  ]);
}

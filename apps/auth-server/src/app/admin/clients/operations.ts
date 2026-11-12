import { InvalidClientError, NotFoundError } from '@qauth-labs/shared-errors';
import {
  backchannelLogoutUriProblem,
  firstPartyPolicySchema,
  InvalidVerifiedDomainError,
  isNativeBrowserLegRedirectUri,
  normaliseVerifiedDomain,
} from '@qauth-labs/shared-validation';
import type { FastifyInstance, FastifyRequest } from 'fastify';

import type {
  AdminOperationDefinition,
  ClassifyInput,
  RenderedField,
  RenderedOperation,
  RenderInput,
} from '../../helpers/admin-operations';
import { UnprocessableContentError } from '../../helpers/api-request-errors';
import { ClientManagedByDocumentError } from '../../helpers/admin-client-errors';
import { parseClientJwkSet } from '../../helpers/client-jwks';
import {
  validatePostLogoutRedirectUri,
  validateRedirectUri,
} from '../../helpers/dynamic-client-registration';
import { resolveEnvironmentPolicy } from '../../helpers/environment-policy';
import { tokenLifetimesOf } from '../../helpers/realm-policy-readers';
import type { RealmRow } from '../../helpers/request-realm';
import {
  applyClientPatch,
  type AppliedClientPatch,
  changedClientFields,
  classifyClientPatch,
  CLIENT_FIELDS,
  type ClientFieldProblem,
} from './fields';
import {
  type AdminClient,
  adminClientOf,
  adminClientVersion,
  CLIENT_URI_MAX_LENGTH,
  storedFirstPartyPolicy,
} from './representation';

/**
 * THE CLIENT OPERATIONS OF THE ADMIN API (ADR-020 §3 and its Appendix,
 * ADR-019 Decision 7, ADR-012, ADR-008; issue #632): list and read every
 * client of a realm, whoever owns it, register one, change it, preview a
 * change, delete it, and suspend it or lift its suspension.
 *
 * - `clients.list`, `clients.get` and `clients.preview` are reads
 *   (`clients.read`). The developer API keeps its own list, of a developer's
 *   own clients only (ADR-012 Decision 4).
 * - `clients.update` patches the client with a JSON Merge Patch and needs
 *   what its change needs, field by field (`./fields.ts`): a security change
 *   needs `clients.security`, so `qauth:admin:security` and an approval, with
 *   the field's effects; any other `clients.write`. A patch of both needs
 *   both, and one approval. Every patch needs `clients.read` too: it answers
 *   the client. `clients.preview` answers what the same patch would change
 *   and need, and writes nothing (#589).
 * - `clients.create` and `clients.delete` are security operations on every
 *   request (`admin-operations-reserved.ts`), and so is `clients.enable`:
 *   lifting a suspension gives the client its tokens back. `clients.disable`,
 *   the suspension, only takes them away: a write.
 *
 * A client registered from a Client ID Metadata Document (CIMD) is read-only
 * (ADR-012 Decision 3): its document is where it is changed, and every
 * resolution rewrites the row from it. An update, its preview and a deletion
 * of one are refused with 409, naming the document. Its suspension is not in
 * the document, so `clients.disable` and `clients.enable` take one too: they
 * are the operator's switch for every client.
 *
 * `clients.update`, `clients.delete` and `clients.enable` read the client
 * (`loadState`): its version is the client's `ETag`, which the request names
 * in `If-Match`, and an approval approves the request against that version
 * only. A client of another realm is 404, as one that does not exist.
 */

/** The ids of the client operations. */
export const CLIENT_OPERATION_IDS = Object.freeze({
  list: 'clients.list',
  get: 'clients.get',
  create: 'clients.create',
  update: 'clients.update',
  preview: 'clients.preview',
  delete: 'clients.delete',
  enable: 'clients.enable',
  disable: 'clients.disable',
} as const);

/** The repositories the state reads, with the transaction they read in. */
type StateServer = Pick<FastifyInstance, 'repositories'>;
type Transaction = Parameters<FastifyInstance['repositories']['oauthClients']['findById']>[2];

/** RFC 9562: the form of the id the admin API names a client by. */
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * The client `id` of the realm, as the admin API shows it, read in `tx` when
 * given.
 *
 * @throws NotFoundError when the realm has no such client: one of another
 *   realm is not found either
 */
export async function readClientState(
  server: StateServer,
  realmId: string,
  id: string,
  tx?: Transaction
): Promise<AdminClient> {
  if (!UUID.test(id)) throw new NotFoundError('OAuthClient', id);
  const row = await server.repositories.oauthClients.findById(realmId, id, tx);
  if (row === undefined) throw new NotFoundError('OAuthClient', id);
  return adminClientOf(row);
}

/**
 * Refuse a change of a client whose settings come from its Client ID
 * Metadata Document (ADR-012 Decision 3).
 *
 * @throws ClientManagedByDocumentError naming the document
 */
export function refuseDocumentClient(client: Pick<AdminClient, 'metadataDocument'>): void {
  if (client.metadataDocument !== null) {
    throw new ClientManagedByDocumentError(client.metadataDocument);
  }
}

/** What the checks of a client's settings read beside the client itself. */
export interface ClientCheckContext {
  /** The private-use redirect URI schemes the deployment allows (`REDIRECT_URI_CUSTOM_SCHEMES`). */
  readonly customSchemes: readonly string[];
  /** The realm's access token lifetime for a client in `environment`. */
  realmAccessLifetime(environment: AdminClient['environment']): number;
  /** The realm's refresh token lifetime. */
  readonly realmRefreshLifetime: number;
}

/** The context of the checks, for the realm `realm` of the request. */
export async function clientCheckContext(
  request: FastifyRequest,
  realm: RealmRow
): Promise<ClientCheckContext> {
  // Imported here, not with the module: the operation registry imports it,
  // and the environment is read and checked at import.
  const { env } = await import('../../../config/env');
  const lifetimes = tokenLifetimesOf(request.server, realm);
  return {
    customSchemes: env.REDIRECT_URI_CUSTOM_SCHEMES,
    realmAccessLifetime: (environment) =>
      resolveEnvironmentPolicy({ environment }, realm).accessTokenLifespanTier === 'long'
        ? lifetimes.developmentAccessTokenLifespanSeconds
        : lifetimes.accessTokenLifespanSeconds,
    realmRefreshLifetime: lifetimes.refreshTokenLifespanSeconds,
  };
}

/** The description of a refusal a registration validator throws. */
function refusalOf(error: unknown): string {
  if (typeof error === 'object' && error !== null) {
    const description = (error as { errorDescription?: unknown }).errorDescription;
    if (typeof description === 'string' && description !== '') return description;
    const message = (error as { message?: unknown }).message;
    if (typeof message === 'string' && message !== '') return message;
  }
  return 'is not valid';
}

/** Whether `uri` is an absolute `https` URL with no credentials and no fragment. */
function isHttpsUri(uri: string): boolean {
  if (uri.length > CLIENT_URI_MAX_LENGTH || /[\s]/.test(uri)) return false;
  try {
    const url = new URL(uri);
    return (
      url.protocol === 'https:' &&
      url.username === '' &&
      url.password === '' &&
      url.hash === '' &&
      !uri.includes('#')
    );
  } catch {
    return false;
  }
}

/** The grants that send a user through the browser, and so need a redirect URI. */
const USER_GRANTS = ['authorization_code', 'refresh_token'];

/**
 * What is wrong with the settings `applied` gives a client, each as a JSON
 * Pointer into the body and a message: empty when nothing is. A member's own
 * checks run when the request names it (`all` for a creation); the rules
 * across members run when it names any member they read, so a stored value an
 * earlier release allowed does not block an unrelated change. The database
 * CHECKs hold first-party trust on every path besides (#631).
 */
export function clientSettingsProblems(
  applied: AppliedClientPatch,
  context: ClientCheckContext,
  all = false
): ClientFieldProblem[] {
  const { client } = applied;
  const named = (...names: (keyof AdminClient)[]): boolean =>
    all || names.some((name) => applied.named.has(name));
  const problems: ClientFieldProblem[] = [...applied.problems];
  const refuse = (pointer: string, message: string) => problems.push({ pointer, message });

  if (named('name') && client.name.trim() === '') refuse('/name', 'name is blank');

  if (named('redirectUris')) {
    client.redirectUris.forEach((uri, index) => {
      try {
        validateRedirectUri(uri, context.customSchemes);
      } catch (error) {
        refuse(`/redirectUris/${index}`, refusalOf(error));
      }
    });
  }
  if (named('postLogoutRedirectUris')) {
    client.postLogoutRedirectUris.forEach((uri, index) => {
      try {
        validatePostLogoutRedirectUri(uri, context.customSchemes);
      } catch (error) {
        refuse(`/postLogoutRedirectUris/${index}`, refusalOf(error));
      }
    });
  }
  if (named('backchannelLogoutUri') && client.backchannelLogoutUri !== null) {
    const problem = backchannelLogoutUriProblem(client.backchannelLogoutUri);
    if (problem !== undefined) refuse('/backchannelLogoutUri', `backchannelLogoutUri ${problem}`);
  }
  if (named('jwksUri') && client.jwksUri !== null && !isHttpsUri(client.jwksUri)) {
    refuse('/jwksUri', 'jwksUri must be an absolute https URL with no credentials and no fragment');
  }
  if (named('jwks') && client.jwks !== null) {
    try {
      parseClientJwkSet(client.jwks, 'jwks');
    } catch (error) {
      if (!(error instanceof InvalidClientError)) throw error;
      refuse('/jwks', error.message);
    }
  }

  // RFC 7591 §2: one key set, and a private_key_jwt client needs one.
  if (named('jwks', 'jwksUri', 'tokenEndpointAuthMethod')) {
    if (client.jwks !== null && client.jwksUri !== null) {
      refuse('/jwks', 'jwks and jwksUri are mutually exclusive (RFC 7591 §2): set at most one');
    }
    if (
      client.tokenEndpointAuthMethod === 'private_key_jwt' &&
      client.jwks === null &&
      client.jwksUri === null
    ) {
      refuse('/tokenEndpointAuthMethod', 'private_key_jwt requires jwks or jwksUri');
    }
  }

  // The grant and response rules of every registration path.
  if (named('grantTypes', 'responseTypes', 'tokenEndpointAuthMethod', 'redirectUris')) {
    const grants: readonly string[] = client.grantTypes;
    const responses: readonly string[] = client.responseTypes;
    if (grants.includes('authorization_code') && !responses.includes('code')) {
      refuse('/responseTypes', 'the authorization_code grant requires the code response type');
    }
    if (!grants.includes('authorization_code') && responses.length > 0) {
      refuse('/responseTypes', 'a response type requires the authorization_code grant');
    }
    if (client.tokenEndpointAuthMethod === 'none' && grants.includes('client_credentials')) {
      refuse(
        '/tokenEndpointAuthMethod',
        'the client_credentials grant requires a confidential client: tokenEndpointAuthMethod must not be none'
      );
    }
    if (grants.some((grant) => USER_GRANTS.includes(grant)) && client.redirectUris.length === 0) {
      refuse(
        '/redirectUris',
        'a client with the authorization_code or refresh_token grant needs a redirect URI'
      );
    }
  }

  // #891: the list narrows `scopes` for the client_credentials grant.
  if (named('clientCredentialsScopes', 'scopes', 'grantTypes') && client.clientCredentialsScopes) {
    if (client.clientCredentialsScopes.length === 0) {
      refuse(
        '/clientCredentialsScopes',
        'clientCredentialsScopes is empty: to let the client get no token as itself, remove the client_credentials grant'
      );
    }
    if (!(client.grantTypes as readonly string[]).includes('client_credentials')) {
      refuse(
        '/clientCredentialsScopes',
        'clientCredentialsScopes applies only to a client with the client_credentials grant'
      );
    }
    const held = new Set(client.scopes);
    for (const scope of client.clientCredentialsScopes) {
      if (!held.has(scope)) {
        refuse(
          '/clientCredentialsScopes',
          `${scope} is not in scopes: the list names only scopes the client holds`
        );
      }
    }
  }

  // ADR-017 Decision 2 (#631), in the operator's own terms first.
  if (
    named(
      'firstPartyProfile',
      'firstPartyPolicy',
      'firstPartyReason',
      'tokenEndpointAuthMethod',
      'isAgent',
      'grantTypes',
      'redirectUris'
    )
  ) {
    firstPartyProblems(client).forEach(({ pointer, message }) => refuse(pointer, message));
  }

  // ADR-019 Decision 6 (#593): only an operator-provisioned client takes one.
  if (named('verifiedDomain') && client.verifiedDomain !== null) {
    try {
      normaliseVerifiedDomain(client.verifiedDomain);
      if (!client.provisionedByOperator) {
        refuse(
          '/verifiedDomain',
          'only a client an operator provisioned takes a verified domain: a developer or the client itself registered this one'
        );
      }
    } catch (error) {
      if (!(error instanceof InvalidVerifiedDomainError)) throw error;
      refuse('/verifiedDomain', error.message);
    }
  }

  // ADR-020 §3: a client's own lifetime is never longer than the realm's.
  if (named('accessTokenLifespanSeconds') && client.accessTokenLifespanSeconds !== null) {
    const realm = context.realmAccessLifetime(client.environment);
    if (client.accessTokenLifespanSeconds > realm) {
      refuse(
        '/accessTokenLifespanSeconds',
        `accessTokenLifespanSeconds is longer than the realm's access token lifetime for this environment, ${realm} seconds: a client's own lifetime may only be shorter`
      );
    }
  }
  if (named('refreshTokenLifespanSeconds') && client.refreshTokenLifespanSeconds !== null) {
    const realm = context.realmRefreshLifetime;
    if (client.refreshTokenLifespanSeconds > realm) {
      refuse(
        '/refreshTokenLifespanSeconds',
        `refreshTokenLifespanSeconds is longer than the realm's refresh token lifetime, ${realm} seconds: a client's own lifetime may only be shorter`
      );
    }
  }
  return problems;
}

/** What first-party trust needs of a client (ADR-017 Decision 2, the seed manifest's rules). */
function firstPartyProblems(client: AdminClient): ClientFieldProblem[] {
  const problems: ClientFieldProblem[] = [];
  const refuse = (pointer: string, message: string) => problems.push({ pointer, message });
  const profile = client.firstPartyProfile;
  if (profile === null) {
    if (client.firstPartyPolicy !== null) {
      refuse('/firstPartyPolicy', 'firstPartyPolicy applies only to the native_backend profile');
    }
    if (client.firstPartyReason !== null) {
      refuse('/firstPartyReason', 'firstPartyReason applies only together with a profile');
    }
    return problems;
  }
  if (client.developerId !== null) {
    refuse('/firstPartyProfile', 'a client a developer owns is never first party');
  }
  if (client.dynamicallyRegistered) {
    refuse('/firstPartyProfile', 'a client that registered itself is never first party');
  }
  if (client.isAgent) refuse('/firstPartyProfile', 'an agent is never first party');
  if (client.tokenEndpointAuthMethod !== 'private_key_jwt') {
    refuse(
      '/tokenEndpointAuthMethod',
      'a first-party client authenticates with private_key_jwt: never with a secret, nor as a public client'
    );
  }
  if (client.firstPartyReason === null || client.firstPartyReason.trim() === '') {
    refuse(
      '/firstPartyReason',
      "a first-party profile needs a written reason: why this deployment's operator controls the app and users see it under the operator's brand"
    );
  }
  if (profile === 'web_redirect') {
    if (client.firstPartyPolicy !== null) {
      refuse('/firstPartyPolicy', 'firstPartyPolicy applies only to the native_backend profile');
    }
    return problems;
  }
  if (
    !firstPartyPolicySchema.safeParse(storedFirstPartyPolicy(client.firstPartyPolicy ?? {})).success
  ) {
    refuse('/firstPartyPolicy', 'firstPartyPolicy is not a valid native_backend policy');
  }
  if (!(client.grantTypes as readonly string[]).includes('authorization_code')) {
    refuse('/grantTypes', 'the native_backend profile requires the authorization_code grant');
  }
  if (!client.redirectUris.some(isNativeBrowserLegRedirectUri)) {
    refuse(
      '/redirectUris',
      'the native_backend profile needs a redirect URI for the browser leg: an https URI, a private-use scheme in reverse domain-name form or an http loopback IP literal'
    );
  }
  return problems;
}

/** The message of a refused change of a client's settings. */
export const CLIENT_SETTINGS_REFUSED_MESSAGE = 'The client settings were refused.';

/**
 * Refuse settings the checks refuse ({@link clientSettingsProblems}).
 *
 * @throws UnprocessableContentError naming each refused member
 */
export function assertClientSettings(
  applied: AppliedClientPatch,
  context: ClientCheckContext,
  all = false
): void {
  const problems = clientSettingsProblems(applied, context, all);
  if (problems.length > 0) {
    throw new UnprocessableContentError(problems, CLIENT_SETTINGS_REFUSED_MESSAGE);
  }
}

/** The caller the authority stage resolved, read off the pipeline's state. */
function pipelineCaller(request: FastifyRequest, operationId: string) {
  // Not through the pipeline module, which imports the registry.
  const caller = request.adminPipeline?.authority;
  if (caller === undefined) {
    throw new Error(`${operationId} reads its client only behind the admin pipeline`);
  }
  return caller;
}

/** The client the request's path names, in the caller's realm. */
async function clientOfRequest(
  request: FastifyRequest,
  input: ClassifyInput,
  operationId: string
): Promise<AdminClient> {
  const caller = pipelineCaller(request, operationId);
  const { clientId } = (input.params ?? {}) as { clientId?: unknown };
  if (typeof clientId !== 'string') throw new NotFoundError('OAuthClient', String(clientId));
  // Inside a handler (approvals.create files the request from its own), the
  // read takes the handler's transaction (#887).
  return readClientState(
    request.server,
    caller.targetRealm.id,
    clientId,
    request.adminPipeline?.transaction
  );
}

/**
 * `clients.update`'s `loadState`: the client the path names, once the patch
 * is checked against it. A CIMD client is refused with 409, and a patch the
 * checks refuse with 422, before it is classified or filed for an approval.
 */
async function loadClientUpdateState(
  request: FastifyRequest,
  input: ClassifyInput
): Promise<AdminClient> {
  const state = await clientOfRequest(request, input, CLIENT_OPERATION_IDS.update);
  refuseDocumentClient(state);
  const caller = pipelineCaller(request, CLIENT_OPERATION_IDS.update);
  assertClientSettings(
    applyClientPatch(state, input.body),
    await clientCheckContext(request, caller.targetRealm)
  );
  return state;
}

/** `clients.delete`'s `loadState`: the client, which must not be a CIMD client. */
async function loadClientDeleteState(
  request: FastifyRequest,
  input: ClassifyInput
): Promise<AdminClient> {
  const state = await clientOfRequest(request, input, CLIENT_OPERATION_IDS.delete);
  refuseDocumentClient(state);
  return state;
}

/** `clients.enable`'s `loadState`: the client, a CIMD one included. */
async function loadClientEnableState(
  request: FastifyRequest,
  input: ClassifyInput
): Promise<AdminClient> {
  return clientOfRequest(request, input, CLIENT_OPERATION_IDS.enable);
}

/** The version of a client state, as `stateVersion` gives it. */
const clientStateVersion = (state: unknown): string => adminClientVersion(state as AdminClient);

/** The longest value an approver is shown, before the display caps it. */
const MAX_RENDERED_VALUE = 500;

/** The most fields one approval shows, under the display's cap of 50 lines. */
const MAX_RENDERED_FIELDS = 46;

/** A value as an approver reads it: JSON, capped. */
export function shownValue(value: unknown): string {
  const text = typeof value === 'string' ? value : (JSON.stringify(value) ?? 'null');
  return text.length > MAX_RENDERED_VALUE ? `${text.slice(0, MAX_RENDERED_VALUE)}…` : text;
}

/** The client an approval is about, as its first lines. */
function clientLines(client: AdminClient): RenderedField[] {
  return [
    { label: 'client', value: `${client.client_id} (${client.name})` },
    {
      label: 'owner',
      value:
        client.developerId === null
          ? 'no developer: an operator or an admin manages it'
          : `developer ${client.developerId}`,
    },
  ];
}

/** `fields`, capped under the display's limit, with a line for the rest. */
function capped(fields: RenderedField[], more: number): RenderedField[] {
  if (more > 0) {
    fields.push({ label: 'and more', value: `${more} more fields, not shown` });
  }
  return fields;
}

/**
 * What an approver is shown of a client update: the client, and each field
 * the patch changes, the stored value beside the new one, against the client
 * as it stood when the approval was filed (`RenderInput.state`).
 */
function renderClientUpdate(input: RenderInput): RenderedOperation {
  const state = input.state as AdminClient | undefined;
  if (state === undefined) {
    throw new Error('A client update is shown against the client it was filed against');
  }
  const { client } = applyClientPatch(state, input.body);
  const changed = changedClientFields(state, client);
  const shown = changed.slice(0, MAX_RENDERED_FIELDS);
  return {
    title:
      changed.length === 1
        ? 'Change one setting of a client'
        : `Change ${changed.length} settings of a client`,
    fields: capped(
      [
        ...clientLines(state),
        ...shown.map((name): RenderedField => ({
          label: name,
          before: shownValue(state[name]),
          value: shownValue(client[name]),
        })),
      ],
      changed.length - shown.length
    ),
  };
}

/** The settings of a new client an approver is shown, in the table's order. */
function renderClientCreate(input: RenderInput): RenderedOperation {
  const body = (input.body ?? {}) as Record<string, unknown>;
  const named = (Object.keys(CLIENT_FIELDS) as (keyof AdminClient)[]).filter((name) =>
    Object.hasOwn(body, name)
  );
  const shown = named.slice(0, MAX_RENDERED_FIELDS);
  return {
    title: 'Register a client',
    fields: capped(
      [
        {
          label: 'effect',
          value:
            'A new client no developer owns, provisioned by the operator. A client that authenticates with a secret gets one, returned once to the admin who registers it.',
        },
        ...shown.map((name): RenderedField => ({ label: name, value: shownValue(body[name]) })),
      ],
      named.length - shown.length
    ),
  };
}

/** What an approver is shown of a deletion: the client, as it stood. */
function renderClientDelete(input: RenderInput): RenderedOperation {
  const state = input.state as AdminClient | undefined;
  if (state === undefined) {
    throw new Error('A deletion is shown against the client it was filed against');
  }
  return {
    title: 'Delete a client',
    fields: [
      ...clientLines(state),
      { label: 'grant types', value: shownValue(state.grantTypes) },
      { label: 'redirect URIs', value: shownValue(state.redirectUris) },
      {
        label: 'effect',
        value:
          'The client is removed with its authorization codes, refresh tokens, consents and API keys: it obtains no token again.',
      },
    ],
  };
}

/** What an approver is shown of lifting a suspension. */
function renderClientEnable(input: RenderInput): RenderedOperation {
  const state = input.state as AdminClient | undefined;
  if (state === undefined) {
    throw new Error('An enable is shown against the client it was filed against');
  }
  return {
    title: 'Enable a client',
    fields: [
      ...clientLines(state),
      {
        label: 'now',
        value: state.suspended
          ? `suspended since ${state.suspendedAt ?? 'an unknown time'}`
          : state.enabled
            ? 'not suspended'
            : 'switched off by its owner',
      },
      {
        label: 'effect',
        value:
          state.developerId === null
            ? 'The suspension is lifted and the client is switched on: it obtains tokens again.'
            : "The suspension is lifted: the client obtains tokens again while its owner's switch is on.",
      },
    ],
  };
}

/** The definitions, for `ADMIN_OPERATIONS` (`helpers/admin-operations.ts`). */
export const CLIENT_OPERATION_DEFINITIONS: readonly AdminOperationDefinition[] = Object.freeze([
  {
    id: CLIENT_OPERATION_IDS.list,
    class: 'read',
    effects: [],
    permissions: ['clients.read'],
    description:
      'List every client of a realm, whoever owns it, newest first, one page at a time, optionally those whose client_id or name holds a search text; never a secret.',
  },
  {
    id: CLIENT_OPERATION_IDS.get,
    class: 'read',
    effects: [],
    permissions: ['clients.read'],
    description: 'Read a client of a realm, whoever owns it, with its ETag; never a secret.',
  },
  {
    id: CLIENT_OPERATION_IDS.create,
    class: 'security',
    effects: ['token-content'],
    permissions: ['clients.security'],
    description:
      'Register a client no developer owns, provisioned by the operator, with its redirect URIs, authentication method and trust; a secret, for a client that authenticates with one, is answered once.',
    render: renderClientCreate,
  },
  {
    id: CLIENT_OPERATION_IDS.update,
    class: 'security',
    effects: ['token-content', 'posture-loosening'],
    permissions: ['clients.write', 'clients.security', 'clients.read'],
    description:
      'Change a client with a JSON Merge Patch against the version it names; each field it changes needs what the client field table says, a security change an approval; a CIMD client is refused; it answers the client, so it needs clients.read too.',
    loadState: loadClientUpdateState,
    stateVersion: clientStateVersion,
    classify: (request: ClassifyInput, state: unknown) =>
      classifyClientPatch(request, state as AdminClient),
    render: renderClientUpdate,
  } as AdminOperationDefinition,
  {
    id: CLIENT_OPERATION_IDS.preview,
    class: 'read',
    effects: [],
    permissions: ['clients.read'],
    description:
      'Preview a change of a client: what the patch clients.update takes would change, field by field, each before and after with its direction, class, effects and scopes, and what the save would need, its approval included; it writes nothing.',
  },
  {
    id: CLIENT_OPERATION_IDS.delete,
    class: 'security',
    effects: ['token-content'],
    permissions: ['clients.security'],
    description:
      'Delete a client with its refresh tokens, consents and API keys, against the version it names; a CIMD client is refused.',
    loadState: loadClientDeleteState,
    stateVersion: clientStateVersion,
    render: renderClientDelete,
  } as AdminOperationDefinition,
  {
    id: CLIENT_OPERATION_IDS.enable,
    class: 'security',
    effects: ['token-content'],
    permissions: ['clients.security'],
    description:
      "Lift a client's suspension, against the version it names, and switch on a client no developer owns: it obtains tokens again.",
    loadState: loadClientEnableState,
    stateVersion: clientStateVersion,
    render: renderClientEnable,
  } as AdminOperationDefinition,
  {
    id: CLIENT_OPERATION_IDS.disable,
    class: 'write',
    effects: [],
    permissions: ['clients.write'],
    description:
      'Suspend a client: it obtains no token until clients.enable lifts the suspension, and its owner cannot lift it.',
  },
]);

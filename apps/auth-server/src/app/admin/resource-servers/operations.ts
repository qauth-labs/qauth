import { NotFoundError } from '@qauth-labs/shared-errors';
import type { FastifyInstance, FastifyRequest } from 'fastify';

import type {
  AdminOperationDefinition,
  ClassifyInput,
  RenderedField,
  RenderedOperation,
  RenderInput,
} from '../../helpers/admin-operations';
import { UnprocessableContentError } from '../../helpers/api-request-errors';
import {
  CREATE_HEADER_LINES,
  resourceServerChangeLines,
  resourceServerCreateLines,
  resourceServerDeleteLines,
  type ResourceServerLineProblem,
  type ResourceServerLines,
  UPDATE_HEADER_LINES,
} from './approval-lines';
import {
  type AdminResourceServer,
  adminResourceServerOf,
  adminResourceServerVersion,
} from './representation';

/**
 * THE RESOURCE SERVER OPERATIONS OF THE ADMIN API (ADR-019 Decision 7, issue
 * #1087): list and read the protected resources a realm registers, register
 * one, change it, preview a change, and remove it.
 *
 * A registered resource decides what a token asserts: each scope it defines
 * is granted only when the authorization request names the resource, to a
 * client the resource is open to (any client of the realm, CIMD and
 * dynamically registered ones included, or the listed `client_id`s), whatever
 * the client's own scope list holds (`helpers/protected-resources.ts`). So
 * registering one, changing its scopes, their consent texts or who may ask
 * for them, and removing it are security operations with the effect
 * `token-content` (ADR-019 Decision 7, "resource-server and audience
 * registration"), reserved in `admin-operations-reserved.ts`: every request
 * needs `resourceServers.security`, so `qauth:admin:security`, and an
 * approval, a narrowing too. `qauth:admin:write` reaches none of them.
 *
 * - `resourceServers.list`, `resourceServers.get` and
 *   `resourceServers.preview` are reads (`resourceServers.read`). The
 *   preview answers what the patch `resourceServers.update` takes would
 *   change and need, and writes nothing.
 * - `resourceServers.update` takes a JSON Merge Patch: `scopes` and
 *   `clients` replace the stored value whole. The resource indicator never
 *   changes (422): another indicator is another resource server.
 * - `resourceServers.update` and `resourceServers.delete` read the resource
 *   server (`loadState`): its row version is its `ETag`, which the request
 *   names in `If-Match`, and an approval approves the request against that
 *   version only. A resource server of another realm is 404, as one that
 *   does not exist.
 *
 * Every value an approver is shown is shown whole (`./approval-lines.ts`): a
 * change that cannot be is refused with 422 before it is filed.
 */

/** The ids of the resource server operations. */
export const RESOURCE_SERVER_OPERATION_IDS = Object.freeze({
  list: 'resourceServers.list',
  get: 'resourceServers.get',
  create: 'resourceServers.create',
  update: 'resourceServers.update',
  preview: 'resourceServers.preview',
  delete: 'resourceServers.delete',
} as const);

/** The repositories the state reads, with the transaction they read in. */
type StateServer = Pick<FastifyInstance, 'repositories'>;
type Transaction = Parameters<FastifyInstance['repositories']['protectedResources']['findById']>[2];

/** RFC 9562: the form of the id the admin API names a resource server by. */
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** The entity a missing resource server is named as. */
export const RESOURCE_SERVER_ENTITY = 'ResourceServer';

/**
 * The resource server `id` of the realm, as the admin API shows it, read in
 * `tx` when given.
 *
 * @throws NotFoundError when the realm has no such resource server: one of
 *   another realm is not found either
 */
export async function readResourceServerState(
  server: StateServer,
  realmId: string,
  id: string,
  tx?: Transaction
): Promise<AdminResourceServer> {
  if (!UUID.test(id)) throw new NotFoundError(RESOURCE_SERVER_ENTITY, id);
  const row = await server.repositories.protectedResources.findById(realmId, id, tx);
  if (row === undefined) throw new NotFoundError(RESOURCE_SERVER_ENTITY, id);
  return adminResourceServerOf(row);
}

/** What a resource server's write sets: its scopes and who may ask for them. */
export interface ResourceServerSettings {
  readonly scopes: AdminResourceServer['scopes'];
  readonly clients: AdminResourceServer['clients'];
}

/** A scope as a body takes it: `sensitive` may be left out, for `false`. */
interface ScopeInput {
  readonly scope: string;
  readonly text: Readonly<Record<string, string>>;
  readonly sensitive?: boolean;
}

/** `scopes`, each with every member present: plain copies, never the body's own objects. */
export function normalisedScopes(scopes: readonly ScopeInput[]): AdminResourceServer['scopes'] {
  return scopes.map((entry) => ({
    scope: entry.scope,
    text: { ...entry.text },
    sensitive: entry.sensitive === true,
  }));
}

/** `clients`, a copy of a list. */
const copiedClients = (clients: AdminResourceServer['clients']): AdminResourceServer['clients'] =>
  Array.isArray(clients) ? [...clients] : clients;

/**
 * The settings `body`, a JSON Merge Patch (RFC 7396) of the resource server
 * `state`, gives it: `scopes` and `clients`, when the patch names them,
 * replace the stored value whole; a member it leaves out is kept. The body
 * is the one the route's schema parsed; {@link assertResourceServerPatch}
 * refuses what it cannot apply.
 */
export function applyResourceServerPatch(
  state: AdminResourceServer,
  body: unknown
): ResourceServerSettings {
  const patch = (typeof body === 'object' && body !== null ? body : {}) as {
    scopes?: readonly ScopeInput[] | null;
    clients?: AdminResourceServer['clients'] | null;
  };
  return {
    scopes: normalisedScopes(
      Array.isArray(patch.scopes) ? (patch.scopes as readonly ScopeInput[]) : state.scopes
    ),
    clients: copiedClients(
      patch.clients === undefined || patch.clients === null ? state.clients : patch.clients
    ),
  };
}

/**
 * What is wrong with `body` as a patch of `state`, each as a JSON Pointer
 * into the body and a message: empty when nothing is. The resource indicator
 * never changes, and `scopes` and `clients` have no default to remove them
 * to.
 */
export function resourceServerPatchProblems(
  state: AdminResourceServer,
  body: unknown
): ResourceServerLineProblem[] {
  const patch = (typeof body === 'object' && body !== null ? body : {}) as Record<string, unknown>;
  const problems: ResourceServerLineProblem[] = [];
  if (Object.hasOwn(patch, 'resource') && patch['resource'] !== state.resource) {
    problems.push({
      pointer: '/resource',
      message:
        'resource is the resource indicator, which never changes: register a resource server for the other indicator, and delete this one',
    });
  }
  for (const name of ['scopes', 'clients']) {
    if (Object.hasOwn(patch, name) && patch[name] === null) {
      problems.push({ pointer: `/${name}`, message: `${name} is required and has no default` });
    }
  }
  return problems;
}

/** The message of a refused change of a resource server. */
export const RESOURCE_SERVER_CHANGE_REFUSED_MESSAGE = 'The resource server change was refused.';

/** The message of a change too large to show an approver in full. */
export const RESOURCE_SERVER_NOT_SHOWN_MESSAGE =
  'The change cannot be shown to an approver in full: file it as smaller changes.';

/**
 * Refuse a patch {@link resourceServerPatchProblems} refuses.
 *
 * @throws UnprocessableContentError naming each refused member
 */
export function assertResourceServerPatch(state: AdminResourceServer, body: unknown): void {
  const problems = resourceServerPatchProblems(state, body);
  if (problems.length > 0) {
    throw new UnprocessableContentError(problems, RESOURCE_SERVER_CHANGE_REFUSED_MESSAGE);
  }
}

/**
 * Refuse a change an approver could not be shown in full
 * (`./approval-lines.ts`): every value whole, in at most the lines one
 * approval holds. Every change of a resource server is a security change, so
 * every one is held to it.
 *
 * @throws UnprocessableContentError naming each member that does not fit
 */
export function assertShownInFull(
  state: AdminResourceServer,
  settings: ResourceServerSettings
): void {
  const { problems } = resourceServerChangeLines(state, settings, UPDATE_HEADER_LINES);
  if (problems.length > 0) {
    throw new UnprocessableContentError(problems, RESOURCE_SERVER_NOT_SHOWN_MESSAGE);
  }
}

/**
 * Refuse a patch of `state` that `resourceServers.update` refuses: one that
 * changes the resource indicator or removes a required member, and one an
 * approver could not be shown in full. Its preview refuses the same.
 *
 * @throws UnprocessableContentError naming each refused member
 */
export function assertResourceServerUpdate(
  state: AdminResourceServer,
  body: unknown
): ResourceServerSettings {
  assertResourceServerPatch(state, body);
  const settings = applyResourceServerPatch(state, body);
  assertShownInFull(state, settings);
  return settings;
}

/** The caller the authority stage resolved, read off the pipeline's state. */
function pipelineCaller(request: FastifyRequest, operationId: string) {
  // Not through the pipeline module, which imports the registry.
  const caller = request.adminPipeline?.authority;
  if (caller === undefined) {
    throw new Error(`${operationId} reads its resource server only behind the admin pipeline`);
  }
  return caller;
}

/** The resource server the request's path names, in the caller's realm. */
async function resourceServerOfRequest(
  request: FastifyRequest,
  input: ClassifyInput,
  operationId: string
): Promise<AdminResourceServer> {
  const caller = pipelineCaller(request, operationId);
  const { resourceServerId } = (input.params ?? {}) as { resourceServerId?: unknown };
  if (typeof resourceServerId !== 'string') {
    throw new NotFoundError(RESOURCE_SERVER_ENTITY, String(resourceServerId));
  }
  // Inside a handler (approvals.create files the request from its own), the
  // read takes the handler's transaction (#887).
  return readResourceServerState(
    request.server,
    caller.targetRealm.id,
    resourceServerId,
    request.adminPipeline?.transaction
  );
}

/**
 * `resourceServers.update`'s `loadState`: the resource server the path names,
 * once the patch is checked against it. A patch that changes the indicator,
 * removes a required member, or could not be shown an approver in full is
 * refused with 422 before it is filed for an approval.
 */
async function loadResourceServerUpdateState(
  request: FastifyRequest,
  input: ClassifyInput
): Promise<AdminResourceServer> {
  const state = await resourceServerOfRequest(request, input, RESOURCE_SERVER_OPERATION_IDS.update);
  assertResourceServerUpdate(state, input.body);
  return state;
}

/** `resourceServers.delete`'s `loadState`: the resource server the path names. */
async function loadResourceServerDeleteState(
  request: FastifyRequest,
  input: ClassifyInput
): Promise<AdminResourceServer> {
  return resourceServerOfRequest(request, input, RESOURCE_SERVER_OPERATION_IDS.delete);
}

/** The version of a resource server state, as `stateVersion` gives it. */
const resourceServerStateVersion = (state: unknown): string =>
  adminResourceServerVersion(state as AdminResourceServer);

/**
 * The lines a change shows, or an error: the state check refuses a change
 * that cannot be shown in full before it is filed, and the body schema a
 * registration, so a renderer meets none.
 */
function shownLines(lines: ResourceServerLines): readonly RenderedField[] {
  if (lines.problems.length > 0) {
    throw new Error(lines.problems.map((problem) => problem.message).join('; '));
  }
  return lines.fields;
}

/** The settings of a new resource server an approver is shown, each whole. */
function renderResourceServerCreate(input: RenderInput): RenderedOperation {
  const fields = shownLines(resourceServerCreateLines(input.body, CREATE_HEADER_LINES));
  return {
    title: 'Register a resource server',
    fields: [
      {
        label: 'effect',
        value:
          'The realm grants each scope below only when an authorization request names this resource, to a client it is open to, whatever the client’s own scopes list; the user still consents, shown the text of their locale.',
      },
      ...fields,
    ],
  };
}

/**
 * What an approver is shown of an update: the resource server, and what the
 * patch changes against it as it stood when the approval was filed
 * (`RenderInput.state`): each scope removed or added, each consent text and
 * sensitive flag it changes beside the value it replaces, each client
 * removed or added. Every value is shown whole (`./approval-lines.ts`).
 */
function renderResourceServerUpdate(input: RenderInput): RenderedOperation {
  const state = input.state as AdminResourceServer | undefined;
  if (state === undefined) {
    throw new Error(
      'A resource server update is shown against the resource server it was filed against'
    );
  }
  const settings = applyResourceServerPatch(state, input.body);
  return {
    title: 'Change the scopes of a resource server, or who may ask for them',
    fields: shownLines(resourceServerChangeLines(state, settings, UPDATE_HEADER_LINES)),
  };
}

/** What an approver is shown of a deletion: the resource server, as it stood. */
function renderResourceServerDelete(input: RenderInput): RenderedOperation {
  const state = input.state as AdminResourceServer | undefined;
  if (state === undefined) {
    throw new Error('A deletion is shown against the resource server it was filed against');
  }
  return {
    title: 'Delete a resource server',
    fields: [
      ...resourceServerDeleteLines(state),
      {
        label: 'effect',
        value:
          'The scopes are no longer bound to this resource: one no other resource server defines is granted again only to a client whose own scopes list it. Tokens already issued keep what they carry until they expire.',
      },
    ],
  };
}

/** The definitions, for `ADMIN_OPERATIONS` (`helpers/admin-operations.ts`). */
export const RESOURCE_SERVER_OPERATION_DEFINITIONS: readonly AdminOperationDefinition[] =
  Object.freeze([
    {
      id: RESOURCE_SERVER_OPERATION_IDS.list,
      class: 'read',
      effects: [],
      permissions: ['resourceServers.read'],
      description:
        'List the resource servers (protected resources) of a realm, newest first, one page at a time, each with its scopes, their consent texts and who may ask for them.',
    },
    {
      id: RESOURCE_SERVER_OPERATION_IDS.get,
      class: 'read',
      effects: [],
      permissions: ['resourceServers.read'],
      description:
        'Read a resource server of a realm, with its scopes, their consent texts and who may ask for them, and its ETag.',
    },
    {
      id: RESOURCE_SERVER_OPERATION_IDS.create,
      class: 'security',
      effects: ['token-content'],
      permissions: ['resourceServers.security'],
      description:
        "Register a resource server: its resource indicator (RFC 8707), the scopes it defines with their consent texts by locale and whether each is sensitive, and who may ask for them, any client of the realm or the listed client_ids; each scope is then granted only for that resource, whatever a client's own scopes list.",
      render: renderResourceServerCreate,
    },
    {
      id: RESOURCE_SERVER_OPERATION_IDS.update,
      class: 'security',
      effects: ['token-content'],
      permissions: ['resourceServers.security'],
      description:
        'Change the scopes of a resource server, their consent texts and sensitive flags, or who may ask for them, with a JSON Merge Patch against the version it names; each member it names replaces the stored one whole, and the resource indicator never changes.',
      loadState: loadResourceServerUpdateState,
      stateVersion: resourceServerStateVersion,
      render: renderResourceServerUpdate,
    } as AdminOperationDefinition,
    {
      id: RESOURCE_SERVER_OPERATION_IDS.preview,
      class: 'read',
      effects: [],
      permissions: ['resourceServers.read'],
      description:
        'Preview a change of a resource server: what the patch resourceServers.update takes would change, its scopes and who may ask for them, each before and after with its direction, and what the save would need, its approval included; it writes nothing.',
    },
    {
      id: RESOURCE_SERVER_OPERATION_IDS.delete,
      class: 'security',
      effects: ['token-content'],
      permissions: ['resourceServers.security'],
      description:
        'Delete a resource server against the version it names: its scopes are no longer bound to its resource.',
      loadState: loadResourceServerDeleteState,
      stateVersion: resourceServerStateVersion,
      render: renderResourceServerDelete,
    } as AdminOperationDefinition,
  ]);

import {
  classifyRequest,
  type OperationClassification,
  type OperationRegistry,
  operationStateVersion,
} from '../../helpers/admin-operations';
import type { PreviewedChange } from '../change-preview';
import {
  applyClientPatch,
  changedClientFields,
  classificationOfClientField,
  directionOfClientField,
} from './fields';
import { CLIENT_OPERATION_IDS } from './operations';
import type { AdminClient } from './representation';

/**
 * THE PREVIEW OF A CLIENT UPDATE (ADR-020 §3, issue #632): what
 * `clients.update` would change and need for the same patch against the same
 * client, computed by the update's own code and written nowhere. It answers
 * the shape every preview answers (`AdminChangePreview`, #589).
 *
 * - The changes are the fields the patched client (`applyClientPatch`)
 *   holds differently, in the order of the field table.
 * - Each change needs what its entry of the table gives it
 *   (`classificationOfClientField`), and moves the way it says
 *   (`directionOfClientField`).
 * - The patch as a whole needs what the pipeline would classify it as:
 *   `classifyRequest` over the registry's `clients.update`, its `classify`
 *   and fail-closed rules included, against the version read.
 *
 * Kept apart from `./operations.ts`, which the registry imports: this module
 * reads the registry.
 */

/** Whether a list of URIs holds an `http` one: a loopback URI, which only a local app has. */
const holdsHttpUri = (value: unknown): boolean =>
  Array.isArray(value) && value.some((uri) => typeof uri === 'string' && /^http:/i.test(uri));

/**
 * Whether a change describes the environment the client runs in, which a
 * sandbox promotion leaves out unless it is selected on its own (ADR-019
 * Decision 11): the client's environment, its `http` and loopback redirect
 * URIs, and where logout tokens are delivered.
 */
function isEnvironmentBound(name: keyof AdminClient, before: unknown, after: unknown): boolean {
  if (name === 'environment' || name === 'backchannelLogoutUri') return true;
  if (name === 'redirectUris' || name === 'postLogoutRedirectUris') {
    return holdsHttpUri(before) || holdsHttpUri(after);
  }
  return false;
}

/** What a client patch would change and need. */
export interface ClientPatchPreview {
  /** The patch, as `clients.update` classifies it against `state`. */
  readonly classification: OperationClassification;
  /** Each field it changes, in the order of the field table. */
  readonly changes: readonly PreviewedChange[];
}

/**
 * Preview `body`, a merge patch of the client `clientId` of the realm
 * `realmId`, against `state`, as `clients.update` reads it.
 *
 * @throws {Error} when the registry holds no `clients.update`
 */
export function previewClientPatch(
  registry: OperationRegistry,
  params: { readonly realmId: string; readonly clientId: string },
  body: unknown,
  state: AdminClient
): ClientPatchPreview {
  const update = registry.get(CLIENT_OPERATION_IDS.update);
  if (update === undefined) {
    throw new Error(`The admin operation registry holds no ${CLIENT_OPERATION_IDS.update}`);
  }
  const { client } = applyClientPatch(state, body);
  const classification = classifyRequest(
    registry,
    update,
    { method: 'PATCH', params, query: {}, body },
    state,
    operationStateVersion(update, state)
  );
  return {
    classification,
    changes: changedClientFields(state, client).map((name) => ({
      path: name,
      before: state[name],
      after: client[name],
      direction: directionOfClientField(name, state[name], client[name]),
      classification: classificationOfClientField(name, state[name], client[name]),
      secret: false,
      environmentBound: isEnvironmentBound(name, state[name], client[name]),
    })),
  };
}

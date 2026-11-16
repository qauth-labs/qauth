import { isDeepStrictEqual } from 'node:util';

import { ANY_CLIENT } from '@qauth-labs/shared-validation';

import {
  classifyRequest,
  type OperationClassification,
  type OperationRegistry,
  operationStateVersion,
} from '../../helpers/admin-operations';
import type { ChangeDirection, PreviewedChange } from '../change-preview';
import {
  applyResourceServerPatch,
  RESOURCE_SERVER_OPERATION_IDS,
  type ResourceServerSettings,
} from './operations';
import type { AdminResourceServer } from './representation';

/**
 * THE PREVIEW OF A RESOURCE SERVER UPDATE (ADR-019 Decision 7, issue #1087):
 * what `resourceServers.update` would change and need for the same patch
 * against the same resource server, computed by the update's own code and
 * written nowhere. It answers the shape every preview answers
 * (`AdminChangePreview`, #589).
 *
 * - The changes are the members the patched settings
 *   (`applyResourceServerPatch`) hold differently: `scopes`, then `clients`.
 * - Every change is a security change with the effect `token-content`: the
 *   update declares it on every request, a narrowing too, so each change
 *   needs what the update needs, and the patch as a whole what the pipeline
 *   would classify it as (`classifyRequest` over the registry's
 *   `resourceServers.update`, against the version read).
 * - A change of the scopes loosens when it adds a scope, clears a sensitive
 *   flag or changes a consent text, whose meaning a user consents to; it
 *   tightens when it only removes scopes or flags them sensitive. A change of
 *   who may ask loosens when it opens the resource to any client or lists a
 *   client more, and tightens when it only takes clients away.
 *
 * Kept apart from `./operations.ts`, which the registry imports: this module
 * reads the registry.
 */

/** Which way a change of the scopes moves. */
export function scopesDirection(
  before: AdminResourceServer['scopes'],
  after: AdminResourceServer['scopes']
): ChangeDirection {
  const was = new Map(before.map((entry) => [entry.scope, entry]));
  const now = new Map(after.map((entry) => [entry.scope, entry]));
  let tightened = false;
  for (const entry of after) {
    const old = was.get(entry.scope);
    if (old === undefined) return 'loosening';
    if (old.sensitive && !entry.sensitive) return 'loosening';
    if (!isDeepStrictEqual(old.text, entry.text)) return 'loosening';
    if (!old.sensitive && entry.sensitive) tightened = true;
  }
  if (before.some((entry) => !now.has(entry.scope))) tightened = true;
  return tightened ? 'tightening' : 'neutral';
}

/** Which way a change of who may ask for the scopes moves. */
export function clientsDirection(
  before: AdminResourceServer['clients'],
  after: AdminResourceServer['clients']
): ChangeDirection {
  if (before === ANY_CLIENT) return after === ANY_CLIENT ? 'neutral' : 'tightening';
  if (after === ANY_CLIENT) return 'loosening';
  if (after.some((clientId) => !before.includes(clientId))) return 'loosening';
  return before.some((clientId) => !after.includes(clientId)) ? 'tightening' : 'neutral';
}

/** What a resource server patch would change and need. */
export interface ResourceServerPatchPreview {
  /** The patch, as `resourceServers.update` classifies it against `state`. */
  readonly classification: OperationClassification;
  /** Each member it changes: `scopes`, then `clients`. */
  readonly changes: readonly PreviewedChange[];
}

/**
 * Preview `body`, a merge patch of the resource server `resourceServerId` of
 * the realm `realmId`, against `state`, as `resourceServers.update` reads it.
 *
 * @throws {Error} when the registry holds no `resourceServers.update`
 */
export function previewResourceServerPatch(
  registry: OperationRegistry,
  params: { readonly realmId: string; readonly resourceServerId: string },
  body: unknown,
  state: AdminResourceServer
): ResourceServerPatchPreview {
  const update = registry.get(RESOURCE_SERVER_OPERATION_IDS.update);
  if (update === undefined) {
    throw new Error(
      `The admin operation registry holds no ${RESOURCE_SERVER_OPERATION_IDS.update}`
    );
  }
  const settings: ResourceServerSettings = applyResourceServerPatch(state, body);
  const classification = classifyRequest(
    registry,
    update,
    { method: 'PATCH', params, query: {}, body },
    state,
    operationStateVersion(update, state)
  );
  const declared = {
    class: update.class,
    effects: [...update.effects],
    permissions: [...update.permissions],
  };
  const changes: PreviewedChange[] = [];
  if (!isDeepStrictEqual(state.scopes, settings.scopes)) {
    changes.push({
      path: 'scopes',
      before: state.scopes,
      after: settings.scopes,
      direction: scopesDirection(state.scopes, settings.scopes),
      classification: declared,
      secret: false,
      environmentBound: false,
    });
  }
  if (!isDeepStrictEqual(state.clients, settings.clients)) {
    changes.push({
      path: 'clients',
      before: state.clients,
      after: settings.clients,
      direction: clientsDirection(state.clients, settings.clients),
      classification: declared,
      secret: false,
      environmentBound: false,
    });
  }
  return { classification, changes };
}

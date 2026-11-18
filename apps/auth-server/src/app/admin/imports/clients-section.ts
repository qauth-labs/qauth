import { realmFileClientSchema } from '@qauth-labs/realm-file';
import { ADMIN_API_AUDIENCE, type SecurityEffect } from '@qauth-labs/shared-validation';

import { holdsAdminScope } from '../clients/fields';
import {
  authenticatesWithSecret,
  clientFieldChanges,
  isEnvironmentBoundClient,
  type StoredClient,
  storedClientOf,
} from './client-fields';
import {
  defineSection,
  type ImportChangeDraft,
  ImportPlanError,
  type ImportPlanIssue,
  type ImportSectionContext,
  type ImportSectionDiff,
} from './section';

/**
 * THE `clients` SECTION OF AN IMPORT (ADR-019 Decision 11, issue #518): the
 * clients the operator manages, matched by `client_id`.
 *
 * - A client the file lists and the realm does not is created: a security
 *   change with the effect `token-content`, as `clients.create` is.
 * - A client both hold is compared field by field (`./client-fields.ts`):
 *   each changed field moves the way its entry says and needs what
 *   `clients.update` would need for it.
 * - A client the realm holds and the file leaves out stays, unless the
 *   import prunes: then it is deleted, a security change with the effect
 *   `token-content`, as `clients.delete` is. A file without a `clients`
 *   section says nothing about clients and deletes none.
 * - Creating or deleting a client that holds an admin scope also has the
 *   effect `administration`: it changes who can obtain admin tokens.
 *
 * A file that names a client of the realm no realm file manages (one a
 * developer owns, one that registered itself, a CIMD client, the system
 * client, a service account's) cannot be planned: the import would take
 * that client over. Nor can one that would create a client under an id the
 * server keeps for such a client (the system client's, a CIMD `client_id`)
 * before the realm holds it: the server would take the operator's client
 * for that one.
 */

/**
 * What creating or deleting `client` needs: `clients.create`'s or
 * `clients.delete`'s declaration, and `administration` for a client that can
 * obtain admin tokens, by an admin scope or an audience that names the admin
 * API, as a change of either field has it.
 */
function wholeClientEffects(client: StoredClient): SecurityEffect[] {
  const effects: SecurityEffect[] = ['token-content'];
  const audience = Array.isArray(client.audience) ? (client.audience as string[]) : [];
  if (
    holdsAdminScope({ scopes: client.scopes as string[] }) ||
    audience.includes(ADMIN_API_AUDIENCE)
  ) {
    effects.push('administration');
  }
  return effects;
}

/** Strings in UTF-16 code unit order. */
const byCodeUnit = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

function diffClientSection({ state, file, prune }: ImportSectionContext): ImportSectionDiff {
  if (file.clients === undefined) return { changes: [] };
  const managed = new Set(state.clients.map((entry) => entry.client_id));
  const issues: ImportPlanIssue[] = [];
  file.clients.forEach((entry, index) => {
    const pointer = `/clients/${index}/client_id`;
    const why = state.unmanagedClients.get(entry.client_id);
    if (why !== undefined) {
      issues.push({
        pointer,
        message: `names a client of the realm that no realm file manages (${why}): an import never takes it over`,
      });
      return;
    }
    if (managed.has(entry.client_id)) return;
    const reserved = state.reservedClientId(entry.client_id);
    if (reserved !== undefined) {
      issues.push({
        pointer,
        message: `is kept for a client no realm file manages (${reserved}): an import never creates one under it`,
      });
    }
  });
  if (issues.length > 0) throw new ImportPlanError(issues);

  const current = new Map(
    state.clients.map((entry) => [entry.client_id, storedClientOf(entry)] as const)
  );
  const wanted = new Map(file.clients.map((entry) => [entry.client_id, storedClientOf(entry)]));
  const keys = [...new Set([...wanted.keys(), ...(prune ? current.keys() : [])])].sort(byCodeUnit);
  const changes: ImportChangeDraft[] = [];
  for (const key of keys) {
    const before = current.get(key);
    const after = wanted.get(key);
    if (after !== undefined && before === undefined) {
      const effects = wholeClientEffects(after);
      changes.push({
        key,
        path: '',
        op: 'create',
        before: null,
        after,
        direction: 'loosening',
        class: 'security',
        effects,
        secret: false,
        environmentBound: isEnvironmentBoundClient(after),
        // A client that authenticates with a secret gets one on the realm.
        needsSecret: authenticatesWithSecret(after),
      });
    } else if (after === undefined && before !== undefined) {
      changes.push({
        key,
        path: '',
        op: 'delete',
        before,
        after: null,
        direction: 'tightening',
        class: 'security',
        effects: wholeClientEffects(before),
        secret: false,
        environmentBound: isEnvironmentBoundClient(before),
        needsSecret: false,
      });
    } else if (after !== undefined && before !== undefined) {
      for (const change of clientFieldChanges(before, after)) {
        const security = change.classification.class === 'security';
        changes.push({
          key,
          path: change.name,
          op: 'update',
          before: change.before,
          after: change.after,
          direction: change.direction,
          class: security ? 'security' : 'write',
          effects: security ? [...change.classification.effects] : [],
          secret: false,
          environmentBound: change.environmentBound,
          needsSecret:
            change.name === 'token_endpoint_auth_method' &&
            authenticatesWithSecret(after) &&
            !authenticatesWithSecret(before),
        });
      }
    }
  }
  return { changes };
}

/** The `clients` section. */
export const CLIENTS_SECTION = defineSection({
  name: 'clients',
  schema: () => realmFileClientSchema,
  naturalKey: 'client_id',
  diff: diffClientSection,
  // As the client operations need them: `clients.security` for a security
  // change, `clients.write` for any other (`classificationOfClientField`).
  permissionsFor: (change) =>
    change.class === 'security' ? ['clients.security'] : ['clients.write'],
});

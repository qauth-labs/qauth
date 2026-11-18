import type { AdminOperationDefinition } from '../../helpers/admin-operations';

/**
 * THE REALM-FILE IMPORT OPERATIONS OF THE ADMIN API (ADR-019 Decisions 7 and
 * 11, ADR-020 fork G, issue #518).
 *
 * `realms.imports.plan` is the dry run: it takes a realm file and answers its
 * import plan (`./plan.ts`), every change with what it needs, and writes
 * nothing but the audit row every admin call leaves. A read: it needs
 * `realms.import.plan`, and since a plan shows the realm's policies and
 * clients as they stand, `realms.read` and `clients.read` too, so the plan
 * shows nothing a read of the realm and its clients would not. Applying an
 * import is `realms.imports.apply` (#531), reserved in
 * `helpers/admin-operations-reserved.ts`.
 *
 * Kept apart from the routes, as every area's definitions are: the registry
 * imports this module.
 */

/** The ids of the import operations. */
export const IMPORT_OPERATION_IDS = Object.freeze({
  plan: 'realms.imports.plan',
} as const);

/** The definitions, for `ADMIN_OPERATIONS` (`helpers/admin-operations.ts`). */
export const IMPORT_OPERATION_DEFINITIONS: readonly AdminOperationDefinition[] = Object.freeze([
  {
    id: IMPORT_OPERATION_IDS.plan,
    class: 'read',
    effects: [],
    permissions: ['realms.import.plan', 'realms.read', 'clients.read'],
    description:
      "Plan the import of a realm file into a realm as a dry run: every change it would make to the realm's policies and its operator-managed clients, each before and after with its direction, class, effects, permissions and scopes, what the whole import would need, the secrets the realm would still need set, and the digest its approval binds to; it applies nothing, deletes an item the file leaves out only when it prunes, and never shows a secret.",
  },
]);

import type { AdminOperationDefinition } from '../../helpers/admin-operations';

/**
 * THE REALM-FILE EXPORT OPERATION OF THE ADMIN API (ADR-018 §5, ADR-019
 * Decision 11, ADR-020 fork G, issue #530).
 *
 * `realms.export` answers the realm as a realm file (`./realm-file.ts`): its
 * policies without any secret and the clients the operator manages. A read:
 * it needs `realms.export`, which the catalog gives every built-in role
 * (`helpers/admin-permissions.ts`), so `qauth:admin:read` is enough. It
 * writes nothing but the audit row every admin call leaves.
 *
 * Kept apart from the routes, as every area's definitions are: the registry
 * imports this module.
 */

/** The ids of the export operations. */
export const EXPORT_OPERATION_IDS = Object.freeze({
  export: 'realms.export',
} as const);

/** The definitions, for `ADMIN_OPERATIONS` (`helpers/admin-operations.ts`). */
export const EXPORT_OPERATION_DEFINITIONS: readonly AdminOperationDefinition[] = Object.freeze([
  {
    id: EXPORT_OPERATION_IDS.export,
    class: 'read',
    effects: [],
    permissions: ['realms.export'],
    description:
      "Export a realm's configuration as a realm file: its policies, a secret field left out, and the clients the operator manages, never a secret; in canonical order, so two exports of the same state are byte-identical, and an import of the file into the realm plans no change.",
  },
]);

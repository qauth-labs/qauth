import {
  classifyRequest,
  type OperationClassification,
  type OperationRegistry,
  operationStateVersion,
} from '../../helpers/admin-operations';
import type { PreviewedChange } from '../change-preview';
import {
  classificationOfPolicyChange,
  policyPatchDiff,
  REALM_OPERATION_IDS,
  type RealmPolicyState,
} from './operations';

/**
 * THE PREVIEW OF A POLICY PATCH (ADR-020 §5 criterion 1, issue #589): what
 * `realms.policies.update` would change and need for the same patch against
 * the same policies, computed by the update's own code and written nowhere.
 *
 * - The changes are the update's diff (`policyPatchDiff`, the registry's
 *   `diffPatch` of the merged document, `diffPolicies`' change rules).
 * - Each change needs what the update's classification gives it
 *   (`classificationOfPolicyChange`).
 * - The patch as a whole needs what the pipeline would classify it as:
 *   `classifyRequest` over the registry's `realms.policies.update`, its
 *   `classify` and fail-closed rules included, against the version read.
 *
 * Kept apart from `./operations.ts`, which the registry imports: this module
 * reads the registry.
 */

/** What a policy patch would change and need. */
export interface PolicyPatchPreview {
  /** The patch, as `realms.policies.update` classifies it against `state`. */
  readonly classification: OperationClassification;
  /** Each field it changes, in registration order. */
  readonly changes: readonly PreviewedChange[];
}

/**
 * Preview `body`, a merge patch of the policies of the realm `realmId`,
 * against `state`, as `realms.policies.update` reads it.
 *
 * @throws PolicyValidationError when the patch is refused: check it first
 *   with `checkPolicyPatch`, which answers 422 as the update does
 * @throws {Error} when the registry holds no `realms.policies.update`
 */
export function previewPolicyPatch(
  registry: OperationRegistry,
  realmId: string,
  body: unknown,
  state: RealmPolicyState
): PolicyPatchPreview {
  const update = registry.get(REALM_OPERATION_IDS.updatePolicies);
  if (update === undefined) {
    throw new Error(`The admin operation registry holds no ${REALM_OPERATION_IDS.updatePolicies}`);
  }
  const diff = policyPatchDiff(body, state);
  const classification = classifyRequest(
    registry,
    update,
    { method: 'PATCH', params: { realmId }, query: {}, body },
    state,
    operationStateVersion(update, state)
  );
  return {
    classification,
    changes: diff.changes.map((change) => ({
      path: change.path,
      before: change.before,
      after: change.after,
      direction: change.direction,
      classification: classificationOfPolicyChange(change),
      secret: change.secret,
      environmentBound: change.environmentBound,
    })),
  };
}

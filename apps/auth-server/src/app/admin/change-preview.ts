import { SECURITY_EFFECTS, type SecurityEffect } from '@qauth-labs/shared-validation';
import { z } from 'zod';

import type { Classification } from '../helpers/admin-operations';
import type { PermissionRegistry } from '../helpers/admin-permissions';
import { ADMIN_SCOPE_LIST, ADMIN_SCOPES, type AdminScope } from '../helpers/admin-scopes';
import type { TwoAdmin } from './approvals/engine';

/**
 * THE PREVIEW OF A CHANGE, AS THE ADMIN API ANSWERS IT (ADR-020 §5 criterion 1,
 * ADR-019 Decision 7, issue #589).
 *
 * A screen shows the old and new values side by side before it saves, marks
 * each change as tightening, loosening or neutral, and says what the save
 * will need: which scopes, whether an approval, and whether a second admin.
 * The server decides all of it, so a screen never decides what is a security
 * change (#678).
 *
 * One shape for every preview: the realm policy preview
 * (`realms.policies.preview`, #589) answers it, and the client update's
 * preview (#632) and the realm-file plan (#518, #531) answer it too. Each
 * change names its field by a dotted path; a preview that spans resources
 * adds what it needs to name the resource beside the members below and keeps
 * these.
 *
 * A secret never appears: a secret field's `before` and `after` are `set` or
 * `not set` ({@link SECRET_STATES}), and the preview takes no value to show.
 */

/** Which way one change moves (ADR-019 Decision 11). */
export const CHANGE_DIRECTIONS = Object.freeze(['tightening', 'loosening', 'neutral'] as const);

export type ChangeDirection = (typeof CHANGE_DIRECTIONS)[number];

/** What a secret field shows before and after a change, in place of a value. */
export const SECRET_STATES = Object.freeze(['set', 'not set'] as const);

/** The class of a save, or of one change of it: never a read. */
const SAVE_CLASSES = ['write', 'security'] as const;

const classSchema = z.enum(SAVE_CLASSES);
const effectsSchema = z.array(z.enum(SECURITY_EFFECTS));
const scopesSchema = z.array(
  z.enum([ADMIN_SCOPES.read, ADMIN_SCOPES.write, ADMIN_SCOPES.security])
);
const permissionsSchema = z.array(z.string());

/** One changed field. */
export const changePreviewEntrySchema = z
  .object({
    path: z.string().meta({
      description: 'The dotted path of the field, such as password.minScore.',
    }),
    before: z.unknown().meta({
      description: 'The stored value; for a secret field, set or not set, never a value.',
    }),
    after: z.unknown().meta({
      description:
        'The value the save would store; for a secret field, set or not set, never a value.',
    }),
    direction: z.enum(CHANGE_DIRECTIONS).meta({
      description:
        'Whether the change tightens, loosens or neither; a change whose direction is unknown counts as loosening.',
    }),
    class: classSchema.meta({
      description: 'security when this change needs qauth:admin:security and an approval.',
    }),
    effects: effectsSchema.meta({
      description: 'The effects that make this change a security change; empty for a write.',
    }),
    permissions: permissionsSchema.meta({
      description: 'The admin permissions this change needs.',
    }),
    scopes: scopesSchema.meta({ description: 'The admin scopes this change needs.' }),
    secret: z.boolean().meta({
      description: 'Whether the field is a secret, shown only as set or not set.',
    }),
    environmentBound: z.boolean().meta({
      description:
        'Whether the value describes the environment the realm runs in, which a sandbox promotion leaves out unless it is selected (ADR-019 Decision 11).',
    }),
  })
  .meta({ id: 'AdminChange' });

/** The preview of a save. */
export const changePreviewSchema = z
  .object({
    etag: z.string().meta({
      description:
        'The ETag of the resource as the preview read it: the save names it in If-Match, and is refused with 412 once the resource has moved on.',
    }),
    class: classSchema.meta({
      description:
        'The strictest class of the save: security when any change is, or the save cannot be classified.',
    }),
    effects: effectsSchema.meta({ description: 'Every effect of the save’s security changes.' }),
    permissions: permissionsSchema.meta({
      description: 'Every admin permission the save needs, reading what it answers included.',
    }),
    scopes: scopesSchema.meta({ description: 'Every admin scope the save needs.' }),
    approvalRequired: z.boolean().meta({
      description:
        'Whether the save runs only with an approval: exactly when it is a security save.',
    }),
    twoAdmin: z.enum(['recommended', 'mandatory']).nullable().meta({
      description:
        'Whether a second admin’s approval is recommended or mandatory for the save; null when it needs no approval.',
    }),
    eligibleApprovers: z.int().min(0).nullable().meta({
      description:
        'How many admins other than the caller hold the right to approve the save on the realm: those a second admin’s approval could come from, among the grants the caller’s realm sees (a grant on every realm only from the operator realm). 0 when the caller is the only one; null when the save needs no approval. Today an approval takes the caller’s own step-up alone, and a second admin’s is recommended.',
    }),
    changes: z.array(changePreviewEntrySchema).meta({
      description: 'Every field the save changes, in the order of the schema; empty when none.',
    }),
  })
  .meta({ id: 'AdminChangePreview' });

export type ChangePreview = z.infer<typeof changePreviewSchema>;
export type ChangePreviewEntry = z.infer<typeof changePreviewEntrySchema>;

/**
 * One change, as a preview takes it: the values, which way it moves, and what
 * it needs. A secret field's `before` and `after` say whether one is set
 * (`true`) and are never values.
 */
export interface PreviewedChange {
  readonly path: string;
  readonly before: unknown;
  readonly after: unknown;
  readonly direction: ChangeDirection;
  readonly classification: Classification;
  readonly secret: boolean;
  readonly environmentBound: boolean;
}

/** What a preview says of the approval a security save needs. */
export interface PreviewedApproval {
  readonly twoAdmin: TwoAdmin;
  /** How many admins other than the caller may approve it now. */
  readonly eligibleApprovers: number;
}

/**
 * The admin scopes `permissions` need, in the order of the scopes.
 *
 * @throws {Error} when a permission is not in the catalog: a preview never
 *   names less than the save needs
 */
export function scopesOf(
  permissions: readonly string[],
  registry: Pick<PermissionRegistry, 'get'>
): AdminScope[] {
  const needed = new Set<AdminScope>();
  for (const id of permissions) {
    const permission = registry.get(id);
    if (permission === undefined) {
      throw new Error(`The admin permission ${JSON.stringify(id)} is not in the catalog`);
    }
    needed.add(ADMIN_SCOPES[permission.class]);
  }
  return ADMIN_SCOPE_LIST.filter((scope) => needed.has(scope));
}

/** A change's class, as a save's: never a read. */
function saveClassOf(classification: Classification): (typeof SAVE_CLASSES)[number] {
  if (classification.class === 'read') {
    throw new Error('A preview is of a save, which is never a read');
  }
  return classification.class;
}

/** A secret's state, as a preview shows it. */
const secretState = (set: unknown): (typeof SECRET_STATES)[number] =>
  set === true ? 'set' : 'not set';

/**
 * The preview of a save: `classification`, what the save needs as the
 * operation's own classification decides it; `changes`, each field it
 * changes; `approval`, for a security save, what its approval needs. A
 * secret field is masked here, whatever the caller passed.
 *
 * @throws {Error} when a security save comes without its approval, or a save
 *   that is not one with one
 */
export function changePreview(
  input: {
    readonly etag: string;
    readonly classification: Classification;
    readonly changes: readonly PreviewedChange[];
    readonly approval: PreviewedApproval | null;
  },
  registry: Pick<PermissionRegistry, 'get'>
): ChangePreview {
  const { classification, approval } = input;
  const security = saveClassOf(classification) === 'security';
  if (security !== (approval !== null)) {
    throw new Error('A preview names an approval exactly when the save is a security save');
  }
  return {
    etag: input.etag,
    class: saveClassOf(classification),
    effects: [...classification.effects],
    permissions: [...classification.permissions],
    scopes: scopesOf(classification.permissions, registry),
    approvalRequired: security,
    twoAdmin: approval?.twoAdmin ?? null,
    eligibleApprovers: approval?.eligibleApprovers ?? null,
    changes: input.changes.map((change): ChangePreviewEntry => {
      const effects: SecurityEffect[] = [...change.classification.effects];
      return {
        path: change.path,
        before: change.secret ? secretState(change.before) : change.before,
        after: change.secret ? secretState(change.after) : change.after,
        direction: change.direction,
        class: saveClassOf(change.classification),
        effects,
        permissions: [...change.classification.permissions],
        scopes: scopesOf(change.classification.permissions, registry),
        secret: change.secret,
        environmentBound: change.environmentBound,
      };
    }),
  };
}

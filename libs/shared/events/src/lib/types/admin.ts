import { z } from 'zod';

import { adminDiffSchema } from '../admin-diff';
import { defineEventType } from '../definition';
import { ACTOR_TYPES, extensibleEnum } from '../envelope';
import { FIRST_RELEASE } from './fields';

/**
 * Admin events (ADR-020 §3, ADR-019 Decision 7, issue #459): what an
 * administrator, a service account or an operator changed. They are always
 * on: no environment key and no realm setting turns them off. The event store
 * chains a realm's admin events by hash, so a changed or removed one shows.
 */

/** An admin operation's id in the permission catalog, such as `realms.policies.write`. */
export const ADMIN_OPERATION_PATTERN = /^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*$/;

/** What kind of thing an admin operation changed, as a `snake_case` code. */
export const ADMIN_TARGET_TYPE_PATTERN = /^[a-z][a-z0-9_]*$/;

/** The most approvals one admin event records. */
export const ADMIN_APPROVALS_MAX = 16;

/** One approval of the operation (ADR-019 Decision 7, two-admin approval). */
export const adminApprovalSchema = z
  .strictObject({
    approverId: z
      .string()
      .min(1)
      .max(255)
      .describe('The account id of the admin who approved the operation.'),
    credentialId: z
      .string()
      .min(1)
      .max(1400)
      .describe(
        'The id of the passkey credential the approval was given with. The rule that an approver uses a credential not registered to the requester is checked against it.'
      ),
    approverCreatedBy: z
      .strictObject({
        type: extensibleEnum(ACTOR_TYPES).describe(
          'Who created the account: `user`, an admin; `client`, a service account; `operator_cli`, an operator on the server host, such as a break-glass enrolment; `system`, QAuth itself.'
        ),
        id: z
          .string()
          .min(1)
          .max(255)
          .optional()
          .describe(
            "The creator's identifier: an account id, a `client_id`, or the operating-system user for `operator_cli`. Absent for `system`."
          ),
      })
      .describe(
        "Who created the approver's account. The two-admin rule binds accounts, not people, so the event shows it."
      ),
    approvedAt: z.iso
      .datetime()
      .optional()
      .describe('When the approval was given, as an RFC 3339 time in UTC.'),
  })
  .describe('One approval of the operation.');

export const adminChangeApplied = defineEventType({
  name: 'admin.change_applied',
  version: 1,
  rc: 0,
  description:
    'An administrator, a service account or an operator changed something in the realm through an admin operation. Emitted for every such change, in its transaction; no setting turns it off. The admin events of a realm form one hash chain.',
  category: 'admin',
  severity: 'info',
  since: FIRST_RELEASE,
  diff: 'diff',
  data: z.strictObject({
    operation: z
      .string()
      .min(1)
      .max(128)
      .regex(ADMIN_OPERATION_PATTERN)
      .describe(
        "The operation's id in the permission catalog, such as `realms.policies.write` (ADR-019 Decision 7)."
      ),
    target: z
      .strictObject({
        type: z
          .string()
          .min(1)
          .max(64)
          .regex(ADMIN_TARGET_TYPE_PATTERN)
          .describe(
            'What kind of thing the operation changed, as a `snake_case` code such as `realm`, `client` or `webhook_subscription`. The set grows with the admin API.'
          ),
        id: z
          .string()
          .min(1)
          .max(255)
          .describe(
            "The changed thing's identifier, such as a realm id or a `client_id`. It stays valid after the thing is deleted."
          ),
      })
      .describe('What the operation changed.'),
    diff: adminDiffSchema,
    approvals: z
      .array(adminApprovalSchema)
      .max(ADMIN_APPROVALS_MAX)
      .describe(
        'The approvals the operation ran on, both of a two-admin operation. Empty when it needed none.'
      ),
  }),
});

export const ADMIN_EVENT_TYPES = [adminChangeApplied] as const;

/** One approval, as an admin event records it. */
export type AdminApproval = z.infer<typeof adminApprovalSchema>;

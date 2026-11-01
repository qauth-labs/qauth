import type { SignInAuditRecord } from '@qauth-labs/server-sign-in-engine';
import { STEP_URNS, type StepName } from '@qauth-labs/server-step-grammar';
import type { EventDataOf } from '@qauth-labs/shared-events';

const STEP_PASSED = 'urn:qauth:event:user.sign_in_step_passed:v1-rc.0' as const;
const SIGN_IN_FAILED = 'urn:qauth:event:user.sign_in_failed:v1-rc.0' as const;

/** One audit record of the engine, as the event the transport emits for it. */
export type SignInAuditEvent =
  | {
      readonly type: typeof STEP_PASSED;
      readonly data: EventDataOf<typeof STEP_PASSED>;
      /** The subject: the user once one is resolved, `null` before. */
      readonly userId: string | null;
    }
  | {
      readonly type: typeof SIGN_IN_FAILED;
      readonly data: EventDataOf<typeof SIGN_IN_FAILED>;
      readonly userId: string | null;
    };

/**
 * The sign-in method a step belongs to, for `user.sign_in_failed`'s
 * `method`. A step a later issue adds needs its entry here, and the event's
 * method set may grow with it.
 */
const STEP_METHODS: Readonly<
  Partial<Record<StepName, EventDataOf<typeof SIGN_IN_FAILED>['method']>>
> = Object.freeze({ identifier: 'password', password: 'password' });

/**
 * Map one of the engine's audit records onto a registered event: an accepted
 * step is `user.sign_in_step_passed`, a refused or ended one
 * `user.sign_in_failed` with the engine's reason. The person is the subject
 * once a user is resolved; before, only the identifier's keyed HMAC names
 * them. Nothing else of the record travels: it holds no password, no code and
 * no identifier to begin with.
 *
 * @throws Error for a step with no sign-in method yet: the issue that adds
 *   the step adds its method
 */
export function signInAuditEvent(record: SignInAuditRecord): SignInAuditEvent {
  const identifierHmac =
    record.identifierHmac === undefined ? {} : { identifierHmac: record.identifierHmac };
  const userId = record.userId ?? null;
  if (record.outcome === 'passed') {
    return {
      type: STEP_PASSED,
      data: { step: STEP_URNS[record.step], ...identifierHmac },
      userId,
    };
  }
  const method = STEP_METHODS[record.step];
  if (method === undefined) throw new Error(`no sign-in method for the ${record.step} step`);
  if (record.reason === undefined) throw new Error('a refused sign-in step without a reason');
  return {
    type: SIGN_IN_FAILED,
    data: { method, reason: record.reason, ...identifierHmac },
    userId,
  };
}

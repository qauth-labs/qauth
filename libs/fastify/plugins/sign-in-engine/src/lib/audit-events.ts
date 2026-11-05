import type { SignInAuditRecord } from '@qauth-labs/server-sign-in-engine';
import { STEP_URNS, type StepName } from '@qauth-labs/server-step-grammar';
import type { EventDataOf } from '@qauth-labs/shared-events';

const STEP_PASSED = 'urn:qauth:event:user.sign_in_step_passed:v1-rc.0' as const;
const SIGN_IN_FAILED = 'urn:qauth:event:user.sign_in_failed:v1-rc.0' as const;
const BREACH_CHECK_FAILED = 'urn:qauth:event:user.password_breach_check_failed:v1-rc.0' as const;

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
    }
  | {
      readonly type: typeof BREACH_CHECK_FAILED;
      readonly data: EventDataOf<typeof BREACH_CHECK_FAILED>;
      readonly userId: string | null;
    };

/**
 * The sign-in method a step belongs to, for `user.sign_in_failed`'s
 * `method`. A step a later issue adds needs its entry here, and the event's
 * method set may grow with it. The email code verifies the address of a
 * password account after its password (#638), and the forced update sets
 * a new one after it (#635): both are part of that sign-in, and never a
 * method of their own. The `upstream` step is a sign-in through an upstream
 * identity provider (#639).
 */
const STEP_METHODS: Readonly<
  Partial<Record<StepName, EventDataOf<typeof SIGN_IN_FAILED>['method']>>
> = Object.freeze({
  identifier: 'password',
  password: 'password',
  email_code: 'password',
  new_password: 'password',
  // A reset's start (#642): the password is what it replaces.
  password_reset: 'password',
  upstream: 'upstream',
  // The bot challenge (#643) proves nothing about the account: like the
  // identifier step, it is part of the password sign-in it holds back.
  captcha: 'password',
});

/**
 * Map one of the engine's audit records onto a registered event: an accepted
 * step is `user.sign_in_step_passed`, a refused or ended one
 * `user.sign_in_failed` with the engine's reason, and a breach-list check
 * that could not be made (`unchecked`, #635)
 * `user.password_breach_check_failed` with its failure. The person is the subject
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
  if (record.outcome === 'unchecked') {
    if (record.failure === undefined) throw new Error('an unchecked password without a failure');
    return {
      type: BREACH_CHECK_FAILED,
      data: { step: STEP_URNS[record.step], reason: record.failure },
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

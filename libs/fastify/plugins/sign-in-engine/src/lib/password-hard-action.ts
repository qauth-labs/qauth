import { PASSWORD_PROVIDER_TYPE } from '@qauth-labs/server-federation';
import type {
  PasswordHardAction,
  PasswordHardActionInput,
} from '@qauth-labs/server-sign-in-engine';

/**
 * THE FAILURE LADDER'S HARD ACTION (PRO-12, #615; ADR-017 Decision 7, NIST SP
 * 800-63B-4 §3.2.2): at 100 consecutive counted failures of an account's
 * password, mark the password disabled (`user_credentials.disabled_at`),
 * notify the owner and alert the operator.
 *
 * The disable ends only at the owner's own reset (#642), which no third party
 * can block, so it is armed only while that reset is on and the deployment
 * can send the owner the notice (#637). Both are asked at run time, in the
 * realm, every time: an operator who turns either off disarms it at once,
 * and the lookup then ignores every mark it left.
 */

/** The `user_credentials` writes the hard action makes, by shape (the auth server's repository). */
export interface HardActionCredentials {
  /** Mark the credential disabled, only where it holds no mark yet; the row when this call marked it. */
  setDisabledAt(
    realmId: string,
    providerType: string,
    externalSub: string,
    disabledAt: number
  ): Promise<{ readonly id: string } | undefined>;
  /** Clear the credential's mark; the row when this call cleared one. */
  clearDisabledAt(
    realmId: string,
    providerType: string,
    externalSub: string
  ): Promise<{ readonly id: string } | undefined>;
}

/**
 * The notice that tells the owner the password was disabled and how to reset
 * it (the template of PRO-14, #637). No implementation exists yet, so no
 * deployment arms the hard action.
 */
export interface PasswordDisabledNotices {
  /** Whether the realm's deployment can send the notice now (a mail transport, a template). */
  canSend(realmId: string): Promise<boolean>;
  /** Tell the owner of `userId` their password was disabled, and how to reset it. */
  passwordDisabled(input: PasswordHardActionInput): Promise<void>;
}

/** Where the hard action reports. `error` is the operator's alert: an alerting rule matches its message. */
export interface HardActionLog {
  warn(details: Record<string, unknown>, message: string): void;
  error(details: Record<string, unknown>, message: string): void;
}

/** What arms the hard action, asked at run time in the realm. */
export interface HardActionArmingSources {
  /**
   * Whether the owner's hosted password reset (#642) is on in the realm: the
   * only way back from the disable. Nothing turns it on yet.
   */
  readonly hostedReset: (realmId: string) => boolean | Promise<boolean>;
  /** The owner's notice, or `undefined` while the deployment has none (#637). */
  readonly notices?: PasswordDisabledNotices;
}

/** Whether the hard action is armed in a realm: an error rejects, so the caller fails closed. */
export type HardActionArming = (realmId: string) => Promise<boolean>;

/**
 * The hard action is armed in a realm only while its hosted reset is on and
 * the deployment can send the notice, both asked at every call.
 */
export function createHardActionArming(sources: HardActionArmingSources): HardActionArming {
  return async (realmId) => {
    if (sources.notices === undefined) return false;
    if ((await sources.hostedReset(realmId)) !== true) return false;
    return (await sources.notices.canSend(realmId)) === true;
  };
}

/** What {@link createPasswordHardAction} needs. */
export interface PasswordHardActionDependencies {
  readonly credentials: HardActionCredentials;
  /**
   * What arms it, and the owner's notice it sends: the same sources the
   * caller hands {@link createHardActionArming}, so the notice that arms the
   * hard action is the one it sends.
   */
  readonly arming: HardActionArmingSources;
  readonly log: HardActionLog;
  /** The clock, in epoch ms. `Date.now` by default. */
  readonly now?: () => number;
}

/** The message of the operator's alert when the ladder disables a password. */
export const PASSWORD_DISABLED_ALERT = 'password disabled by the failure ladder';

/**
 * The hard action over the auth server's credentials.
 *
 * - `ceilingReached`: unarmed, it changes nothing and logs a warning (the
 *   account is being guessed at, and nothing stops it but the wait); armed, it
 *   marks the password, and only the call that marked it alerts the operator
 *   and sends the notice, so a run of failures past the ceiling sends one.
 *   The notice is sent without being awaited: a slow mail transport must not
 *   lengthen the refused attempt's answer, which would tell an account that
 *   exists from one that does not. A notice that fails is alerted too; the
 *   mark stays, as the owner's reset ends it.
 * - `clearIgnoredMark`: clears a mark the lookup ignored while the hard action
 *   was unarmed, after the password proved the account.
 *
 * The log carries the realm and the user, never the identifier.
 */
export function createPasswordHardAction(deps: PasswordHardActionDependencies): PasswordHardAction {
  const now = deps.now ?? (() => Date.now());
  const armed = createHardActionArming(deps.arming);
  return Object.freeze({
    async ceilingReached(input: PasswordHardActionInput): Promise<void> {
      const subject = { realmId: input.realmId, userId: input.userId };
      if (!(await armed(input.realmId))) {
        deps.log.warn(
          { ...subject, reason: 'hard_action_unarmed' },
          'password failure ladder reached its hard ceiling; the hard action is unarmed, so the password stays usable'
        );
        return;
      }
      const marked = await deps.credentials.setDisabledAt(
        input.realmId,
        PASSWORD_PROVIDER_TYPE,
        input.identifier,
        now()
      );
      // Already marked by another attempt, or no such credential: nothing new.
      if (marked === undefined) return;
      // The operator's alert: this log line is the alerting hook.
      deps.log.error({ ...subject, credentialId: marked.id }, PASSWORD_DISABLED_ALERT);
      const notTold = (error: unknown) =>
        deps.log.error(
          { ...subject, credentialId: marked.id, err: error },
          'the owner was not told their password was disabled'
        );
      const notices = deps.arming.notices;
      if (notices === undefined) {
        notTold(new Error('no notice to send'));
        return;
      }
      // Off the answer's path: not awaited, its failure alerted.
      let sending: Promise<void>;
      try {
        sending = notices.passwordDisabled(input);
      } catch (error) {
        sending = Promise.reject(error);
      }
      sending.catch(notTold);
    },

    async clearIgnoredMark(input: PasswordHardActionInput): Promise<void> {
      const cleared = await deps.credentials.clearDisabledAt(
        input.realmId,
        PASSWORD_PROVIDER_TYPE,
        input.identifier
      );
      if (cleared !== undefined) {
        deps.log.warn(
          { realmId: input.realmId, userId: input.userId, credentialId: cleared.id },
          'a successful sign-in cleared a disabled mark the unarmed hard action ignored'
        );
      }
    },
  });
}

import {
  type LadderHook,
  type LadderReservation,
  type LadderSettlement,
  NOTHING_DUE,
} from '../hooks';
import type { AccountDirectory, SignInAccount, TotpCredentials } from '../ports';
import { fromStore, SignInStoreUnavailableError } from '../store';
import type { StepHandler, StepVerdict } from './handler';

/** What the TOTP step needs. */
export interface TotpStepDependencies {
  readonly totp: TotpCredentials;
  readonly accounts: AccountDirectory;
  readonly ladder: LadderHook;
  /** A settle, a notice or a hard action that failed: reported, never answered. */
  readonly onReportFailure?: (error: SignInStoreUnavailableError) => void;
}

/** Every refused code, whatever the reason: nothing says whether it was wrong or used already. */
const REFUSED: StepVerdict = Object.freeze({
  kind: 'refused',
  error: 'invalid_credentials',
  audit: Object.freeze({ reason: 'invalid_credentials' }),
});

/** Whether `account` holds a TOTP it can use: bound and not disabled. */
export function holdsUsableTotp(account: SignInAccount): boolean {
  return account.factors.some((factor) => factor.type === 'totp' && !factor.disabled);
}

/** Whether `account` holds a TOTP, a disabled one included: it owes it after its first factor. */
export function holdsTotp(account: SignInAccount): boolean {
  return account.factors.some((factor) => factor.type === 'totp');
}

/**
 * The `totp` step (#653; ADR-017 Decisions 4, 7 and 10,
 * `graphs/flows/core/totp/flow.yaml`): a code from the account's
 * authenticator app, after the first factor. A second factor: it never names
 * the account, and the engine asks for it only once a first factor fixed the
 * subject. Its amr is `otp`, so after a password the sign-in carries
 * `["pwd","otp","mfa"]`.
 *
 * 1. Reserve the attempt on the ladder's `totp` counter, keyed on the realm
 *    and the user (ADR-017 Decision 7, the second-factor row): one counter
 *    shared by every transaction, client, transport and IP, with no end-user
 *    IP, so no known IP skips its wait. Inside a wait the answer is refused
 *    as `throttled` (429), neither checked nor counted.
 * 2. Check the code through the port: within one step of now and later than
 *    the last step the TOTP accepted, taken in the write that accepts it.
 * 3. A right code settles the attempt as a success, which clears the TOTP
 *    counter and no other; a correct password never clears it.
 * 4. A wrong one settles it as a failure. After a correct password in the
 *    same transaction the user is told, at most once a day (the port holds
 *    the claim); and a failure counted at or past the ladder's hard ceiling
 *    fires the port's hard action, which disables the TOTP while it is
 *    armed.
 *
 * Settling, the notice and the hard action never change the answer: the
 * attempt is already counted as a failure, so one that fails is reported.
 */
export function createTotpStep(deps: TotpStepDependencies): StepHandler<'totp'> {
  const report = (port: string, error: unknown) => {
    try {
      deps.onReportFailure?.(new SignInStoreUnavailableError(port, error));
    } catch {
      // A reporter that fails must not change the code's verdict either.
    }
  };
  const settle = async (
    reservation: LadderReservation,
    outcome: 'success' | 'failure'
  ): Promise<LadderSettlement> => {
    try {
      const settled = await reservation.settle(outcome);
      return settled?.ceilingReached === true ? settled : NOTHING_DUE;
    } catch (error) {
      report('ladder', error);
      return NOTHING_DUE;
    }
  };
  const afterRefusal = async (call: () => Promise<void>) => {
    try {
      await call();
    } catch (error) {
      report('totp', error);
    }
  };
  const handler: StepHandler<'totp'> = {
    step: 'totp',
    role: 'second_factor',
    factor: 'totp',
    usableBy: holdsUsableTotp,
    params: () => ({ digits: 6 }),
    personal: ({ identifier }) => (identifier === undefined ? {} : { identifier }),
    async verify({ realmId, clientId, transaction }, read) {
      const userId = transaction.subject;
      // A second factor follows a first one: the engine never asks for it before.
      if (userId === undefined) throw new Error('totp step: no subject');
      const reservation = await fromStore('ladder', () =>
        deps.ladder.reserve({ realmId, userId, factor: 'totp' })
      );
      if (reservation.kind === 'wait') {
        return {
          kind: 'throttled',
          retryAfterSeconds: reservation.retryAfterSeconds,
          audit: { reason: 'locked_out' },
        };
      }
      const outcome: unknown = await fromStore('totp', () =>
        deps.totp.verify({ realmId, userId, clientId, code: read.answer.otp })
      );
      const kind = (outcome as { kind?: unknown } | null)?.kind;
      if (kind === 'refused') {
        const settled = await settle(reservation, 'failure');
        if (transaction.verified.some((step) => step.step === 'password')) {
          await afterRefusal(() => deps.totp.failedAfterPassword({ realmId, userId, clientId }));
        }
        if (settled.ceilingReached) {
          await afterRefusal(() => deps.totp.ceilingReached({ realmId, userId }));
        }
        return REFUSED;
      }
      if (kind !== 'accepted') {
        throw new SignInStoreUnavailableError('totp', new Error('not a verification'));
      }
      await settle(reservation, 'success');
      const account = await fromStore('accounts', () =>
        deps.accounts.findByUserId(realmId, userId)
      );
      if (account === null || account.userId !== userId) return REFUSED;
      return Object.freeze({
        kind: 'proved',
        account: Object.freeze({
          userId: account.userId,
          enabled: account.enabled,
          verified: account.verified,
        }),
      });
    },
  };
  return Object.freeze(handler);
}

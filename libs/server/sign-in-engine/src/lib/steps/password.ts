import {
  type LadderHook,
  type LadderReservation,
  type LadderSettlement,
  NOTHING_DUE,
} from '../hooks';
import type {
  AccountDirectory,
  PasswordHardAction,
  PasswordVerifier,
  SignInAccount,
} from '../ports';
import { fromStore, SignInStoreUnavailableError } from '../store';
import type { StepHandler, StepVerdict, VerdictAudit } from './handler';

/** What the password step needs. */
export interface PasswordStepDependencies {
  readonly accounts: AccountDirectory;
  readonly passwords: PasswordVerifier;
  readonly ladder: LadderHook;
  /** The ladder's hard action (#615): at the hard ceiling, and for an ignored mark a success clears. */
  readonly hardAction: PasswordHardAction;
  /** `REQUIRE_VERIFIED_ACCOUNT`: an unverified account is refused like a wrong password. */
  readonly requireVerifiedAccount: boolean;
  /** Told when settling a reservation or the hard action failed: reported, never answered. */
  readonly onSettleFailure?: (error: SignInStoreUnavailableError) => void;
}

/**
 * The password step (ADR-017 Decision 3: `urn:qauth:ia:password`, answer
 * `password`, `amr` `pwd`). Offered with no params and the transaction's
 * identifier as personal data, the same for every account.
 *
 * Verifying an answer, in this order (ADR-017 Decision 7):
 *
 * 1. Reserve the attempt on the ladder, keyed on the identifier's HMAC. An
 *    attempt inside a wait is refused, neither verified nor counted.
 * 2. Read what the password needs of the account the identifier names: its
 *    user, its enabled flag, whether it is verified, its password. Nothing
 *    more, so an account that exists costs and risks one read more than none.
 * 3. One Argon2id verification, whatever the account: against its hash when
 *    it has a usable password, else against the dummy hash (no account, a
 *    passkey-only account, a disabled or unreadable password).
 * 4. Refuse, every time with `invalid_credentials`: a wrong password, no
 *    usable password, a disabled user (nothing about it changes), and an
 *    unverified account while `REQUIRE_VERIFIED_ACCOUNT` is on
 *    (ANT-2026-SPEMY9GU; PRO-15 verifies it inline instead). Each refusal
 *    settles the attempt as a failure. Only the audit record's reason tells
 *    them apart.
 *    When the failure counted at the ladder's hard ceiling (#615) and the
 *    identifier names an enabled account with a password not yet disabled,
 *    the hard action is called: it disables the password only while it is
 *    armed. A disabled user is never changed.
 * 5. Otherwise settle the attempt as a success: the password proved the
 *    account, and its counter is cleared. A disabled mark the lookup ignored
 *    (the hard action unarmed) is cleared too, as a reset would.
 *
 * Settling and the hard action never change the answer: the attempt is
 * already counted as a failure, so a settle that fails is reported and leaves
 * it so, whichever way the password went, and a hard action that fails is
 * reported and fires again at the run's next failure.
 */
export function createPasswordStep(deps: PasswordStepDependencies): StepHandler<'password'> {
  const report = (port: string, error: unknown) => {
    try {
      deps.onSettleFailure?.(new SignInStoreUnavailableError(port, error));
    } catch {
      // A reporter that fails must not change the password's verdict either.
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
  const hardAction = async (call: () => Promise<void>) => {
    try {
      await call();
    } catch (error) {
      report('hardAction', error);
    }
  };
  const handler: StepHandler<'password'> = {
    step: 'password',
    role: 'first_factor',
    factor: 'password',
    usableBy: (account: SignInAccount) =>
      account.factors.some((factor) => factor.type === 'password' && !factor.disabled),
    params: () => ({}),
    personal: (round) => (round.identifier === undefined ? {} : { identifier: round.identifier }),
    async verify(round, read) {
      const { identifier } = round;
      // The engine asks for a password only once the transaction holds an identifier.
      if (identifier === undefined) throw new Error('password step: no identifier');
      const identifierHmac = await round.identifierHmac();

      const reservation = await fromStore('ladder', () =>
        deps.ladder.reserve({
          realmId: round.realmId,
          identifierHmac,
          factor: 'password',
          ...(round.endUserIp === undefined ? {} : { endUserIp: round.endUserIp }),
        })
      );
      if (reservation.kind === 'wait') {
        return {
          kind: 'throttled',
          retryAfterSeconds: reservation.retryAfterSeconds,
          audit: { reason: 'locked_out' },
        };
      }

      const candidate = await fromStore('accounts', () =>
        deps.accounts.findByIdentifier(round.realmId, identifier)
      );
      const password = candidate?.password;
      const hash =
        password !== undefined && password !== null && !password.disabled ? password.hash : null;
      const presented = read.answer.password;
      let valid = false;
      if (hash === null) {
        await fromStore('passwords', () => deps.passwords.verifyDecoy(presented));
      } else {
        valid = await fromStore('passwords', () => deps.passwords.verify(hash, presented));
      }

      const target = (userId: string) => ({ realmId: round.realmId, userId, identifier });
      const refuse = async (audit: VerdictAudit): Promise<StepVerdict> => {
        const settled = await settle(reservation, 'failure');
        // The hard action, for an account that exists and is enabled, whose
        // password is not already disabled. A disabled user is never changed.
        if (
          settled.ceilingReached &&
          candidate !== null &&
          candidate.enabled &&
          password !== undefined &&
          password !== null &&
          !password.disabled
        ) {
          await hardAction(() => deps.hardAction.ceilingReached(target(candidate.userId)));
        }
        return { kind: 'refused', error: 'invalid_credentials', audit };
      };
      if (candidate === null || !valid) return refuse({ reason: 'invalid_credentials' });
      // Never a subject for a disabled user, and nothing about it changes.
      if (!candidate.enabled) return refuse({ reason: 'account_disabled' });
      if (!candidate.verified && deps.requireVerifiedAccount) {
        return refuse({ reason: 'email_not_verified' });
      }
      await settle(reservation, 'success');
      // A mark the lookup ignored while the hard action is unarmed: a
      // successful sign-in clears it, as a reset does (ADR-017 Decision 7).
      if (password?.ignoredMark === true) {
        await hardAction(() => deps.hardAction.clearIgnoredMark(target(candidate.userId)));
      }
      return {
        kind: 'proved',
        account: {
          userId: candidate.userId,
          enabled: candidate.enabled,
          verified: candidate.verified,
        },
      };
    },
  };
  return Object.freeze(handler);
}

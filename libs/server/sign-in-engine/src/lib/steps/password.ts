import { passwordForVerification } from '@qauth-labs/shared-validation';

import {
  type LadderHook,
  type LadderReservation,
  type LadderSettlement,
  type LadderSuccessOptions,
  NOTHING_DUE,
} from '../hooks';
import type {
  AccountDirectory,
  BreachCheckVerdict,
  BreachedPasswordCheck,
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
  /** The realm's breach list (#635), checked once a password proved its account. */
  readonly breachCheck?: BreachedPasswordCheck;
}

/**
 * Check `password` against the realm's breach list. A port that throws, or
 * answers something else than a verdict, is a failed check: no breach-list
 * check ever blocks a sign-in (ADR-020 §3, #635).
 */
export async function checkBreachList(
  check: BreachedPasswordCheck | undefined,
  realmId: string,
  password: string
): Promise<BreachCheckVerdict> {
  if (check === undefined) return Object.freeze({ kind: 'off' });
  try {
    const verdict = await check.check({ realmId, password });
    switch (verdict?.kind) {
      case 'off':
      case 'not_listed':
      case 'listed':
        return Object.freeze({ kind: verdict.kind });
      case 'failed':
        return Object.freeze({ kind: 'failed', failure: verdict.failure });
      default:
        return Object.freeze({ kind: 'failed', failure: 'unavailable' });
    }
  } catch {
    return Object.freeze({ kind: 'failed', failure: 'unavailable' });
  }
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
 *    (the hard action unarmed) is cleared too, as a reset would. For an
 *    account whose address is not proved yet (verified inline, #638) the
 *    end-user IP is not made known and the mark stays: whoever chose the
 *    password need not own the address.
 * 6. Check the right password against the realm's breach list (#635), as it
 *    was verified: QAuth keeps only the hash, so this is the one moment it
 *    can. The verdict travels with the proof; a listed password asks for a
 *    new one in rule 8, and a check that fails changes nothing but the record.
 *    Only a right password is checked, so no refusal costs a lookup.
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
    outcome: 'success' | 'failure',
    options?: LadderSuccessOptions
  ): Promise<LadderSettlement> => {
    try {
      const settled = await (options === undefined
        ? reservation.settle(outcome)
        : reservation.settle(outcome, options));
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
      let asHashed = presented;
      if (hash === null) {
        await fromStore('passwords', () => deps.passwords.verifyDecoy(presented));
      } else {
        // In NFC when the credential records the marker of the one password
        // policy, as typed when it records none (#634).
        asHashed = passwordForVerification(presented, password?.normalization);
        valid = await fromStore('passwords', () => deps.passwords.verify(hash, asHashed));
      }

      const target = (userId: string) => ({ realmId: round.realmId, userId, identifier });
      const refuse = async (audit: VerdictAudit): Promise<StepVerdict> => {
        const settled = await settle(reservation, 'failure');
        // The hard action, for an account that exists and is enabled, whose
        // password was usable: not already disabled, its data readable. A
        // disabled user is never changed.
        if (settled.ceilingReached && candidate !== null && candidate.enabled && hash !== null) {
          await hardAction(() => deps.hardAction.ceilingReached(target(candidate.userId)));
        }
        return { kind: 'refused', error: 'invalid_credentials', audit };
      };
      if (candidate === null || !valid) return refuse({ reason: 'invalid_credentials' });
      // Never a subject for a disabled user, and nothing about it changes.
      if (!candidate.enabled) return refuse({ reason: 'account_disabled' });
      if (!candidate.verified && deps.requireVerifiedAccount) {
        return refuse({ reason: 'account_not_verified' });
      }
      // The right password of an account whose address is not proved yet
      // (#638) clears the counter, and makes no IP known: until the address
      // is verified, whoever chose the password need not be its owner, and a
      // known IP would later skip the owner's waits and send caps.
      await settle(reservation, 'success', candidate.verified ? undefined : { rememberIp: false });
      // A mark the lookup ignored while the hard action is unarmed: a
      // successful sign-in of the owner clears it, as a reset does (ADR-017
      // Decision 7); an unverified account's sign-in leaves it.
      if (password?.ignoredMark === true && candidate.verified) {
        await hardAction(() => deps.hardAction.clearIgnoredMark(target(candidate.userId)));
      }
      const breachCheck = await checkBreachList(deps.breachCheck, round.realmId, asHashed);
      return {
        kind: 'proved',
        account: {
          userId: candidate.userId,
          enabled: candidate.enabled,
          verified: candidate.verified,
        },
        ...(breachCheck.kind === 'off' ? {} : { breachCheck }),
      };
    },
  };
  return Object.freeze(handler);
}

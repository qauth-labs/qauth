import type { LadderHook } from '../hooks';
import type { AccountDirectory, PasswordVerifier, SignInAccount } from '../ports';
import { fromStore } from '../store';
import type { StepHandler, StepVerdict, VerdictAudit } from './handler';

/** What the password step needs. */
export interface PasswordStepDependencies {
  readonly accounts: AccountDirectory;
  readonly passwords: PasswordVerifier;
  readonly ladder: LadderHook;
  /** `REQUIRE_VERIFIED_ACCOUNT`: an unverified account is refused like a wrong password. */
  readonly requireVerifiedAccount: boolean;
}

/** The account's password, when it has one it can use: bound, not disabled, readable. */
function usablePasswordHash(account: SignInAccount | null): string | null {
  if (account === null) return null;
  for (const factor of account.factors) {
    if (factor.type === 'password' && !factor.disabled && factor.hash !== null) return factor.hash;
  }
  return null;
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
 * 2. Read the account the identifier names.
 * 3. One Argon2id verification, whatever the account: against its hash when
 *    it has a usable password, else against the dummy hash (no account, a
 *    passkey-only account, a disabled or unreadable password).
 * 4. Refuse, every time with `invalid_credentials`: a wrong password, no
 *    usable password, a disabled user (nothing about it changes), and an
 *    unverified account while `REQUIRE_VERIFIED_ACCOUNT` is on
 *    (ANT-2026-SPEMY9GU; PRO-15 verifies it inline instead). Each refusal
 *    settles the attempt as a failure. Only the audit record tells them
 *    apart.
 * 5. Otherwise settle the attempt as a success: the password proved the
 *    account.
 */
export function createPasswordStep(deps: PasswordStepDependencies): StepHandler<'password'> {
  const handler: StepHandler<'password'> = {
    step: 'password',
    role: 'first_factor',
    factor: 'password',
    usableBy: (account: SignInAccount) => usablePasswordHash(account) !== null,
    params: () => ({}),
    personal: (round) => (round.identifier === undefined ? {} : { identifier: round.identifier }),
    async verify(round, read) {
      const { identifier } = round;
      // The engine asks for a password only once the transaction holds an identifier.
      if (identifier === undefined) throw new Error('password step: no identifier');
      const identifierHmac = await round.identifierHmac();

      const reservation = await fromStore('ladder', () =>
        deps.ladder.reserve({ realmId: round.realmId, identifierHmac, factor: 'password' })
      );
      if (reservation.kind === 'wait') {
        return {
          kind: 'throttled',
          retryAfterSeconds: reservation.retryAfterSeconds,
          audit: { reason: 'locked_out' },
        };
      }

      const account = await fromStore('accounts', () =>
        deps.accounts.findByIdentifier(round.realmId, identifier)
      );
      const hash = usablePasswordHash(account);
      const presented = read.answer.password;
      let valid = false;
      if (hash === null) {
        await fromStore('passwords', () => deps.passwords.verifyDecoy(presented));
      } else {
        valid = await fromStore('passwords', () => deps.passwords.verify(hash, presented));
      }

      const refuse = async (audit: VerdictAudit): Promise<StepVerdict> => {
        await fromStore('ladder', () => reservation.settle('failure'));
        return { kind: 'refused', error: 'invalid_credentials', audit };
      };
      if (account === null || !valid) return refuse({ reason: 'invalid_credentials' });
      // Never a subject for a disabled user, and nothing about it changes.
      if (!account.enabled) return refuse({ reason: 'account_disabled' });
      if (!account.verified && deps.requireVerifiedAccount) {
        return refuse({ reason: 'email_not_verified', userId: account.userId });
      }
      await fromStore('ladder', () => reservation.settle('success'));
      return { kind: 'proved', account };
    },
  };
  return Object.freeze(handler);
}

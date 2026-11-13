import { type OfferedStep, type StepName, transactionAmr } from '@qauth-labs/server-step-grammar';

import type { BoundFactor, FactorType, MfaMode, MfaPolicy, SignInAccount } from './ports';

/**
 * The downgrade rule and the MFA policy (ADR-017 Decision 4), as pure
 * functions of the account, the transaction and the policy just read.
 */

/**
 * How strong each first factor is: a passkey above a password. A second
 * factor is not ranked: the MFA policy asks for it, the downgrade rule does
 * not. An upstream sign-in ranks with the password: {@link UPSTREAM_STRENGTH}.
 */
export const FIRST_FACTOR_STRENGTH: Readonly<Partial<Record<FactorType, number>>> = Object.freeze({
  password: 1,
  passkey: 2,
});

/**
 * How strong a sign-in through an upstream identity provider is (#639): with
 * the password, below a passkey (ADR-017 Decision 4, decided 2026-10-23). An
 * account that holds a passkey proves it after its upstream sign-in, whatever
 * the MFA policy says.
 */
export const UPSTREAM_STRENGTH = 1;

/**
 * Whether a factor is new at `now` (#1064; ADR-017 Decision 8, amended
 * 2026-11-12): bound after a sign-in that proved only the password, inside
 * the realm's window.
 */
export function isNewFactor(factor: BoundFactor, now: number): boolean {
  return factor.newUntil !== undefined && now < factor.newUntil;
}

/**
 * The account as the rules that guard it against its password read it
 * (#1064): every factor that is not new. A new factor signs in as usual, but
 * it is not the account's strongest factor for the downgrade rule, the TOTP
 * owed after a first factor, a reset or a forced password update. Disabled
 * factors stay, as they always count as bound.
 */
export function settledAccount(account: SignInAccount, now: number): SignInAccount {
  if (!account.factors.some((factor) => isNewFactor(factor, now))) return account;
  return Object.freeze({
    ...account,
    factors: Object.freeze(account.factors.filter((factor) => !isNewFactor(factor, now))),
  });
}

/** The strength of one factor type: 0 for a factor the downgrade rule does not rank. */
export function factorStrength(factor: FactorType | undefined): number {
  return factor === undefined ? 0 : (FIRST_FACTOR_STRENGTH[factor] ?? 0);
}

/**
 * The strength of the account's strongest bound first factor. A disabled
 * factor counts: disabling one never lowers what a sign-in must prove.
 */
export function strongestBoundFactor(account: SignInAccount): number {
  let strongest = 0;
  for (const factor of account.factors)
    strongest = Math.max(strongest, factorStrength(factor.type));
  return strongest;
}

/**
 * The strength of the strongest first factor the transaction proved.
 * `factorOf` names the factor each step proves: the engine passes its
 * handlers', so a step and its rank have one source. An `upstream` step
 * proves {@link UPSTREAM_STRENGTH}.
 */
export function provenFactorStrength(
  verified: readonly OfferedStep[],
  factorOf: (step: StepName) => FactorType | undefined
): number {
  let strongest = 0;
  for (const step of verified) {
    const strength =
      step.step === 'upstream' ? UPSTREAM_STRENGTH : factorStrength(factorOf(step.step));
    strongest = Math.max(strongest, strength);
  }
  return strongest;
}

/** Whether a mode asks this account for a second factor. `optional` lets the person choose, so it asks nothing. */
function requires(mode: MfaMode, account: SignInAccount): boolean {
  return mode === 'required' || (mode === 'required_for_admins' && account.admin);
}

/** Whether the realm's or the client's policy requires a second factor of this account. */
export function secondFactorRequired(policy: MfaPolicy, account: SignInAccount): boolean {
  return requires(policy.realm, account) || requires(policy.client, account);
}

/** Whether the transaction's `amr` carries `mfa`: the only way to meet a policy that requires a second factor. */
export function provesMfa(verified: readonly OfferedStep[]): boolean {
  return transactionAmr(verified)?.includes('mfa') ?? false;
}

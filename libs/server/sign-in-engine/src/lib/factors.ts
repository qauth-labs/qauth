import { type OfferedStep, type StepName, transactionAmr } from '@qauth-labs/server-step-grammar';

import type { FactorType, MfaMode, MfaPolicy, SignInAccount } from './ports';

/**
 * The downgrade rule and the MFA policy (ADR-017 Decision 4), as pure
 * functions of the account, the transaction and the policy just read.
 */

/**
 * How strong each first factor is: a passkey above a password. A second
 * factor is not ranked: the MFA policy asks for it, the downgrade rule does
 * not. An upstream sign-in will rank with the password (#639).
 */
export const FIRST_FACTOR_STRENGTH: Readonly<Partial<Record<FactorType, number>>> = Object.freeze({
  password: 1,
  passkey: 2,
});

/** The factor each verifying step proves. */
export const STEP_FACTOR: Readonly<Partial<Record<StepName, FactorType>>> = Object.freeze({
  password: 'password',
  webauthn_get: 'passkey',
  totp: 'totp',
});

/**
 * The strength of the account's strongest bound first factor. A disabled
 * factor counts: disabling one never lowers what a sign-in must prove.
 */
export function strongestBoundFactor(account: SignInAccount): number {
  let strongest = 0;
  for (const factor of account.factors) {
    strongest = Math.max(strongest, FIRST_FACTOR_STRENGTH[factor.type] ?? 0);
  }
  return strongest;
}

/** The strength of the strongest first factor the transaction proved. */
export function provenFactorStrength(verified: readonly OfferedStep[]): number {
  let strongest = 0;
  for (const step of verified) {
    const factor = STEP_FACTOR[step.step];
    if (factor !== undefined) strongest = Math.max(strongest, FIRST_FACTOR_STRENGTH[factor] ?? 0);
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

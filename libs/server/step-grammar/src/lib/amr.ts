import { StepMappingError } from './mapping-error';
import { checkParams, type OfferedStep, refuseUnknownMembers } from './offer';
import { isStepName, STEP_AMR, type StepName, type StepNamed, type StepParams } from './steps';

/**
 * A transaction's `amr` (ADR-017 Decision 10), from the steps it verified.
 * Each step adds the values of its `amr` (`STEP_AMR`: `password` `pwd`,
 * `webauthn_get` `pop` and `mfa`, `totp` `otp`), and factors of two kinds
 * add `mfa`. The decision's table, row by row:
 *
 * | Transaction                                              | `amr`                 |
 * | -------------------------------------------------------- | --------------------- |
 * | Password (with or without the post-password email check) | `["pwd"]`             |
 * | Passkey with user verification                           | `["pop","mfa"]`       |
 * | Password, then passkey (downgrade rule)                  | `["pwd","pop","mfa"]` |
 * | Password and TOTP                                        | `["pwd","otp","mfa"]` |
 * | Registration, reset                                      | omitted               |
 *
 * An email code and a recovery code add nothing (ADR-017 Decisions 5 and
 * 8), so a recovery code standing in for a factor never makes `mfa`.
 */

/** An `amr` value a step may add. */
export type AmrValue = StepNamed<StepName>['amr'][number];

/** The order the decision's table writes the values in. */
const AMR_ORDER: readonly AmrValue[] = Object.freeze(['pwd', 'pop', 'otp', 'mfa'] as const);

/** The values that each name a factor; `mfa` names their combination. */
const FACTORS: readonly AmrValue[] = Object.freeze(['pwd', 'pop', 'otp'] as const);

/** Whether a verified step makes the transaction a registration or a reset. */
function registersOrResets(step: OfferedStep): boolean {
  if (step.step === 'password_reset') return true;
  if (step.step !== 'new_password') return false;
  const { purpose } = step.params as StepParams<'new_password'>;
  return purpose === 'register' || purpose === 'reset';
}

/**
 * The `amr` of a transaction that verified `verifiedSteps`: every step whose
 * answer the engine accepted, in order, with the params it was offered with
 * (the `step` and `params` of each accepted `readAnswer`). `undefined` means
 * the code and its tokens carry neither `amr` nor `auth_time`: a
 * registration (`new_password` for `register`), a reset (`password_reset`,
 * or `new_password` for `reset`), whatever factor it also verified, and a
 * transaction that verified no factor. Throws {@link StepMappingError} for
 * a step the grammar does not know or params outside its schema.
 */
export function transactionAmr(
  verifiedSteps: readonly OfferedStep[]
): readonly AmrValue[] | undefined {
  if (!Array.isArray(verifiedSteps)) {
    throw new StepMappingError('unknown_member', 'verifiedSteps is not an array');
  }
  const values = new Set<AmrValue>();
  let omitted = false;
  verifiedSteps.forEach((verified, index) => {
    const at = `verifiedSteps.${index}`;
    refuseUnknownMembers(verified, ['step', 'params'], at);
    const name: unknown = verified.step;
    if (typeof name !== 'string' || !isStepName(name)) {
      throw new StepMappingError('unknown_step', `${at}.step`);
    }
    const step = { step: name, params: checkParams(name, verified.params, at) } as OfferedStep;
    if (registersOrResets(step)) omitted = true;
    for (const value of STEP_AMR[name] as readonly AmrValue[]) values.add(value);
  });
  const factors = FACTORS.filter((value) => values.has(value));
  if (omitted || factors.length === 0) return undefined;
  if (factors.length > 1) values.add('mfa');
  return Object.freeze(AMR_ORDER.filter((value) => values.has(value)));
}

import type { StepDefinition } from '../step-definition';
import {
  emailCode,
  newPassword,
  passwordReset,
  recoveryCodes,
  totpSetup,
  webauthnCreate,
} from './account';
import { consent, deviceCode, deviceConfirm, logoutConfirm } from './authorization';
import {
  captcha,
  identifier,
  password,
  recoveryCode,
  selectAccount,
  totp,
  webauthnGet,
} from './sign-in';

/**
 * Every step of the Interaction API v1: first the steps ADR-017 Decision 3
 * lists, which the FiPA endpoint serves too, in that record's order, then the
 * steps only the Interaction API serves. This order is the order of the
 * published document and of the docs page.
 */
export const STEPS: readonly StepDefinition[] = [
  identifier,
  password,
  emailCode,
  newPassword,
  passwordReset,
  captcha,
  webauthnGet,
  webauthnCreate,
  totp,
  recoveryCode,
  recoveryCodes,
  totpSetup,
  consent,
  selectAccount,
  deviceCode,
  deviceConfirm,
  logoutConfirm,
];

/** The step with this short name. Throws for a name no step has. */
export function stepNamed(name: string): StepDefinition {
  const step = STEPS.find((candidate) => candidate.name === name);
  if (step === undefined) throw new Error(`no step is named ${name}`);
  return step;
}

/** The step with this URN, or `undefined`. */
export function stepByUrn(urn: string): StepDefinition | undefined {
  return STEPS.find((candidate) => candidate.urn === urn);
}

/** The union of every step's errors, in first-seen order. */
export function stepErrorCodes(steps: readonly StepDefinition[] = STEPS): string[] {
  return [...new Set(steps.flatMap((step) => step.errors))];
}

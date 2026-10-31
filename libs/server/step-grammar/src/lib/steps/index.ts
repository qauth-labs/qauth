import type { z } from 'zod';

import type { AnyGrammarStep, StepUrnOf } from '../grammar';
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

export { EMAIL_CODE_PURPOSES } from './account';

/**
 * Every step of the grammar, in the order of the Interaction API contract:
 * first the steps ADR-017 Decision 3 lists, which the FiPA endpoint may serve
 * too, then the steps only the Interaction API serves.
 */
export const STEP_LIST = Object.freeze([
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
] as const);

/** The union of every step. A new step joins it here, and then needs a mapper on each transport. */
export type GrammarStepUnion = (typeof STEP_LIST)[number];

/** A step's short name: `password`. */
export type StepName = GrammarStepUnion['name'];

/** A step's name on the wire: `urn:qauth:ia:password:v1-rc.0`. */
export type StepUrn = GrammarStepUnion['urn'];

/** The step named `N`. */
export type StepNamed<N extends StepName> = Extract<GrammarStepUnion, { readonly name: N }>;

/** The steps the FiPA endpoint may serve: those ADR-017 Decision 3 lists. */
export type FipaStepName = Extract<
  GrammarStepUnion,
  { readonly transports: readonly ['interaction', 'fipa'] }
>['name'];

/** The steps only the Interaction API serves. The FiPA mapper cannot emit them. */
export type InteractionOnlyStepName = Exclude<StepName, FipaStepName>;

/** What the screen of step `N` needs. */
export type StepParams<N extends StepName> = z.output<StepNamed<N>['params']>;

/** The personal data of step `N`. */
export type StepPersonal<N extends StepName> = z.output<StepNamed<N>['personal']>;

/** An answer to step `N`, as the server reads it. */
export type StepAnswer<N extends StepName> = z.output<StepNamed<N>['answer']>;

/** Why an answer to step `N` was refused: its closed set (`never` for a step that refuses none). */
export type StepError<N extends StepName> = StepNamed<N>['errors'][number];

/** Every step's error, one closed set. */
export type StepErrorCode = StepError<StepName>;

/** Every step, by its short name. */
export const STEP_GRAMMAR = Object.freeze(
  Object.fromEntries(STEP_LIST.map((step) => [step.name, step]))
) as { readonly [N in StepName]: StepNamed<N> };

/** Every step name, in grammar order. */
export const STEP_NAMES: readonly StepName[] = Object.freeze(STEP_LIST.map((step) => step.name));

/** The URN of every step, by its short name. */
export const STEP_URNS = Object.freeze(
  Object.fromEntries(STEP_LIST.map((step) => [step.name, step.urn]))
) as { readonly [N in StepName]: StepUrnOf<N> };

/** The `amr` values a successful answer to each step adds, by its short name. */
export const STEP_AMR = Object.freeze(
  Object.fromEntries(STEP_LIST.map((step) => [step.name, step.amr]))
) as { readonly [N in StepName]: StepNamed<N>['amr'] };

/** The closed error set of each step, by its short name. */
export const STEP_ERRORS = Object.freeze(
  Object.fromEntries(STEP_LIST.map((step) => [step.name, step.errors]))
) as { readonly [N in StepName]: StepNamed<N>['errors'] };

/** The union of every step's errors, in first-seen order: the contract's `StepError` values. */
export const STEP_ERROR_CODES: readonly StepErrorCode[] = Object.freeze([
  ...new Set<StepErrorCode>(STEP_LIST.flatMap((step) => step.errors)),
]);

/** The steps the FiPA endpoint may serve, in grammar order. */
export const FIPA_STEP_NAMES = Object.freeze(
  STEP_LIST.filter((step): step is Extract<GrammarStepUnion, { readonly name: FipaStepName }> =>
    (step.transports as readonly string[]).includes('fipa')
  ).map((step) => step.name)
) as readonly FipaStepName[];

/** The steps only the Interaction API serves, in grammar order. */
export const INTERACTION_ONLY_STEP_NAMES = Object.freeze(
  STEP_NAMES.filter((name) => !(FIPA_STEP_NAMES as readonly string[]).includes(name))
) as readonly InteractionOnlyStepName[];

/** Whether `name` names a step of the grammar. */
export function isStepName(name: string): name is StepName {
  return Object.hasOwn(STEP_GRAMMAR, name);
}

/** Whether the FiPA endpoint may serve the step `name`. */
export function isFipaStepName(name: StepName): name is FipaStepName {
  return (FIPA_STEP_NAMES as readonly string[]).includes(name);
}

const BY_URN = new Map<string, StepName>(STEP_LIST.map((step) => [step.urn, step.name]));

/** The short name of the step with this URN, or `undefined` for a URN no step has. */
export function stepNameOfUrn(urn: string): StepName | undefined {
  return BY_URN.get(urn);
}

/** Any step, for code that handles each the same way. */
export function grammarStep(name: StepName): AnyGrammarStep {
  return STEP_GRAMMAR[name];
}

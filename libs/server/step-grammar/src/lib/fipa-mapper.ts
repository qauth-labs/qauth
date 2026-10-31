import { z } from 'zod';

import type { AnyGrammarStep } from './grammar';
import { StepMappingError } from './mapping-error';
import { checkParams, readOffer, refuseUnknownMembers, type StepOffer } from './offer';
import {
  FIPA_STEP_NAMES,
  type FipaStepName,
  type GrammarStepUnion,
  isFipaStepName,
  isStepName,
  STEP_URNS,
  type StepError,
  type StepName,
  type StepNamed,
} from './steps';
import { base64url } from './zod-kit';

/**
 * The FiPA authorization challenge endpoint's mapper (ADR-017 Decision 3): an
 * offer as the endpoint's `403 insufficient_authorization` body, or as
 * `403 redirect_to_web` when the endpoint cannot serve the step the engine
 * asks for (ADR-017 Decision 4).
 *
 * The body carries no prose: no `error_description`, nothing that says why
 * the step was asked for or how many tries remain. `qauth_interaction_error`
 * is the current step's closed error set, and `qauth_interaction_params`
 * holds only what each offered step's screen needs.
 */

/** Marks a step only the Interaction API serves, in the FiPA mapper table. */
export const INTERACTION_ONLY: unique symbol = Symbol('step-grammar.interaction-only');

/** What the FiPA endpoint makes of one step's params: the same object, or a refusal. */
export type FipaStepMapper<S extends AnyGrammarStep> = (
  params: z.output<S['params']>
) => z.output<S['params']>;

/**
 * One entry per step: a mapper for each step the FiPA endpoint may serve, and
 * {@link INTERACTION_ONLY} for each it may not. Keyed by the step union, so a
 * step added to the grammar without an entry fails the type check, and an
 * Interaction-API-only step cannot be given a mapper.
 */
export type FipaMapperTable<S extends AnyGrammarStep = GrammarStepUnion> = {
  readonly [K in S as K['name']]: K['transports'] extends readonly ['interaction', 'fipa']
    ? FipaStepMapper<K>
    : typeof INTERACTION_ONLY;
};

const same = <P>(params: P): P => params;

export const FIPA_STEP_MAPPERS: FipaMapperTable = Object.freeze({
  identifier: same,
  password: same,
  email_code: same,
  new_password: same,
  password_reset: same,
  captcha: same,
  webauthn_get: same,
  webauthn_create: same,
  totp: same,
  recovery_code: INTERACTION_ONLY,
  recovery_codes: INTERACTION_ONLY,
  totp_setup: INTERACTION_ONLY,
  consent: INTERACTION_ONLY,
  select_account: INTERACTION_ONLY,
  device_code: INTERACTION_ONLY,
  device_confirm: INTERACTION_ONLY,
  logout_confirm: INTERACTION_ONLY,
});

/**
 * The steps that never become `redirect_to_web` when the client did not list
 * them: a bot challenge, which the engine answers with its delay and 429
 * instead, so an attacker is not moved to a path with other controls
 * (ADR-017 Decisions 4 and 7).
 */
export const NEVER_REDIRECTED: readonly FipaStepName[] = Object.freeze(['captcha'] as const);

/** The URN of a step the FiPA endpoint may serve. */
export type FipaStepUrn = StepNamed<FipaStepName>['urn'];

/** `403 insufficient_authorization`: the next step, or a refused answer (ADR-017 Decision 3). */
export interface FipaInsufficientAuthorization {
  readonly error: 'insufficient_authorization';
  readonly iss: string;
  readonly auth_session: string;
  /** Always a step the client listed in `interaction_types_supported`. */
  readonly interaction_type_required: FipaStepUrn;
  /** Every step the engine accepts next, preferred first; the first is `interaction_type_required`. */
  readonly qauth_interaction_types_offered: readonly FipaStepUrn[];
  /** The params of every offered step, keyed by step name. */
  readonly qauth_interaction_params: Readonly<Partial<Record<FipaStepUrn, unknown>>>;
  /** Why the last answer was refused, from the required step's closed set. */
  readonly qauth_interaction_error?: StepError<FipaStepName>;
}

/** `403 redirect_to_web`: continue in a browser (FiPA §5.2.2.1.1). */
export interface FipaRedirectToWeb {
  readonly error: 'redirect_to_web';
  readonly iss: string;
}

/** What the endpoint answers for an offer. */
export interface FipaChallengeResponse {
  readonly status: 403;
  readonly body: FipaInsufficientAuthorization | FipaRedirectToWeb;
}

/** Which steps a deployment's FiPA endpoint serves: some of those ADR-017 lists, by phase. */
export interface FipaTransportConfig {
  readonly serves: readonly FipaStepName[];
}

/** What the endpoint knows of this round, besides the offer. */
export interface FipaRoundContext {
  /** The realm's issuer: every response carries it (RFC 9207). */
  readonly issuer: string;
  /** The new `auth_session` handle of this round: 32 random bytes, base64url (ADR-017 Decision 6). */
  readonly authSession: string;
  /** The step URNs the client listed in `interaction_types_supported`, parsed. Unknown URNs are ignored. */
  readonly interactionTypesSupported: readonly string[];
}

/** The most entries `interaction_types_supported` may list (ADR-017 Decision 3). */
export const MAX_INTERACTION_TYPES_SUPPORTED = 16;

const contextSchema = z.strictObject({
  // An issuer identifier has no query and no fragment (RFC 8414 §2). `http`
  // only for a development realm's issuer; the endpoint itself is `https`.
  issuer: z
    .url({ protocol: /^https?$/ })
    .max(2048)
    .refine((value) => !value.includes('?') && !value.includes('#')),
  authSession: base64url(43, 43, 'The auth_session handle.'),
  interactionTypesSupported: z.array(z.string().max(1024)).max(MAX_INTERACTION_TYPES_SUPPORTED),
});

export interface FipaMapper {
  /** The steps this transport serves, in grammar order. */
  readonly serves: readonly FipaStepName[];
  /**
   * The endpoint's answer to `offer`. A step the endpoint cannot serve (an
   * Interaction-API-only step, one this deployment does not serve, or one
   * the client did not list) is `redirect_to_web` when it is the current
   * step, and left out when it is an alternative. The steps the body names
   * in `qauth_interaction_types_offered` are the ones the client may answer
   * next (none after `redirect_to_web`). Throws {@link StepMappingError} for
   * an offer the grammar refuses, and for a bot challenge the client did not
   * list.
   */
  challenge(offer: StepOffer, context: FipaRoundContext): FipaChallengeResponse;
}

/** Build the FiPA endpoint's mapper for the steps `config` names. */
export function createFipaMapper(config: FipaTransportConfig): FipaMapper {
  refuseUnknownMembers(config, ['serves'], 'config');
  const serves = new Set<FipaStepName>();
  for (const name of config.serves as readonly string[]) {
    if (!isStepName(name) || !isFipaStepName(name)) {
      throw new StepMappingError('invalid_configuration', `serves ${name}`);
    }
    if (serves.has(name))
      throw new StepMappingError('invalid_configuration', `serves ${name} twice`);
    serves.add(name);
  }

  // What a per-step mapper returns is checked again, so no mapper can add a
  // member or a value the step's schema does not allow.
  const mapParams = (name: FipaStepName, params: unknown) =>
    checkParams(
      name,
      (FIPA_STEP_MAPPERS[name] as (value: unknown) => unknown)(params),
      'FiPA mapper'
    );

  return {
    serves: Object.freeze(FIPA_STEP_NAMES.filter((name) => serves.has(name))),
    challenge(offer, context) {
      const read = readOffer(offer);
      const parsedContext = contextSchema.safeParse(context);
      if (!parsedContext.success) {
        const paths = parsedContext.error.issues.map((issue) => issue.path.join('.') || '(root)');
        throw new StepMappingError('invalid_configuration', `context: ${paths.join(', ')}`);
      }
      const { issuer, authSession, interactionTypesSupported } = parsedContext.data;
      const listed = new Set(interactionTypesSupported);
      const negotiated = (name: StepName): name is FipaStepName =>
        isFipaStepName(name) && serves.has(name) && listed.has(STEP_URNS[name]);

      const { current } = read;
      if (!negotiated(current.step)) {
        if ((NEVER_REDIRECTED as readonly StepName[]).includes(current.step)) {
          throw new StepMappingError('not_negotiated', current.step);
        }
        return { status: 403, body: { error: 'redirect_to_web', iss: issuer } };
      }
      const offered: { step: FipaStepName; params: unknown }[] = [
        { step: current.step, params: current.params },
      ];
      for (const alternative of read.alternatives) {
        if (negotiated(alternative.step)) {
          offered.push({ step: alternative.step, params: alternative.params });
        }
      }
      const types = offered.map((step) => STEP_URNS[step.step]);
      return {
        status: 403,
        body: {
          error: 'insufficient_authorization',
          iss: issuer,
          auth_session: authSession,
          interaction_type_required: STEP_URNS[current.step],
          qauth_interaction_types_offered: types,
          qauth_interaction_params: Object.fromEntries(
            offered.map((step) => [STEP_URNS[step.step], mapParams(step.step, step.params)])
          ),
          ...(current.error === undefined
            ? {}
            : { qauth_interaction_error: current.error as StepError<FipaStepName> }),
        },
      };
    },
  };
}

/** Every step the FiPA endpoint may serve: the configuration of a deployment that serves them all. */
export const FIPA_SERVES_ALL: FipaTransportConfig = { serves: FIPA_STEP_NAMES };

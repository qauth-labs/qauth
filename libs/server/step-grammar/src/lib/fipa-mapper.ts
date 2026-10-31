import { z } from 'zod';

import { StepAnswerError } from './answer-error';
import type { AnyGrammarStep } from './grammar';
import { StepMappingError } from './mapping-error';
import {
  checkParams,
  type ReadAnswer,
  readAnswer,
  type ReadOffer,
  readOffer,
  refuseUnknownMembers,
  type StepOffer,
} from './offer';
import {
  FIPA_STEP_NAMES,
  type FipaStepName,
  type GrammarStepUnion,
  isFipaStepName,
  isStepName,
  STEP_URNS,
  type StepError,
  type StepErrorCode,
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
 * Passkey enrolment (`webauthn_create`) is offered here only to an account
 * that already holds a recovery-code set: a first enrolment issues the set,
 * and only the hosted pages show it (`recovery_codes` is the Interaction
 * API's alone). Any other account gets `redirect_to_web`. That is the
 * engine's rule (#614, #665): the offer does not say whether the account
 * holds a set, so the mapper cannot check it.
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
 * (ADR-017 Decisions 4 and 7). The engine asks {@link FipaMapper.negotiates}
 * before it offers one; an offer of one to a client that cannot answer it is
 * refused with `not_negotiated`.
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
  /**
   * Makes this round's new `auth_session` handle: 32 random bytes, base64url
   * (ADR-017 Decision 6). The mapper calls it once, and only for an answer
   * that carries the handle (`insufficient_authorization`), after every check
   * has passed: a `redirect_to_web` or a refused offer makes none. The
   * endpoint has burned the old handle before; it binds the new one, the one
   * the body carries, only then (burn first, then bind).
   */
  readonly newAuthSession: () => string;
  /** The step URNs the client listed in `interaction_types_supported`, parsed. Unknown URNs are ignored. */
  readonly interactionTypesSupported: readonly string[];
}

/** What {@link FipaMapper.negotiates} reads of the round: the client's listing. The whole context will do. */
export type FipaListing = Pick<FipaRoundContext, 'interactionTypesSupported'>;

/** The most entries `interaction_types_supported` may list (ADR-017 Decision 3). */
export const MAX_INTERACTION_TYPES_SUPPORTED = 16;

const listingSchema = z.array(z.string().max(1024)).max(MAX_INTERACTION_TYPES_SUPPORTED);

const contextSchema = z.strictObject({
  // An issuer identifier has no query and no fragment (RFC 8414 §2), and no
  // userinfo. `http` only for a development realm's issuer; the endpoint
  // itself is `https`.
  issuer: z
    .url({ protocol: /^https?$/ })
    .max(2048)
    .refine((value) => !value.includes('?') && !value.includes('#'))
    .refine((value) => {
      // Zod runs this after a failed URL check too.
      if (!URL.canParse(value)) return false;
      const url = new URL(value);
      return url.username === '' && url.password === '';
    }),
  newAuthSession: z.custom<() => string>((value) => typeof value === 'function'),
  interactionTypesSupported: listingSchema,
});

const authSessionSchema = base64url(43, 43, 'The auth_session handle.');

function refuseContext(error: z.ZodError, at: string): never {
  const paths = error.issues.map((issue) => issue.path.join('.') || '(root)');
  throw new StepMappingError('invalid_configuration', `${at}: ${[...new Set(paths)].join(', ')}`);
}

/** What the endpoint presents for an offer: the steps it names, required first, or nothing. */
type Presented =
  | { readonly redirect: true }
  | {
      readonly redirect: false;
      readonly steps: readonly { readonly step: FipaStepName; readonly params: unknown }[];
      readonly error?: StepErrorCode;
    };

export interface FipaMapper {
  /** The steps this transport serves, in grammar order. */
  readonly serves: readonly FipaStepName[];
  /**
   * Whether this endpoint can offer `step` to the client of `listing`: a step
   * ADR-017 lists, that this deployment serves and the client listed. The
   * engine asks it before it offers a bot challenge: a client that cannot
   * answer one gets the engine's delay and 429 instead (ADR-017 Decisions 4
   * and 7), never `redirect_to_web`. Throws {@link StepMappingError} for an
   * unknown step or a malformed listing.
   */
  negotiates(step: StepName, listing: FipaListing): boolean;
  /**
   * The endpoint's answer to `offer`. The steps the body names in
   * `qauth_interaction_types_offered` are the ones the client may answer
   * next (none after `redirect_to_web`). An alternative the endpoint cannot
   * serve (an Interaction-API-only step, one this deployment does not serve,
   * or one the client did not list) is left out. A current step it cannot
   * serve gives `redirect_to_web`, except in two cases: when the offer says
   * the step is not required (`required: false`) and the client can answer
   * one of the alternatives, the first such alternative becomes
   * `interaction_type_required`, with its own params and no error carried
   * over; and a bot challenge is refused with `not_negotiated`, since the
   * engine answers that client with its delay and 429. Throws
   * {@link StepMappingError} for an offer the grammar refuses.
   */
  challenge(offer: StepOffer, context: FipaRoundContext): FipaChallengeResponse;
  /**
   * Read an answer to `lastOffer`, the offer the last response was built
   * from, for the client of `listing`: only a step that response named in
   * `qauth_interaction_types_offered` may be answered (none after
   * `redirect_to_web`), and only its answer members are taken from `form`,
   * the request's form body. Throws {@link StepAnswerError} for a refused
   * answer, and {@link StepMappingError} for an offer the endpoint refuses.
   */
  readAnswer(
    lastOffer: StepOffer,
    listing: FipaListing,
    stepUrn: string,
    form: unknown
  ): ReadAnswer;
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

  // The round's context will do: only its listing is read.
  const readListing = (listing: FipaListing): ReadonlySet<string> => {
    const parsed = listingSchema.safeParse(
      (listing as Partial<FipaListing> | null)?.interactionTypesSupported
    );
    if (!parsed.success) refuseContext(parsed.error, 'listing');
    return new Set(parsed.data);
  };

  const negotiatedBy =
    (listed: ReadonlySet<string>) =>
    (name: StepName): name is FipaStepName =>
      isFipaStepName(name) && serves.has(name) && listed.has(STEP_URNS[name]);

  const present = (read: ReadOffer, listed: ReadonlySet<string>): Presented => {
    const negotiated = negotiatedBy(listed);
    const { current } = read;
    const alternatives = read.alternatives.filter(
      (alternative): alternative is { step: FipaStepName; params: unknown } =>
        negotiated(alternative.step)
    );
    if (negotiated(current.step)) {
      return {
        redirect: false,
        steps: [{ step: current.step, params: current.params }, ...alternatives],
        ...(current.error === undefined ? {} : { error: current.error }),
      };
    }
    if ((NEVER_REDIRECTED as readonly StepName[]).includes(current.step)) {
      throw new StepMappingError('not_negotiated', current.step);
    }
    if (!read.required && alternatives.length > 0) return { redirect: false, steps: alternatives };
    return { redirect: true };
  };

  return {
    serves: Object.freeze(FIPA_STEP_NAMES.filter((name) => serves.has(name))),
    negotiates(step, listing) {
      if (typeof step !== 'string' || !isStepName(step)) {
        throw new StepMappingError('unknown_step', 'negotiates');
      }
      return negotiatedBy(readListing(listing))(step);
    },
    readAnswer(lastOffer, listing, stepUrn, form) {
      const read = readOffer(lastOffer);
      const presented = present(read, readListing(listing));
      if (presented.redirect) throw new StepAnswerError('not_offered', 'the answered step');
      const [first, ...others] = presented.steps;
      // The step the response required: the offer's own current step, with
      // its error, or the alternative that took its place.
      const current =
        first.step === read.current.step
          ? { ...first, ...(read.current.error === undefined ? {} : { error: read.current.error }) }
          : first;
      return readAnswer({ current, alternatives: others } as StepOffer, stepUrn, form, 'form');
    },
    challenge(offer, context) {
      const read = readOffer(offer);
      const parsedContext = contextSchema.safeParse(context);
      if (!parsedContext.success) refuseContext(parsedContext.error, 'context');
      const { issuer, newAuthSession, interactionTypesSupported } = parsedContext.data;
      const presented = present(read, new Set(interactionTypesSupported));
      if (presented.redirect) {
        return { status: 403, body: { error: 'redirect_to_web', iss: issuer } };
      }
      const types = presented.steps.map((step) => STEP_URNS[step.step]);
      const params = Object.fromEntries(
        presented.steps.map((step) => [STEP_URNS[step.step], mapParams(step.step, step.params)])
      );
      // Last, after every check: a refused offer makes no handle.
      const authSession = authSessionSchema.safeParse(newAuthSession());
      if (!authSession.success) refuseContext(authSession.error, 'context.newAuthSession');
      return {
        status: 403,
        body: {
          error: 'insufficient_authorization',
          iss: issuer,
          auth_session: authSession.data,
          interaction_type_required: types[0],
          qauth_interaction_types_offered: types,
          qauth_interaction_params: params,
          ...(presented.error === undefined
            ? {}
            : { qauth_interaction_error: presented.error as StepError<FipaStepName> }),
        },
      };
    },
  };
}

/** Every step the FiPA endpoint may serve: the configuration of a deployment that serves them all. */
export const FIPA_SERVES_ALL: FipaTransportConfig = Object.freeze({ serves: FIPA_STEP_NAMES });

import type { RoundResult } from '@qauth-labs/fastify-plugin-sign-in-engine';
import { type RestartNotice, stepUrn } from '@qauth-labs/shared-interaction-contract';

import type { InteractionStep } from './interaction-record';
import type { UpstreamLinkRefusal } from './upstream-links';

/**
 * The outcomes of a sign-in that reach the ceremony page as interaction state
 * (#1081; ADR-019 Decisions 5 and 6), as a refused answer's `error` does: the
 * page draws them in its own words, and the auth server shows no page of its
 * own for them.
 *
 * - **A restart.** The engine ended its transaction, and the sign-in went
 *   back to its first step: the step read carries a notice of why
 *   ({@link restartNoticeOf}), once.
 * - **A provider that did not sign the person in.** The callback sends the
 *   browser back to the ceremony page, whose `upstream` step carries the
 *   error and the provider ({@link refusedUpstreamStep}).
 * - **A refused link** (#670). The `upstream_link` step comes back with its
 *   reason ({@link refusedLinkStep}); where the sign-in had already finished
 *   the interaction, as the first step of the request's next one.
 */

/** Why the engine ended a transaction (#1081): what `transaction_ended` carries. */
export type TransactionEndCause = Extract<
  RoundResult,
  { readonly reason: 'transaction_ended' }
>['cause'];

/**
 * The notice of a sign-in the engine ended and started again (#1081): the
 * closed set of the contract, which names no account. `code_burned` and
 * `subject_mismatch` say what the person did, and read the same for every
 * identifier; every other end is `expired`, so that no cause that depends on
 * the account (one disabled, a reset since) tells a person who has proved no
 * factor anything about it (ADR-017 Decision 4).
 */
export function restartNoticeOf(cause: TransactionEndCause): RestartNotice {
  switch (cause) {
    case 'code_burned':
      return 'code_burned';
    case 'subject_mismatch':
      return 'subject_mismatch';
    default:
      return 'expired';
  }
}

/** The `upstream` step's name (`urn:qauth:ia:upstream:v1-rc.0`, #639). */
const UPSTREAM_STEP_URN = stepUrn('upstream');

/** The `upstream_link` step's name (`urn:qauth:ia:upstream_link:v1-rc.0`, #670). */
const UPSTREAM_LINK_STEP_URN = stepUrn('upstream_link');

/** Why an upstream provider did not sign the person in (#1081). */
export type UpstreamProviderError = 'provider_declined' | 'provider_error';

/** A provider as the `upstream` and `upstream_link` steps name it: its type and its name. */
export interface StepProvider {
  readonly provider: string;
  readonly name: string;
}

/**
 * `step`, the step the person picked `provider` at, with its `upstream` step
 * current and refused with `error` (#1081), and the provider in its params:
 * the page offers the other ways in. The other steps keep their order behind
 * it, as the engine orders a refused answer's offer. `undefined` when `step`
 * offers no `upstream` step, such as one the realm's visible providers left
 * out: the caller shows `step` as it was.
 */
export function refusedUpstreamStep(
  step: InteractionStep,
  provider: StepProvider,
  error: UpstreamProviderError
): InteractionStep | undefined {
  const params = upstreamParamsOf(step);
  if (params === undefined) return undefined;
  const others = [step.name, ...step.alternatives].filter((name) => name !== UPSTREAM_STEP_URN);
  const alternativeParams: Record<string, Readonly<Record<string, unknown>>> = {};
  for (const name of others) {
    const held = name === step.name ? step.params : step.alternativeParams?.[name];
    if (held !== undefined && Object.keys(held).length > 0) alternativeParams[name] = { ...held };
  }
  return {
    name: UPSTREAM_STEP_URN,
    params: {
      ...params,
      error_provider: { provider: provider.provider, name: provider.name },
    },
    alternatives: others,
    ...(Object.keys(alternativeParams).length === 0 ? {} : { alternativeParams }),
    error,
  };
}

/**
 * The provider of `type` as `step`'s `upstream` step lists it (#1081): its
 * name as the person saw it, for a provider the realm no longer serves.
 */
export function listedUpstreamProvider(
  step: InteractionStep,
  type: string
): StepProvider | undefined {
  const providers = upstreamParamsOf(step)?.['providers'];
  if (!Array.isArray(providers)) return undefined;
  for (const listed of providers as readonly unknown[]) {
    if (typeof listed !== 'object' || listed === null) continue;
    const { provider, name } = listed as { readonly provider?: unknown; readonly name?: unknown };
    if (provider === type && typeof name === 'string') return { provider, name };
  }
  return undefined;
}

/** The `upstream` step's params `step` holds, current or as an alternative. */
function upstreamParamsOf(step: InteractionStep): Readonly<Record<string, unknown>> | undefined {
  if (step.name === UPSTREAM_STEP_URN) {
    // A provider refused before: its error and provider give way to this one.
    const params: Record<string, unknown> = { ...step.params };
    delete params['error_provider'];
    return params;
  }
  if (!step.alternatives.includes(UPSTREAM_STEP_URN)) return undefined;
  return step.alternativeParams?.[UPSTREAM_STEP_URN] ?? {};
}

/**
 * The `upstream_link` step of a refused link (#670, #1081): the provider and
 * the reason, from the closed set the link's event records. It offers no new
 * account and takes no answer: the page says why and offers the cancel, which
 * ends the request as a cancel does. Nothing of the identity, nor any
 * account, is on it.
 */
export function refusedLinkStep(
  provider: StepProvider,
  reason: UpstreamLinkRefusal
): InteractionStep {
  return {
    name: UPSTREAM_LINK_STEP_URN,
    params: { provider: { provider: provider.provider, name: provider.name }, create: false },
    alternatives: [],
    error: reason,
  };
}

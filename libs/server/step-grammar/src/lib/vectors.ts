import { stepNamed, stepRecordExample } from '@qauth-labs/shared-interaction-contract';

import { createFipaMapper, FIPA_SERVES_ALL } from './fipa-mapper';
import { createInteractionMapper } from './interaction-mapper';
import type { StepOffer } from './offer';
import { FIPA_STEP_NAMES, STEP_NAMES, STEP_URNS, type StepName, stepNameOfUrn } from './steps';

/**
 * The Interaction API contract's step examples (#590) as shared test vectors
 * (`test-vectors/interaction/steps.json`, format `qauth-vectors/1-rc.0`), with
 * what each transport's mapper makes of them. An SDK in any language reads the
 * file with a JSON parser alone; the server's own tests run every case
 * through the mappers (`vectors.test.ts`).
 */

/** Where the file lives, from the repository root, and its vector id. */
export const STEP_VECTORS_PATH = 'test-vectors/interaction/steps.json';
export const STEP_VECTORS_ID = 'interaction/steps';

/** The command that writes it. */
export const VECTORS_EXPORT_COMMAND =
  'pnpm exec nx run server-step-grammar:vectors-export --skip-nx-cache';

/** The FiPA round of every case: an example issuer and `auth_session`. */
export const VECTOR_FIPA_ROUND = {
  iss: 'https://auth.example.com',
  auth_session: 'YXV0aC1zZXNzaW9uLWhhbmRsZS1vZi0zMi1ieXRlcyE',
} as const;

/** The FiPA round of one case: the client lists the steps it is given. */
export interface StepVectorFipaRound {
  readonly iss: string;
  readonly auth_session: string;
  readonly interaction_types_supported: readonly string[];
}

/**
 * What the client of a case lists: every step the FiPA endpoint may serve,
 * and every step only the Interaction API serves that the case names, so the
 * case shows that listing one changes nothing. At most 16 entries, the
 * endpoint's limit.
 */
function clientListing(named: readonly StepName[]): string[] {
  const extra = named.filter((name) => !(FIPA_STEP_NAMES as readonly StepName[]).includes(name));
  return [...FIPA_STEP_NAMES, ...new Set(extra)].map((name) => STEP_URNS[name]);
}

/** One case's input: the step as its example shows it, the alternatives offered beside it, and the FiPA round. */
export interface StepVectorInput {
  /** The step's example record: `examples[0]` of its published schema file. */
  readonly step: ReturnType<typeof stepRecordExample>;
  /** The steps offered beside it, preferred first, each with its example params. */
  readonly alternatives: readonly { readonly type: string; readonly params: unknown }[];
  readonly fipa: StepVectorFipaRound;
}

/** One case's expected result: the Interaction API's step-read members and the FiPA endpoint's response. */
export interface StepVectorExpected {
  readonly interaction: unknown;
  readonly fipa: { readonly status: number; readonly body: unknown };
}

/** The input of the case of step `name`. */
export function stepVectorInput(name: StepName): StepVectorInput {
  const documented = stepNamed(name);
  const alternatives = (documented.example.alternatives ?? []) as readonly StepName[];
  return {
    step: stepRecordExample(documented),
    alternatives: alternatives.map((alternative) => ({
      type: STEP_URNS[alternative],
      params: stepNamed(alternative).example.step.params,
    })),
    fipa: {
      ...VECTOR_FIPA_ROUND,
      interaction_types_supported: clientListing([name, ...alternatives]),
    },
  };
}

/** The engine's offer a case's input stands for. */
export function vectorOffer(input: StepVectorInput): StepOffer {
  const nameOf = (urn: string): StepName => {
    const name = stepNameOfUrn(urn);
    if (name === undefined) throw new Error(`no step is named ${urn}`);
    return name;
  };
  return {
    current: {
      step: nameOf(input.step.type),
      params: input.step.params,
      ...(input.step.error === undefined ? {} : { error: input.step.error }),
    },
    alternatives: input.alternatives.map((alternative) => ({
      step: nameOf(alternative.type),
      params: alternative.params,
    })),
  } as StepOffer;
}

/** What the mappers make of a case's input. */
export function stepVectorExpected(input: StepVectorInput): StepVectorExpected {
  const offer = vectorOffer(input);
  return {
    interaction: createInteractionMapper().stepView(offer),
    fipa: createFipaMapper(FIPA_SERVES_ALL).challenge(offer, {
      issuer: input.fipa.iss,
      newAuthSession: () => input.fipa.auth_session,
      interactionTypesSupported: input.fipa.interaction_types_supported,
    }),
  };
}

const DESCRIPTION = [
  'The steps of the QAuth step grammar, Interaction API v1-rc.0, one case per step: each is the example of the Interaction API contract, and what each transport sends for it.',
  'input.step is the step as its example shows it: its name (type), params, answer, personal data, the error of a refused answer when the example shows one, and amr. It is examples[0] of the step’s JSON Schema file, published at https://docs.qauth.dev/interaction/v1-rc.0/steps/<name>.json (apps/docs-site/public/interaction/v1-rc.0/steps/ in the repository), and validates against it.',
  'input.alternatives are the other steps the engine accepts next, preferred first, each with its params. input.fipa is the FiPA round: the issuer, the new auth_session and the step names the client listed in interaction_types_supported. The client lists every step the FiPA endpoint serves and every step of the case that only the Interaction API serves, so the case shows that listing such a step changes nothing.',
  'expected.interaction is the step read’s step-grammar members on the Interaction API: step (input.step.type), error when there is one, alternatives (every input alternative’s name, in order) and params (each offered step’s params, keyed by its name). The page’s other members (csrf, client, brand, uiLocales, expiresAt) are not the grammar’s and are left out.',
  'expected.fipa is the FiPA authorization challenge endpoint’s response (ADR-017 Decision 3): for a step it serves, status 403 with error insufficient_authorization, iss, auth_session, interaction_type_required (input.step.type), qauth_interaction_types_offered (the required step, then each alternative the endpoint serves and the client listed, in order), qauth_interaction_params (keyed by those names) and qauth_interaction_error when there is an error; for a step only the Interaction API serves, status 403 with error redirect_to_web and iss. A step the FiPA endpoint cannot serve never appears in its response, and no response carries error_description or any other prose.',
  'A server computes expected from input; a client reads expected and recovers the step, its params and its error.',
].join(' ');

/** The vector file's content, in grammar order. */
export function stepVectorFile() {
  return {
    schema: 'qauth-vectors/1-rc.0',
    id: STEP_VECTORS_ID,
    description: DESCRIPTION,
    source:
      'The step examples of the Interaction API v1-rc.0 contract (libs/shared/interaction-contract, issue 590) and the step grammar’s transport mappers (libs/server/step-grammar); generated by the server-step-grammar:vectors-export target.',
    cases: STEP_NAMES.map((name) => {
      const input = stepVectorInput(name);
      return { id: name.replaceAll('_', '-'), input, expected: stepVectorExpected(input) };
    }),
  };
}

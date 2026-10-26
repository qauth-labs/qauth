import {
  answerResultSchema,
  assetSchema,
  brandSchema,
  brandStringsSchema,
  cancelRequestSchema,
  clientDisplaySchema,
  csrfSchema,
  EXAMPLE_BRAND,
  EXAMPLE_CLIENT,
  EXAMPLE_CSRF,
  EXAMPLE_EXPIRES_AT,
  EXAMPLE_TRACE_ID,
  EXAMPLE_UNVERIFIED_CLIENT,
  interactionIdSchema,
  interactionSchema,
  nextStepResultSchema,
  problemSchema,
  redirectResultSchema,
} from './envelope';
import {
  FLOW_COOKIE_NAME,
  INTERACTION_API_PREFIX,
  INTERACTION_API_VERSION,
  WALLET_RETURN_PREFIX,
} from './identifiers';
import { codesWithStatus, STATUS_TITLES } from './problems';
import { API_RULES, DOCUMENT_PATH_RULE, RESERVED_PREFIX_RULE, VERSIONING_RULES } from './rules';
import type { JsonSchema } from './schema-kit';
import type { StepDefinition } from './step-definition';
import { stepNamed, STEPS } from './steps';

/**
 * The Interaction API v1 contract as one OpenAPI 3.1 document (#590). Pure:
 * `artifacts.ts` serialises it, the export script writes it, the auth server
 * serves it, and the typed client is generated from the written file.
 *
 * The document is self-contained: every step contributes its components
 * (`PasswordStep`, `PasswordParams`, `PasswordAnswer`, …) and every reference
 * points into `#/components`, so a tool that cannot follow external
 * references reads it whole. The per-step JSON Schema files (`step-schema.ts`)
 * carry the same schemas with local `$defs`.
 */

export type OpenApiDocument = { readonly [key: string]: unknown };

/** The OpenAPI version, the one the auth server's own export declares. */
export const OPENAPI_VERSION = '3.1.0';

/** `email_code` → `EmailCode`. */
export function pascalCase(name: string): string {
  return name
    .split('_')
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join('');
}

/** The component names one step contributes. */
export function stepComponentNames(step: StepDefinition) {
  const base = pascalCase(step.name);
  return {
    step: `${base}Step`,
    params: `${base}Params`,
    error: `${base}Error`,
    answer: `${base}Answer`,
    personal: `${base}Personal`,
    personalData: `${base}PersonalData`,
  } as const;
}

const ref = (name: string) => ({ $ref: `#/components/schemas/${name}` });

/** The step object of `step`, as a step read carries it. */
function stepObjectSchema(step: StepDefinition): JsonSchema {
  const names = stepComponentNames(step);
  return {
    type: 'object',
    title: step.urn,
    description: step.description,
    'x-qauth-transports': [...step.transports],
    'x-qauth-amr': [...step.amr],
    properties: {
      type: { const: step.urn },
      params: ref(names.params),
      ...(step.errors.length === 0 ? {} : { error: ref(names.error) }),
    },
    required: ['type', 'params'],
  };
}

/** The answer request of `step`: the envelope's `type` and `csrf`, and the step's answer fields. */
function answerRequestSchema(step: StepDefinition): JsonSchema {
  const fields = (step.answer['properties'] ?? {}) as Record<string, JsonSchema>;
  const required = (step.answer['required'] ?? []) as string[];
  return {
    type: 'object',
    description: `An answer to \`${step.urn}\`.`,
    properties: {
      type: { const: step.urn, description: 'The step this request answers.' },
      csrf: ref('Csrf'),
      ...fields,
    },
    required: ['type', 'csrf', ...required],
    additionalProperties: false,
  };
}

/** The personal-data response of `step`. */
function personalSchema(step: StepDefinition): JsonSchema {
  return {
    type: 'object',
    description: `The personal data of \`${step.urn}\`.`,
    properties: {
      type: { const: step.urn },
      data: ref(stepComponentNames(step).personalData),
    },
    required: ['type', 'data'],
  };
}

/** Every component one step contributes, in a fixed order. */
function stepComponents(step: StepDefinition): Array<[string, JsonSchema]> {
  const names = stepComponentNames(step);
  return [
    [names.step, stepObjectSchema(step)],
    [names.params, step.params],
    ...(step.errors.length === 0
      ? []
      : ([
          [
            names.error,
            {
              type: 'string',
              enum: [...step.errors],
              description: `Why the last answer to \`${step.urn}\` was refused. A closed set.`,
            },
          ],
        ] as Array<[string, JsonSchema]>)),
    [names.answer, answerRequestSchema(step)],
    [names.personal, personalSchema(step)],
    [names.personalData, step.personal],
  ];
}

/** A union of one component per step, discriminated by `type`. */
function stepUnion(description: string, component: (step: StepDefinition) => string): JsonSchema {
  return {
    description,
    oneOf: STEPS.map((step) => ref(component(step))),
    discriminator: {
      propertyName: 'type',
      mapping: Object.fromEntries(
        STEPS.map((step) => [step.urn, `#/components/schemas/${component(step)}`])
      ),
    },
  };
}

// ---------------------------------------------------------------------------
// Examples
// ---------------------------------------------------------------------------

/** The step object a step read carries for `step` when it is offered beside the current one. */
function alternativeObject(step: StepDefinition) {
  const { type, params } = step.example.step;
  return { type, params };
}

/** The client an example interaction is for. */
function exampleClient(step: StepDefinition) {
  if (step.name === 'device_code') return undefined;
  if (step.name === 'consent') return EXAMPLE_UNVERIFIED_CLIENT;
  return EXAMPLE_CLIENT;
}

/** The step read of an interaction whose current step is `step`, as its example shows it. */
export function exampleInteraction(step: StepDefinition) {
  const client = exampleClient(step);
  return {
    step: step.example.step,
    alternatives: (step.example.alternatives ?? []).map((name) =>
      alternativeObject(stepNamed(name))
    ),
    csrf: EXAMPLE_CSRF,
    ...(client === undefined ? {} : { client }),
    brand: EXAMPLE_BRAND,
    uiLocales: ['en'],
    expiresAt: EXAMPLE_EXPIRES_AT,
  };
}

/** The JSON answer the example of `step` sends. */
export function exampleAnswer(step: StepDefinition) {
  return { type: step.urn, csrf: EXAMPLE_CSRF, ...step.example.answer };
}

/** What the example answer of `step` leads to. */
export function exampleAnswerResult(step: StepDefinition) {
  const { next } = step.example;
  if ('redirect' in next) return { result: 'redirect', location: next.redirect };
  const nextStep = stepNamed(next.step);
  const following = exampleInteraction(nextStep);
  return {
    result: 'step',
    interaction: {
      ...following,
      step: { type: nextStep.urn, params: nextStep.example.step.params },
    },
  };
}

/** The personal-data read of `step`, as its example shows it. */
export function examplePersonal(step: StepDefinition) {
  return { type: step.urn, data: step.example.personal ?? {} };
}

const examplesByStep = (value: (step: StepDefinition) => unknown) =>
  Object.fromEntries(STEPS.map((step) => [step.name, { summary: step.urn, value: value(step) }]));

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

const NO_STORE = { 'Cache-Control': { $ref: '#/components/headers/CacheControl' } };

/** The problem responses for `statuses`, each naming the codes it may carry. */
function problemResponses(statuses: readonly number[]) {
  return Object.fromEntries(
    statuses.map((status) => {
      const codes = codesWithStatus(status);
      if (codes.length === 0) throw new Error(`no problem code is sent with ${status}`);
      return [
        String(status),
        {
          description: `${STATUS_TITLES[status]}: ${codes.map((code) => `\`${code}\``).join(' or ')}.`,
          'x-qauth-problem-codes': codes,
          headers: {
            ...NO_STORE,
            ...(status === 429
              ? { 'Retry-After': { $ref: '#/components/headers/RetryAfter' } }
              : {}),
          },
          content: {
            'application/problem+json': {
              schema: ref('Problem'),
              example: {
                type: 'about:blank',
                title: STATUS_TITLES[status],
                status,
                code: codes[0],
                trace_id: EXAMPLE_TRACE_ID,
              },
            },
          },
        },
      ];
    })
  );
}

const SEE_OTHER = {
  description:
    'For a form post: the next page. `Location` is the ceremony app’s page for the next step, or the final redirect. A form post never gets the JSON result.',
  headers: { ...NO_STORE, Location: { $ref: '#/components/headers/Location' } },
};

const interactionIdParameter = {
  name: 'interactionId',
  in: 'path',
  required: true,
  description: 'The interaction id the page read from its own URL.',
  schema: ref('InteractionId'),
};

/** What a request needs, as the operation's two extensions say. */
function requirements(flowCookie: boolean, csrf: boolean) {
  return {
    security: flowCookie ? [{ flowCookie: [] }] : [],
    'x-qauth-flow-cookie': flowCookie ? 'required' : 'none',
    'x-qauth-csrf': csrf ? 'required' : 'none',
  };
}

const FORM_ENCODING_NOTE =
  'As JSON or as a plain HTML form post (`application/x-www-form-urlencoded`, UTF-8) with the same members, so a page works without JavaScript. In a form post every value is a string: a boolean is `true` or `false` (an unchecked checkbox sends nothing, which means `false`), and no member may be repeated. The answer carries the flow cookie and comes from the realm origin: the server checks `Origin` and `Sec-Fetch-Site`, then the flow cookie, then the CSRF value, and runs no engine work before all three pass.';

function paths() {
  const base = `${INTERACTION_API_PREFIX}/{interactionId}`;
  return {
    [base]: {
      get: {
        operationId: 'interactions.get',
        summary: 'Read the current step',
        description:
          'The current step of the interaction, the steps offered beside it, a CSRF value for one answer, the client’s display data and the realm’s brand. The interaction id alone is enough, so the ceremony app’s server can read it while the proxy strips QAuth’s cookies; for the same reason the read returns no personal data. Reading does not change the interaction.',
        tags: ['Interaction'],
        'x-qauth-stability': 'stable',
        ...requirements(false, false),
        parameters: [interactionIdParameter],
        responses: {
          '200': {
            description: 'The current step.',
            headers: NO_STORE,
            content: {
              'application/json': {
                schema: ref('Interaction'),
                examples: examplesByStep(exampleInteraction),
              },
            },
          },
          ...problemResponses([410, 421, 429, 500, 503]),
        },
      },
    },
    [`${base}/personal`]: {
      get: {
        operationId: 'interactions.personal.get',
        summary: 'Read the personal data of the current step',
        description:
          'The personal data the current step’s screen shows: the account chooser’s list, the identifier being signed in, a secret shown once. Only the browser that started the interaction can read it: the request needs the flow cookie, so the page calls it from the browser. A step with no personal data answers an empty `data`.',
        tags: ['Interaction'],
        'x-qauth-stability': 'stable',
        ...requirements(true, false),
        parameters: [interactionIdParameter],
        responses: {
          '200': {
            description: 'The current step’s personal data.',
            headers: NO_STORE,
            content: {
              'application/json': {
                schema: ref('PersonalData'),
                examples: examplesByStep(examplePersonal),
              },
            },
          },
          ...problemResponses([410, 421, 429, 500, 503]),
        },
      },
    },
    [`${base}/answer`]: {
      post: {
        operationId: 'interactions.answer',
        summary: 'Answer the current step',
        description: `Answer the current step, or one of the alternatives it offers, with the CSRF value of the step read. ${FORM_ENCODING_NOTE} A refused answer, such as a wrong password, is not an error: the same step comes back with \`error\` set and a new CSRF value.`,
        tags: ['Interaction'],
        'x-qauth-stability': 'stable',
        ...requirements(true, true),
        parameters: [interactionIdParameter],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: ref('AnswerRequest'),
              examples: examplesByStep(exampleAnswer),
            },
            'application/x-www-form-urlencoded': { schema: ref('AnswerRequest') },
          },
        },
        responses: {
          '200': {
            description: 'For a JSON answer: the next step, or the final redirect.',
            headers: NO_STORE,
            content: {
              'application/json': {
                schema: ref('AnswerResult'),
                examples: examplesByStep(exampleAnswerResult),
              },
            },
          },
          '303': SEE_OTHER,
          ...problemResponses([400, 403, 410, 413, 415, 421, 429, 500, 503]),
        },
      },
    },
    [`${base}/cancel`]: {
      post: {
        operationId: 'interactions.cancel',
        summary: 'Cancel the interaction',
        description: `End the interaction without completing it: the client gets \`access_denied\`, and a logout ends with the person still signed in. ${FORM_ENCODING_NOTE}`,
        tags: ['Interaction'],
        'x-qauth-stability': 'stable',
        ...requirements(true, true),
        parameters: [interactionIdParameter],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: ref('CancelRequest'),
              example: { csrf: EXAMPLE_CSRF },
            },
            'application/x-www-form-urlencoded': { schema: ref('CancelRequest') },
          },
        },
        responses: {
          '200': {
            description: 'For a JSON request: the final redirect.',
            headers: NO_STORE,
            content: {
              'application/json': {
                schema: ref('RedirectResult'),
                example: {
                  result: 'redirect',
                  location:
                    'https://app.example.com/callback?error=access_denied&state=af0ifjsldkj&iss=https%3A%2F%2Fauth.example.com',
                },
              },
            },
          },
          '303': SEE_OTHER,
          ...problemResponses([400, 403, 410, 413, 415, 421, 429, 500, 503]),
        },
      },
    },
  };
}

// ---------------------------------------------------------------------------
// The document
// ---------------------------------------------------------------------------

const bullets = (lines: readonly string[]) => lines.map((line) => `- ${line}`).join('\n');

/** `info.description`: what the API is, its rules and its versioning rules. */
export function documentDescription(): string {
  return [
    'The Interaction API is how a sign-in page reaches the QAuth engine (ADR-019 Decision 6). The reference ceremony app, and any UI that replaces it, reads the current step of an interaction, answers it and follows the result, until the interaction ends in a redirect. It shares its step grammar with the FiPA authorization challenge endpoint, the transport for first-party native apps (ADR-017 Decision 3): a step is the same object on both, and only the envelope differs.',
    'Status: this document is the contract, published before the implementation. The auth server serves it today; the operations it describes arrive with the Interaction API implementation.',
    `## Rules\n\n${bullets(API_RULES)}`,
    `## Versioning\n\n${bullets(VERSIONING_RULES)}`,
    `## Paths\n\n${bullets([RESERVED_PREFIX_RULE, DOCUMENT_PATH_RULE])}`,
  ].join('\n\n');
}

/** Build the document. Deterministic: the same contract gives the same bytes. */
export function buildInteractionOpenApi(): OpenApiDocument {
  return {
    openapi: OPENAPI_VERSION,
    info: {
      title: 'QAuth Interaction API',
      version: INTERACTION_API_VERSION,
      description: documentDescription(),
      license: { name: 'Apache-2.0', identifier: 'Apache-2.0' },
    },
    servers: [
      {
        url: '/',
        description:
          'The realm origin. The API is same-origin: a page calls it on the host it was served from.',
      },
    ],
    tags: [
      {
        name: 'Interaction',
        description: 'The current step of an interaction: read it, answer it, or cancel.',
      },
    ],
    'x-qauth-reserved-prefixes': [WALLET_RETURN_PREFIX],
    paths: paths(),
    components: {
      securitySchemes: {
        flowCookie: {
          type: 'apiKey',
          in: 'cookie',
          name: FLOW_COOKIE_NAME,
          description:
            'The flow cookie the authorization endpoint set when it created the interaction: `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/`, no `Domain`. It binds the interaction to the browser that started it; a wrong or missing cookie gets the same `interaction_expired` as an unknown id.',
        },
      },
      headers: {
        CacheControl: {
          description: 'Every answer is `no-store` (ADR-019 Decision 5).',
          schema: { type: 'string', const: 'no-store' },
        },
        RetryAfter: {
          description: 'How many seconds to wait before trying again.',
          schema: { type: 'integer', minimum: 0 },
        },
        Location: {
          description: 'Where the browser goes next.',
          schema: { type: 'string', format: 'uri-reference', maxLength: 8192 },
        },
      },
      schemas: Object.fromEntries([
        ['InteractionId', interactionIdSchema],
        ['Csrf', csrfSchema],
        ['Interaction', interactionSchema],
        ['Step', stepUnion('One step, by its name.', (step) => stepComponentNames(step).step)],
        [
          'AnswerRequest',
          stepUnion(
            'An answer to one step, by its name: the envelope’s `type` and `csrf`, and the step’s answer fields.',
            (step) => stepComponentNames(step).answer
          ),
        ],
        ['AnswerResult', answerResultSchema],
        ['NextStepResult', nextStepResultSchema],
        ['RedirectResult', redirectResultSchema],
        ['CancelRequest', cancelRequestSchema],
        [
          'PersonalData',
          stepUnion(
            'The personal data of the current step, by its name.',
            (step) => stepComponentNames(step).personal
          ),
        ],
        ['ClientDisplay', clientDisplaySchema],
        ['Brand', brandSchema],
        ['BrandStrings', brandStringsSchema],
        ['Asset', assetSchema],
        ['Problem', problemSchema],
        ...STEPS.flatMap(stepComponents),
      ]),
    },
  };
}

/** The document, built once. */
export const INTERACTION_OPENAPI: OpenApiDocument = buildInteractionOpenApi();

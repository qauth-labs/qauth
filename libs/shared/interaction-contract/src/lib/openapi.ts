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
  personalDataSchema,
  problemSchema,
  redirectResultSchema,
} from './envelope';
import {
  FLOW_COOKIE_NAME,
  INTERACTION_API_PREFIX,
  INTERACTION_API_VERSION,
  STEP_URN_SCHEMA_PATTERN,
  WALLET_RETURN_PREFIX,
} from './identifiers';
import {
  codesWithStatus,
  INTERACTION_PROBLEM_CODES,
  problemTypeUri,
  STATUS_TITLES,
} from './problems';
import { API_RULES, DOCUMENT_PATH_RULE, RESERVED_PREFIX_RULE, VERSIONING_RULES } from './rules';
import { extensibleEnum, type JsonSchema, whenEquals } from './schema-kit';
import type { StepDefinition } from './step-definition';
import { stepErrorCodes, stepNamed, STEPS } from './steps';

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
    params: `${base}Params`,
    answer: `${base}Answer`,
    personalData: `${base}PersonalData`,
  } as const;
}

const ref = (name: string) => ({ $ref: `#/components/schemas/${name}` });

/**
 * The step's params, with what the step grammar says about the step beside
 * them: its name, transports, closed error set and `amr`. The per-step schema
 * file (`step-schema.ts`) carries the same as JSON Schema.
 */
function paramsComponent(step: StepDefinition): JsonSchema {
  return {
    ...step.params,
    'x-qauth-step': {
      name: step.urn,
      transports: [...step.transports],
      errors: [...step.errors],
      amr: [...step.amr],
    },
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

/** Every component one step contributes, in a fixed order. */
function stepComponents(step: StepDefinition): Array<[string, JsonSchema]> {
  const names = stepComponentNames(step);
  return [
    [names.params, paramsComponent(step)],
    [names.answer, answerRequestSchema(step)],
    [names.personalData, step.personal],
  ];
}

/**
 * The step names: an extensible set. A new step within a major version is a
 * new value here and a new optional member of the keyed objects below, both
 * additions a client already ignores, so it is not a break.
 */
function stepNameSchema(): JsonSchema {
  return extensibleEnum(
    STEPS.map((step) => step.urn),
    STEP_URN_SCHEMA_PATTERN,
    96,
    'A step name, `urn:qauth:ia:<name>:v1-rc.0`. A page shows its error page for a step it does not know.'
  );
}

/** The errors of every step: each step’s own set is closed; the union grows with new steps. */
function stepErrorSchema(): JsonSchema {
  return extensibleEnum(
    stepErrorCodes(),
    '^[a-z][a-z0-9_]{0,63}$',
    64,
    'Why an answer was refused. Each step names its own closed set (`x-qauth-step` beside its params, and its schema file).'
  );
}

/**
 * The step read, with one rule per step: `params` always holds the current
 * step's own params, and a `consent` step names its client, with the redirect
 * target when the client is unverified (ADR-019 Decision 6).
 */
function interactionComponent(): JsonSchema {
  const consentUrn = stepNamed('consent').urn;
  return {
    ...interactionSchema,
    allOf: STEPS.map((step) =>
      step.urn === consentUrn
        ? whenEquals('step', [step.urn], {
            required: ['client'],
            properties: {
              params: { type: 'object', required: [step.urn] },
              client: {
                type: 'object',
                ...whenEquals('kind', ['unverified'], { required: ['redirect'] }),
              },
            },
          })
        : whenEquals('step', [step.urn], {
            properties: { params: { type: 'object', required: [step.urn] } },
          })
    ),
  };
}

/** An object with one optional member per step, keyed by the step name. */
function keyedByStep(description: string, component: (step: StepDefinition) => string): JsonSchema {
  return {
    type: 'object',
    description,
    properties: Object.fromEntries(STEPS.map((step) => [step.urn, ref(component(step))])),
  };
}

/** The request body of an answer: one variant per step, by its name. */
function answerUnion(): JsonSchema {
  return {
    description:
      'An answer to one step, by its name: the envelope’s `type` and `csrf`, and the step’s answer fields. A new step adds a variant, which widens what the server accepts.',
    oneOf: STEPS.map((step) => ref(stepComponentNames(step).answer)),
    discriminator: {
      propertyName: 'type',
      mapping: Object.fromEntries(
        STEPS.map((step) => [step.urn, `#/components/schemas/${stepComponentNames(step).answer}`])
      ),
    },
  };
}

// ---------------------------------------------------------------------------
// Examples
// ---------------------------------------------------------------------------

/** The client an example interaction is for. */
function exampleClient(step: StepDefinition) {
  if (step.name === 'device_code') return undefined;
  if (step.name === 'consent') return EXAMPLE_UNVERIFIED_CLIENT;
  return EXAMPLE_CLIENT;
}

/** The step read of an interaction whose current step is `step`, as its example shows it. */
export function exampleInteraction(step: StepDefinition, options: { withError?: boolean } = {}) {
  const client = exampleClient(step);
  const alternatives = (step.example.alternatives ?? []).map(stepNamed);
  const error = options.withError === false ? undefined : step.example.step.error;
  return {
    step: step.urn,
    ...(error === undefined ? {} : { error }),
    alternatives: alternatives.map((alternative) => alternative.urn),
    params: Object.fromEntries(
      [step, ...alternatives].map((offered) => [offered.urn, offered.example.step.params])
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
  return {
    result: 'step',
    interaction: exampleInteraction(stepNamed(next.step), { withError: false }),
  };
}

/** The personal-data read of `step`, as its example shows it. */
export function examplePersonal(step: StepDefinition) {
  return {
    step: step.urn,
    data: step.example.personal === undefined ? {} : { [step.urn]: step.example.personal },
  };
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
                type: problemTypeUri(codes[0]),
                title: INTERACTION_PROBLEM_CODES[codes[0]].title,
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

/**
 * The same-origin check of every request that carries the flow cookie, before
 * the cookie itself is looked at.
 */
const SAME_ORIGIN_NOTE =
  'The request must come from the realm origin: `Sec-Fetch-Site` must be `same-origin`; when the browser sent no `Sec-Fetch-Site`, `Origin` must equal the realm origin, and an `Origin` of `null` or of any other origin is refused. A request that fails gets 403 `forbidden`.';

/**
 * The origin check of the personal-data read: a GET, which changes nothing.
 * CORS already keeps its answer from another origin's page, so the check is
 * defence in depth and lets a browser that sends neither header through.
 */
const SAME_ORIGIN_READ_NOTE =
  'The read refuses a request from another origin with 403 `forbidden`: one whose `Sec-Fetch-Site` is present and not `same-origin`, or whose `Origin` is present and not the realm origin (`null` included). A request with neither header is allowed, such as from a browser that sends neither (Safari before 16.4): the server sends no CORS headers, so a page on another origin cannot read the answer anyway, and the check is defence in depth.';

const FORM_ENCODING_NOTE = `As JSON or as a plain HTML form post (\`application/x-www-form-urlencoded\`, UTF-8) with the same members, so a page works without JavaScript. In a form post every value is a string: a boolean is \`true\` or \`false\` (an unchecked checkbox sends nothing, which means \`false\`), and no member may be repeated. ${SAME_ORIGIN_NOTE} The server checks the origin, then the flow cookie, then the CSRF value, and runs no engine work before all three pass. A body is at most 16 KiB, or 64 KiB for an answer to \`webauthn_create\` (ADR-017 Decision 7); a larger one gets 413.`;

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
        description: `The personal data the current step’s screen shows: the account chooser’s list, the identifier being signed in, a secret shown once. Only the browser that started the interaction can read it: the request needs the flow cookie, so the page calls it from the browser. ${SAME_ORIGIN_READ_NOTE} The server checks the origin, then the flow cookie. A step with no personal data answers an empty \`data\`.`,
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
          ...problemResponses([403, 410, 421, 429, 500, 503]),
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
        ['Interaction', interactionComponent()],
        ['StepName', stepNameSchema()],
        ['StepError', stepErrorSchema()],
        [
          'StepParams',
          keyedByStep(
            'The params of the offered steps, keyed by step name: the current step’s and each alternative’s. What any reader of the interaction id may see.',
            (step) => stepComponentNames(step).params
          ),
        ],
        ['AnswerRequest', answerUnion()],
        ['AnswerResult', answerResultSchema],
        ['NextStepResult', nextStepResultSchema],
        ['RedirectResult', redirectResultSchema],
        ['CancelRequest', cancelRequestSchema],
        ['PersonalData', personalDataSchema],
        [
          'StepPersonalData',
          keyedByStep(
            'The current step’s personal data, under its step name. Empty for a step that has none.',
            (step) => stepComponentNames(step).personalData
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

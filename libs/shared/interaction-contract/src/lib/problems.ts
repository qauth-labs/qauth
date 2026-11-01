/**
 * The errors of the Interaction API: RFC 9457 problem details with a stable
 * `code` and a `trace_id` (ADR-019 Decision 7), and no prose.
 *
 * The Interaction API answers errors in the problem format of the other API
 * families (`reference/api-conventions` on the docs site), restricted to what a
 * ceremony page may show: no `detail`, no `instance` and no `errors` list, all
 * of which may hold sentences. A page branches on `code` and the status and
 * shows its own text with the `trace_id`.
 *
 * A step whose answer was refused (a wrong password, an expired code) is not an
 * error here: the answer succeeds, and the step comes back with its `error` set
 * and a new CSRF value. These codes are for requests the API refuses before the
 * engine runs, and for failures.
 *
 * Every code here is also published in the auth server's problem registry
 * (`apps/auth-server/src/app/api-conventions/problem.ts`), with the same
 * status, problem type and title; a test there keeps the two equal.
 */

/**
 * Where the problem types are documented: a document's `type` is this base
 * followed by the type's slug (RFC 9457 §3.1.1), as on every other route that
 * answers problem documents.
 */
export const PROBLEM_TYPE_BASE = 'https://docs.qauth.dev/reference/problem-types/#';

/**
 * One code: the status it is sent with, its problem type's slug and title
 * (RFC 9457 §3.1.3, the same in every document with this code), and what it
 * means here.
 */
export interface InteractionProblemCode {
  readonly status: number;
  readonly type: string;
  readonly title: string;
  readonly description: string;
}

export const INTERACTION_PROBLEM_CODES = {
  bad_request: {
    status: 400,
    type: 'bad-request',
    title: 'Bad request',
    description: 'The request is malformed and no more specific code applies.',
  },
  invalid_answer: {
    status: 400,
    type: 'invalid-answer',
    title: 'Invalid answer',
    description:
      'The answer does not match the schema of the step it names, names a step the interaction does not offer, or repeats a field. The engine was not called.',
  },
  forbidden: {
    status: 403,
    type: 'forbidden',
    title: 'Forbidden',
    description:
      'The request is not same-origin, or its CSRF value is missing, already used or not the current step’s. The engine was not called.',
  },
  interaction_expired: {
    status: 410,
    type: 'interaction-expired',
    title: 'Interaction expired',
    description:
      'The interaction is unknown, expired or finished, the flow cookie does not belong to it, or a finish came after the browser session its sign-in started had ended. Every reason gets this one answer.',
  },
  content_too_large: {
    status: 413,
    type: 'content-too-large',
    title: 'Content too large',
    description: 'The request body is larger than the server accepts.',
  },
  unsupported_media_type: {
    status: 415,
    type: 'unsupported-media-type',
    title: 'Unsupported media type',
    description:
      'The request body is neither `application/json` nor `application/x-www-form-urlencoded`.',
  },
  misdirected_request: {
    status: 421,
    type: 'misdirected-request',
    title: 'Misdirected request',
    description: 'The server does not answer for the host the request names.',
  },
  too_many_requests: {
    status: 429,
    type: 'too-many-requests',
    title: 'Too many requests',
    description: 'Too many requests. `Retry-After` says when to try again.',
  },
  internal_error: {
    status: 500,
    type: 'internal-error',
    title: 'Internal error',
    description: 'The server failed. `trace_id` finds the failure in the server log.',
  },
  service_unavailable: {
    status: 503,
    type: 'service-unavailable',
    title: 'Service unavailable',
    description:
      'The server cannot answer now, for example while a store the engine needs is down. It fails closed.',
  },
} as const satisfies Record<string, InteractionProblemCode>;

export type InteractionProblemCodeName = keyof typeof INTERACTION_PROBLEM_CODES;

/** The `type` URI of a code: {@link PROBLEM_TYPE_BASE} and its slug. */
export function problemTypeUri(code: InteractionProblemCodeName): string {
  return `${PROBLEM_TYPE_BASE}${INTERACTION_PROBLEM_CODES[code].type}`;
}

/**
 * The status phrase that describes each error response in the document, as the
 * auth server's own OpenAPI documents describe theirs: Node's
 * `http.STATUS_CODES`. Node still calls 413 "Payload Too Large", the name RFC
 * 9110 §15.5.14 replaced. A test in the auth server keeps this table equal to
 * the phrase it uses.
 */
export const STATUS_TITLES: Readonly<Record<number, string>> = {
  400: 'Bad Request',
  403: 'Forbidden',
  410: 'Gone',
  413: 'Payload Too Large',
  415: 'Unsupported Media Type',
  421: 'Misdirected Request',
  429: 'Too Many Requests',
  500: 'Internal Server Error',
  503: 'Service Unavailable',
};

/** The codes sent with `status`, in the order above. */
export function codesWithStatus(status: number): InteractionProblemCodeName[] {
  return (Object.keys(INTERACTION_PROBLEM_CODES) as InteractionProblemCodeName[]).filter(
    (code) => INTERACTION_PROBLEM_CODES[code].status === status
  );
}

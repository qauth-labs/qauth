/**
 * The errors of the account API: RFC 9457 problem details with a stable `code`
 * and a `trace_id` (ADR-019 Decision 7), and no prose.
 *
 * The account API answers errors in the problem format of the API families
 * (`reference/api-conventions` on the docs site), restricted, like the
 * Interaction API's, to what a console may show without rewording: no
 * `detail` and no `instance`, and a field error names a reason code instead of
 * a message. The account console shows its own text for each code and reason,
 * with the `trace_id`.
 *
 * Every code here is also published in the auth server's problem registry
 * (`apps/auth-server/src/app/api-conventions/problem.ts`), with the same
 * status, problem type and title; a test there keeps the two equal.
 */

/**
 * Where the problem types are documented: a document's `type` is this base
 * followed by the type's slug (RFC 9457 §3.1.1).
 */
export const PROBLEM_TYPE_BASE = 'https://docs.qauth.dev/reference/problem-types/#';

/**
 * One code: the status it is sent with, its problem type's slug and title (the
 * same in every document with this code), and what it means on the account
 * API. `added` marks a code this contract adds to the server's registry.
 */
export interface AccountProblemCode {
  readonly status: number;
  readonly type: string;
  readonly title: string;
  readonly description: string;
}

/** The codes the account API sends, in status order. */
export const ACCOUNT_PROBLEM_CODES = {
  bad_request: {
    status: 400,
    type: 'bad-request',
    title: 'Bad request',
    description: 'The request is malformed and no more specific code applies.',
  },
  validation_error: {
    status: 400,
    type: 'validation-error',
    title: 'Validation error',
    description:
      'The request does not match the schema of the operation. `errors` names each field and why.',
  },
  invalid_cursor: {
    status: 400,
    type: 'invalid-cursor',
    title: 'Invalid cursor',
    description: 'The `cursor` does not parse, or it belongs to another list.',
  },
  invalid_current_password: {
    status: 400,
    type: 'invalid-current-password',
    title: 'Invalid current password',
    description:
      'The current password a password change names is wrong. It counts on the account’s failure ladder, as a failed sign-in does.',
  },
  invalid_code: {
    status: 400,
    type: 'invalid-code',
    title: 'Invalid code',
    description:
      'A one-time code in the request is wrong, expired or used: the first TOTP code of an enrolment, or a code mailed to an address. It counts on the account’s failure ladder for that code.',
  },
  unauthorized: {
    status: 401,
    type: 'unauthorized',
    title: 'Unauthorized',
    description:
      'The request carries no access token. `WWW-Authenticate` names the scheme and no error.',
  },
  access_token_expired: {
    status: 401,
    type: 'access-token-expired',
    title: 'Access token expired',
    description: 'The access token has expired.',
  },
  invalid_access_token: {
    status: 401,
    type: 'invalid-access-token',
    title: 'Invalid access token',
    description:
      'The access token is not valid, is not valid for this operation, or names no active user.',
  },
  insufficient_user_authentication: {
    status: 401,
    type: 'insufficient-user-authentication',
    title: 'Insufficient user authentication',
    description:
      'The operation needs fresh authentication and the sign-in behind the token is too old or lacks the account’s strongest bound factor (RFC 9470 §3). `max_age` and the `WWW-Authenticate` challenge say how fresh the next sign-in must be.',
  },
  forbidden: {
    status: 403,
    type: 'forbidden',
    title: 'Forbidden',
    description: 'The token lacks a scope the operation needs.',
  },
  delegated_token_refused: {
    status: 403,
    type: 'delegated-token-refused',
    title: 'Delegated token refused',
    description:
      'The token is an act-chain token (RFC 8693 `act`), and the operation changes a credential, an identifier, the contact address or a linked account, or deletes the account: only the person may do that (ADR-019 Decision 7).',
  },
  disabled_by_realm: {
    status: 403,
    type: 'disabled-by-realm',
    title: 'Disabled by realm',
    description:
      'The realm’s policy does not let a person do this themselves, such as deleting the account or changing the sign-in address. An admin can.',
  },
  not_found: {
    status: 404,
    type: 'not-found',
    title: 'Not found',
    description:
      'The resource does not exist, or belongs to another account: the answer is the same.',
  },
  conflict: {
    status: 409,
    type: 'conflict',
    title: 'Conflict',
    description: 'The request conflicts with the current state of the account.',
  },
  last_credential: {
    status: 409,
    type: 'last-credential',
    title: 'Last credential',
    description:
      'The change would leave the account with no way to sign in, such as deleting the only passkey of a passkey-only account.',
  },
  second_factor_required: {
    status: 409,
    type: 'second-factor-required',
    title: 'Second factor required',
    description:
      'The change would remove the last second factor while the realm’s policy requires one for this account.',
  },
  precondition_failed: {
    status: 412,
    type: 'precondition-failed',
    title: 'Precondition failed',
    description: 'The `If-Match` value does not match the current `ETag` of the resource.',
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
    description: 'The media type of the request body is not one the operation accepts.',
  },
  misdirected_request: {
    status: 421,
    type: 'misdirected-request',
    title: 'Misdirected request',
    description: 'The server does not answer for the host the request names.',
  },
  unprocessable_content: {
    status: 422,
    type: 'unprocessable-content',
    title: 'Unprocessable content',
    description:
      'The request is well formed, but its result fails a rule of the resource, such as a profile field the realm’s profile schema does not accept. `errors` names each field and why.',
  },
  weak_password: {
    status: 422,
    type: 'weak-password',
    title: 'Weak password',
    description: 'The new password does not meet the realm’s password policy. `reasons` lists why.',
  },
  precondition_required: {
    status: 428,
    type: 'precondition-required',
    title: 'Precondition required',
    description: 'The update needs an `If-Match` header.',
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
      'The server cannot answer now, for example while a store it needs is down. It fails closed.',
  },
} as const satisfies Record<string, AccountProblemCode>;

export type AccountProblemCodeName = keyof typeof ACCOUNT_PROBLEM_CODES;

/**
 * The codes this contract adds to the auth server's problem registry: no
 * route sent them before the account API.
 */
export const ADDED_PROBLEM_CODES: readonly AccountProblemCodeName[] = [
  'invalid_current_password',
  'invalid_code',
  'insufficient_user_authentication',
  'delegated_token_refused',
  'disabled_by_realm',
  'last_credential',
  'second_factor_required',
];

/** The `type` URI of a code: {@link PROBLEM_TYPE_BASE} and its slug. */
export function problemTypeUri(code: AccountProblemCodeName): string {
  return `${PROBLEM_TYPE_BASE}${ACCOUNT_PROBLEM_CODES[code].type}`;
}

/**
 * The status phrase that describes each error response, Node's
 * `http.STATUS_CODES`, as the auth server's own documents describe theirs
 * (Node still calls 413 "Payload Too Large").
 */
export const STATUS_TITLES: Readonly<Record<number, string>> = {
  400: 'Bad Request',
  401: 'Unauthorized',
  403: 'Forbidden',
  404: 'Not Found',
  409: 'Conflict',
  412: 'Precondition Failed',
  413: 'Payload Too Large',
  415: 'Unsupported Media Type',
  421: 'Misdirected Request',
  422: 'Unprocessable Entity',
  428: 'Precondition Required',
  429: 'Too Many Requests',
  500: 'Internal Server Error',
  503: 'Service Unavailable',
};

/**
 * Why a field of a request was refused, in `errors[].reason`: a closed reason
 * per field, never a sentence. The console shows its own text, or the message
 * the realm's profile schema gives the field's validator.
 */
export const FIELD_ERROR_REASONS = [
  'required',
  'unknown',
  'read_only',
  'too_short',
  'too_long',
  'invalid_format',
  'not_allowed',
] as const;

/**
 * Why a new password was refused, in `reasons` of `weak_password`: the
 * reasons of the password policy (ADR-017 Decision 8) and the breach list
 * (ADR-020 §3).
 */
export const PASSWORD_REJECTION_REASONS = [
  'too_short',
  'too_long',
  'blocklisted',
  'too_weak',
  'breached',
] as const;

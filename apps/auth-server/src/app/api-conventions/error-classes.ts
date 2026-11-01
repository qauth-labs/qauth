import { SsfRequestError } from '@qauth-labs/fastify-plugin-ssf';
import {
  BadRequestError,
  EmailAlreadyVerifiedError,
  EmailNotVerifiedError,
  ForbiddenError,
  InvalidClientError,
  InvalidClientMetadataError,
  InvalidConfigurationError,
  InvalidCredentialsError,
  InvalidCsrfTokenError,
  InvalidDpopProofError,
  InvalidGrantError,
  InvalidRedirectUriError,
  InvalidRequestError,
  InvalidScopeError,
  InvalidTargetError,
  InvalidTokenError,
  JWTExpiredError,
  JWTInvalidError,
  MisdirectedRequestError,
  MissingAccessTokenError,
  NotFoundError,
  PreconditionFailedError,
  PreconditionRequiredError,
  ProviderAlreadyRegisteredError,
  ProviderNotRegisteredError,
  TemporarilyUnavailableError,
  TokenAlreadyUsedError,
  TokenExpiredError,
  TooManyRequestsError,
  UnauthorizedClientError,
  UniqueConstraintError,
  UnsupportedGrantTypeError,
  WeakPasswordError,
} from '@qauth-labs/shared-errors';

import {
  InvalidCursorError,
  UnprocessableContentError,
  UnsupportedMediaTypeError,
} from '../helpers/api-request-errors';
import { ApprovalRequiredError, ApprovalStateError } from '../helpers/approval-required';
import { InteractionExpiredError } from '../helpers/interaction-expired';
import { RealmPolicyRefusedError } from '../helpers/realm-policy-update';
import { SignInRequiredError } from '../helpers/sign-in-required';
import { SsfNotFoundError, SsfStreamExistsError } from '../helpers/ssf-errors';
import type { OAuthErrorCode } from './oauth-error';
import { PROBLEM_CODES, type ProblemCode, problemTypeUri } from './problem';

/**
 * THE ERROR REGISTRY (#513): what each domain error class of
 * `@qauth-labs/shared-errors` answers, in either error format.
 *
 * - `code` is the class's problem code, and through {@link PROBLEM_CODES} its
 *   status, problem type and title. A problem document carries exactly these.
 * - `oauthError` is the `error` an OAuth protocol endpoint answers when the
 *   class reaches it. An OAuth error class names its own token.
 *
 * One table keeps the codes stable: they are part of the 1.0 promise (ADR-018
 * §5), so a class is mapped here once, never at a throw site. A test fails
 * when a class of the package has no entry. The classes a route or a server
 * library defines itself are mapped the same way, in {@link APP_ERROR_CLASSES}.
 *
 * A class's own `code` member is its published code in upper case, and a test
 * keeps the two equal. Six were renamed before they froze into the 1.0 promise
 * (2026-10-26): `jwt_invalid` and `jwt_expired` became `invalid_access_token`
 * and `access_token_expired`, the one-time token's `invalid_token`,
 * `token_expired` and `token_already_used` became
 * `invalid_verification_token`, `verification_token_expired` and
 * `verification_token_used`, and `unique_constraint_violation` became
 * `already_exists`. The exceptions are the server-side failures, whose code
 * says nothing a caller may act on (`internal_error`), and the shed request
 * (`service_unavailable`).
 */

/** A class of `@qauth-labs/shared-errors`, whatever its constructor takes. */
export type DomainErrorClass = abstract new (...args: never[]) => Error;

/** What one domain error class answers. */
export interface ErrorClassEntry {
  readonly errorClass: DomainErrorClass;
  readonly code: ProblemCode;
  readonly oauthError: OAuthErrorCode;
}

/** The registry, one entry per class, in the package's order. */
export const ERROR_CLASSES: readonly ErrorClassEntry[] = [
  // Common errors.
  { errorClass: BadRequestError, code: 'bad_request', oauthError: 'invalid_request' },
  { errorClass: ForbiddenError, code: 'forbidden', oauthError: 'access_denied' },
  {
    errorClass: InvalidConfigurationError,
    code: 'internal_error',
    oauthError: 'server_error',
  },
  {
    errorClass: InvalidCsrfTokenError,
    code: 'invalid_csrf_token',
    oauthError: 'invalid_request',
  },
  {
    errorClass: MisdirectedRequestError,
    code: 'misdirected_request',
    oauthError: 'invalid_request',
  },
  { errorClass: NotFoundError, code: 'not_found', oauthError: 'invalid_request' },
  {
    errorClass: PreconditionFailedError,
    code: 'precondition_failed',
    oauthError: 'invalid_request',
  },
  {
    errorClass: PreconditionRequiredError,
    code: 'precondition_required',
    oauthError: 'invalid_request',
  },
  {
    errorClass: TemporarilyUnavailableError,
    code: 'service_unavailable',
    oauthError: 'temporarily_unavailable',
  },
  {
    errorClass: TooManyRequestsError,
    code: 'too_many_requests',
    oauthError: 'temporarily_unavailable',
  },

  // Database errors.
  {
    errorClass: UniqueConstraintError,
    code: 'already_exists',
    oauthError: 'invalid_request',
  },

  // Authentication errors.
  {
    errorClass: EmailAlreadyVerifiedError,
    code: 'email_already_verified',
    oauthError: 'invalid_request',
  },
  { errorClass: EmailNotVerifiedError, code: 'email_not_verified', oauthError: 'access_denied' },
  { errorClass: InvalidClientError, code: 'invalid_client', oauthError: 'invalid_client' },
  {
    errorClass: InvalidClientMetadataError,
    code: 'invalid_client_metadata',
    oauthError: 'invalid_client_metadata',
  },
  {
    errorClass: InvalidCredentialsError,
    code: 'invalid_credentials',
    oauthError: 'invalid_grant',
  },
  {
    errorClass: InvalidDpopProofError,
    code: 'invalid_dpop_proof',
    oauthError: 'invalid_dpop_proof',
  },
  { errorClass: InvalidGrantError, code: 'invalid_grant', oauthError: 'invalid_grant' },
  {
    errorClass: InvalidRedirectUriError,
    code: 'invalid_redirect_uri',
    oauthError: 'invalid_redirect_uri',
  },
  { errorClass: InvalidRequestError, code: 'invalid_request', oauthError: 'invalid_request' },
  { errorClass: InvalidScopeError, code: 'invalid_scope', oauthError: 'invalid_scope' },
  { errorClass: InvalidTargetError, code: 'invalid_target', oauthError: 'invalid_target' },
  {
    errorClass: InvalidTokenError,
    code: 'invalid_verification_token',
    oauthError: 'invalid_request',
  },
  { errorClass: JWTExpiredError, code: 'access_token_expired', oauthError: 'invalid_token' },
  { errorClass: JWTInvalidError, code: 'invalid_access_token', oauthError: 'invalid_token' },
  // No credentials (RFC 6750 §3.1): `unauthorized`, not `invalid_access_token`.
  // An OAuth resource's body still needs an `error`, and userinfo's has
  // always been `invalid_token`.
  { errorClass: MissingAccessTokenError, code: 'unauthorized', oauthError: 'invalid_token' },
  {
    errorClass: ProviderAlreadyRegisteredError,
    code: 'internal_error',
    oauthError: 'server_error',
  },
  {
    errorClass: ProviderNotRegisteredError,
    code: 'internal_error',
    oauthError: 'server_error',
  },
  {
    errorClass: TokenAlreadyUsedError,
    code: 'verification_token_used',
    oauthError: 'invalid_request',
  },
  {
    errorClass: TokenExpiredError,
    code: 'verification_token_expired',
    oauthError: 'invalid_request',
  },
  {
    errorClass: UnauthorizedClientError,
    code: 'unauthorized_client',
    oauthError: 'unauthorized_client',
  },
  {
    errorClass: UnsupportedGrantTypeError,
    code: 'unsupported_grant_type',
    oauthError: 'unsupported_grant_type',
  },
  { errorClass: WeakPasswordError, code: 'weak_password', oauthError: 'invalid_request' },
];

/**
 * The error classes defined outside `@qauth-labs/shared-errors` that reach the
 * error handler, each with the code it answers (#513): the refusal of a
 * cookie-authenticated route without a browser session, and the Shared Signals
 * Framework transmitter's refusals (SSF 1.0 §8.1 defines no error body, so its
 * routes answer problem documents), the admin pipeline's refusal of a
 * security operation that carries no approval, an approval's refused move,
 * and a refused realm policy update. Each code is one the problem types page
 * publishes, for the status the class carries.
 *
 * A test fails when an error class of the app that declares a `statusCode` has
 * no entry here. The one exception answers the code of whichever status it is
 * thrown with: the wallet-link API's `WalletLinkRefusal` (`unauthorized`,
 * `not_found` or `internal_error`).
 */
export const APP_ERROR_CLASSES: readonly ErrorClassEntry[] = [
  { errorClass: SignInRequiredError, code: 'unauthorized', oauthError: 'invalid_request' },
  // The admin pipeline's approval gate (#511): a security operation that
  // carries no approval never runs.
  { errorClass: ApprovalRequiredError, code: 'approval_required', oauthError: 'access_denied' },
  // The approval engine (#512): a move an approval cannot make from where it
  // stands.
  { errorClass: ApprovalStateError, code: 'conflict', oauthError: 'invalid_request' },
  // The Interaction API's one refusal of a request at an interaction (#592):
  // unknown, expired, finished or not bound to the browser's flow cookie.
  {
    errorClass: InteractionExpiredError,
    code: 'interaction_expired',
    oauthError: 'invalid_request',
  },
  // The list and update conventions of the account and developer APIs
  // (#506, #524): a cursor another list issued or that does not parse, and a
  // merge patch whose result fails the resource's schema, and an update sent
  // as another media type than a merge patch.
  { errorClass: InvalidCursorError, code: 'invalid_cursor', oauthError: 'invalid_request' },
  {
    errorClass: UnprocessableContentError,
    code: 'unprocessable_content',
    oauthError: 'invalid_request',
  },
  {
    errorClass: UnsupportedMediaTypeError,
    code: 'unsupported_media_type',
    oauthError: 'invalid_request',
  },
  // A realm policy update the schema or a rule refuses (#529), such as the
  // smtp transport without a password. Its message names paths, never values.
  {
    errorClass: RealmPolicyRefusedError,
    code: 'unprocessable_content',
    oauthError: 'invalid_request',
  },
  // `@qauth-labs/server-ssf`, through the SSF plugin: a stream request the
  // protocol refuses. Its message, which echoes no value, is the `detail`.
  { errorClass: SsfRequestError, code: 'bad_request', oauthError: 'invalid_request' },
  { errorClass: SsfNotFoundError, code: 'not_found', oauthError: 'invalid_request' },
  { errorClass: SsfStreamExistsError, code: 'conflict', oauthError: 'invalid_request' },
];

/** Every entry the error handler reads: the package's classes, then the app's own. */
const ALL_ERROR_CLASSES: readonly ErrorClassEntry[] = [...ERROR_CLASSES, ...APP_ERROR_CLASSES];

/** What a problem document says about one error class. */
export interface ProblemDescription {
  readonly code: ProblemCode;
  readonly status: number;
  readonly type: string;
  readonly title: string;
}

/** The registry entry for `error`'s class, or `undefined` for an error no entry lists. */
export function errorClassEntryOf(error: unknown): ErrorClassEntry | undefined {
  if (!(error instanceof Error)) return undefined;
  // Exact class first, so a subclass registered after its parent still wins.
  return (
    ALL_ERROR_CLASSES.find((entry) => error.constructor === entry.errorClass) ??
    ALL_ERROR_CLASSES.find((entry) => error instanceof entry.errorClass)
  );
}

/** The status, type, title and code a problem document carries for `code`. */
export function describeProblem(code: ProblemCode): ProblemDescription {
  const { status, title } = PROBLEM_CODES[code];
  return { code, status, type: problemTypeUri(code), title };
}

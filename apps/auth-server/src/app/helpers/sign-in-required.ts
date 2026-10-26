/**
 * The refusal of a cookie-authenticated JSON route reached without a valid
 * browser session (#513): `401`, answered as the `unauthorized` problem
 * document (`api-conventions/error-classes.ts`), the code every other route
 * answers a request that carries no valid credentials with.
 *
 * The credential is the `__Host-qauth_session` cookie, which no HTTP
 * authentication scheme names, so the answer carries no `WWW-Authenticate`
 * challenge: the route is not bearer-protected, and the error handler adds
 * none. Before #513, `GET /consents` answered this case with `{ "consents":
 * [] }` and `DELETE /consents/{id}` with an empty body.
 *
 * Kept free of imports so the registry, and with it the error handler, can
 * load it without loading the session helpers and their configuration.
 */
export class SignInRequiredError extends Error {
  readonly statusCode = 401;

  constructor(message = 'Sign in first: the request carries no valid browser session.') {
    super(message);
    this.name = 'SignInRequiredError';
  }
}

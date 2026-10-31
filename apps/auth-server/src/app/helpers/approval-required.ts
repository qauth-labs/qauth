/**
 * The refusal of a security operation that carries no usable approval
 * (ADR-019 Decision 7, #511, #512): `403`, answered as the `approval_required`
 * problem document (`api-conventions/error-classes.ts`). The admin pipeline's
 * approval gate throws it before the handler, and again inside the
 * operation's transaction when the approval was used meanwhile, so the
 * operation never runs.
 *
 * A request that names no approval in `QAuth-Approval`, and one whose
 * approval is unknown, not approved yet, used, cancelled, denied, expired, or
 * made for another request, get the same answer: the client reads the
 * approval to learn where it stands.
 *
 * Kept free of imports so the registry, and with it the error handler, can
 * load it without loading the admin pipeline.
 */
export class ApprovalRequiredError extends Error {
  readonly statusCode = 403;
  readonly code = 'APPROVAL_REQUIRED';

  constructor(
    message = 'This is a security operation: it runs only with a fresh approval bound to it.'
  ) {
    super(message);
    this.name = 'ApprovalRequiredError';
  }
}

/**
 * A move an approval cannot make from where it stands (#512): `409`, the
 * `conflict` problem document. Approving or declining one that is no longer
 * pending, and withdrawing one that was used, denied, cancelled or has
 * expired.
 */
export class ApprovalStateError extends Error {
  readonly statusCode = 409;
  readonly code = 'CONFLICT';

  constructor(
    message = 'The approval is no longer open: it was used, denied or cancelled, or it has expired.'
  ) {
    super(message);
    this.name = 'ApprovalStateError';
  }
}

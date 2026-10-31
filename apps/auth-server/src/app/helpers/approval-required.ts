/**
 * The refusal of a security operation that carries no approval (ADR-019
 * Decision 7, #511): `403`, answered as the `approval_required` problem
 * document (`api-conventions/error-classes.ts`). The admin pipeline's
 * approval gate throws it before the handler, so the operation never runs.
 *
 * Until approvals ship (#512), the gate fails closed: every request whose
 * classification is `security` gets this answer, and none runs.
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

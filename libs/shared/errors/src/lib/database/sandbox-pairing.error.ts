/**
 * The rules of the paired sandbox realm (ADR-019 Decision 11, issue #554),
 * each held by the database whoever writes the row:
 *
 * - `one_sandbox`: a live realm has at most one sandbox.
 * - `sandbox_of_sandbox`: a sandbox realm has no sandbox.
 * - `operator`: the operator realm is no sandbox and has none.
 * - `self`: a realm is not its own sandbox.
 * - `permanent`: the pairing is set when the sandbox is created, and never
 *   changes.
 * - `ceiling`: a sandbox's environment ceiling is never `development`.
 * - `live_realm_has_sandbox`: a live realm is not deleted while its sandbox
 *   exists.
 */
export type SandboxPairingRule =
  | 'one_sandbox'
  | 'sandbox_of_sandbox'
  | 'operator'
  | 'self'
  | 'permanent'
  | 'ceiling'
  | 'live_realm_has_sandbox';

const SANDBOX_PAIRING_MESSAGES: Readonly<Record<SandboxPairingRule, string>> = {
  one_sandbox: 'The live realm already has a sandbox realm',
  sandbox_of_sandbox: 'A sandbox realm has no sandbox realm',
  operator: 'The operator realm is no sandbox realm and has none',
  self: 'A realm is not its own sandbox realm',
  permanent: 'A sandbox realm stays paired with the live realm it was created for',
  ceiling: "A sandbox realm's environment ceiling is staging or production, never development",
  live_realm_has_sandbox: 'The realm has a sandbox realm: delete the sandbox realm first',
};

/**
 * Error thrown when a write breaks a rule of the paired sandbox realm (#554):
 * `409 Conflict` with the realm's current state. `rule` says which; the
 * message is fixed per rule and names no realm.
 */
export class SandboxPairingError extends Error {
  public readonly statusCode = 409;
  public readonly code = 'CONFLICT';

  constructor(
    public readonly rule: SandboxPairingRule,
    cause?: unknown
  ) {
    super(SANDBOX_PAIRING_MESSAGES[rule]);
    this.name = 'SandboxPairingError';
    // Ensure proper prototype chain for instanceof checks
    Object.setPrototypeOf(this, SandboxPairingError.prototype);
    if (cause !== undefined) {
      this.cause = cause;
    }
    // Maintains proper stack trace for where our error was thrown (only available on V8)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, SandboxPairingError);
    }
  }
}

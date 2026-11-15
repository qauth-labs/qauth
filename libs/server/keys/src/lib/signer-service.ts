import type { Signer, SignerOperation } from './signer';
import { SignerAccessDeniedError } from './signer-errors';
import { hasSignerGrant, isSignerCaller, type SignerCaller } from './signer-policy';
import {
  decodeSignerRequest,
  encodeSignerError,
  encodeSignerResult,
  type SignerOperationArgs,
  type SignerWireBody,
} from './signer-wire';

/**
 * THE SIGNER SERVICE (ADR-019 Decision 9, issue #497): what the signer role
 * answers a peer's call with, apart from HTTP. The auth server's internal
 * route module (`/internal/signer/v1-rc.0`) reads the peer's role from its
 * client certificate and hands it here with the body; this decides the
 * answer.
 *
 * - The caller is the peer's role, never a name the request carries, and
 *   never `local`: that name is for a caller inside the signer's own process.
 * - A role whose grant in `SIGNER_POLICY` does not name the operation is
 *   refused before the body is read; the in-process signer then checks the
 *   call itself (the token type, the context), as it does for every caller.
 * - Every refusal for the caller's role is marked, so the route logs and
 *   counts it per role and operation.
 * - An error answers with public fields only (`encodeSignerError`).
 */

/** The signer service's answer to one call. */
export interface SignerServiceAnswer {
  readonly status: number;
  readonly body: SignerWireBody;
  /**
   * The call was refused for the caller's role (`SIGNER_ACCESS_DENIED`): what
   * the route logs and counts. The role is the peer's, or `unknown` for a
   * role the signer has no grants for.
   */
  readonly refused?: { readonly caller: string; readonly operation: SignerOperation };
  /** The signer failed in a way it does not name: what the route logs. Never sent. */
  readonly fault?: { readonly name: string; readonly code?: string };
}

/** The signer service over one signer. */
export interface SignerService {
  /**
   * Run `operation` for a peer of role `caller` with the request body it
   * sent, parsed as JSON. Never throws: every outcome is an answer.
   */
  call(caller: unknown, operation: SignerOperation, body: unknown): Promise<SignerServiceAnswer>;
  /**
   * The answer to a call of `operation` that a peer of role `caller` may not
   * make whatever its body says, `undefined` when its role has a grant for
   * the operation: what {@link call} answers first. A route checks it before
   * it reads the request's body, so a role with no grant for an operation
   * gets its refusal without the signer reading what it sent.
   */
  precheck(caller: unknown, operation: SignerOperation): SignerServiceAnswer | undefined;
}

/** Make the signer service over `signer`, the signer role's in-process signer. */
export function createSignerService(signer: Signer): SignerService {
  const precheck = (callerInput: unknown, operation: SignerOperation) => {
    const role = isSignerCaller(callerInput) && callerInput !== 'local' ? callerInput : undefined;
    if (role === undefined || !hasSignerGrant(role, operation)) {
      return {
        role,
        answer: refusal(new SignerAccessDeniedError(role, operation), role, operation),
      };
    }
    return { role, answer: undefined };
  };
  return Object.freeze({
    precheck(callerInput: unknown, operation: SignerOperation): SignerServiceAnswer | undefined {
      return precheck(callerInput, operation).answer;
    },
    async call(
      callerInput: unknown,
      operation: SignerOperation,
      body: unknown
    ): Promise<SignerServiceAnswer> {
      const { role, answer } = precheck(callerInput, operation);
      if (answer !== undefined || role === undefined) {
        return answer ?? refusal(new SignerAccessDeniedError(role, operation), role, operation);
      }
      try {
        const args = decodeSignerRequest(operation, body);
        const result = await invoke(signer, role, operation, args);
        return { status: 200, body: { result } };
      } catch (error) {
        const encoded = encodeSignerError(error);
        if (encoded.body.error.code === 'SIGNER_ACCESS_DENIED') {
          return { ...refusal(error, role, operation), body: encoded.body };
        }
        return encoded;
      }
    },
  });
}

/** Call `operation` on `signer` as `caller`, and encode its answer. */
async function invoke<O extends SignerOperation>(
  signer: Signer,
  caller: SignerCaller,
  operation: O,
  args: SignerOperationArgs<O>
): Promise<unknown> {
  const method = signer[operation] as unknown as (
    caller: SignerCaller,
    ...rest: SignerOperationArgs<O>
  ) => ReturnType<Signer[O]>;
  const result = await method.call(signer, caller, ...args);
  return encodeSignerResult(operation, result as Awaited<ReturnType<Signer[O]>>);
}

function refusal(
  error: unknown,
  role: SignerCaller | undefined,
  operation: SignerOperation
): SignerServiceAnswer {
  const encoded = encodeSignerError(error);
  return {
    status: encoded.status,
    body: encoded.body,
    refused: { caller: role ?? 'unknown', operation },
  };
}

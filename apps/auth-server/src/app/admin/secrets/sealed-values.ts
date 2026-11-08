import { ADMIN_SEALED_VALUE_CONTEXT_PREFIX } from '@qauth-labs/fastify-plugin-signer';
import { BadRequestError } from '@qauth-labs/shared-errors';
import type { FastifyInstance, FastifyRequest } from 'fastify';

import type { AdminOperation } from '../../helpers/admin-operations';
import { requestClassification } from '../../plugins/admin-operations';
import { requestAdminCaller } from '../pipeline';
import { isSecretMember, secretMemberMatches } from './secret-members';

/**
 * SEALED VALUES (ADR-019 Decision 7, issue #984): a secret of a security
 * operation's request, encrypted with the realm's `data_at_rest` key before
 * the request is filed, under a context bound to the operation and the
 * member, beside the realm.
 *
 * `secrets.seal` seals a value ({@link sealValue}); the handler of the
 * operation opens it ({@link openRequestSealedValue}), only for its own
 * operation, which it reads from the request's classification, never from an
 * argument, for a member its operation declares, and for the realm the request
 * acts on. A value sealed for another operation, member or realm does not open:
 * the signer authenticates the context and the realm with the ciphertext.
 *
 * Both run as the signer's `admin` caller, whose grant encrypts and decrypts
 * only {@link ADMIN_SEALED_VALUE_CONTEXT_PREFIX} contexts, so a sealed value
 * never opens as a stored secret of another kind, nor a stored secret as a
 * sealed value. A handler that keeps the secret seals it again for its own
 * store (a plugin secret, under the plugin's context): what the approval bound
 * is never what is stored.
 */

/** The signer caller a sealed value is sealed and opened as. */
export const SEALED_VALUE_SIGNER_CALLER = 'admin';

/**
 * The `context` a value sealed for `member` of the operation `operationId` is
 * encrypted under: `admin-sealed-value:<operation id>:<member>`. An operation
 * id holds no `:`, so a context reads one way only.
 */
export function sealedValueContext(operationId: string, member: string): string {
  return `${ADMIN_SEALED_VALUE_CONTEXT_PREFIX}${operationId}:${member}`;
}

/**
 * Seal `plaintext` for `member` of `operation` in the realm `realmId`.
 *
 * @throws {Error} when the operation declares no secret member `member`
 */
export async function sealValue(
  fastify: Pick<FastifyInstance, 'signer'>,
  realmId: string,
  operation: Pick<AdminOperation, 'id' | 'secretMembers'>,
  member: string,
  plaintext: string
): Promise<string> {
  requireDeclaredMember(operation, member);
  return fastify.signer.encrypt(SEALED_VALUE_SIGNER_CALLER, {
    realmId,
    plaintext: Buffer.from(plaintext, 'utf8'),
    context: sealedValueContext(operation.id, member),
  });
}

/** Whether `operation` declares `member` among its secret members. */
export function declaresSecretMember(
  operation: Pick<AdminOperation, 'secretMembers'> | undefined,
  member: string
): boolean {
  return (
    operation !== undefined &&
    isSecretMember(member) &&
    (operation.secretMembers ?? []).some((pattern) => secretMemberMatches(pattern, member))
  );
}

/** Throws when `operation` does not declare `member`: a handler that opens another is a bug. */
function requireDeclaredMember(
  operation: Pick<AdminOperation, 'id' | 'secretMembers'>,
  member: string
): void {
  if (!declaresSecretMember(operation, member)) {
    throw new Error(`The admin operation ${operation.id} declares no secret member ${member}`);
  }
}

/** Signer error codes that say a ciphertext was not made for this context in this realm. */
const NOT_SEALED_HERE: ReadonlySet<unknown> = new Set([
  'DATA_DECRYPTION_FAILED',
  'SIGNER_KEY_NOT_FOUND',
]);

/**
 * The plaintext of `sealed`, which must open for `member` of `operation` in
 * the realm `realmId`. One sealed for another operation, member or realm, or
 * changed, is refused with 400; `label` names the member in the refusal (the
 * caller passes a name it checked, never one of the request's own strings it
 * did not). Any other failure, such as the signer unreachable, is thrown on.
 *
 * @throws {Error} when the operation declares no secret member `member`
 */
export async function openSealedValue(
  fastify: Pick<FastifyInstance, 'signer'>,
  realmId: string,
  operation: Pick<AdminOperation, 'id' | 'secretMembers'>,
  member: string,
  sealed: string,
  label = 'a secret member'
): Promise<string> {
  requireDeclaredMember(operation, member);
  try {
    const plaintext = await fastify.signer.decrypt(SEALED_VALUE_SIGNER_CALLER, {
      realmId,
      ciphertext: sealed,
      context: sealedValueContext(operation.id, member),
    });
    return plaintext.toString('utf8');
  } catch (error) {
    if (NOT_SEALED_HERE.has((error as { code?: unknown } | null)?.code)) {
      throw new BadRequestError(
        `The value for ${label} was not sealed for it, for this operation, in this realm: seal it with secrets.seal for this operation and member`
      );
    }
    throw error;
  }
}

/**
 * The plaintext of `sealed`, a value the request carries at `member`, opened
 * for the request's own operation (its classification's, so a handler cannot
 * open a value sealed for another) and the realm it acts on.
 *
 * @throws {BadRequestError} when the value was not sealed for that operation,
 *   member and realm
 * @throws {Error} when the request has no classification, or its operation
 *   declares no secret member `member`
 */
export async function openRequestSealedValue(
  request: FastifyRequest,
  member: string,
  sealed: string,
  label?: string
): Promise<string> {
  const { operationId } = requestClassification(request);
  const operation = request.server.adminApi.registry.get(operationId);
  if (operation === undefined) {
    throw new Error(`The admin operation ${operationId} is not in the registry`);
  }
  return openSealedValue(
    request.server,
    requestAdminCaller(request).targetRealm.id,
    operation,
    member,
    sealed,
    label
  );
}

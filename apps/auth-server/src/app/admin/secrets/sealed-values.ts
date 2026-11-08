import { createHash } from 'node:crypto';

import { ADMIN_SEALED_VALUE_CONTEXT_PREFIX } from '@qauth-labs/fastify-plugin-signer';
import { BadRequestError } from '@qauth-labs/shared-errors';
import type { FastifyInstance, FastifyRequest } from 'fastify';

import type { AdminOperation } from '../../helpers/admin-operations';
import { requestClassification } from '../../plugins/admin-operations';
import { type AdminOperationRoute, requestAdminCaller } from '../pipeline';
import { isSecretMember, secretMemberMatches } from './secret-members';

/**
 * SEALED VALUES (ADR-019 Decision 7, issue #984): a secret of a security
 * operation's request, encrypted with the realm's `data_at_rest` key before
 * the request is filed, under a context bound to the operation, the member
 * and what the request acts on ({@link SealBinding}: its path parameters but
 * the realm's, such as the plugin a configure names, and what its route adds,
 * such as that plugin's package and type), beside the realm.
 *
 * `secrets.seal` seals a value ({@link sealValue}); the handler of the
 * operation opens it ({@link openRequestSealedValue}), only for its own
 * operation, which it reads from the request's classification, never from an
 * argument, for a member its operation declares, for its own path parameters
 * and for the realm the request acts on. A value sealed for another
 * operation, member, resource or realm does not open: the signer
 * authenticates the context and the realm with the ciphertext.
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

/** The path parameter that names the realm, which the signer binds apart. */
const REALM_PARAMETER = 'realmId';

/**
 * What a sealed value is bound to beside its operation, member and realm: the
 * resource the request acts on.
 */
export interface SealBinding {
  /**
   * The request's path parameters, as its route parses them; the realm's
   * (`realmId`) is left out, as the signer binds the realm itself.
   */
  readonly params: Readonly<Record<string, unknown>>;
  /** What the operation's route adds (`config.sealScope`), or `null` when it adds nothing. */
  readonly scope: string | null;
}

/**
 * The binding of a value sealed for, or opened by, a request of the route
 * `route` with the parsed path parameters `params`, or `undefined` when the
 * route's `sealScope` says they name nothing the operation acts on.
 */
export async function sealBindingOf(
  route: Pick<AdminOperationRoute, 'sealScope'>,
  params: Readonly<Record<string, unknown>>
): Promise<SealBinding | undefined> {
  const scope = route.sealScope === undefined ? null : await route.sealScope(params);
  if (scope === undefined) return undefined;
  if (scope !== null && typeof scope !== 'string') {
    throw new TypeError('A sealScope answers a string, or undefined');
  }
  return { params, scope };
}

/**
 * The `context` a value sealed for `member` of the operation `operationId`,
 * with `binding`, is encrypted under: `admin-sealed-value:<operation id>:`
 * and the SHA-256, base64url, of the JSON of the operation id, the member,
 * the path parameters but the realm's (sorted by name) and the route's scope.
 * The digest keeps a context within the signer's length, whatever the member
 * and the parameters, and reads one way only.
 */
export function sealedValueContext(
  operationId: string,
  member: string,
  binding: SealBinding
): string {
  const params = Object.keys(binding.params)
    .filter((name) => name !== REALM_PARAMETER)
    .sort()
    .map((name) => [name, binding.params[name] ?? null]);
  const digest = createHash('sha256')
    .update(JSON.stringify([operationId, member, params, binding.scope]), 'utf8')
    .digest('base64url');
  return `${ADMIN_SEALED_VALUE_CONTEXT_PREFIX}${operationId}:${digest}`;
}

/**
 * Seal `plaintext` for `member` of `operation`, with `binding`, in the realm
 * `realmId`.
 *
 * @throws {Error} when the operation declares no secret member `member`
 */
export async function sealValue(
  fastify: Pick<FastifyInstance, 'signer'>,
  realmId: string,
  operation: Pick<AdminOperation, 'id' | 'secretMembers'>,
  member: string,
  binding: SealBinding,
  plaintext: string
): Promise<string> {
  requireDeclaredMember(operation, member);
  return fastify.signer.encrypt(SEALED_VALUE_SIGNER_CALLER, {
    realmId,
    plaintext: Buffer.from(plaintext, 'utf8'),
    context: sealedValueContext(operation.id, member, binding),
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

/** The refusal of a value that was not sealed for the member, operation and resource it is sent for. */
function notSealedHere(label: string): BadRequestError {
  return new BadRequestError(
    `The value for ${label} was not sealed for it, for this operation, in this realm: seal it with secrets.seal for this operation, member and path parameters`
  );
}

/**
 * The plaintext of `sealed`, which must open for `member` of `operation`,
 * with `binding`, in the realm `realmId`. One sealed for another operation,
 * member, binding or realm, or changed, is refused with 400; `label` names
 * the member in the refusal (the caller passes a name it checked, never one
 * of the request's own strings it did not). Any other failure, such as the
 * signer unreachable, is thrown on.
 *
 * @throws {Error} when the operation declares no secret member `member`
 */
export async function openSealedValue(
  fastify: Pick<FastifyInstance, 'signer'>,
  realmId: string,
  operation: Pick<AdminOperation, 'id' | 'secretMembers'>,
  member: string,
  binding: SealBinding,
  sealed: string,
  label = 'a secret member'
): Promise<string> {
  requireDeclaredMember(operation, member);
  try {
    const plaintext = await fastify.signer.decrypt(SEALED_VALUE_SIGNER_CALLER, {
      realmId,
      ciphertext: sealed,
      context: sealedValueContext(operation.id, member, binding),
    });
    return plaintext.toString('utf8');
  } catch (error) {
    if (NOT_SEALED_HERE.has((error as { code?: unknown } | null)?.code)) {
      throw notSealedHere(label);
    }
    throw error;
  }
}

/**
 * The plaintext of `sealed`, a value the request carries at `member`, opened
 * for the request's own operation (its classification's, so a handler cannot
 * open a value sealed for another), its own path parameters as its route
 * parsed them, what its route binds beside them, and the realm it acts on.
 *
 * @throws {BadRequestError} when the value was not sealed for that operation,
 *   member, resource and realm
 * @throws {Error} when the request has no classification, its operation has
 *   no route on the listener, or declares no secret member `member`
 */
export async function openRequestSealedValue(
  request: FastifyRequest,
  member: string,
  sealed: string,
  label = 'a secret member'
): Promise<string> {
  const { operationId } = requestClassification(request);
  const operation = request.server.adminApi.registry.get(operationId);
  if (operation === undefined) {
    throw new Error(`The admin operation ${operationId} is not in the registry`);
  }
  const route = request.server.adminApi.routeOf(operationId);
  if (route === undefined) {
    throw new Error(`The admin operation ${operationId} has no route on this listener`);
  }
  const params = (request.params ?? {}) as Readonly<Record<string, unknown>>;
  const binding = await sealBindingOf(route, params);
  if (binding === undefined) throw notSealedHere(label);
  return openSealedValue(
    request.server,
    requestAdminCaller(request).targetRealm.id,
    operation,
    member,
    binding,
    sealed,
    label
  );
}

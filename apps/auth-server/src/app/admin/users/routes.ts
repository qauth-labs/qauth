import { PreconditionFailedError } from '@qauth-labs/shared-errors';
import {
  OPERATOR_VERIFICATION_METHODS,
  parseOperatorVerifiedBy,
} from '@qauth-labs/shared-validation';
import type { FastifyInstance, FastifyPluginAsync } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { rfc3339 } from '../../api-conventions/time';
import { type AdminOperation, operationSchemaExtensions } from '../../helpers/admin-operations';
import { emitUserEvent } from '../../helpers/user-events';
import { requestClassification } from '../../plugins/admin-operations';
import {
  ADMIN_SECURITY_SCHEME,
  type AdminChange,
  adminEventActor,
  adminTransaction,
  recordAdminChange,
  requestAdminCaller,
} from '../pipeline';
import { deleteAccountOfRealm } from './deletion';
import {
  accountVerificationStateVersion,
  type DeletableAccount,
  readAccountVerificationState,
  USER_OPERATION_IDS,
} from './operations';

/**
 * THE ACCOUNT ROUTES OF THE ADMIN API (ADR-015 Decision 8, amended
 * 2026-11-08; issue #1052):
 *
 *   POST /admin/v1-rc.0/realms/{realmId}/users/{userId}/verification — users.verify,
 *        If-Match required, an approval required
 *   DELETE /admin/v1-rc.0/realms/{realmId}/users/{userId} — users.delete,
 *        If-Match required, an approval required; idempotent by id (#681)
 *
 * `users.verify` reads the account (`./operations.ts`), so the pipeline
 * answers 428 without `If-Match` and 412 when it names another version of
 * the account. No route reads an account yet (the admin console's user
 * screen, #682, adds one), so `If-Match: *` names whichever version is
 * current: the approval binds the version it was filed against either way,
 * and the call it approves runs only against that one.
 *
 * The handler reads the account again in its transaction and records the
 * verification only while the account is the one the call was classified
 * and approved against: a change in between is 412, and the conditional
 * write (an enabled account no operator verified yet) refuses the rest. The
 * `user.verified` event, with the method `operator` and the admin as its
 * actor, commits with it and with the call's audit row.
 *
 * `users.delete` locks the account, ends its sessions with their
 * back-channel logout notices and deletes it, all in the handler's
 * transaction (`./deletion.ts`), and answers 204. An id the realm does not
 * hold answers 204 too, and changes nothing: its audit row records the call
 * with no change, and no event is written.
 */

/** The path of an account's verification, as the admin listener routes it. */
const VERIFICATION_PATH = '/admin/v1-rc.0/realms/:realmId/users/:userId/verification';

const verificationParams = z.object({ realmId: z.uuid(), userId: z.uuid() });

const verificationHeaders = z.looseObject({
  'if-match': z.string().meta({
    description:
      "The ETag of the account, or * for its current state: the approval binds the account's state it was filed against either way.",
  }),
});

/**
 * The body of a verification: an empty object. The request names everything
 * in its path; a security operation's body is parsed by a schema all the
 * same, so the request an approval binds is the one the handler reads, and
 * `{}` is always the same body.
 */
const verificationBody = z.strictObject({}).meta({ id: 'AdminAccountVerificationRequest' });

/** An operator's verification of an account, as the admin API answers it. */
export const accountVerificationSchema = z
  .object({
    userId: z.uuid(),
    verifiedAt: z.iso.datetime().meta({ description: 'When the operator verified the account.' }),
    method: z.enum(OPERATOR_VERIFICATION_METHODS).meta({
      description:
        "How it was verified: operator, an admin's approved users.verify; operator_cli, the verify-account command on the server host. The set may grow.",
    }),
    verifiedBy: z.string().nullable().meta({
      description:
        'Who verified it: the admin account for operator, the operating-system user for operator_cli, or null when the host named none.',
    }),
  })
  .meta({ id: 'AdminAccountVerification' });

type AccountVerification = z.infer<typeof accountVerificationSchema>;

/** The verification `users` stores, as {@link accountVerificationSchema} answers it. */
export function accountVerificationOf(user: {
  readonly id: string;
  readonly operatorVerifiedAt: number | null;
  readonly operatorVerifiedBy: string | null;
}): AccountVerification {
  const verifier =
    user.operatorVerifiedBy === null ? null : parseOperatorVerifiedBy(user.operatorVerifiedBy);
  if (user.operatorVerifiedAt === null || verifier === null) {
    throw new Error('The account holds no operator verification of a known form');
  }
  return {
    userId: user.id,
    verifiedAt: rfc3339(user.operatorVerifiedAt),
    method: verifier.method,
    verifiedBy: verifier.method === 'operator' ? verifier.accountId : verifier.osUser,
  };
}

/** The path of an account, as the admin listener routes it. */
const ACCOUNT_PATH = '/admin/v1-rc.0/realms/:realmId/users/:userId';

const accountParams = z.object({ realmId: z.uuid(), userId: z.uuid() });

const deletionHeaders = z.looseObject({
  'if-match': z.string().meta({
    description:
      "The ETag of the account, or * for its state as it is: the approval binds the account's state it was filed against either way. A retry sends *: one that names the account's ETag answers 412 once the account is gone.",
  }),
});

/**
 * The body of a deletion: none, or an empty object. An approval binds the
 * request as it is sent, so one filed without a body approves only a call
 * without one, and one filed with `{}` only a call with `{}`.
 */
const deletionBody = z
  .strictObject({})
  .nullable()
  .optional()
  .meta({ id: 'AdminAccountDeletionRequest', description: 'No body, or an empty object.' });

/**
 * What the audit row keeps of a deleted account: its id, when it was created,
 * whether it was enabled, the id and type of each credential and how many
 * sessions the deletion ended. Never an address or any other attribute of the
 * person: the account is gone, and the audit log outlives it.
 */
export function deletedAccountAudit(
  userId: string,
  account: DeletableAccount,
  endedSessions: number
): Record<string, string | number | boolean | Record<string, string | boolean>[]> {
  return {
    userId,
    createdAt: rfc3339(account.createdAt),
    enabled: account.enabled,
    credentials: account.credentials.map((credential) => ({
      id: credential.id,
      type: credential.type,
      primary: credential.primary,
    })),
    endedSessions,
  };
}

/** The account operations the routes serve. */
interface UserOperations {
  readonly verify: AdminOperation;
  readonly delete: AdminOperation;
}

/**
 * The account operations in the pipeline's registry, or `undefined` when it
 * holds none: a test registry built from fixture operations alone serves no
 * account route, and the server's own registry (`OPERATION_REGISTRY`) holds
 * them all.
 */
function userOperations(fastify: FastifyInstance): UserOperations | undefined {
  const verify = fastify.adminApi.registry.get(USER_OPERATION_IDS.verify);
  const remove = fastify.adminApi.registry.get(USER_OPERATION_IDS.delete);
  return verify === undefined || remove === undefined ? undefined : { verify, delete: remove };
}

/** Register the account routes behind the admin pipeline. */
export const userRoutes: FastifyPluginAsync = async (fastify) => {
  const typed = fastify.withTypeProvider<ZodTypeProvider>();
  const operations = userOperations(fastify);
  if (operations === undefined) return;

  typed.post(
    VERIFICATION_PATH,
    {
      config: { operation: operations.verify.id },
      schema: {
        ...operationSchemaExtensions(operations.verify),
        'x-qauth-stability': 'experimental' as const,
        // A DPoP-bound admin token (#520).
        security: [{ [ADMIN_SECURITY_SCHEME]: [] }],
        summary: 'Verify an account as the operator',
        description:
          "Records the operator's verification on the account: it counts as verified beside its primary identity, for signing in where verified accounts are required and for owning an agent, and an unclaimed account is claimed, so another person's later mailbox proof no longer ends it. email_verified is not changed. A security operation: it needs users.security and an approval, filed with approvals.create against the account as it stands. Its body is an empty object. 404 for an account the realm does not hold, 409 for a disabled account or one an operator already verified. An approval filed against the account as it stood no longer matches once a credential is added, removed or proved: the call is answered 403 approval_required, and 412 when the account changes during the call.",
        'x-qauth-errors': [400, 401, 403, 404, 409, 412, 428],
        params: verificationParams,
        headers: verificationHeaders,
        body: verificationBody,
        response: { 200: accountVerificationSchema },
      },
    },
    async (request) => {
      const caller = requestAdminCaller(request);
      const realmId = caller.targetRealm.id;
      const { userId } = request.params;
      const tx = adminTransaction(request);
      const { stateVersion } = requestClassification(request);

      // The account as the call was classified, and approved, against: read
      // again in the transaction the verification commits in.
      const state = await readAccountVerificationState(request.server, realmId, userId, tx);
      if (accountVerificationStateVersion(state) !== stateVersion) {
        throw new PreconditionFailedError({ operation: operations.verify.id });
      }
      // Through `users_record_operator_verification` (migration 0070): the
      // admin role writes these two columns of the account and no other.
      const user = await request.server.repositories.users.recordOperatorVerification(
        realmId,
        userId,
        caller.userId,
        tx
      );
      // Disabled, or verified by another call, since the read.
      if (user === undefined) {
        throw new PreconditionFailedError({ operation: operations.verify.id });
      }

      await emitUserEvent(
        request,
        'urn:qauth:event:user.verified:v1-rc.0',
        { method: 'operator' },
        { tx, realmId, userId, actor: adminEventActor(caller) }
      );
      const verification = accountVerificationOf(user);
      recordAdminChange(request, {
        change: {
          before: { userId, operatorVerifiedAt: null, operatorVerifiedBy: null },
          after: {
            userId,
            operatorVerifiedAt: verification.verifiedAt,
            operatorVerifiedBy: user.operatorVerifiedBy,
          },
        },
        annotations: {},
      });
      return verification;
    }
  );

  typed.delete(
    ACCOUNT_PATH,
    {
      config: { operation: operations.delete.id },
      schema: {
        ...operationSchemaExtensions(operations.delete),
        'x-qauth-stability': 'experimental' as const,
        // A DPoP-bound admin token (#520).
        security: [{ [ADMIN_SECURITY_SCHEME]: [] }],
        summary: 'Delete an account',
        description:
          "Deletes the account at once, with its credentials, recovery codes, consents, attributes, upstream identities, refresh tokens and codes. Every session it holds ends first, browser and logout-only alike, and each client a session signed in to with a back-channel logout URI is queued a logout token in the same transaction; its access tokens no longer introspect. A security operation: it needs users.delete and an approval, filed with approvals.create against the account as it stands. Idempotent by id: an id the realm does not hold, whether unknown, deleted already or another realm's account, is approved and answered as a deletion is, 204, and changes nothing and records no event, so a retry with If-Match: * and an approval of its own (an approval is used once) answers as the first call did. A service account's account, and an account that holds an admin grant, are refused with 409. An approval filed against the account as it stood no longer matches once a credential is added, removed or proved: the call is answered 403 approval_required, and 412 when the account changes during the call.",
        'x-qauth-errors': [400, 401, 403, 404, 409, 412, 428],
        params: accountParams,
        headers: deletionHeaders,
        body: deletionBody,
        response: {
          204: z.null().meta({
            description:
              'The account is deleted, or the realm holds no account with this id: the answer is the same.',
          }),
        },
      },
    },
    async (request, reply) => {
      const caller = requestAdminCaller(request);
      const outcome = await deleteAccountOfRealm(request, {
        realmId: caller.targetRealm.id,
        userId: request.params.userId,
        stateVersion: requestClassification(request).stateVersion,
        tx: adminTransaction(request),
        actor: adminEventActor(caller),
      });
      // An id the realm does not hold changed nothing: its audit row records
      // the call, with no change.
      if (outcome.kind === 'deleted') {
        recordAdminChange(request, {
          change: {
            before: deletedAccountAudit(
              outcome.userId,
              outcome.account,
              outcome.endedSessions.length
            ),
            after: null,
          },
          annotations: {},
        } as AdminChange);
      }
      reply.code(204);
      return undefined;
    }
  );
};

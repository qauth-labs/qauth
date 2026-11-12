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
  adminTransaction,
  recordAdminChange,
  requestAdminCaller,
} from '../pipeline';
import {
  accountVerificationStateVersion,
  readAccountVerificationState,
  USER_OPERATION_IDS,
} from './operations';

/**
 * THE ACCOUNT ROUTES OF THE ADMIN API (ADR-015 Decision 8, amended
 * 2026-11-08; issue #1052):
 *
 *   POST /admin/v1-rc.0/realms/{realmId}/users/{userId}/verification — users.verify,
 *        If-Match required, an approval required
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

/**
 * The account operations in the pipeline's registry, or `undefined` when it
 * holds none: a test registry built from fixture operations alone serves no
 * account route, and the server's own registry (`OPERATION_REGISTRY`) holds
 * them all.
 */
function userOperations(fastify: FastifyInstance): { verify: AdminOperation } | undefined {
  const verify = fastify.adminApi.registry.get(USER_OPERATION_IDS.verify);
  return verify === undefined ? undefined : { verify };
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
        { tx, realmId, userId, actor: { type: 'user', id: caller.userId } }
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
};

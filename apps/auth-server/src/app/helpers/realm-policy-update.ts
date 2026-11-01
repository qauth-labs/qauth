import {
  type PolicyIssue,
  PolicyValidationError,
  type RealmPolicySnapshot,
} from '@qauth-labs/fastify-plugin-realm-policy';
import type { FastifyInstance } from 'fastify';

/**
 * A realm policy update the policy schema or one of its rules refuses (#529),
 * such as one that selects the smtp mail transport without a password: 422,
 * `unprocessable_content`. The message lists each issue's path and what is
 * wrong, never a value, so a refused secret reaches neither the response nor
 * the log.
 */
export class RealmPolicyRefusedError extends Error {
  override readonly name = 'RealmPolicyRefusedError';
  readonly statusCode = 422;

  constructor(
    readonly issues: readonly PolicyIssue[] = [],
    options?: { cause?: unknown }
  ) {
    super(
      issues.length === 0
        ? 'The realm policies are not valid'
        : `The realm policies are not valid: ${issues
            .map((issue) => `${issue.path || '(document)'} ${issue.message}`)
            .join('; ')}`,
      options
    );
  }
}

/**
 * Update a realm's policies through the policy store (#516), answering a
 * refused update with a {@link RealmPolicyRefusedError} (422). Every other
 * error of the store passes through as it is. The admin API's realm policy
 * update (#517) calls this.
 *
 * @throws RealmPolicyRefusedError when the patch or the document it gives is
 *   refused, by its schema or a rule, such as the mail transport's
 */
export async function updateRealmPolicies(
  fastify: Pick<FastifyInstance, 'policyStore'>,
  realmId: string,
  patch: unknown,
  options: Parameters<FastifyInstance['policyStore']['update']>[2]
): Promise<RealmPolicySnapshot> {
  try {
    return await fastify.policyStore.update(realmId, patch, options);
  } catch (error) {
    if (error instanceof PolicyValidationError) {
      throw new RealmPolicyRefusedError(error.issues, { cause: error });
    }
    throw error;
  }
}

import {
  type PolicyIssue,
  PolicyValidationError,
  type RealmPolicySnapshot,
} from '@qauth-labs/fastify-plugin-realm-policy';
import type { FastifyInstance } from 'fastify';

import { UnprocessableContentError, type UnprocessableField } from './api-request-errors';

/** The message of a realm policy update the schema or a rule refuses. */
export const REALM_POLICIES_REFUSED_MESSAGE = 'The realm policies are not valid.';

/**
 * A policy issue as a field of the `unprocessable_content` problem document
 * (#506): an RFC 6901 JSON Pointer into the policy document, from the issue's
 * dotted path, and what is wrong. An issue names a path, never a value.
 */
export function unprocessablePolicyField(issue: PolicyIssue): UnprocessableField {
  const segments = issue.path === '' ? [] : issue.path.split('.');
  return {
    pointer: segments
      .map((segment) => `/${segment.replaceAll('~', '~0').replaceAll('/', '~1')}`)
      .join(''),
    message: issue.path === '' ? issue.message : `${issue.path} ${issue.message}`,
  };
}

/**
 * Update a realm's policies through the policy store (#516), answering a
 * refused update with an {@link UnprocessableContentError} (422,
 * `unprocessable_content`), whose `errors` name each refused field, as every
 * merge patch of the account and developer APIs is answered (#506). Every
 * other error of the store passes through as it is. The admin API's realm
 * policy update (#517) calls this.
 *
 * @throws UnprocessableContentError when the patch or the document it gives
 *   is refused, by its schema or a rule, such as the mail transport's
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
      throw new UnprocessableContentError(
        error.issues.map(unprocessablePolicyField),
        REALM_POLICIES_REFUSED_MESSAGE
      );
    }
    throw error;
  }
}

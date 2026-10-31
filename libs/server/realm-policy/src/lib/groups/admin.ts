import { z } from 'zod';

import { groupDocsLink } from '../docs';
import { policyField } from '../field';

const link = groupDocsLink('admin');

/**
 * An admin operation id, `<resource>.<verb>` (`realms.policies.update`), as
 * `OPERATION_ID_PATTERN` in the auth server's operation registry
 * (`helpers/admin-operations.ts`) writes it. Whether the id names a
 * registered operation is the two-admin rule's check (#521); this library
 * cannot see the registry.
 */
const OPERATION_ID_PATTERN = /^[a-z][a-zA-Z0-9]*(?:\.[a-z][a-zA-Z0-9]*)+$/;

/**
 * Administration (`admin`, #514): changes who administers, so every security
 * change of it has the effect `administration` (ADR-019 Decision 7).
 *
 * - `twoAdminMandatoryOperations`: the operations for which the realm makes
 *   a second admin's approval mandatory (#521). More entries is stricter.
 *   ADR-019 Decision 7 counts "the two-admin configuration" itself among the
 *   changes of who administers, so every change of the set, an added entry
 *   included, is a security operation. One admin alone may still add an
 *   entry; only the second-admin rule tells the two directions apart.
 * - `workloadIssuers`: the issuers whose workload OIDC tokens CI may exchange
 *   for admin API tokens (RFC 8693, #526). Fewer is stricter, and every change
 *   is a security operation, as for any trusted issuer. They name issuers of
 *   the realm's environment, so a sandbox promotion leaves them out unless
 *   they are selected.
 */
export const ADMIN_POLICY_GROUP = {
  twoAdminMandatoryOperations: policyField(
    z.array(z.string().max(128).regex(OPERATION_ID_PATTERN)).max(200),
    {
      seedEnv: null,
      default: [],
      direction: 'superset-is-stricter',
      securityWhen: 'any-change',
      effects: ['administration'],
      secret: false,
      environmentBound: false,
      doc: {
        summary:
          'The admin operations that need a second admin approval in this realm, by operation id.',
        link,
      },
    }
  ),
  workloadIssuers: policyField(
    z
      .array(
        z
          .url({ protocol: /^https$/ })
          .max(2048)
          .regex(/^https:\/\//)
      )
      .max(20),
    {
      seedEnv: null,
      default: [],
      direction: 'subset-is-stricter',
      securityWhen: 'any-change',
      effects: ['administration'],
      secret: false,
      environmentBound: true,
      doc: {
        summary:
          'The HTTPS issuers whose workload tokens a CI service account may exchange for admin API tokens.',
        link,
      },
    }
  ),
} as const;

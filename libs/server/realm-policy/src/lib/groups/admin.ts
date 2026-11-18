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

/** The JSON Schema form of {@link isIssuerUrl}, for a reader that cannot run it. */
const ISSUER_URL_PATTERN = '^https://[^\\s?#@]+$';

/**
 * A workload token's expected `aud`: printable text with no white space or
 * control character, as a CI system lets a job name it.
 */
const WORKLOAD_AUDIENCE_PATTERN = /^[^\s\u0000-\u001f\u007f-\u009f]+$/;

/**
 * The subject a workload token must name: its `sub` exactly, or a prefix of
 * it written with a final `*` (`repo:acme/infra:*`). The `*` is the only
 * wildcard, only at the end, and never alone, so a subject never matches
 * every token of an issuer that many tenants share. No control character.
 */
export const WORKLOAD_SUBJECT_PATTERN = /^[^*\u0000-\u001f\u007f-\u009f]+\*?$/;

/**
 * A service account's name, as the host's `service-accounts` command takes it
 * (`SERVICE_ACCOUNT_NAME_PATTERN` of `@qauth-labs/infra-db`, issue #522):
 * lower-case words joined by single hyphens, starting with a letter.
 */
const SERVICE_ACCOUNT_NAME_PATTERN = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/;

/** The longest service account name (`SERVICE_ACCOUNT_NAME_MAX_LENGTH` of `@qauth-labs/infra-db`). */
const SERVICE_ACCOUNT_NAME_MAX_LENGTH = 64;

/**
 * An issuer identifier: an https URL with no user info, query or fragment
 * (RFC 8414 §2). User info would also put a credential into a field the
 * representation and every diff show.
 */
function isIssuerUrl(value: string): boolean {
  // The URL parser also reads `https:host`, `https:/host` and `HTTPS://host`
  // as https URLs; the pattern, and so the JSON Schema, does not.
  if (!value.startsWith('https://') || /[\s?#@]/.test(value)) return false;
  try {
    const url = new URL(value);
    return (
      url.protocol === 'https:' && url.hostname !== '' && url.username === '' && url.password === ''
    );
  } catch {
    return false;
  }
}

/**
 * One trusted workload issuer (#526): the CI system whose tokens a service
 * account of the operator realm exchanges for an admin token (RFC 8693).
 *
 * - `issuer`: the token's `iss`, compared byte for byte. Its keys are found
 *   through its OIDC discovery document, at this URL.
 * - `audience`: the value the token's `aud` must hold, as the CI job asks
 *   for it.
 * - `subject`: the token's `sub`, exactly, or a prefix of it ending in `*`.
 * - `serviceAccount`: the name of the service account the token acts as.
 */
const workloadIssuerSchema = z.strictObject({
  issuer: z
      .url({ protocol: /^https$/ })
      .max(2048)
      .refine(isIssuerUrl, {
        message: 'is an https URL with no user info, query or fragment',
      })
      .meta({ pattern: ISSUER_URL_PATTERN }),
    audience: z.string().min(1).max(2048).regex(WORKLOAD_AUDIENCE_PATTERN, {
      message: 'is text with no white space or control character',
    }),
    subject: z.string().min(1).max(255).regex(WORKLOAD_SUBJECT_PATTERN, {
      message: 'is a subject, or a prefix of one ending in a single *, which is the only wildcard',
    }),
    serviceAccount: z
      .string()
      .min(1)
      .max(SERVICE_ACCOUNT_NAME_MAX_LENGTH)
      .regex(SERVICE_ACCOUNT_NAME_PATTERN, {
        message: 'is a service account name: lower-case words joined by single hyphens',
      }),
});

/** A trusted workload issuer, as the policy stores it. */
export type WorkloadIssuer = z.infer<typeof workloadIssuerSchema>;

/** Whether no two entries name the same issuer, audience and subject. */
function hasDistinctWorkloadIssuers(entries: readonly WorkloadIssuer[]): boolean {
  const keys = entries.map((entry) =>
    JSON.stringify([entry.issuer, entry.audience, entry.subject])
  );
  return new Set(keys).size === keys.length;
}

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
 * - `workloadIssuers`: the CI issuers whose workload OIDC tokens the token
 *   endpoint exchanges for an admin token of a service account (RFC 8693,
 *   #526), each entry with the issuer, the audience and the subject a token
 *   must carry, and the service account it acts as. Read in the operator
 *   realm, where service accounts live. Fewer is stricter, and every change
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
    z.array(workloadIssuerSchema).max(20).refine(hasDistinctWorkloadIssuers, {
      message: 'lists an issuer, audience and subject more than once',
    }),
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
          'The CI issuers whose workload tokens the operator realm exchanges for a service account admin token, with the audience, subject and service account of each.',
        link,
      },
    }
  ),
} as const;

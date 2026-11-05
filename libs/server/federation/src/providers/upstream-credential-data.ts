import { z } from 'zod';

/**
 * The `credential_data` JSONB shape of a credential an upstream identity
 * provider holds (#639): a `user_credentials` row whose `provider_type` is the
 * provider's AuthMethod type (`oidc_<alias>`, or a plugin's type) and whose
 * `external_sub` is the provider's subject. This module is its only owner:
 * nothing else may hand-roll the object.
 *
 * - `kind` is {@link UPSTREAM_CREDENTIAL_KIND}, which tells such a row apart
 *   whatever its type.
 * - `iss` is the issuer whose ID token named the subject, when the provider
 *   has one (an OpenID Connect provider always does). A later sign-in whose
 *   issuer differs is refused: a subject is the provider's only together
 *   with its issuer.
 * - `verified` is whether the account counts as verified: `true` when the
 *   provider's verified switch was on as the account was created (ADR-020
 *   §3), `false` until QAuth verified the address itself.
 *
 * Keys are snake_case, like every `credential_data` shape. Deliberately NOT
 * `.strict()`: a later change may add a sibling key, and today's binary must
 * keep reading the row then.
 */
export const upstreamCredentialDataSchema = z.object({
  kind: z.literal('upstream'),
  iss: z.string().min(1).max(2048).optional(),
  verified: z.boolean(),
});

export type UpstreamCredentialData = z.infer<typeof upstreamCredentialDataSchema>;

/** The `kind` of an upstream provider's credential data. */
export const UPSTREAM_CREDENTIAL_KIND = 'upstream';

/** Whether `credentialData` claims to be an upstream provider's, well formed or not. */
export function isUpstreamCredentialData(credentialData: unknown): boolean {
  return (
    typeof credentialData === 'object' &&
    credentialData !== null &&
    (credentialData as Record<string, unknown>)['kind'] === UPSTREAM_CREDENTIAL_KIND
  );
}

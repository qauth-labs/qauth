import { z } from 'zod';

import type { ValidatedCredential } from '../oid4vp/validated-credential';
import type { CredentialStatusChecker } from '../status/credential-status-checker';
import { ValidatedIssuer } from '../trust/issuer-identity';
import type { TrustRegistry } from '../trust/trust-registry';

/**
 * What stands behind a `source='wallet'` attribute row, and whether it still
 * does (ADR-002, #235/#236/#297; ANT-2026-ULJIA4P4).
 *
 * A presentation passes the issuer-trust and credential-status gates once. The
 * rows it leaves behind are emitted as verified claims on every later token,
 * including tokens obtained with a linked password or a refresh token, where no
 * presentation happens. `expires_at` carries one way a credential ends to those
 * emissions. It says nothing about the two that can come earlier: the operator
 * stops trusting the issuer, or the issuer revokes the credential.
 *
 * So each row records what is needed to ask both questions again:
 *
 * - **Issuer trust** is asked at every emission (`resolveEmailClaims`). It is a
 *   local check against the realm's allowlist, so it costs no outbound request.
 * - **Credential status** is asked again at the account's next wallet sign-in,
 *   for every row that presentation did not rewrite. That path already talks to
 *   the status host. The token and userinfo paths deliberately do not: a
 *   status-list fetch there would put a third party's availability on every
 *   token grant.
 *
 * The proofs that need the holder (signature, disclosures, key binding) are not
 * repeated; they do not change after the fact.
 */

/**
 * `user_attributes.provenance` JSONB shape for `source='wallet'` rows.
 *
 * This module is the single owner of the shape, as `wallet.provider.ts` is for
 * `credential_data`. Not `.strict()`, for the same forward-compatibility reason.
 *
 * `status` is the issuer-signed `status` claim VERBATIM, because that is the
 * status checker's input contract (`unknown` in, a decision out). It is absent
 * when the credential carried none.
 */
export const walletAttributeProvenanceSchema = z.object({
  issuer: z.string().min(1),
  issuer_key_resolution: z.enum(['x5c', 'issuer-metadata']),
  status: z.unknown().optional(),
});

export type WalletAttributeProvenance = z.infer<typeof walletAttributeProvenanceSchema>;

/**
 * Build the `provenance` object for the rows a validated credential asserts.
 *
 * @param credential - the validated presentation (#234), from a trusted issuer
 * (#236).
 * @returns the JSONB object, ready for `user_attributes.provenance`.
 * @throws Error when the credential carries no branded `ValidatedIssuer`. That
 * is an invariant breach (only #234 produces these), never a wire error.
 */
export function buildWalletAttributeProvenance(
  credential: ValidatedCredential
): WalletAttributeProvenance {
  const issuer: unknown = credential?.issuer;

  if (!ValidatedIssuer.isValidated(issuer)) {
    throw new Error(
      'buildWalletAttributeProvenance requires a ValidatedCredential carrying a branded ValidatedIssuer (#234). A credential-asserted `iss` must never be recorded as the issuer an attribute rests on.'
    );
  }

  // `status` cannot be introduced or overwritten by a Disclosure, so this is
  // the claim the status gate read off the verified payload.
  const status: unknown = credential.claims?.['status'];

  return {
    issuer: issuer.identifier,
    issuer_key_resolution: issuer.keyResolution,
    ...(status === undefined || status === null ? {} : { status }),
  };
}

/**
 * Read a stored `provenance` value, or `undefined` when there is none to read
 * (a row written before provenance was recorded, or a value of the wrong shape).
 */
export function readWalletAttributeProvenance(raw: unknown): WalletAttributeProvenance | undefined {
  const parsed = walletAttributeProvenanceSchema.safeParse(raw);
  return parsed.success ? parsed.data : undefined;
}

/**
 * Whether the realm still trusts the issuer a stored wallet attribute rests on.
 *
 * Fail-closed and never throws: a row with no readable provenance cannot be
 * asked about, so it is not trusted.
 *
 * @param provenance - the raw JSONB value, from the database.
 * @param registry - the issuer allowlist in force for the account's realm NOW.
 */
export function isWalletAttributeIssuerTrusted(
  provenance: unknown,
  registry: TrustRegistry
): boolean {
  const recorded = readWalletAttributeProvenance(provenance);
  if (recorded === undefined) return false;

  try {
    // Re-branding a RECORDED identity: `buildWalletAttributeProvenance` only
    // ever writes one that presentation validation established. A value that
    // no longer canonicalizes throws here and is not trusted.
    return registry.isTrusted(
      ValidatedIssuer.fromValidatedPresentation({
        identifier: recorded.issuer,
        keyResolution: recorded.issuer_key_resolution,
      })
    );
  } catch {
    return false;
  }
}

/**
 * Whether the credential behind a stored wallet attribute still reads `VALID`
 * on its status list.
 *
 * Fail-closed and never throws: a row with no readable provenance is not
 * valid, and every status outcome other than a positively read `VALID` (an
 * unreachable list included) is the checker's refusal, unchanged. A credential
 * that carried no `status`, or a deployment that configured no status checking,
 * has nothing to ask, exactly as at presentation.
 *
 * @param provenance - the raw JSONB value, from the database.
 * @param checker - the deployment's status checker, or `undefined` when none
 * is configured.
 */
export async function isWalletAttributeStatusValid(
  provenance: unknown,
  checker: CredentialStatusChecker | undefined
): Promise<boolean> {
  const recorded = readWalletAttributeProvenance(provenance);
  if (recorded === undefined) return false;
  if (recorded.status === undefined || checker === undefined) return true;

  try {
    const { decision } = await checker.resolveCredentialStatus(recorded.status, {
      statusRequired: false,
    });
    return decision === 'valid';
  } catch {
    return false;
  }
}

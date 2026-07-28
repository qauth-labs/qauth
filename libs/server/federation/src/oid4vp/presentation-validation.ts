/**
 * Presentation validation DISPATCH (issue #234).
 *
 * The entry point a `direct_post` route calls once the transport layer (#233)
 * has correlated the response and structurally parsed the `vp_token`. It does
 * three things and delegates everything else:
 *
 *  1. pairs each Presentation with the DCQL Credential Query it answers,
 *     **by Credential Query id and nothing else**;
 *  2. resolves that entry's format adapter, fail-closed against the active
 *     profile;
 *  3. hands the entry to the adapter and collects {@link ValidatedCredential}s.
 *
 * ## Selection is by DCQL Credential Query id, full stop
 *
 * OID4VP 1.0 §8.1: the `vp_token` is a JSON object whose keys ARE the Credential
 * Query ids. There is no submission descriptor, no descriptor map, no
 * `presentation_definition` and no separate matching step — the wallet already
 * told us which query each Presentation answers, by putting it under that key.
 * DIF Presentation Exchange belonged to OID4VP Draft 22 and is superseded
 * (ADR-004's spec refresh). Nothing in this module may grow a second selection
 * path: two ways to decide which query a Presentation satisfies is one way too
 * many, and the weaker one becomes the attack.
 *
 * ## This module names no Credential Format
 *
 * Deliberately, and it is checked by a test. Every format-specific decision
 * lives behind {@link CredentialFormatAdapter}; adding `mso_mdoc` is a
 * registration in `credential-format.ts` and touches nothing here.
 *
 * ## It still authenticates nobody
 *
 * A {@link ValidatedCredential} is a cryptographic finding. Issuer trust (#236)
 * and subject resolution (#300) both run AFTER this and both can refuse. See
 * `validated-credential.ts`.
 */

import type { CredentialFormatAdapterRegistry, PresentedCredential } from './credential-format';
import { resolveCredentialFormatAdapter } from './credential-format';
import type { DcqlCredentialQuery, DcqlQuery } from './dcql';
import { rejectPresentation } from './presentation-rejection';
import type { PresentationValidationContext, ValidatedCredential } from './validated-credential';

/**
 * Validate every Presentation in a structurally-parsed `vp_token`.
 *
 * All-or-nothing: the first refusal aborts the batch. A partial result would
 * leave a caller holding "some of what was asked for" with no way to tell
 * whether the missing part was withheld or rejected — and the caller most likely
 * to get that wrong is the one deciding whether to authenticate.
 *
 * @param presentations - the output of {@link import('./direct-post').parseVpToken}.
 * @param query - the DCQL query from the redeemed request state.
 * @param context - bindings and policy — see {@link PresentationValidationContext}.
 * @param adapters - the adapter table; defaults to everything QAuth ships. See
 * {@link resolveCredentialFormatAdapter}.
 * @returns one {@link ValidatedCredential} per Presentation, in input order.
 * @throws PresentationValidationRejection on the first refusal — carrying a
 * distinct server-side reason, and the single non-enumerating client error.
 * @throws InvalidCredentialsError from the credential-status gate (#297), when
 * `context.credentialStatus` is set and refuses. It carries no reason and no
 * detail by design; see {@link import('./credential-format').CredentialFormatAdapter.validatePresentation}.
 */
export async function validatePresentations(
  presentations: readonly PresentedCredential[],
  query: DcqlQuery,
  context: PresentationValidationContext,
  adapters?: CredentialFormatAdapterRegistry
): Promise<readonly ValidatedCredential[]> {
  const queriesById = new Map<string, DcqlCredentialQuery>(
    query.credentials.map((credential) => [credential.id, credential])
  );

  const validated: ValidatedCredential[] = [];

  for (const presented of presentations) {
    const credentialQuery = queriesById.get(presented.queryId);

    if (credentialQuery === undefined) {
      throw rejectPresentation(
        'malformed-presentation',
        `Presentation answers Credential Query '${presented.queryId}', which this request never asked for`
      );
    }

    if (credentialQuery.format !== presented.format) {
      throw rejectPresentation(
        'unsupported-credential-format',
        `Presentation for '${presented.queryId}' arrived in a format the Credential Query did not ask for`
      );
    }

    let adapter;

    try {
      adapter = resolveCredentialFormatAdapter(
        presented.format,
        context.permittedFormats,
        adapters
      );
    } catch (error) {
      // Unshipped format, or one the active profile forbids. Both are the same
      // outcome to the caller and neither reveals which.
      throw rejectPresentation(
        'unsupported-credential-format',
        `no usable format adapter for Credential Query '${presented.queryId}'`,
        error
      );
    }

    validated.push(await adapter.validatePresentation(presented, credentialQuery, context));
  }

  return validated;
}

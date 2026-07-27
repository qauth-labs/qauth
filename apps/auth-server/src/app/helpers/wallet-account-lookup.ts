import {
  readWalletBinding,
  type SubjectAccountCandidate,
  type SubjectAccountLookup,
  WALLET_PROVIDER_TYPE,
} from '@qauth-labs/fastify-plugin-federation';
import type { FastifyInstance } from 'fastify';

/**
 * The account store behind `SubjectAccountLookup` (issue #238, ADR-009 / #300).
 *
 * #300 shipped the subject-resolution strategies as pure functions over a PORT,
 * for a layering reason it states explicitly: `server-federation` is
 * `scope:server` and may not import `infra-db`. This module is the adapter that
 * port was waiting for — `user_credentials` projected onto
 * {@link SubjectAccountCandidate}.
 *
 * ## Two lookups, two keys, and never the same query
 *
 * - `byAssertedIdentifier` is keyed on **unauthenticated user input** (an email
 *   the user typed, or the identifier the linking flow read off their account).
 *   It returns every credential in the realm carrying that `external_sub`,
 *   ACROSS provider types. Restricting it to wallet rows would hide ADR-009's
 *   second bootstrap case — an existing password account with no wallet binding
 *   — and a hidden refusal becomes a `no-match` that a caller may enrol over.
 * - `byWalletSubject` is keyed on a value derived from a **validated issuer's
 *   signed claim**, and looks only at `provider_type='wallet'` rows, because
 *   that key exists in no other provider's column.
 *
 * ## What a candidate carries, and what it deliberately does not
 *
 * `{ userId, walletBinding }` and nothing else. No email, no claims, no
 * credential id: the strategies decide identity from the binding and the key
 * alone, and handing them more would invite a future strategy to key on
 * something ADR-009 forbids. `walletBinding` is `null` for every row that does
 * not carry a parseable one (every password row, and any wallet row written by a
 * scheme this binary cannot read) — the documented "this account has no wallet
 * binding" value, which `asserted-lookup` treats as a REFUSAL.
 *
 * ## Errors are not caught here
 *
 * A database failure propagates. `runAccountLookup` in `server-federation`
 * contains it, reports it through `onLookupError`, and turns it into the same
 * uniform refusal as "no account" — so containing it a second time here would
 * only make the failure harder to see, and swallowing it into an empty array
 * would turn a broken database into "no such account", which a caller is allowed
 * to enrol over.
 */

/**
 * Build the {@link SubjectAccountLookup} over `user_credentials`.
 *
 * @param fastify - server instance, for its repositories.
 * @returns a realm-scoped, read-only account lookup.
 */
export function createWalletAccountLookup(fastify: FastifyInstance): SubjectAccountLookup {
  return {
    async byAssertedIdentifier(
      realmId: string,
      identifier: string
    ): Promise<readonly SubjectAccountCandidate[]> {
      const rows = await fastify.repositories.userCredentials.findAllByRealmAndExternalSub(
        realmId,
        identifier
      );

      return rows.map((row) => ({
        userId: row.userId,
        // A password row contributes a candidate with NO binding, which is what
        // makes ADR-009's second bootstrap case visible to the strategy.
        walletBinding:
          row.providerType === WALLET_PROVIDER_TYPE ? readWalletBinding(row.credentialData) : null,
      }));
    },

    async byWalletSubject(
      realmId: string,
      externalSub: string
    ): Promise<readonly SubjectAccountCandidate[]> {
      const row = await fastify.repositories.userCredentials.findByRealmProviderSub(
        realmId,
        WALLET_PROVIDER_TYPE,
        externalSub
      );

      if (row === undefined) return [];

      return [{ userId: row.userId, walletBinding: readWalletBinding(row.credentialData) }];
    },
  };
}

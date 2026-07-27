import type { FastifyInstance } from 'fastify';

/**
 * The wallet-login AUTHENTICATION SEAM (issue #239).
 *
 * This module is the single point where "a wallet answered our presentation
 * request" would become "this browser is signed in as this user". It is the
 * boundary the UI consumes, and today it REFUSES every time.
 *
 * ## Why it refuses
 *
 * Turning a presentation into a session needs three things that do not exist
 * yet, and no combination of the ones that do exist is a substitute:
 *
 * - **#234 — presentation validation.** The `direct_post` endpoint parses a
 *   `vp_token` STRUCTURALLY and stops. Nothing checks the Issuer-signed JWT's
 *   signature, the Disclosure digests, or the Key Binding JWT's `nonce`/`aud`.
 *   Everything reaching this module is therefore still attacker-supplied bytes.
 * - **#236 — issuer trust.** A validated credential from an untrusted issuer is
 *   not a credential. The trust registry exists (`assert-trusted-issuers`) but
 *   there is nothing validated for it to be applied to.
 * - **#300 — subject resolution.** ADR-009 §1: the user asserts an identifier
 *   and the presentation proves ENTITLEMENT to it. The strategy MUST verify that
 *   the presented credential matches the binding stored for the asserted
 *   account; without that check, anyone holding any valid credential can sign in
 *   as anyone. ADR-009 states this as the likeliest way the feature gets built
 *   wrong.
 *
 * Refusing is therefore the only correct behaviour, and it must stay correct by
 * construction rather than by discipline: `WalletProvider.verify()` still throws
 * for exactly the same reason (ADR-003 mints a QAuth token for whatever
 * `externalSub` a provider returns, so a transport round-trip that yielded a
 * subject would let anyone who can POST to `/oid4vp/response` self-register).
 * Nothing here may work around that throw.
 *
 * ## What lands here when the dependencies do
 *
 * The signature is the contract: given the asserted identifier and the redeemed
 * request, return an authenticated user or a single, non-enumerating refusal.
 * The implementation replaced below is the ONLY thing that changes — the route
 * already handles both outcomes, including session minting, auditing and the
 * uniform error copy.
 *
 * TODO(#234, #236, #300): implement resolution — validate the presentation,
 * apply the realm's issuer allowlist, then run the realm's
 * `SubjectResolutionStrategy` (`asserted-lookup` by default) against
 * {@link WalletPresentationInput.assertedIdentifier}. Until all three land this
 * function must keep returning `rejected`.
 */

/** What the UI knows when a presentation has arrived. */
export interface WalletPresentationInput {
  /** Realm the presentation request was created in. */
  readonly realmId: string;
  /** SHA-256 of the request `state`, hex — identifies the redeemed request. */
  readonly stateHash: string;
  /**
   * The normalized identifier the user asserted (ADR-009 §1). An INPUT to
   * resolution, never its result: it is unauthenticated user input until a
   * validated presentation is shown to entitle its holder to that account.
   */
  readonly assertedIdentifier: string;
}

/**
 * The outcome of turning a presentation into an account.
 *
 * There is ONE failure shape, deliberately. #236's rule is that an untrusted
 * issuer must be indistinguishable from a malformed presentation, and #234 is
 * required to reuse that same refusal; a resolution layer that distinguished
 * "no such account" from "credential rejected" would reintroduce exactly the
 * enumeration oracle both of them close — and it would do so on the UI, where
 * the difference is directly observable by an anonymous caller.
 */
export type WalletPresentationResolution =
  | {
      readonly status: 'authenticated';
      /** `users.id` the presentation resolved to. */
      readonly userId: string;
      /** Value stored as `user_credentials.external_sub` for this credential. */
      readonly externalSub: string;
    }
  | { readonly status: 'rejected' };

/**
 * Resolve a presented credential to an account, or refuse.
 *
 * @param fastify - server instance, for logging and (later) repositories.
 * @param input - the asserted identifier and the redeemed request it belongs to.
 * @returns `rejected`, always, until #234/#236/#300 land. See the module JSDoc.
 */
export async function resolveWalletPresentation(
  fastify: FastifyInstance,
  input: WalletPresentationInput
): Promise<WalletPresentationResolution> {
  fastify.log.warn(
    { realmId: input.realmId, stateHash: input.stateHash },
    'wallet presentation received but cannot be resolved: presentation validation (#234), issuer trust (#236) and subject resolution (#300) are not implemented — refusing'
  );
  return { status: 'rejected' };
}

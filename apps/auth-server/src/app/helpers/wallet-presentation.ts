import {
  assertIssuerTrusted,
  createSubjectResolutionStrategy,
  resolveSubjectResolution,
  resolveTrustRegistry,
  resolveVerifierProfile,
  type ValidatedCredential,
} from '@qauth-labs/fastify-plugin-federation';
import type { FastifyInstance } from 'fastify';

import { env } from '../../config/env';
import { resolveWalletAccount } from './wallet-account';

/**
 * The wallet-login AUTHENTICATION SEAM (issue #239, implemented in #235).
 *
 * This module is the single point where "a wallet answered our presentation
 * request" becomes "this browser is signed in as this user". It is the boundary
 * the UI consumes, and it refuses unless every gate below has been passed.
 *
 * ## The gates, in order, and why the order is the security property
 *
 *  1. **#234 — presentation validation.** A `ValidatedCredential` means the
 *     issuer's signature verified, every Disclosure digest matched, the validity
 *     window includes now, and the holder proved possession of the bound key
 *     against THIS request's `nonce` and QAuth's `client_id`. Nothing weaker may
 *     be passed as {@link WalletPresentationInput.credential}.
 *  2. **#236 — issuer trust.** Applied HERE, per realm. A validly signed
 *     credential from an issuer this realm does not trust is a forgery with
 *     extra steps, and a deployment that configured no allowlist trusts nobody.
 *  3. **#299 — verifier posture.** The credential's format must be one the
 *     active profile permits. Re-checked because this runs at a different time
 *     from the request that produced it, against a posture that may have
 *     changed.
 *  4. **#300 / ADR-009 — subject resolution.** The user asserts an identifier
 *     and the presentation proves ENTITLEMENT to it. The strategy verifies the
 *     presented credential against the binding stored for the asserted account;
 *     without that check anyone holding any valid credential signs in as anyone.
 *     ADR-009 states this as the likeliest way the feature gets built wrong.
 *  5. **#235 — enrolment and claims.** `helpers/wallet-account.ts` turns the
 *     resolution into an account, honouring ADR-009's bootstrap rule: a first
 *     presentation for an unknown identifier establishes the account and its
 *     binding together; a presentation matching a PRE-EXISTING account with no
 *     wallet binding is refused, because that path is linking (#238) and needs
 *     an authenticated session.
 *
 * Reordering these is not a refactor. Trust before resolution, and resolution
 * before any write, are what keep an untrusted credential from being matched
 * against real accounts and an unproven one from creating one.
 *
 * ## Why the credential is an INPUT and is optional today
 *
 * `POST /oid4vp/response` still stops at the structural parse: it holds
 * `PresentedCredential` entries and no way to turn them into validated ones,
 * because validation needs the issuer's verification key and QAuth has no
 * configuration that supplies one (`createStaticIssuerKeyResolver` exists;
 * nothing populates it, and `OID4VP_TRUSTED_ISSUERS` names issuers, not keys).
 * So the route passes no credential and this function refuses — the same
 * outcome as before #235, reached for one remaining reason instead of four.
 *
 * The seam is nevertheless IMPLEMENTED rather than stubbed: given a validated
 * credential it performs every gate above and writes the rows, and its tests
 * drive it with credentials issued, presented and validated for real. When
 * issuer key material becomes configurable, the route change is to validate and
 * pass `credential` — not to write this function.
 *
 * ## One failure shape, deliberately
 *
 * #236's rule is that an untrusted issuer must be indistinguishable from a
 * malformed presentation, and #234 reuses that refusal. A resolution layer that
 * distinguished "no such account" from "credential rejected" would reintroduce
 * exactly the enumeration oracle both of them close — and would do so on the UI,
 * where the difference is directly observable by an anonymous caller. Every
 * refusal below returns the identical value and logs its reason server-side.
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
  /**
   * The presentation, VALIDATED (#234). Absent while the response route cannot
   * produce one — see the module JSDoc — in which case this function refuses.
   *
   * Never a structurally-parsed `PresentedCredential`: only the validator may
   * mint this type, and its `issuer` carries a brand app code cannot forge.
   */
  readonly credential?: ValidatedCredential;
}

/**
 * The outcome of turning a presentation into an account.
 *
 * There is ONE failure shape — see the module JSDoc.
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
 * @param fastify - server instance, for logging and repositories.
 * @param input - the asserted identifier, the redeemed request it belongs to,
 * and the validated presentation when one exists.
 * @returns the authenticated account, or the single uniform refusal.
 */
export async function resolveWalletPresentation(
  fastify: FastifyInstance,
  input: WalletPresentationInput
): Promise<WalletPresentationResolution> {
  const credential = input.credential;

  if (credential === undefined) {
    fastify.log.warn(
      { realmId: input.realmId, stateHash: input.stateHash },
      'wallet presentation received without a validated credential: the direct_post route cannot validate one until issuer key material is configurable — refusing'
    );
    return { status: 'rejected' };
  }

  try {
    // (1) Posture. `undefined` means no profile is selected, which refuses
    // wallet flows outright rather than falling back to a permissive one (#296).
    const profile = resolveVerifierProfile(null, {
      OID4VP_VERIFIER_PROFILE: env.OID4VP_VERIFIER_PROFILE,
    });

    if (profile === undefined) {
      fastify.log.warn({ realmId: input.realmId }, 'no VerifierProfile selected — refusing');
      return { status: 'rejected' };
    }

    if (!profile.credentialFormats.includes(credential.format)) {
      fastify.log.warn(
        { realmId: input.realmId, format: credential.format, profile: profile.id },
        'validated credential is in a format the active verifier profile forbids — refusing'
      );
      return { status: 'rejected' };
    }

    // (2) Issuer trust (#236), per realm. `resolveTrustRegistry` never returns
    // undefined: an unknown realm, a missing allowlist and a corrupt one are all
    // the same posture — trust nobody — so there is no unconfigured case to
    // forget. The realm row is read for its NAME, which is the key
    // `OID4VP_TRUSTED_ISSUERS` is authored against.
    const realm = await fastify.repositories.realms.findById(input.realmId);

    assertIssuerTrusted(
      resolveTrustRegistry(
        { name: realm?.name ?? null },
        { OID4VP_TRUSTED_ISSUERS: env.OID4VP_TRUSTED_ISSUERS }
      ),
      credential.issuer,
      {
        onBackendError: (error: unknown) => {
          fastify.log.error({ err: error, realmId: input.realmId }, 'trust registry threw');
        },
      }
    );

    // (3) Which account (#300, ADR-009). The configuration is resolved per
    // request for the same reason the profile is: a deployment that ends up
    // half-configured must refuse the flow rather than run a strategy nobody
    // chose. `resolveSubjectResolution` THROWS for a half-configured selection
    // and returns undefined for an unconfigured one; both land in a refusal
    // here, and the operator distinguishes them from the log.
    const config = resolveSubjectResolution(null, env, profile);

    if (config === undefined) {
      fastify.log.warn(
        { realmId: input.realmId },
        'no subject-resolution strategy is configured for this deployment — refusing'
      );
      return { status: 'rejected' };
    }

    const strategy = createSubjectResolutionStrategy(config);

    // (4) Resolve, and enrol on a first presentation (#235).
    const resolution = await resolveWalletAccount(fastify, {
      realmId: input.realmId,
      credential,
      assertedIdentifier: input.assertedIdentifier,
      strategy,
      config,
    });

    if (resolution.status !== 'authenticated') return { status: 'rejected' };

    fastify.log.info(
      {
        realmId: input.realmId,
        userId: resolution.userId,
        enrolled: resolution.enrolled,
        strategy: strategy.id,
      },
      'wallet presentation resolved to an account'
    );

    return {
      status: 'authenticated',
      userId: resolution.userId,
      externalSub: resolution.externalSub,
    };
  } catch (error) {
    // Every refusal renders identically on the wire, including the ones that
    // arrive as exceptions: `assertIssuerTrusted` throws the non-enumerating
    // `InvalidCredentialsError`, and a half-configured strategy throws an
    // `InvalidConfigurationError`. Neither may become a distinguishable
    // response, so the reason stays in the log.
    fastify.log.warn(
      { err: error, realmId: input.realmId, stateHash: input.stateHash },
      'wallet presentation rejected'
    );
    return { status: 'rejected' };
  }
}

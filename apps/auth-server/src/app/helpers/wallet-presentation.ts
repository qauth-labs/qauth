import {
  type AssuranceLevel,
  createSubjectResolutionStrategy,
  type DcqlQuery,
  parseStoredDcqlQuery,
  PASSWORD_PROVIDER_TYPE,
  prepareWalletLink,
  resolveAssurancePolicy,
  resolveCredentialAssurance,
  type SubjectResolutionStrategyId,
  type ValidatedCredential,
  verifyWalletPresentations,
  WALLET_PROVIDER_TYPE,
} from '@qauth-labs/fastify-plugin-federation';
import { UniqueConstraintError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';

import { env } from '../../config/env';
import { resolveWalletAccount } from './wallet-account';
import { createWalletAccountLookup } from './wallet-account-lookup';
import { readWalletPresentationStash } from './wallet-login-flow';
import { resolveRealmTrustRegistry, resolveWalletVerificationSetup } from './wallet-verification';

/**
 * The wallet AUTHENTICATION and ACCOUNT-LINKING seam (issues #239, #235, #238).
 *
 * The single point where "a wallet answered our presentation request" becomes
 * either "this browser is signed in as this user" or "this account now holds a
 * wallet credential". Both live here because they share every gate except the
 * last one, and splitting them across two modules is how one of them ends up
 * running four checks instead of five.
 *
 * ## The order is the security property
 *
 * 1. **Validate the presentation (#234).** Issuer signature, every Disclosure
 *    digest, the validity window, and the Key Binding JWT bound to THIS
 *    request's `nonce` and THIS Verifier's `client_id`.
 * 2. **Trust the issuer (#236).** A validated credential from an untrusted
 *    issuer is a forgery with extra steps.
 * 3. **Read the assurance level (#237).** Strictly AFTER the trust gate: an
 *    untrusted issuer and an unassured trusted issuer both resolve to `'low'`,
 *    so reading a level first would report "authenticated at low assurance"
 *    where the answer is "not authenticated". `'low'` is reported as ABSENT,
 *    which is what makes a wallet login carry no `acr` unless one was earned.
 * 4. **Resolve the subject (#300, ADR-009).** For a LOGIN, the configured
 *    `SubjectResolutionStrategy` — `asserted-lookup` by default, which checks
 *    that the presented credential matches the binding stored for the asserted
 *    account. For a LINK, `session-binding`: the account comes from the session,
 *    and the presentation is never allowed to name one.
 * 5. **Enrol and normalize claims (#235).** `helpers/wallet-account.ts` turns
 *    the resolution into an account and writes the credential's claims as
 *    `user_attributes` rows.
 *
 * Steps 1 and 2 are composed in `verifyWalletPresentations`
 * (`@qauth-labs/fastify-plugin-federation`) precisely so a caller cannot wire up
 * only the first. Step 4 is the one ADR-009 §1 says is *"the likeliest way this
 * gets built wrong"*: validity is necessary and not sufficient, because a valid
 * credential proves its holder has *a* credential, not that they own *this
 * account*.
 *
 * ## Enrolment happens on `no-match`, and ONLY there
 *
 * ADR-009 §1 keeps two bootstrap cases apart and this module must not conflate
 * them. No account for the asserted identifier is `no-match` and enrols — the
 * presentation establishes the account and its binding together. An account that
 * EXISTS for the identifier without a matching wallet binding (typically a
 * password account on the same email) is `rejected` and must never become an
 * enrolment: that path is account linking, and it requires a session.
 *
 * ## Where the inputs come from, and why that matters
 *
 * The presented bytes come from the wallet, through an unauthenticated
 * `direct_post` (`routes/oid4vp/response.ts`) that parks them and decides
 * nothing. Everything they are CHECKED AGAINST — the `nonce`, the `client_id`,
 * the DCQL query, the realm, the asserted identifier, the session — comes from
 * the browser-side flow record or from a verified session cookie. A wallet can
 * therefore choose what it presents and nothing about what makes a presentation
 * acceptable.
 *
 * ## One refusal, always
 *
 * `rejected` covers an unvalidatable presentation, an untrusted issuer, an
 * unknown account, a mismatched binding, an ambiguous lookup and a degraded
 * account store alike. #236's rule is that an untrusted issuer must not be
 * distinguishable from a malformed presentation, and on a login screen the
 * difference between "no such account" and "credential rejected" is an account
 * oracle available to anyone. The specific reason is logged; the browser gets
 * one sentence.
 *
 * Linking adds ONE distinguishable outcome, `conflict`, and only where ADR-009
 * permits it — see {@link linkWalletPresentation}.
 */

/** What both flows know about the presentation request that was answered. */
interface WalletPresentationRequestView {
  /** Realm the presentation request was created in. */
  readonly realmId: string;
  /** SHA-256 of the request `state`, hex — addresses the parked presentation. */
  readonly stateHash: string;
  /** The request `nonce`, from the browser-side flow record. */
  readonly nonce: string;
  /** The request `client_id`, from the browser-side flow record. */
  readonly clientId: string;
  /** The DCQL query that was sent, as stored. */
  readonly dcqlQuery: Record<string, unknown>;
}

/** What the UI knows when a presentation has arrived for a LOGIN. */
export interface WalletPresentationInput extends WalletPresentationRequestView {
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
 * There is ONE failure shape, deliberately. See the module JSDoc.
 */
export type WalletPresentationResolution =
  | {
      readonly status: 'authenticated';
      /** `users.id` the presentation resolved to. */
      readonly userId: string;
      /** Value stored as `user_credentials.external_sub` for this credential. */
      readonly externalSub: string;
      /**
       * eIDAS Level of Assurance this presentation established (#237,
       * ADR-004/ADR-010) — the value that becomes the ID token's `acr` claim.
       *
       * Derived from the CREDENTIAL and its ISSUER, never from anything the
       * wallet signed: OID4VP 1.0 §5 fixes the response type to `vp_token`, so
       * there is no wallet-signed assertion for a level to travel in.
       *
       * Optional, and ABSENT means `'low'` — no `acr` claim. Absence is the
       * correct default for every path that has not positively established a
       * level, including every password login.
       */
      readonly assuranceLevel?: AssuranceLevel;
    }
  | { readonly status: 'rejected' };

/** What the linking flow knows when a presentation has arrived. */
export interface WalletLinkInput extends WalletPresentationRequestView {
  /**
   * `users.id` the browser is ALREADY authenticated as, read from a VERIFIED
   * session at completion time — not from the flow record alone, and never from
   * a request parameter. This value is the entire authority for the link.
   */
  readonly authenticatedUserId: string;
}

/** The outcome of attaching a wallet credential to the session's account. */
export type WalletLinkResolution =
  | {
      readonly status: 'linked';
      /** `user_credentials.id` of the row written. */
      readonly credentialId: string;
      /** The value written to `external_sub`. */
      readonly externalSub: string;
      /** Which of ADR-009's account-keying models produced it. */
      readonly subjectSource: SubjectResolutionStrategyId;
      /** Whether an existing wallet row was re-bound rather than a new one added. */
      readonly rebound: boolean;
    }
  /**
   * That wallet, or that `external_sub`, already belongs to a DIFFERENT account.
   *
   * Safe to explain, unlike every refusal on the login path: the caller is an
   * authenticated user acting on their own account, so it enumerates nothing
   * they could not already establish.
   */
  | { readonly status: 'conflict' }
  /** Everything else. One shape. */
  | { readonly status: 'rejected' };

/**
 * Validate the parked presentation and confirm its issuer is trusted.
 *
 * @returns the single validated, issuer-trusted credential, or `null` for every
 * refusal — including a deployment that cannot serve wallet flows at all.
 */
async function verifyPresentedCredential(
  fastify: FastifyInstance,
  request: WalletPresentationRequestView
): Promise<ValidatedCredential | null> {
  let setup;
  try {
    setup = resolveWalletVerificationSetup(fastify);
  } catch (error) {
    // Half-configured (a strategy selected with no binding claims, say). An
    // OPERATOR error, logged loudly — but surfaced as a refusal rather than a
    // 500, because on this path a distinct status is a signal an anonymous
    // caller can drive.
    fastify.log.error({ err: error }, 'wallet verification is misconfigured; refusing');
    return null;
  }
  if (setup === undefined) {
    fastify.log.warn('wallet presentation arrived but this deployment serves no wallet flows');
    return null;
  }

  const presentations = await readWalletPresentationStash(fastify, request.stateHash);
  if (presentations === null || presentations.length === 0) {
    fastify.log.warn({ stateHash: request.stateHash }, 'no presented credential is parked');
    return null;
  }

  let dcqlQuery: DcqlQuery;
  try {
    dcqlQuery = parseStoredDcqlQuery(request.dcqlQuery);
  } catch (error) {
    fastify.log.error({ err: error }, 'wallet flow carries an unusable DCQL query');
    return null;
  }

  let validated: readonly ValidatedCredential[];
  try {
    validated = await verifyWalletPresentations(presentations, {
      profile: setup.profile,
      clientId: request.clientId,
      nonce: request.nonce,
      dcqlQuery,
      resolveIssuerKey: setup.resolveIssuerKey,
      trustRegistry: await resolveRealmTrustRegistry(fastify, request.realmId),
      onRefusal: (refusal) => {
        fastify.log.warn(
          { gate: refusal.gate, detail: refusal.detail, realmId: request.realmId },
          'wallet presentation refused'
        );
      },
    });
  } catch {
    // `verifyWalletPresentations` throws the single non-enumerating refusal and
    // has already reported the reason through `onRefusal`.
    return null;
  }

  // Exactly one, deliberately. QAuth's flows request exactly one Credential
  // Query, so more than one credential means the response does not correspond to
  // the request that was sent — and picking one of several would make WHICH
  // credential authenticates depend on wallet-chosen ordering.
  if (validated.length !== 1 || validated[0] === undefined) {
    fastify.log.warn(
      { count: validated.length },
      'wallet response carried an unexpected number of credentials'
    );
    return null;
  }

  return validated[0];
}

/**
 * Read the eIDAS Level of Assurance a validated, issuer-TRUSTED credential
 * establishes (#237).
 *
 * Never throws and never gates: a deployment with no assurance policy simply
 * emits no `acr`. `'low'` is returned as `undefined` so the single
 * representation of "no assurance" is absence, all the way down to the NULL in
 * `authorization_codes.assurance_level`.
 */
async function resolveAssurance(
  fastify: FastifyInstance,
  realmId: string,
  credential: ValidatedCredential
): Promise<AssuranceLevel | undefined> {
  const realm = await fastify.repositories.realms.findById(realmId);

  const level = resolveCredentialAssurance(
    resolveAssurancePolicy(
      { name: realm?.name ?? null },
      { OID4VP_ISSUER_ASSURANCE: env.OID4VP_ISSUER_ASSURANCE }
    ),
    credential,
    undefined,
    {
      onPolicyError: (error: unknown) => {
        fastify.log.error({ err: error, realmId }, 'assurance policy threw');
      },
    }
  );

  return level === 'low' ? undefined : level;
}

/**
 * Resolve a presented credential to an account, or refuse (LOGIN).
 *
 * @param fastify - server instance, for repositories and logging.
 * @param input - the asserted identifier and the request it answers.
 * @returns the authenticated account, or the single uniform refusal.
 */
export async function resolveWalletPresentation(
  fastify: FastifyInstance,
  input: WalletPresentationInput
): Promise<WalletPresentationResolution> {
  const credential = await verifyPresentedCredential(fastify, input);
  if (credential === null) return { status: 'rejected' };

  const setup = resolveWalletVerificationSetup(fastify);
  if (setup === undefined) return { status: 'rejected' };

  try {
    // Assurance (#237) — after trust, before anything is written. See the module
    // JSDoc for why that order is not interchangeable.
    const assuranceLevel = await resolveAssurance(fastify, input.realmId, credential);

    const strategy = createSubjectResolutionStrategy(setup.subjectResolution);

    // Resolve, and enrol on a first presentation (#235). `resolveWalletAccount`
    // owns the ADR-009 bootstrap distinction: it enrols on `no-match` and on
    // nothing else.
    const resolution = await resolveWalletAccount(fastify, {
      realmId: input.realmId,
      credential,
      assertedIdentifier: input.assertedIdentifier,
      strategy,
      config: setup.subjectResolution,
    });

    if (resolution.status !== 'authenticated') return { status: 'rejected' };

    fastify.log.info(
      {
        realmId: input.realmId,
        userId: resolution.userId,
        enrolled: resolution.enrolled,
        strategy: strategy.id,
        assuranceLevel,
      },
      'wallet presentation resolved to an account'
    );

    return {
      status: 'authenticated',
      userId: resolution.userId,
      externalSub: resolution.externalSub,
      ...(assuranceLevel === undefined ? {} : { assuranceLevel }),
    };
  } catch (error) {
    // Every refusal renders identically on the wire, including the ones that
    // arrive as exceptions. Neither an `InvalidCredentialsError` nor an
    // `InvalidConfigurationError` may become a distinguishable response, so the
    // reason stays in the log.
    fastify.log.warn(
      { err: error, realmId: input.realmId, stateHash: input.stateHash },
      'wallet presentation rejected'
    );
    return { status: 'rejected' };
  }
}

/**
 * Attach a presented credential to the account the browser is already
 * authenticated as (LINK, #238).
 *
 * ADR-004's account-linking model in one function: one `users.id`, a second
 * `user_credentials` row. The wallet row's `external_sub` is the identifier the
 * account ALREADY owns (ADR-009 §1 — *"the same column `PasswordProvider`
 * fills"*), which is what makes a later wallet login resolve back to this exact
 * account rather than to a duplicate.
 *
 * ## Re-linking is an update, not a second row
 *
 * Under `asserted-lookup` every wallet credential on an account keys on the same
 * identifier, and `uniqueIndex(realm_id, provider_type, external_sub)` allows
 * one such row. So a user linking a RE-ISSUED credential re-binds the row they
 * already own. That is safe here in a way it never is on the login path: the
 * caller has proven they are the account holder with a session, which is exactly
 * the proof ADR-009 §5 says linking requires. Refusing instead would lock a user
 * out of wallet login the first time their credential is re-issued.
 *
 * A row owned by a DIFFERENT account is a `conflict` and is never overwritten.
 *
 * @param fastify - server instance, for repositories and logging.
 * @param input - the session's account and the request that was answered.
 */
export async function linkWalletPresentation(
  fastify: FastifyInstance,
  input: WalletLinkInput
): Promise<WalletLinkResolution> {
  const credential = await verifyPresentedCredential(fastify, input);
  if (credential === null) return { status: 'rejected' };

  const setup = resolveWalletVerificationSetup(fastify);
  if (setup === undefined) return { status: 'rejected' };

  // The identifier the account already owns, read from the account rather than
  // from anything the user typed in this flow. Two rows that disagree about the
  // identifier are two accounts as far as every later lookup is concerned.
  const anchor = await fastify.repositories.userCredentials.findByUserIdAndType(
    input.authenticatedUserId,
    PASSWORD_PROVIDER_TYPE
  );
  if (anchor === undefined) {
    fastify.log.warn(
      { userId: input.authenticatedUserId },
      'cannot link a wallet credential: the account carries no identifier-bearing credential'
    );
    return { status: 'rejected' };
  }

  const plan = await prepareWalletLink(credential, setup.subjectResolution, {
    realmId: input.realmId,
    authenticatedUserId: input.authenticatedUserId,
    accountIdentifier: anchor.externalSub,
    lookup: createWalletAccountLookup(fastify),
    onLookupError: (error: unknown) => {
      fastify.log.error({ err: error }, 'wallet account lookup failed; refusing the link');
    },
  });

  if (plan.kind === 'conflict') return { status: 'conflict' };
  if (plan.kind !== 'linkable') return { status: 'rejected' };

  try {
    return await fastify.db.transaction(async (tx) => {
      const existing = await fastify.repositories.userCredentials.findByRealmProviderSub(
        input.realmId,
        WALLET_PROVIDER_TYPE,
        plan.externalSub,
        tx
      );

      if (existing !== undefined) {
        // Never overwrite another account's row. Note what this is and is not:
        // an `external_sub` KEY COLLISION, not the "this physical wallet is
        // already linked elsewhere" detection ADR-009 says is unavailable under
        // `asserted-lookup`. The two must not be conflated in what an operator
        // is told.
        if (existing.userId !== plan.userId) return { status: 'conflict' as const };

        const updated = await fastify.repositories.userCredentials.updateCredentialData(
          existing.id,
          plan.credentialData,
          tx
        );

        return {
          status: 'linked' as const,
          credentialId: updated.id,
          externalSub: plan.externalSub,
          subjectSource: plan.subjectSource,
          rebound: true,
        };
      }

      const created = await fastify.repositories.userCredentials.create(
        {
          userId: plan.userId,
          realmId: input.realmId,
          providerType: WALLET_PROVIDER_TYPE,
          externalSub: plan.externalSub,
          credentialData: plan.credentialData,
        },
        tx
      );

      return {
        status: 'linked' as const,
        credentialId: created.id,
        externalSub: plan.externalSub,
        subjectSource: plan.subjectSource,
        rebound: false,
      };
    });
  } catch (error) {
    // The unique index is the authority under concurrency: two simultaneous
    // links racing for the same `external_sub` both see no existing row, and one
    // of them loses at the insert. A conflict, not a 500.
    if (error instanceof UniqueConstraintError) {
      fastify.log.warn(
        { userId: input.authenticatedUserId },
        'wallet link lost a race for its external_sub'
      );
      return { status: 'conflict' };
    }
    throw error;
  }
}

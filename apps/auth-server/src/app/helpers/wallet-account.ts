import {
  buildWalletAttributeProvenance,
  type CredentialStatusChecker,
  extractWalletAttributes,
  findInexactNumericBindingClaims,
  issuerVouchesForEmail,
  isWalletAttributeIssuerTrusted,
  isWalletAttributeStatusValid,
  readWalletAttributeProvenance,
  type SubjectResolutionConfig,
  type SubjectResolutionStrategy,
  type TrustRegistry,
  type ValidatedCredential,
  WALLET_SOURCE,
} from '@qauth-labs/fastify-plugin-federation';
import type { FastifyInstance } from 'fastify';

import { createWalletAccountLookup } from './wallet-account-lookup';

/**
 * Wallet account resolution (issue #235, ADR-009).
 *
 * Where the three layers below finally meet a database:
 *
 *  1. #234 produced a {@link ValidatedCredential} — a cryptographic finding.
 *  2. #236 accepted its issuer — the finding is worth something in this realm.
 *  3. #300 decides WHICH account it is, through a configured
 *     `SubjectResolutionStrategy` over the `SubjectAccountLookup` port.
 *
 * `server-federation` is `scope:server` and may not import `infra-db`, which is
 * why the port has no implementation there. `helpers/wallet-account-lookup.ts`
 * (#238) is that implementation; this module turns the strategy's answer into
 * an account, or into the one refusal.
 *
 * ## Wallet sign-in never creates an account (ADR-009 §1, amended 2026-10-19)
 *
 * Only `matched` signs anyone in. `no-match`, `ambiguous` and `rejected` all
 * end in the SAME refusal, with nothing written:
 *
 * - **an account exists with no matching wallet binding** (typically a password
 *   account on the same email, or a wallet account bound to someone else's
 *   credential) → refused. Signing in here would let any holder of any trusted
 *   credential claim an existing account by asserting its identifier.
 * - **no account exists for the asserted identifier** → refused as well.
 *   Until 2026-10-19 this case enrolled a new account bound to the presenter.
 *   That made the login screen an account oracle (a taken identifier was
 *   refused, a free one signed in) and let anyone with a trusted credential
 *   claim an identifier that belongs to someone else (ANT-2026-NCX3VXDP). A
 *   typed identifier is an attribute the user asserts, not a proof that it is
 *   theirs.
 *
 * A wallet gets onto an account in one way today: its owner signs in to the
 * account and links the wallet from that session (account linking, #238,
 * `session-binding`; see `linkWalletPresentation`). Wallet-first sign-up
 * arrives with the hosted sign-up pages (ADR-017). Accounts that wallet sign-in
 * enrolled before the amendment keep signing in: they are `matched`.
 *
 * ## What is written, and what is NOT
 *
 * On a `matched` sign-in: the credential's claims, as `user_attributes` rows
 * with `source='wallet'`, refreshed on every sign-in; and the verified wallet
 * rows an earlier credential left are re-checked (ANT-2026-ULJIA4P4). No
 * `users` row and no `user_credentials` row is ever written here.
 *
 * `external_sub` is whatever the strategy resolved. It is never derived here,
 * and there is deliberately no code path in this module that could derive one:
 * no `cnf`, no holder key, no `x5c`, no thumbprint, no DID. ADR-009 Finding 1 is
 * that no such stable value exists, and #235's job is to CONSUME #300's answer.
 */

/** The outcome of resolving a presentation to an account. */
export type WalletAccountResolution =
  | {
      readonly status: 'authenticated';
      /** `users.id` the presentation resolved to. */
      readonly userId: string;
      /** The account's `user_credentials.external_sub` for this credential. */
      readonly externalSub: string;
    }
  | { readonly status: 'rejected' };

/** Everything {@link resolveWalletAccount} needs. */
export interface WalletAccountInput {
  /** Realm the presentation request was created in. Scopes every read and write. */
  readonly realmId: string;
  /** The validated presentation, from an issuer this realm trusts. */
  readonly credential: ValidatedCredential;
  /** The identifier the user asserted (ADR-009 §1). Unauthenticated input. */
  readonly assertedIdentifier: string;
  /** The realm's strategy, built from {@link config}. */
  readonly strategy: SubjectResolutionStrategy;
  /**
   * The resolved configuration. Read only to name, in the operator's log, a
   * binding claim that QAuth cannot represent exactly (ANT-2026-FKDN4Q29).
   */
  readonly config: SubjectResolutionConfig;
  /**
   * The gates a returning account's existing wallet attributes are re-checked
   * against (ANT-2026-ULJIA4P4). See {@link withdrawUnbackedWalletAttributes}.
   */
  readonly attributeGates: WalletAttributeGates;
  /**
   * `OID4VP_EMAIL_VERIFYING_ISSUERS` (ANT-2026-BGP7XCR2): issuers whose email
   * counts as verified without a disclosed `email_verified: true`. Empty means
   * none, the default.
   */
  readonly emailVerifyingIssuers: readonly string[];
}

/** The issuer-trust and credential-status gates, as a presentation meets them. */
export interface WalletAttributeGates {
  /** The issuer allowlist in force for the realm (#236). */
  readonly trustRegistry: TrustRegistry;
  /**
   * The deployment's status checker (#297), or `undefined` when it configured
   * none. That is the posture under which a presentation is not
   * status-checked either.
   */
  readonly credentialStatus: CredentialStatusChecker | undefined;
}

/**
 * Write the attribute rows a credential asserts.
 *
 * Called on every wallet sign-in, because a credential re-presented next month
 * may disclose different claims, carry a later `exp`, or have been re-issued
 * with a corrected value. Refreshing on every sign-in is what keeps
 * `user_attributes` a view of the credential rather than a snapshot of the day
 * it was first presented.
 *
 * An empty list is a no-op rather than an error: `upsertMany` short-circuits on
 * it, and a credential that asserts nothing QAuth maps (an age attestation) is a
 * legitimate login.
 */
async function writeWalletAttributes(
  fastify: FastifyInstance,
  userId: string,
  credential: ValidatedCredential,
  emailVerifyingIssuers: readonly string[]
): Promise<ReadonlySet<string>> {
  // The email row is verified only on a disclosed `email_verified: true`, or
  // for an issuer the operator vouches for (ANT-2026-BGP7XCR2).
  const attributes = extractWalletAttributes(credential, undefined, {
    issuerVouchesForEmail: issuerVouchesForEmail(credential.issuer, emailVerifyingIssuers),
  });
  // What every row rests on: the validated issuer and the issuer-signed
  // `status` reference (ANT-2026-ULJIA4P4). Claim resolution stops asserting a
  // row whose issuer is no longer trusted, and a later wallet sign-in
  // re-checks the status of a row it does not rewrite.
  const provenance = buildWalletAttributeProvenance(credential);

  await fastify.repositories.userAttributes.upsertMany(
    userId,
    attributes.map((attr) => ({
      source: attr.source,
      attrKey: attr.attrKey,
      attrValue: attr.attrValue,
      verified: attr.verified,
      // The federation contract speaks `Date`; the schema speaks epoch-ms.
      // Identical conversion to `routes/auth/register.ts`, deliberately.
      expiresAt: attr.expiresAt ? attr.expiresAt.getTime() : null,
      provenance,
    }))
  );

  return new Set(attributes.map((attr) => attr.attrKey));
}

/**
 * Withdraw the wallet attributes an EARLIER credential left that no longer
 * stand (ANT-2026-ULJIA4P4).
 *
 * A presentation rewrites only the claims it discloses. A row written by an
 * earlier credential, which the holder has since replaced (or which the issuer
 * has revoked), would otherwise keep being emitted as verified. So at every
 * wallet sign-in of a returning account, each verified wallet row this
 * presentation did NOT rewrite is asked again, through the same gates a
 * presentation meets: is its issuer still trusted, and does its credential
 * still read `VALID` on its status list? A row that fails either is set
 * `verified=false`, which takes it out of claim resolution until a valid
 * credential discloses that claim again.
 *
 * This is the one place revocation is re-checked after the fact. The sign-in
 * path already talks to the status host, and the checker caches verified lists.
 * The token and userinfo paths deliberately do not re-check it.
 *
 * A row with no readable provenance (written before it was recorded) is left
 * alone here: claim resolution already withholds it. Never throws: a failure
 * here is logged and must not fail a sign-in that has already succeeded.
 */
async function withdrawUnbackedWalletAttributes(
  fastify: FastifyInstance,
  userId: string,
  rewritten: ReadonlySet<string>,
  gates: WalletAttributeGates
): Promise<void> {
  try {
    const rows = await fastify.repositories.userAttributes.findByUserIdAndSource(
      userId,
      WALLET_SOURCE
    );
    const withdrawn: string[] = [];

    for (const row of rows) {
      if (!row.verified || rewritten.has(row.attrKey)) continue;
      if (readWalletAttributeProvenance(row.provenance) === undefined) continue;

      const stands =
        isWalletAttributeIssuerTrusted(row.provenance, gates.trustRegistry) &&
        (await isWalletAttributeStatusValid(row.provenance, gates.credentialStatus));
      if (stands) continue;

      await fastify.repositories.userAttributes.setVerified(
        userId,
        WALLET_SOURCE,
        row.attrKey,
        false
      );
      withdrawn.push(row.attrKey);
    }

    if (withdrawn.length > 0) {
      fastify.log.info(
        { userId, attributes: withdrawn },
        'withdrew wallet attributes whose credential is no longer valid or whose issuer is no longer trusted'
      );
    }
  } catch (error) {
    fastify.log.error(
      { err: error, userId },
      'failed to re-check the wallet attributes an earlier credential left'
    );
  }
}

/**
 * Say in the log when a refusal is down to a binding claim that arrived as a
 * JSON number QAuth cannot represent exactly (ANT-2026-FKDN4Q29).
 *
 * Such a claim no longer takes part in any binding, because two holders'
 * different numbers can round to one value. An account enrolled on one before
 * that rule therefore stops matching, and the uniform refusal on the wire
 * gives its holder and the operator nothing to go on. Claim names only, never
 * values.
 *
 * @returns whether anything was logged.
 */
export function warnOnInexactNumericBindingClaims(
  fastify: FastifyInstance,
  config: SubjectResolutionConfig,
  credential: ValidatedCredential,
  realmId: string
): boolean {
  const claims = findInexactNumericBindingClaims(config, credential);
  if (claims.length === 0) return false;

  fastify.log.warn(
    { realmId, claims },
    'wallet presentation refused: a configured binding claim is a JSON number QAuth cannot represent exactly (outside ±(2^53 − 1), or a fraction), so it no longer binds an account. An account enrolled on such a value can no longer sign in with this credential; the issuer must encode the claim as a string'
  );
  return true;
}

/**
 * Resolve a validated presentation to an EXISTING account, or refuse.
 *
 * Never creates an account (ADR-009 §1, amended 2026-10-19; see the module
 * JSDoc). An unknown identifier, a taken one and every other non-match return
 * the same `{ status: 'rejected' }` after the same single lookup, so the caller
 * cannot render them differently.
 *
 * PRECONDITIONS, in this order, both the caller's:
 *
 *  1. the credential VALIDATED (#234);
 *  2. its issuer is trusted by this realm (#236).
 *
 * Stated rather than re-checked because neither is checkable from here — this
 * module has no key resolver and no registry — and stated at all because the
 * order is not obvious: a credential from an untrusted issuer that reached
 * resolution would be matched against real accounts.
 *
 * @param fastify - server instance.
 * @param input - see {@link WalletAccountInput}.
 * @returns the account, or the single uniform refusal.
 */
export async function resolveWalletAccount(
  fastify: FastifyInstance,
  input: WalletAccountInput
): Promise<WalletAccountResolution> {
  const context = {
    realmId: input.realmId,
    assertedIdentifier: input.assertedIdentifier,
    lookup: createWalletAccountLookup(fastify),
    onLookupError: (error: unknown) => {
      fastify.log.error(
        { err: error, realmId: input.realmId },
        'wallet account lookup failed — refusing the presentation'
      );
    },
  };

  const outcome = await input.strategy.resolve(input.credential, context);

  if (outcome.kind !== 'matched') {
    // ONE refusal for every non-match, `no-match` included. The reason goes to
    // the operator's log only; the wire never learns which it was.
    if (outcome.kind === 'no-match') {
      fastify.log.info(
        { realmId: input.realmId },
        'wallet presentation named an identifier with no account — wallet sign-in creates no accounts (ADR-009 §1, amended 2026-10-19); refusing'
      );
    } else {
      warnOnInexactNumericBindingClaims(fastify, input.config, input.credential, input.realmId);
    }
    return { status: 'rejected' };
  }

  const externalSub = input.strategy.deriveExternalSub(input.credential, context);
  if (externalSub === null) {
    // A matched account whose subject cannot be re-derived would be signed in
    // on a value nothing can name. Refuse rather than mint a session for it.
    fastify.log.error(
      { realmId: input.realmId, userId: outcome.userId },
      'wallet presentation matched an account but yielded no external_sub — refusing'
    );
    return { status: 'rejected' };
  }

  const rewritten = await writeWalletAttributes(
    fastify,
    outcome.userId,
    input.credential,
    input.emailVerifyingIssuers
  );
  await withdrawUnbackedWalletAttributes(fastify, outcome.userId, rewritten, input.attributeGates);

  return { status: 'authenticated', userId: outcome.userId, externalSub };
}

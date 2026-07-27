import {
  buildWalletCredentialData,
  deriveEnrolmentWalletBinding,
  extractWalletAttributes,
  type SubjectAccountCandidate,
  type SubjectAccountLookup,
  type SubjectResolutionConfig,
  type SubjectResolutionStrategy,
  type ValidatedCredential,
  WALLET_PROVIDER_TYPE,
  walletCredentialDataSchema,
} from '@qauth-labs/fastify-plugin-federation';
import { UniqueConstraintError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';

/**
 * Wallet account resolution and enrolment (issue #235, ADR-009).
 *
 * Where the three layers below finally meet a database:
 *
 *  1. #234 produced a {@link ValidatedCredential} — a cryptographic finding.
 *  2. #236 accepted its issuer — the finding is worth something in this realm.
 *  3. #300 decides WHICH account it is, through a configured
 *     `SubjectResolutionStrategy` over the `SubjectAccountLookup` port.
 *
 * `server-federation` is `scope:server` and may not import `infra-db`, which is
 * why the port has no implementation there. This module is that implementation,
 * plus the write half #300 deliberately does not have (*"strategies never create
 * accounts"*).
 *
 * ## What is written, and what is NOT
 *
 * On a first presentation for an unknown identifier: one `users` row, one
 * `user_credentials` row with `provider_type='wallet'`, and the credential's
 * claims as `user_attributes` rows with `source='wallet'`, `verified=true` — all
 * in ONE transaction, because a `users` row without its credential row is
 * unloginable AND blocks re-enrolment (the same reasoning `routes/auth/register.ts`
 * records for password registration).
 *
 * `external_sub` is whatever the strategy resolved. It is never derived here,
 * and there is deliberately no code path in this module that could derive one:
 * no `cnf`, no holder key, no `x5c`, no thumbprint, no DID. ADR-009 Finding 1 is
 * that no such stable value exists, and #235's job is to CONSUME #300's answer.
 *
 * ## The bootstrap rule, which is the security property
 *
 * ADR-009 §1 keeps two cases apart and this module must not conflate them:
 *
 * - **no account for the asserted identifier** → enrol. The presentation
 *   establishes the account and its wallet binding together.
 * - **an account exists with no matching wallet binding** (typically a password
 *   account on the same email) → REFUSE. Enrolling here would let any holder of
 *   any trusted credential claim an existing account by asserting its email.
 *   That path is account linking (#238) and requires an authenticated session.
 *
 * The distinction is already made for us: `asserted-lookup` returns `no-match`
 * for the first and `rejected` for the second, and this module only enrols on
 * `no-match`. It is restated here because a future edit that treats "not
 * matched" as one case would reintroduce the takeover without touching #300.
 */

/** The outcome of resolving a presentation to an account. */
export type WalletAccountResolution =
  | {
      readonly status: 'authenticated';
      /** `users.id` the presentation resolved to, or the account just enrolled. */
      readonly userId: string;
      /** The value written to (or already in) `user_credentials.external_sub`. */
      readonly externalSub: string;
      /** Whether this presentation created the account. */
      readonly enrolled: boolean;
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
  /** The resolved configuration — the enrolment binding is derived from it. */
  readonly config: SubjectResolutionConfig;
}

/**
 * Read the wallet binding a credential row carries, or `null`.
 *
 * `null` means "this account has no wallet binding", which `selectSoleAccount`
 * treats as ADR-009's second bootstrap case and refuses. Every non-wallet row
 * yields `null` by construction — a password credential cannot prove anything
 * about a wallet — and so does a wallet row whose `credential_data` does not
 * parse. Fail-closed in both directions: a corrupt row makes its account
 * unclaimable by a presentation, never claimable by any presentation.
 */
function candidateBinding(credentialData: unknown, providerType: string): string | null {
  if (providerType !== WALLET_PROVIDER_TYPE) return null;

  const parsed = walletCredentialDataSchema.safeParse(credentialData);
  if (!parsed.success) return null;

  return parsed.data.wallet_binding;
}

/**
 * The `SubjectAccountLookup` port over `user_credentials` (#300).
 *
 * Realm-scoped on both lookups, and both return EVERY match across every
 * provider type — the port's two hard requirements, and the second is what makes
 * ADR-009's second bootstrap case visible at all.
 *
 * @param fastify - server instance, for its repositories.
 */
export function createWalletAccountLookup(fastify: FastifyInstance): SubjectAccountLookup {
  return {
    async byAssertedIdentifier(
      realmId: string,
      identifier: string
    ): Promise<readonly SubjectAccountCandidate[]> {
      const rows = await fastify.repositories.userCredentials.findByRealmAndSub(
        realmId,
        identifier
      );

      return rows.map((row) => ({
        userId: row.userId,
        walletBinding: candidateBinding(row.credentialData, row.providerType),
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

      return [
        {
          userId: row.userId,
          walletBinding: candidateBinding(row.credentialData, row.providerType),
        },
      ];
    },
  };
}

/**
 * The transaction handle the attribute writer accepts.
 *
 * Derived from the decorator rather than imported: `apps/auth-server` is
 * `scope:app` and may not depend on `@qauth-labs/infra-db`, so `DbClient` is
 * reached through the repository signature it already sees. Same decoupling
 * `helpers/realm.ts` and `helpers/consent.ts` document.
 */
type AttributeWriteTx = Parameters<
  FastifyInstance['repositories']['userAttributes']['upsertMany']
>[2];

/**
 * Write the attribute rows a credential asserts.
 *
 * Called on BOTH paths — enrolment and a returning user — because a credential
 * re-presented next month may disclose different claims, carry a later `exp`, or
 * have been re-issued with a corrected value. Refreshing on every login is what
 * keeps `user_attributes` a view of the credential rather than a snapshot of the
 * day the account was created.
 *
 * An empty list is a no-op rather than an error: `upsertMany` short-circuits on
 * it, and a credential that asserts nothing QAuth maps (an age attestation) is a
 * legitimate login.
 */
async function writeWalletAttributes(
  fastify: FastifyInstance,
  userId: string,
  credential: ValidatedCredential,
  tx?: AttributeWriteTx
): Promise<void> {
  const attributes = extractWalletAttributes(credential);

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
    })),
    tx
  );
}

/**
 * Resolve a validated presentation to an account, enrolling on first use.
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

  // The strategy's answer, and the value it would key an enrolment on. Derived
  // BEFORE anything is written and independently of the outcome, so the two can
  // never disagree about which account this is.
  const outcome = await input.strategy.resolve(input.credential, context);
  const externalSub = input.strategy.deriveExternalSub(input.credential, context);

  if (outcome.kind === 'matched') {
    if (externalSub === null) {
      // A matched account whose subject cannot be re-derived would be an
      // account nothing could re-enrol or re-key. Refuse rather than sign in
      // on a value we cannot name.
      fastify.log.error(
        { realmId: input.realmId, userId: outcome.userId },
        'wallet presentation matched an account but yielded no external_sub — refusing'
      );
      return { status: 'rejected' };
    }

    await writeWalletAttributes(fastify, outcome.userId, input.credential);

    return { status: 'authenticated', userId: outcome.userId, externalSub, enrolled: false };
  }

  // ADR-009 §1's first bootstrap case, and the ONLY outcome that may enrol.
  // `ambiguous` and `rejected` fall through to the uniform refusal below —
  // `rejected` in particular carries the account that exists WITHOUT a wallet
  // binding, which must never become an enrolment (see the module JSDoc).
  if (outcome.kind !== 'no-match') return { status: 'rejected' };

  if (externalSub === null) return { status: 'rejected' };

  // The proof half of every LATER presentation. Derived from the same claim set
  // `asserted-lookup` will re-derive from, and refused when it cannot be
  // derived: an account enrolled with no binding is one `asserted-lookup` can
  // never match, so the user would be silently locked out of the account their
  // first presentation created.
  const walletBinding = deriveEnrolmentWalletBinding(input.config, input.credential);

  if (walletBinding === null) {
    fastify.log.warn(
      { realmId: input.realmId },
      'wallet presentation withheld a configured binding claim — refusing to enrol an account nothing could later prove entitlement to'
    );
    return { status: 'rejected' };
  }

  const credentialData = buildWalletCredentialData({
    credential: input.credential,
    walletBinding,
    subjectResolution: input.strategy.id,
  });

  try {
    const userId = await fastify.db.transaction(async (tx) => {
      const user = await fastify.repositories.users.create({ realmId: input.realmId }, tx);

      await fastify.repositories.userCredentials.create(
        {
          userId: user.id,
          realmId: input.realmId,
          providerType: WALLET_PROVIDER_TYPE,
          externalSub,
          credentialData,
        },
        tx
      );

      await writeWalletAttributes(fastify, user.id, input.credential, tx);

      return user.id;
    });

    return { status: 'authenticated', userId, externalSub, enrolled: true };
  } catch (error) {
    // A concurrent enrolment for the same `(realm_id, 'wallet', external_sub)`
    // loses the unique index. Rendered as the SAME refusal every other failure
    // renders: a distinguishable "already exists" here would tell an anonymous
    // caller which identifiers have wallet credentials.
    if (error instanceof UniqueConstraintError) {
      fastify.log.warn(
        { realmId: input.realmId },
        'wallet enrolment lost a race on the credential unique index — refusing'
      );
      return { status: 'rejected' };
    }

    throw error;
  }
}

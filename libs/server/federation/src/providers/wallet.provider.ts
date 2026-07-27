import { z } from 'zod';

import { resolveCredentialClaimAdapter } from '../claims/credential-claim-adapters';
import type {
  CredentialClaimAdapterRegistry,
  CredentialClaimSet,
} from '../claims/credential-claims.types';
import type { CredentialValidityWindow, ValidatedCredential } from '../oid4vp/validated-credential';
import type { CredentialFormat } from '../profiles/verifier-profile.types';
import { ValidatedIssuer } from '../trust/issuer-identity';
import type {
  AssuranceLevel,
  CredentialProvider,
  UserAttribute,
  VerifiedIdentity,
} from './credential-provider.interface';

/**
 * WalletProvider — the `type='wallet'` {@link CredentialProvider} (ADR-004).
 *
 * `verify()` is still the NON-FUNCTIONAL SKELETON issue #232 shipped;
 * `extractAttributes()` is implemented as of issue #235. Read
 * "## Why `verify()` still throws while `extractAttributes()` works" below
 * before assuming either half is a mistake.
 *
 * ## Why an unimplemented provider exists
 *
 * Epic #231 splits wallet federation across issues that must be developable in
 * parallel: #233 (OID4VP 1.0 authorization request generation + `direct_post`
 * response intake), #234
 * (OID4VP Verifiable Presentation validation, SD-JWT VC), #235 (VC claims
 * normalization into `user_attributes`), #236 (trust registry — per-realm
 * issuer allowlist), #237 (`acr` propagation) and #238 (account linking).
 * ADR-003's promise is that adding a provider is a REGISTRATION, not an
 * auth-engine change, so this module establishes the file, the `type`
 * discriminator and the registry entry up front and the follow-ups fill in the
 * two method bodies against a stable shell. It intentionally contains no
 * protocol logic — no OID4VP, no DCQL, no trust registry.
 *
 * ## Fail-closed: `verify()` THROWS, and must keep throwing
 *
 * `verify()` rejects unconditionally. That is a security property, not an
 * oversight: a stub that resolved a placeholder {@link VerifiedIdentity} would
 * be an authentication-bypass primitive the moment `WALLET_FEDERATION_ENABLED`
 * is flipped or a route wires up `resolve('wallet')` — the auth engine upserts
 * whatever `externalSub` it is handed and mints a token for it, with no
 * provider-specific second guess (that is exactly ADR-003's design).
 *
 * So: do NOT soften it into a no-op or a placeholder return to make a caller
 * compile or a test go green.
 *
 * ## Why `verify()` still throws while `extractAttributes()` works
 *
 * The two methods answer different questions, and only one of them has an
 * answer today:
 *
 * - `verify()` asks **who is this?**, and ADR-003 makes its result an
 *   authentication. Answering needs a per-realm issuer allowlist (#236), the
 *   identifier the user asserted, and an account store to match a presented
 *   credential against the binding recorded for that account (#300). This
 *   provider is stateless and dependency-free by construction and is handed
 *   none of them. See the seam that IS wired to all three:
 *   `apps/auth-server/src/app/helpers/wallet-presentation.ts`.
 * - `extractAttributes()` asks **what does this credential assert?**, which is a
 *   pure mapping over claims that #234 already proved. It authenticates nobody:
 *   it produces `user_attributes` rows and cannot produce a subject, a session
 *   or a token. Handing it a credential does not sign anyone in, and the rows it
 *   returns are only ever written against a `users.id` some OTHER gate resolved.
 *
 * #232's original reason for making this method throw survives intact and is
 * why the implementation is shaped the way it is: *"a stub that returned `[]`
 * would look identical to a working provider handed a credential carrying no
 * claims, silently dropping identity data instead of failing loudly."* So the
 * implementation still THROWS on a malformed input — a `rawClaims` that is not
 * the envelope `verify()` would have produced is a wiring error, not an empty
 * credential — and returns `[]` only for a credential that genuinely disclosed
 * nothing this deployment maps.
 *
 * ## Still true after #234 (presentation validation landed)
 *
 * #233 shipped the OID4VP transport and #234 the SD-JWT VC validator, so QAuth
 * can now take a `vp_token`, verify the issuer's signature, check every
 * selective-disclosure digest, enforce the validity window, and verify the Key
 * Binding JWT against the credential's `cnf` key with this request's `nonce` and
 * QAuth's `client_id`. The result is a `ValidatedCredential` — and `verify()`
 * still throws, because a validated credential is not an authenticated user:
 *
 * - **Whose credential is it worth anything from?** #236's per-realm issuer
 *   allowlist decides, from the `ValidatedIssuer` #234 surfaces. Until that gate
 *   runs, "validly signed" says nothing about "trusted".
 * - **Which account is this?** ADR-009: there is no stable wallet subject
 *   identifier, and wallet key material (`cnf`, the `x5c` chain) MUST NOT become
 *   one — OID4VP §15.5–§15.6 treat it as a linkability defect wallets rotate
 *   away. #300 landed the `SubjectResolutionStrategy` seam (`src/subject/`) that
 *   decides instead, with `asserted-lookup` as the fail-closed default — but a
 *   strategy is not an answer on its own. It needs the realm's configuration,
 *   the identifier the user asserted, and an account store to look the asserted
 *   identifier up in, so that the presented credential can be matched against
 *   the binding stored for that account. This provider is handed none of the
 *   three.
 *
 * Both gates are absent here, so this method fails closed. `safety-boundary.test.ts`
 * pins that a REAL, fully valid Presentation still authenticates nobody.
 *
 * ## The ADR-004 model this shell will grow into
 *
 * Wallet-agnostic by construction — any OID4VP wallet (EUDI, Lissi, Sphereon,
 * walt-id, …), never EUDI-specific code. Extracted attributes carry
 * `source = 'wallet'` ({@link WALLET_SOURCE}), the highest ADR-002 trust rank,
 * above the `oidc_*` family and `self_reported`; `assuranceLevel` is the eIDAS
 * LoA that propagates downstream as the OIDC `acr` claim (#237).
 *
 * NOTE: the 2026-03-11 model had `externalSub` = the holder's DID. That does not
 * survive the 2026-07-20 corrections — see the forward constraints below.
 *
 * ## Forward constraint — ADR-004 spec refresh (2026-07-19)
 *
 * ADR-004 was authored 2026-03-11 against then-draft specs and **MUST NOT be
 * implemented as originally written**. Two constraints bind #233–#235:
 *
 * - **DCQL, not Presentation Exchange.** OID4VP 1.0 is Final and its credential
 *   query mechanism is DCQL (Digital Credentials Query Language). The
 *   `presentation_definition` model of OID4VP Draft 22 is superseded and DIF
 *   Presentation Exchange remains a PRE-DRAFT specification, operationally
 *   superseded for OID4VP flows. The presentation-request path MUST be built on
 *   DCQL. QAuth carries no Presentation Exchange dependency today, so this is a
 *   forward constraint, not a migration — there is nothing to unwind, only a
 *   wrong turn to avoid.
 * - **HAIP 1.0 is the testable eIDAS profile.** Generic "OID4VP support" does
 *   not imply conformance: OpenID4VC High Assurance Interoperability Profile
 *   (HAIP) 1.0 constrains credential formats, cryptographic suites and client
 *   authentication beyond base OID4VP, and is the profile the EUDI ecosystem
 *   aligns to. ADR-004's eIDAS claim should be re-stated against HAIP, which is
 *   its falsifiable form — but re-stating the claim in HAIP's terms is not the
 *   same as adopting HAIP, and whether QAuth targets it is OPEN (#296). Read
 *   this as "what conformance would mean", not "conform".
 *
 * ## Forward constraint — ADR-004 correction (2026-07-20)
 *
 * The 2026-07-19 refresh above also asserted that "SIOPv2 remains the
 * self-issued-OP mechanism this ADR describes". **That is wrong** (#295) and is
 * superseded. Three further constraints bind #233–#238:
 *
 * - **OID4VP 1.0 is the mechanism; SIOPv2 is not part of it.** HAIP 1.0 §5:
 *   "The Response type MUST be `vp_token`" — which excludes the
 *   `vp_token id_token` Response Type that carries a Self-Issued ID Token
 *   (OID4VP 1.0 §8). The strings `SIOP`, `Self-Issued` and `id_token` occur zero
 *   times in HAIP 1.0. SIOPv2 is draft 13 (2023-11-28) and never reached Final.
 *   Do NOT implement a SIOPv2 authorization request or consume a self-issued
 *   `id_token`. Note that the `direct_post` in #233's title is the BASE OID4VP
 *   1.0 Response Mode; HAIP 1.0 §5.1 requires the encrypted `direct_post.jwt`
 *   instead. Which one #233 implements follows #296 and the JWE work in #298.
 * - **There is no stable wallet subject identifier.** OID4VP 1.0 §15.5 treats
 *   the issuer signature and the credential-bound public key as linkability
 *   defects that wallets are expected to rotate away; §15.6 tells Verifiers not
 *   to fingerprint the End-User. So `externalSub` CANNOT be keyed on wallet
 *   cryptography (no DID, no JWK thumbprint). The replacement basis for
 *   `user_credentials.external_sub` and account linking (#238) is an OPEN
 *   decision — see #296. Do not invent one here.
 * - **The crypto layer cannot speak the profile yet.** `@qauth-labs/core-crypto`
 *   is EdDSA-only; no signing backend produces `ES256` and there is no JWE
 *   support. HAIP 1.0 §7 requires ES256 at minimum; §5.1 requires response
 *   encryption via `direct_post.jwt`, and §5 constrains it to JWE `alg`
 *   `ECDH-ES` on P-256, `enc` `A128GCM`/`A256GCM`.
 *   Prerequisite, sequenced in #298 — federation code cannot compensate for it.
 *
 * Which profile QAuth targets, and which OID4VP Client Identifier Prefixes it
 * implements, are NOT decided. Nothing above commits QAuth to HAIP conformance;
 * it records what the profile would require. Tracked in #296.
 *
 * @see docs/adr/004-wallet-agnostic-federation.md — §§ "Spec status (2026-07-19)",
 *   "Spec status (2026-07-20)"
 * @see docs/adr/003-credential-provider-interface.md
 */

/** `user_credentials.provider_type` / registry key for this provider. */
export const WALLET_PROVIDER_TYPE = 'wallet';

/**
 * `user_attributes.source` for wallet-derived (VC-backed) attributes.
 *
 * This value is load-bearing for claim resolution: `claims/attribute-trust.ts`
 * ranks `'wallet'` above every other source (ADR-002), so changing this literal
 * without changing `rankAttributeSource` would silently demote every
 * wallet-issued attribute to rank 0. `wallet.provider.test.ts` pins the pair.
 */
export const WALLET_SOURCE = 'wallet';

/**
 * `rawClaims` envelope for `provider_type='wallet'` (issue #235).
 *
 * ## Why an envelope and not the bare claim set
 *
 * `PasswordProvider` puts its two claims directly in `rawClaims`, because for a
 * password there is nothing else to know. A wallet credential's claims cannot be
 * read without three further facts, and all three come from outside the claim
 * set:
 *
 * - the **format**, because the claim vocabulary is format-specific (see
 *   `claims/credential-claims.types.ts` — `birthdate` in SD-JWT VC is
 *   `birth_date` in mdoc);
 * - the **credential type** and **issuer**, which are what a `credential_data`
 *   row records and what makes a stored binding re-derivable;
 * - the credential's **expiry**, because ADR-002 gives every wallet attribute an
 *   `expires_at` bounded by the credential that asserted it.
 *
 * A `type` alias rather than an `interface`, deliberately: TypeScript gives
 * object type literals an implicit index signature and interfaces none, so only
 * this form is assignable to {@link VerifiedIdentity.rawClaims}'s
 * `Record<string, unknown>` without a cast.
 *
 * Keys are snake_case to match the `credential_data` shapes this package already
 * owns and to read as what it is — a claims envelope, not a TypeScript view.
 */
export type WalletRawClaims = {
  /** Credential Format the claims were read from. */
  readonly credential_format: CredentialFormat;
  /** The `vct` (SD-JWT VC) or doctype (mdoc) the issuer asserted. */
  readonly credential_type: string;
  /**
   * The VALIDATED issuer identity, canonicalized — never a credential-asserted
   * `iss`. Carried as a string because a `ValidatedIssuer` is a branded class
   * that must not be reconstructible from a JSON round-trip; anything needing
   * the brand reads `ValidatedCredential.issuer` instead.
   */
  readonly issuer: string;
  /** The disclosed claims, exactly as #234 surfaced them. */
  readonly claims: Readonly<Record<string, unknown>>;
  /** `exp`, epoch SECONDS (the JWT unit), when the credential carries one. */
  readonly expires_at?: number;
};

/**
 * Input contract of {@link CredentialProvider.extractAttributes} for `'wallet'`.
 *
 * `.strict()` for the same reason `passwordVerifyInputSchema` is: callers
 * construct this object in-process through {@link buildWalletVerifiedIdentity},
 * so an unknown key means a programming error rather than forward-compatible
 * data. `claims` is `z.record(z.string(), z.unknown())` and NOT inspected here —
 * deciding what a claim means is the format adapter's job, and duplicating any
 * part of that decision in a schema would create a second place for the two to
 * disagree.
 */
export const walletRawClaimsSchema = z
  .object({
    credential_format: z.string().min(1),
    credential_type: z.string().min(1),
    issuer: z.string().min(1),
    claims: z.record(z.string(), z.unknown()),
    expires_at: z.number().int().positive().optional(),
  })
  .strict();

/**
 * `credential_data` JSONB shape for `provider_type='wallet'` rows (#235).
 *
 * This module is the single owner of the shape, exactly as it is for
 * `'password'` — a camelCase drift or a renamed key here would pass every DB
 * constraint and silently break the entitlement check on every returning user,
 * so nothing else may hand-roll this object.
 *
 * Deliberately NOT `.strict()`: #238 (account linking) and later issues may add
 * sibling keys, and readers of today's binary must keep parsing then.
 *
 * `wallet_binding` is the load-bearing field. It is the value `asserted-lookup`
 * re-derives and compares on every later presentation (ADR-009 §1), so it is
 * nullable in the SCHEMA — a row from a future strategy that stores none must
 * still parse — while #235's enrolment path refuses to write a row without one.
 * A stored `null` therefore reads as "this account has no wallet binding", which
 * `selectSoleAccount` treats as ADR-009's second bootstrap case and refuses.
 */
export const walletCredentialDataSchema = z.object({
  credential_format: z.string().min(1),
  credential_type: z.string().min(1),
  issuer: z.string().min(1),
  wallet_binding: z.string().min(1).nullable(),
  subject_resolution: z.string().min(1),
  enrolled_at: z.number().int().nonnegative(),
  credential_expires_at: z.number().int().positive().nullable().optional(),
});

export type WalletCredentialData = z.infer<typeof walletCredentialDataSchema>;

/** What {@link buildWalletCredentialData} records about an enrolled credential. */
export interface WalletCredentialDataInput {
  /** The validated presentation being enrolled. */
  readonly credential: ValidatedCredential;
  /**
   * The binding `asserted-lookup` will compare against on every later
   * presentation — `deriveEnrolmentWalletBinding`'s output, stored VERBATIM.
   */
  readonly walletBinding: string;
  /** Which strategy resolved this enrolment, for the operator reading the row. */
  readonly subjectResolution: string;
  /** Enrolment instant, epoch-ms (the schema's unit). Defaults to now. */
  readonly enrolledAt?: number;
}

/**
 * Build the `credential_data` object for a wallet credential row.
 *
 * The only sanctioned constructor of this shape. Note what is NOT in it: no
 * `cnf`, no holder key, no JWK thumbprint, no DID, and no claim VALUES. The
 * binding is a digest (`subject-binding.ts`), so an operator inspecting the
 * column sees what the account is keyed on without the column becoming a second
 * copy of the person's identity attributes — ADR-009 Finding 2's concern, and
 * OID4VP 1.0 §15.5–§15.6's.
 *
 * @param input - see {@link WalletCredentialDataInput}.
 * @returns the JSONB object, ready for `user_credentials.credential_data`.
 * @throws Error when the credential carries no validated issuer — an invariant
 * breach (only #234 produces these), never a wire error.
 */
export function buildWalletCredentialData(input: WalletCredentialDataInput): WalletCredentialData {
  const issuer: unknown = input?.credential?.issuer;

  if (!ValidatedIssuer.isValidated(issuer)) {
    throw new Error(
      'buildWalletCredentialData requires a ValidatedCredential carrying a branded ValidatedIssuer (#234). A credential-asserted `iss` must never be recorded as the issuer a binding is scoped to (ADR-009 §2).'
    );
  }

  const expiresAt = validityExpirySeconds(input.credential.validity);

  return {
    credential_format: input.credential.format,
    credential_type: input.credential.credentialType,
    issuer: issuer.identifier,
    wallet_binding: input.walletBinding,
    subject_resolution: input.subjectResolution,
    enrolled_at: input.enrolledAt ?? Date.now(),
    credential_expires_at: expiresAt ?? null,
  };
}

/**
 * Read a credential's `exp` as a usable epoch-SECONDS value.
 *
 * Defensive about a number the type already promises: `validity` crosses no
 * trust boundary today, but a non-finite or negative value would become an
 * `Invalid Date` in `user_attributes.expires_at` and an attribute that can never
 * be selected — silent claim loss rather than a loud failure.
 */
function validityExpirySeconds(validity: CredentialValidityWindow | undefined): number | undefined {
  const expiresAt = validity?.expiresAt;
  if (typeof expiresAt !== 'number' || !Number.isFinite(expiresAt) || expiresAt <= 0) {
    return undefined;
  }
  return Math.floor(expiresAt);
}

/**
 * Package a validated credential as the {@link VerifiedIdentity} the ADR-003
 * auth engine consumes (#235).
 *
 * **This function does not authenticate anyone**, and its two non-credential
 * arguments are why:
 *
 * - `externalSub` is whatever `SubjectResolutionStrategy.deriveExternalSub`
 *   resolved (#300, ADR-009). It is NEVER derived here, never from the holder
 *   key, `cnf`, an `x5c` chain or a DID — there is no protocol-guaranteed stable
 *   wallet subject identifier, and inventing one is the mistake ADR-009 exists
 *   to record.
 * - `assuranceLevel` is #237's decision, made from the credential AND the issuer
 *   this realm trusts. `'low'` is the fail-closed default and emits no `acr`
 *   (ADR-003).
 *
 * Both are INPUTS because both are decisions this provider is not in a position
 * to make. A version of this function that computed either would be the
 * authentication-bypass primitive `verify()` throws to prevent.
 *
 * @param credential - the validated presentation (#234), from a trusted issuer
 * (#236).
 * @param externalSub - the value #300's strategy resolved.
 * @param assuranceLevel - #237's level; defaults to the fail-closed `'low'`.
 * @throws Error when the credential carries no validated issuer.
 */
export function buildWalletVerifiedIdentity(
  credential: ValidatedCredential,
  externalSub: string,
  assuranceLevel: AssuranceLevel = 'low'
): VerifiedIdentity {
  const issuer: unknown = credential?.issuer;

  if (!ValidatedIssuer.isValidated(issuer)) {
    throw new Error(
      'buildWalletVerifiedIdentity requires a ValidatedCredential carrying a branded ValidatedIssuer (#234). Without it there is no validated issuer identity to scope the credential to.'
    );
  }

  if (typeof externalSub !== 'string' || externalSub.length === 0) {
    throw new Error(
      'buildWalletVerifiedIdentity requires the external_sub resolved by SubjectResolutionStrategy (#300, ADR-009). There is no wallet-cryptographic value this provider may substitute for it.'
    );
  }

  const expiresAt = validityExpirySeconds(credential.validity);

  const rawClaims: WalletRawClaims = {
    credential_format: credential.format,
    credential_type: credential.credentialType,
    issuer: issuer.identifier,
    claims: credential.claims,
    ...(expiresAt === undefined ? {} : { expires_at: expiresAt }),
  };

  return { externalSub, assuranceLevel, rawClaims };
}

/**
 * What {@link extractWalletAttributes} reads.
 *
 * A structural SUBSET of `ValidatedCredential`, which satisfies it without a
 * cast — so the enrolment path passes the credential itself, and the ADR-003
 * method passes a view rebuilt from its envelope, and neither needs to fabricate
 * the fields it does not have. Nothing that could carry a trust or assurance
 * decision is in it; see `claims/credential-claims.types.ts`.
 */
export interface WalletAttributeSource extends CredentialClaimSet {
  /** The credential's own validity window; its `exp` bounds every row. */
  readonly validity?: CredentialValidityWindow;
}

/**
 * Normalize a validated credential's claims into `user_attributes` rows (#235).
 *
 * The workhorse behind {@link CredentialProvider.extractAttributes}, exported
 * because the enrolment path in `apps/auth-server` needs the rows for a
 * credential it holds directly, without round-tripping through an envelope it
 * would have to build only to have this function take it apart again.
 *
 * Every row is `source='wallet'` and `verified=true`. The `verified` flag is not
 * read from the credential and CANNOT be: #234 proved the issuer's signature
 * over these exact claims and #236 accepted that issuer, so an issuer-supplied
 * `email_verified: false` may not downgrade what QAuth cryptographically
 * established — nor may its absence. (`email_verified` is in
 * `SD_JWT_VC_UNMAPPED_CLAIMS` for the same reason.)
 *
 * Every row's `expiresAt` is the CREDENTIAL's `exp`, or absent when it carries
 * none. ADR-002's rule, and the reason `selectTrustedAttribute` filters on
 * expiry: an attribute asserted by a credential that expires tomorrow must not
 * outlive it and go on being emitted as a verified claim.
 *
 * @param source - the validated presentation, or a view of it; a
 * `ValidatedCredential` satisfies {@link WalletAttributeSource} directly.
 * @param adapters - the claim adapter table; defaults to everything QAuth ships.
 * @returns the rows, possibly empty when nothing mappable was disclosed.
 * @throws Error when the source is malformed or QAuth ships no claim adapter
 * for its format — a wiring error, never an empty result.
 */
export function extractWalletAttributes(
  source: WalletAttributeSource,
  adapters?: CredentialClaimAdapterRegistry
): UserAttribute[] {
  if (source === null || typeof source !== 'object') {
    throw new Error(
      'extractWalletAttributes requires a validated credential or a view of one (#234).'
    );
  }

  const adapter = resolveCredentialClaimAdapter(source.format, adapters);
  const expiresAt = validityExpirySeconds(source.validity);

  return adapter.normalizeClaims(source).map((claim) => ({
    source: WALLET_SOURCE,
    attrKey: claim.attrKey,
    attrValue: claim.attrValue,
    verified: true,
    ...(expiresAt === undefined ? {} : { expiresAt: new Date(expiresAt * 1000) }),
  }));
}

/**
 * Build the fail-closed error thrown by every method of the skeleton.
 *
 * Deliberately a plain `Error` rather than a `@qauth-labs/shared-errors` domain
 * error. Those carry `statusCode`/`code` and are mapped onto the wire by the
 * global error handler, which would frame this as a reachable, client-facing
 * outcome with a stable error contract. It is not one: no route resolves
 * `'wallet'` today, and the provider only enters the registry behind
 * `WALLET_FEDERATION_ENABLED` (off by default). Reaching it means QAuth is
 * mis-wired, and a generic 500 plus a server-side stack trace is precisely the
 * right signal. Minting a `NotImplementedError` in the shared lib would also
 * create permanent public wire surface for a condition that must never occur —
 * and would invite treating "not implemented" as a normal auth outcome.
 *
 * @param method - the {@link CredentialProvider} method that was called.
 * @param followUp - what lands where, so the reader gets the issue number.
 */
function walletSkeletonError(method: string, followUp: string): Error {
  return new Error(
    `WalletProvider.${method}() is not implemented — WalletProvider is a registration-only skeleton (#232). ${followUp} Failing closed: this method never returns a value, so no wallet can authenticate until the follow-ups land.`
  );
}

/**
 * Create the wallet {@link CredentialProvider} shell.
 *
 * Stateless and dependency-free (it holds no HTTP client, no trust registry, no
 * key material), so it is safe to construct at bootstrap and register in the
 * provider registry — registering it is inert, because every method fails
 * closed. See the module JSDoc before adding behaviour here.
 */
export function createWalletProvider(): CredentialProvider {
  return {
    type: WALLET_PROVIDER_TYPE,

    /**
     * NOT IMPLEMENTED — always rejects (see module JSDoc).
     *
     * The `input` is not even inspected, and — since #234 — that is now a
     * DELIBERATE REFUSAL rather than a gap. Presentation validation exists:
     * `oid4vp/presentation-validation.ts` will turn a `vp_token` into a
     * `ValidatedCredential`, proving the issuer signature, the disclosure
     * digests, the validity window and holder binding to this request. Calling
     * it from here would still not authenticate anyone, and wiring it in would
     * make it look as though it did:
     *
     * - A `ValidatedCredential` from an issuer this realm does not trust is a
     *   forgery with extra steps. The gate is `assertIssuerTrusted` (#236),
     *   which needs a per-realm registry this provider is not given.
     * - There is no protocol-guaranteed stable wallet subject identifier
     *   (ADR-009), so there is no `externalSub` to return. Resolving one is
     *   `SubjectResolutionStrategy`'s job, and that seam now exists (#300,
     *   `src/subject/`) — but under the `asserted-lookup` default it needs the
     *   identifier the user asserted and an account store to match the presented
     *   credential against the binding recorded for that account. This provider
     *   is stateless and dependency-free by construction, so it has neither.
     *
     * So the honest state is: QAuth can now VALIDATE a wallet credential and
     * still cannot AUTHENTICATE a wallet user. Returning a placeholder identity
     * to close that gap would be an authentication bypass, not progress.
     *
     * @throws Error always — never resolves a {@link VerifiedIdentity}.
     */
    async verify(): Promise<VerifiedIdentity> {
      throw walletSkeletonError(
        'verify',
        'The OID4VP transport landed in #233 and presentation validation in #234 (see oid4vp/presentation-validation.ts, which produces a ValidatedCredential — a cryptographic finding, not an identity). Authentication additionally requires issuer trust (#236) and subject resolution (#300, ADR-009); the strategy seam for the latter exists in subject/, but this provider is wired to neither a trust registry nor an account store.'
      );
    },

    /**
     * Normalize the credential's disclosed claims into `user_attributes` rows
     * (issue #235). See {@link extractWalletAttributes} for the mapping rules
     * and the module JSDoc for why this method works while
     * {@link CredentialProvider.verify} still throws.
     *
     * PRECONDITION: `result` was built by {@link buildWalletVerifiedIdentity}
     * from a credential that validated (#234) and whose issuer this realm trusts
     * (#236). The envelope is re-parsed here rather than trusted, because
     * `VerifiedIdentity.rawClaims` is `Record<string, unknown>` and any caller
     * can construct one.
     *
     * The envelope is re-wrapped as a {@link WalletAttributeSource}, which
     * carries no issuer and no assurance signal. Nothing is fabricated to make
     * that fit: `ValidatedIssuer` has a private brand and a private constructor
     * precisely so it cannot be rebuilt from a string, and neither the claim
     * adapter nor this method has any business making a trust decision.
     *
     * @throws Error when `rawClaims` is not the envelope `verify()` would have
     * produced, or when QAuth ships no claim adapter for its format — a wiring
     * error, which must fail loudly rather than record an empty attribute set.
     */
    extractAttributes(result: VerifiedIdentity): UserAttribute[] {
      const parsed = walletRawClaimsSchema.safeParse(result?.rawClaims);

      if (!parsed.success) {
        throw new Error(
          `WalletProvider.extractAttributes received rawClaims that buildWalletVerifiedIdentity did not produce (#235): ${parsed.error.message}. Returning no attributes here would be indistinguishable from a credential that disclosed nothing, so it fails loudly instead.`
        );
      }

      const envelope = parsed.data;

      return extractWalletAttributes({
        format: envelope.credential_format as CredentialFormat,
        credentialType: envelope.credential_type,
        claims: envelope.claims,
        validity: envelope.expires_at === undefined ? {} : { expiresAt: envelope.expires_at },
      });
    },
  };
}

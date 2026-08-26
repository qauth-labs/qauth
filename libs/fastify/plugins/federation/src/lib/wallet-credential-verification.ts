import {
  assertIssuerTrusted,
  createStaticIssuerKeyResolver,
  type CredentialStatusChecker,
  type DcqlQuery,
  isPresentationValidationRejection,
  type IssuerKeyResolver,
  issuerTrustRejection,
  type KeyStorageAssuranceGate,
  type PresentationValidationContext,
  type PresentedCredential,
  type StaticIssuerKeyEntry,
  type TrustRegistry,
  type ValidatedCredential,
  validatePresentations,
  type VerifierProfile,
} from '@qauth-labs/server-federation';

/**
 * Turning a `vp_token` into a TRUSTED credential — the #234 + #236 seam, wired
 * for `apps/auth-server` (issue #238).
 *
 * ## Why this lives in the fastify layer
 *
 * `apps/auth-server` is `scope:app` and may not import `scope:server` libraries
 * directly; `libs/server/federation` is a pure library with no configuration and
 * no logger. So the composition of the two halves — validate the presentation,
 * then decide whether its issuer is worth anything to this realm — needs a home
 * in between, and this is it.
 *
 * Composition, not convenience. The gates have a MANDATORY ORDER and a
 * mandatory conjunction:
 *
 * 1. **#234 validates.** Issuer signature, every Disclosure digest, the validity
 *    window, and the Key Binding JWT's `aud`/`nonce`/`sd_hash` — the proof that
 *    the bytes are a credential presented to THIS Verifier for THIS request.
 * 2. **#308 resolves key-storage assurance.** Inside the same call, layered on
 *    top of holder binding and never in place of it: holder binding proves the
 *    presenter controls the credential's key now, this asks where that key
 *    LIVES. Threaded in as a
 *    {@link WalletCredentialVerificationOptions.keyStorageAssurance} gate for
 *    the same reason the status checker is — only the producer of
 *    `ValidatedCredential.assurance` can make
 *    `assurance.keyStorageAssurance` state what actually happened, and #379 is
 *    the issue recording that a gate which existed, was tested and was never
 *    threaded left that field reading `'none'` for every credential the
 *    auth-server has ever produced.
 * 3. **#297 checks status.** Inside the same call, and deliberately LAST within
 *    it: the Token Status List bit for this credential must positively read
 *    `VALID`, or the presentation is refused. It runs after the Issuer signature
 *    and after the Key Binding JWT because the status list URI is bytes the
 *    WALLET chose until the issuer's signature covers them, and dialling a URI
 *    out of an unverified payload is an SSRF primitive. Threaded in as a
 *    {@link WalletCredentialVerificationOptions.credentialStatus} checker rather
 *    than run as a third gate out here, so that
 *    `ValidatedCredential.assurance.statusChecked` can state what actually
 *    happened instead of being a field that permanently lies (#378).
 * 4. **#236 decides trust.** A validated credential from an issuer this realm
 *    does not trust is, in `wallet.provider.ts`'s words, *"a forgery with extra
 *    steps"*.
 *
 * None is sufficient and none can be skipped, so exposing them as one function
 * is how a caller is prevented from wiring up only the first. That is not
 * hypothetical: the first produces a plausible-looking `ValidatedCredential`
 * with claims in it, which is exactly the object someone in a hurry would use —
 * and #378 is the issue recording that a status gate which existed, was tested
 * and was never threaded meant a revoked credential authenticated a user exactly
 * like a live one.
 *
 * ## Every refusal is the same refusal
 *
 * #236's rule — restated in `issuer-trust-rejection.ts` as binding on #234 —
 * is that an untrusted issuer must be indistinguishable from a malformed
 * presentation. So every path out of this module that is not success throws the
 * identical `InvalidCredentialsError`, whether the signature was forged, a
 * digest did not match, the credential expired, the holder binding failed, the
 * issuer is not on the realm's allowlist, or no key could be resolved for it at
 * all. The specific reason is returned to the CALLER's logger through
 * {@link WalletCredentialVerificationOptions.onRefusal} and never onto the wire.
 *
 * ## What it deliberately does not do
 *
 * It does not resolve an account, derive an `external_sub`, or create anything.
 * A trusted credential is a cryptographic finding about a document; which USER
 * it belongs to is ADR-009's question and `SubjectResolutionStrategy`'s answer
 * (#300). Keeping those apart is what stops "the signature checked out" from
 * turning into "you are signed in".
 */

/** The reason a verification refused, for the caller's log. Never for the wire. */
export interface WalletCredentialRefusal {
  /**
   * A stable, coarse label. Deliberately coarser than #234's own
   * `PresentationRejectionReason`: it separates the two GATES so an operator can
   * tell "no wallet can ever verify here" (a key/config problem) from "this
   * particular presentation was bad", without the log becoming a place where the
   * fine-grained reason gets copied onto a response by a future caller.
   */
  readonly gate: 'validation' | 'issuer-trust';
  /** Free-form server-side detail. */
  readonly detail: string;
}

/** Everything verification needs that is not the presented bytes. */
export interface WalletCredentialVerificationOptions {
  /** The active `VerifierProfile` (#299) — supplies the posture, never a branch. */
  readonly profile: VerifierProfile;
  /**
   * The `client_id` the request carried. The Key Binding JWT's `aud` is compared
   * against it in constant time, which is what binds the presentation to THIS
   * Verifier rather than to any verifier the wallet has ever talked to.
   */
  readonly clientId: string;
  /** The request `nonce`, verbatim from the redeemed request state. */
  readonly nonce: string;
  /** The DCQL query that was sent, as stored. */
  readonly dcqlQuery: DcqlQuery;
  /** Issuer key backend — see {@link createConfiguredIssuerKeyResolver}. */
  readonly resolveIssuerKey: IssuerKeyResolver;
  /** The presenting realm's issuer allowlist (#236). */
  readonly trustRegistry: TrustRegistry;
  /**
   * This deployment's credential-revocation checker (#297), built ONCE per
   * process by {@link createConfiguredCredentialStatusChecker}.
   *
   * REQUIRED, and explicitly `undefined` when this deployment configured no
   * status checking — never optional, mirroring
   * `PresentationValidationContext.credentialStatus` one layer down. An
   * optional member would let a future caller of this seam omit the checker,
   * compile, and silently serve logins with no revocation checking: #378's
   * defect, reintroduced at the layer built to prevent it. The gate a caller
   * cannot forget is the only kind that holds.
   *
   * `undefined` means nothing is fetched and `assurance.statusChecked` reports
   * `'not-required'`. That is safe only because the two ways of getting it wrong
   * are already closed elsewhere — a profile whose `requireCredentialStatus` is
   * `true` never boots without a checker
   * (`assertCredentialStatusProvisioned`), and validation refuses outright if it
   * somehow did.
   *
   * The posture it is read against is NOT a second option here: it is
   * {@link WalletCredentialVerificationOptions.profile}'s own
   * `requireCredentialStatus`, passed through below. A separate knob would be a
   * second answer to a question the profile already answers, and #299's rule is
   * that profiles are data, not branches.
   */
  readonly credentialStatus: CredentialStatusChecker | undefined;
  /**
   * This deployment's key-storage-assurance gate (HAIP §9.2/§4.5.1, #308/#379).
   *
   * REQUIRED, and explicitly `undefined` only when this deployment evaluates no
   * key storage at all — never optional, for exactly the reason
   * {@link credentialStatus} above is not. #379 is the issue recording that
   * `keyStorageAssuranceGateFor`, `createKeyStorageAssuranceResolver` and
   * `createStaticAttestingIssuers` shipped complete, exported and tested with
   * ZERO non-test callers, so every credential the auth-server produced carried
   * `assurance.keyStorageAssurance === { assurance: 'none' }` unconditionally.
   * An omittable gate is how that happens.
   *
   * Build it with `keyStorageAssuranceGateFor(profile, resolver)` and NEVER by
   * object literal. The helper pairs the profile's POSTURE with the deployment's
   * RESOLVER, which is why the two travel as one object: a literal lets a caller
   * supply a resolver without the policy it must be read against, or a policy
   * with no resolver, either of which silently disables the gate. With the
   * helper, a `required` profile whose resolver was never provisioned refuses
   * every presentation instead of downgrading itself to `forbidden`.
   *
   * `undefined` is materially weaker than a gate built from the profile — the
   * adapter reads it as "not evaluated" without consulting the profile at all —
   * so a caller that has {@link profile} in hand always has something better to
   * pass. It is nullable rather than absent only so a caller with no profile
   * resolved can still state the answer.
   */
  readonly keyStorageAssurance: KeyStorageAssuranceGate | undefined;
  /** Where the server-side reason goes. Wire it to the request logger. */
  readonly onRefusal?: (refusal: WalletCredentialRefusal) => void;
}

/**
 * Build the configuration-pinned issuer key resolver from `OID4VP_ISSUER_JWKS`.
 *
 * Constructed ONCE per key map — it validates every entry eagerly and throws on
 * a malformed one, which is correct at bootstrap and wrong on a request path.
 *
 * The parameter is deliberately structural rather than `server-config`'s
 * `PerIssuerKeySets`: this layer should not force a config-library type on
 * anything that wants to supply keys from somewhere else (a database, a fetching
 * backend). What matters is the shape.
 *
 * @param issuerJwks - issuer identifier → that issuer's public JWKs.
 * @returns a resolver over the pinned key sets. An issuer absent from the map
 * resolves to nothing, which refuses the presentation — never accepts it.
 * @throws Error when an entry is unusable (a mis-provisioned deployment).
 */
export function createConfiguredIssuerKeyResolver(
  issuerJwks: Readonly<Record<string, readonly Readonly<Record<string, unknown>>[]>>
): IssuerKeyResolver {
  const entries: StaticIssuerKeyEntry[] = Object.entries(issuerJwks ?? {}).map(
    ([issuer, jwks]) => ({ issuer, jwks: jwks as StaticIssuerKeyEntry['jwks'] })
  );

  return createStaticIssuerKeyResolver(entries);
}

/**
 * Validate presented credentials and confirm their issuers are trusted.
 *
 * @param presentations - what `parseVpToken` structurally parsed. Attacker bytes.
 * @param options - see {@link WalletCredentialVerificationOptions}.
 * @returns every credential, validated and issuer-trusted. Never a partial set:
 * the batch is all-or-nothing, matching `validatePresentations`, because a
 * caller that received "these three of five are fine" would have to decide which
 * absence is acceptable — and that decision does not belong at a call site.
 * @throws InvalidCredentialsError — the SAME one, for every refusal.
 */
export async function verifyWalletPresentations(
  presentations: readonly PresentedCredential[],
  options: WalletCredentialVerificationOptions
): Promise<readonly ValidatedCredential[]> {
  const refuse = (gate: WalletCredentialRefusal['gate'], detail: string): never => {
    try {
      options.onRefusal?.({ gate, detail });
    } catch {
      // A logger that throws must not turn a uniform refusal into a 500 — the
      // thing that reports a failure may not become one.
    }
    throw issuerTrustRejection();
  };

  // An empty batch is a refusal, not a vacuous success. `validatePresentations`
  // would return `[]` and every `.every()` over it would be true, which is the
  // classic way an "all credentials are trusted" loop authenticates nobody's
  // credential.
  if (!Array.isArray(presentations) || presentations.length === 0) {
    return refuse('validation', 'the response carried no presentations');
  }

  let validated: readonly ValidatedCredential[];
  try {
    validated = await validatePresentations(presentations, options.dcqlQuery, {
      clientId: options.clientId,
      nonce: options.nonce,
      // The profile's declared algorithms ARE the ecosystem's algorithm
      // envelope: `oid4vp-1.0-base` permits EdDSA and ES256, `haip-1.0` pins
      // ES256 (HAIP §7). Reading them from the profile rather than from a
      // separate variable keeps "which algorithms does this deployment speak"
      // a single answer — #299's rule that profiles are data, not branches.
      signatureAlgorithms: options.profile
        .signingAlgs as PresentationValidationContext['signatureAlgorithms'],
      resolveIssuerKey: options.resolveIssuerKey,
      permittedFormats: options.profile.credentialFormats,
      // Credential revocation (#297/#378). Both members come from this
      // deployment's own configuration, never from the presentation: the checker
      // is the process-wide singleton, and the posture is copied verbatim off
      // the resolved profile the same way `permittedFormats` and
      // `signatureAlgorithms` are just above. Passed unconditionally — a
      // conditional spread here would reproduce the omission the required
      // members below the seam exist to make impossible.
      credentialStatus: options.credentialStatus,
      requireCredentialStatus: options.profile.requireCredentialStatus,
      // Key-storage assurance (#308/#379). Passed through verbatim rather than
      // rebuilt here: the gate carries the profile's posture AND this
      // deployment's resolver, and reconstructing either half at this seam would
      // be the second answer to a question the caller already answered. Passed
      // unconditionally for the same reason the two members above are — a
      // conditional spread would reproduce the omission that made #308's gate
      // unreachable in the first place.
      keyStorageAssurance: options.keyStorageAssurance,
    });
  } catch (error) {
    if (isPresentationValidationRejection(error)) {
      return refuse('validation', `${error.reason}: ${error.detail}`);
    }
    // Everything else is rethrown rather than laundered into an authentication
    // failure, so a broken deployment does not look like a wallet that presented
    // a bad credential.
    //
    // ONE thing reaching here is a refusal rather than a fault, and is left
    // unwrapped on purpose: the `InvalidCredentialsError` the status checker
    // throws (#297). Its message already IS the single non-enumerating refusal
    // `refuse()` would produce, so the wire is byte-identical either way, and
    // catching it to re-shape it would gain nothing but a `detail` string whose
    // only honest content is the status list URI and index the WALLET chose.
    // The precise server-side reason is not lost — it reaches the operator
    // through the checker's own `onAudit` sink, which reports every check
    // including the accepted ones, so `onRefusal` is not the log seam for
    // status and must not be made into one.
    throw error;
  }

  if (validated.length === 0) {
    return refuse('validation', 'validation produced no credentials');
  }

  for (const credential of validated) {
    try {
      // Contained by `assertIssuerTrusted`, which throws the same refusal for a
      // registry backend that failed as for one that said no.
      assertIssuerTrusted(options.trustRegistry, credential.issuer, {
        onBackendError: (error) => {
          options.onRefusal?.({
            gate: 'issuer-trust',
            detail: `trust registry backend threw: ${String(error)}`,
          });
        },
      });
    } catch {
      // Re-thrown through `refuse` rather than propagated verbatim, so the
      // caller's logger sees WHICH gate refused. The error a caller receives is
      // byte-identical either way — that is the non-enumeration property, and
      // the reason the identifier is not on it.
      return refuse('issuer-trust', 'the credential issuer is not trusted by this realm');
    }
  }

  return validated;
}

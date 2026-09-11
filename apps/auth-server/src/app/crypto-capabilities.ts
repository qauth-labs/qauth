/**
 * What THIS deployment's crypto layer can actually operate, for the
 * `VerifierProfile` fail-closed boot gate (#299).
 *
 * Split out of `app.ts` so it is a pure, unit-testable function of the
 * deployment's provisioned key material rather than a literal buried in the
 * bootstrap. The gate it feeds
 * (`assertProfileWithinCryptoCapabilities`) refuses to start a deployment whose
 * selected profile declares crypto this deployment cannot honour, so a
 * capability claimed here that is not real is not a documentation bug — it is a
 * lifted security control, and the failure surfaces as 100% of wallet
 * presentations failing in production.
 *
 * The distinction this module exists to hold:
 *
 *   - `@qauth-labs/core-crypto` EXPORTING an algorithm means the code to compute
 *     it exists.
 *   - This deployment being able to OPERATE it means there is a code path that
 *     uses it AND whatever that path needs is in place — a provisioned key,
 *     where the path needs one.
 *
 * `VerifierCryptoCapabilities` documents its fields with the second meaning
 * ("can sign a request with TODAY", "CAN encrypt an Authorization Response"), so
 * this module answers the second question. Deriving the answer from the first —
 * from the mere existence of a library function — is what makes a stale
 * descriptor, and a stale capability descriptor is worse than none.
 *
 * The two halves of that second question do not weigh the same for every
 * capability, and the descriptor has one entry where they come apart. Every
 * SIGNING algorithm needs operator material, so its answer is a predicate over
 * provisioned keys. Response ENCRYPTION needs none — the pair is minted per
 * request (HAIP §5) and the intake decrypts with it — so once the code path
 * exists (#377 Phase C) its answer is a property of the BUILD, not of the
 * configuration, and it is `true` for every deployment. It stays in this
 * function rather than being hoisted to a constant elsewhere so that the whole
 * descriptor is still derived in one place from one stated rule.
 */
import type { JwsAlgorithm } from '@qauth-labs/core-crypto';
import type { VerifierCryptoCapabilities } from '@qauth-labs/fastify-plugin-federation';

/**
 * The signing key material the operator has actually provisioned, taken straight
 * from the parsed env.
 *
 * Passed in rather than read from `../config/env` here so this stays a pure
 * function: the boot gate's behaviour is then provable in a unit test that does
 * not need a valid environment, which is the same property
 * `createConfiguredProviders` is built around.
 */
export interface ProvisionedSigningKeys {
  /**
   * `JWT_RS256_PRIVATE_KEY` / `_PATH` after resolution (#309). `undefined` when
   * the operator configured no RS256 key, which is the default posture.
   */
  readonly rs256PrivateKey: string | undefined;
  /**
   * `OID4VP_VERIFIER_SIGNING_KEY` / `_PATH` after resolution (#377) — the ES256
   * key QAuth signs an OID4VP Authorization Request with.
   *
   * A DIFFERENT key set from the two above, and deliberately named as such. The
   * `rs256PrivateKey` field is a TOKEN-ISSUANCE key whose public half is
   * published in `GET /.well-known/jwks.json`; this one proves QAuth's identity
   * to a WALLET and is published nowhere. #298's risk note: *"the two key sets
   * must not be interchangeable."*
   */
  readonly verifierEs256PrivateKey: string | undefined;
  /**
   * `OID4VP_VERIFIER_CERTIFICATE_CHAIN` / `_PATH` after resolution (#377), as
   * individual PEM certificates.
   *
   * Read alongside the key because a key with no chain cannot sign anything a
   * wallet can act on: the Verifier identity is established from the `x5c`
   * header, so a signature under a certificate nobody received identifies
   * nobody. Whether the chain VALIDATES is `createVerifierSigningMaterial`'s
   * answer at boot — a deployment whose chain does not validate never reaches a
   * request, because it does not finish starting.
   */
  readonly verifierCertificateChainPems: readonly string[];
}

/**
 * Derive the deployment's verifier crypto capabilities from provisioned keys.
 *
 * The inner record is pinned EXHAUSTIVELY to the crypto layer's own union with
 * `satisfies Record<JwsAlgorithm, boolean>` (#299): widening `JwsAlgorithm`
 * stops this literal compiling until the new algorithm is given an ANSWER, so
 * the descriptor can never go stale by silence. What changed after #298 is the
 * shape of that answer — `true` used to mean "the union names it", which
 * conflated the library with the deployment; now each entry states whether a key
 * for that algorithm exists HERE.
 *
 * Note that "a key exists here" is answered per ALGORITHM, not per PURPOSE. The
 * `ES256` entry reads the OID4VP verifier's key and the `EdDSA`/`RS256` entries
 * read the token-issuance keys, and those two key sets are not interchangeable
 * (#298): a deployment claiming `ES256` can sign an Authorization Request to a
 * wallet, and that is the only thing it claims.
 *
 * @param keys - provisioned signing key material.
 * @returns the capability descriptor handed to `createConfiguredProviders`.
 */
export function deriveCryptoCapabilities(keys: ProvisionedSigningKeys): VerifierCryptoCapabilities {
  const signingKeyProvisioned = {
    // The env schema REQUIRES an EdDSA key (`JWT_PRIVATE_KEY` or its `_PATH`)
    // and refuses to parse without one, so any deployment that reached this
    // function has one. This is the algorithm every QAuth token is signed with.
    EdDSA: true,
    // OPTIONAL and env-provisioned (#309). Absent by default, and when it is
    // absent nothing in this build can produce an RS256 signature — claiming it
    // unconditionally was the same category of error as claiming ES256.
    RS256: keys.rs256PrivateKey !== undefined && keys.rs256PrivateKey.trim().length > 0,
    // OPTIONAL and env-provisioned (#377), and the ONLY entry whose predicate
    // reads two variables rather than one. #298 landed `sign(..., 'ES256', ...)`
    // years before anything could use it; what was missing was never the
    // algorithm but the MATERIAL, and the material is a pair. A P-256 key with
    // no certificate chain can produce a signature no wallet can attribute to
    // anyone — OID4VP 1.0 §5.9.3 establishes the Verifier identity from the
    // `x5c` header — so claiming ES256 on the key alone would lift the gate for
    // a deployment that still cannot present a verifiable request.
    //
    // Both halves are read as CONFIGURED, not as VALID. Validity is
    // `createVerifierSigningMaterial`'s answer, and it is a boot REFUSAL rather
    // than a capability downgrade: a deployment whose chain does not anchor
    // never finishes starting, so it never reaches this descriptor with a false
    // claim. Re-deriving validity here would need this pure function to parse
    // certificates, which is exactly the layering the module JSDoc rejects.
    ES256:
      keys.verifierEs256PrivateKey !== undefined &&
      keys.verifierEs256PrivateKey.trim().length > 0 &&
      keys.verifierCertificateChainPems.length > 0,
  } satisfies Record<JwsAlgorithm, boolean>;

  return {
    signingAlgs: Object.entries(signingKeyProvisioned)
      .filter(([, provisioned]) => provisioned)
      .map(([alg]) => alg),
    // TRUE, UNCONDITIONALLY — and deliberately so, in a function whose other
    // entries are predicates over provisioned keys (#377 Phase C).
    //
    // The standard this module holds is "can this deployment OPERATE it", and
    // for a signing algorithm that means a key exists here. Response encryption
    // needs no operator key: the ECDH-ES pair is minted PER REQUEST (HAIP §5,
    // "ephemeral encryption public keys specific to each Authorization
    // Request"), its public half is published in `client_metadata`, its private
    // half rides the request-state row, and `POST /oid4vp/response` decrypts
    // with it. All of that ships in this build, so every deployment running it
    // can operate the `direct_post.jwt` mode with nothing configured — which
    // makes `true` the truthful answer and any predicate a lie by omission.
    //
    // It was FALSE before Phase C for the reason ES256 once was: the primitives
    // existed and nothing called them, so a descriptor claiming the capability
    // would have asked wallets for a response QAuth had nowhere to hand to.
    // What changed is the code path, not the configuration, and that is why
    // this entry reads no key. `OID4VP_RESPONSE_KEY_SECRET` is NOT a
    // precondition: it changes how the private half is stored, not whether the
    // path works, and a misconfigured value is a boot refusal in `app.ts`.
    responseEncryption: true,
  };
}

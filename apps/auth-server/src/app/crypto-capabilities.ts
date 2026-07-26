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
 *   - This deployment being able to SIGN WITH it means a key for it has been
 *     provisioned and there is a code path that uses it.
 *
 * `VerifierCryptoCapabilities` documents its fields with the second meaning
 * ("can sign a request with TODAY", "CAN encrypt an Authorization Response"), so
 * this module answers the second question. Deriving the answer from the first —
 * from the mere existence of a library function — is what makes a stale
 * descriptor, and a stale capability descriptor is worse than none.
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
    // FALSE, and not because the crypto layer cannot compute an ES256 signature
    // — #298 landed `sign(..., 'ES256', ...)` and it works. There is no way for
    // an operator to provision a P-256 signing key: no env var, no schema field,
    // no JWKS entry, and no federation code path that would sign an OID4VP
    // Authorization Request with one. Certificate/key provisioning for the
    // signed Client Identifier Prefixes is #233's job; this flips to a real
    // predicate over that config in the same commit that adds it, and `haip-1.0`
    // becomes selectable then — not before.
    ES256: false,
  } satisfies Record<JwsAlgorithm, boolean>;

  return {
    signingAlgs: Object.entries(signingKeyProvisioned)
      .filter(([, provisioned]) => provisioned)
      .map(([alg]) => alg),
    // FALSE for the same reason. `@qauth-labs/core-crypto` exports `encryptJwe`
    // / `decryptJwe` and the per-request ephemeral key helpers, but nothing in
    // the workspace calls them: the federation layer has no `direct_post.jwt`
    // response mode, no published `client_metadata` encryption JWK, and no
    // intake route to decrypt at. A deployment that advertised
    // `direct_post.jwt` to wallets on the strength of an uncalled library
    // function would ask for a response it has nowhere to hand to — exactly the
    // "asking a wallet for a response it cannot decrypt" the gate's refusal
    // text names. Flips with the #233/#234 response-intake path.
    responseEncryption: false,
  };
}

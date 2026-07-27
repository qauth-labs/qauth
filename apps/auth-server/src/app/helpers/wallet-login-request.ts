import {
  buildOid4vpAuthorizationRequest,
  type CredentialRequestSpec,
  DIRECT_POST_RESPONSE_MODE,
  encodeOid4vpRequestUri,
  generateOid4vpRequestSecrets,
  hashOid4vpState,
  type Oid4vpAuthorizationRequest,
  resolveOid4vpExpiry,
  resolveVerifierProfile,
  SD_JWT_VC_FORMAT,
  type VerifierProfile,
} from '@qauth-labs/fastify-plugin-federation';
import type { FastifyInstance } from 'fastify';

import { env } from '../../config/env';
import { resolveIssuerIdentifier } from './discovery';

/**
 * Wallet-login request construction and the FAIL-CLOSED availability gate
 * (issue #239, ADR-004).
 *
 * ## The gate is the feature
 *
 * #296 is LOCKED on this: *"There is never a permissive fallback to the more
 * capable profile."* A deployment that has not selected a `VerifierProfile`
 * (#299) does not get a degraded wallet login — it gets no wallet login, and no
 * button offering one. {@link resolveWalletLoginCapability} is where that is
 * decided, and it answers `undefined` for every reason a wallet flow could not
 * be served correctly:
 *
 * - wallet federation is switched off (`WALLET_FEDERATION_ENABLED`, #232);
 * - no profile is selected, or the selected one is not provisioned (#299);
 * - the profile's posture needs capabilities this deployment does not have —
 *   a signed request or an encrypted response, both of which wait on #298;
 * - the profile does not permit the one credential format QAuth ships an
 *   adapter for (`dc+sd-jwt`; `mso_mdoc` needs ISO/IEC 18013-5, epic #231);
 * - the operator has not said WHICH credential to ask for
 *   (`OID4VP_REQUESTED_VCT`) — a query with no type constraint asks a wallet for
 *   any credential it holds, which OID4VP 1.0 §15.6 warns against.
 *
 * The posture checks duplicate refusals that `buildOid4vpAuthorizationRequest`
 * makes anyway, and that duplication is deliberate: the builder throwing is the
 * correct behaviour at request time, but a login page must not RENDER a button
 * whose only possible outcome is a 500. The builder remains the authority — it
 * is called with the same profile and re-asks every question — so the two cannot
 * drift into disagreement about what is permitted, only about when it is
 * noticed.
 */

/** Path of the `direct_post` Response Endpoint (`routes/oid4vp/response.ts`). */
export const OID4VP_RESPONSE_PATH = '/oid4vp/response';

/**
 * DCQL Credential Query id used by the login flow.
 *
 * One query, one id: the `vp_token` a wallet returns is a map keyed by these
 * ids (OID4VP 1.0 §8.1), and a stable id keeps the correlation trivial for #234.
 */
export const WALLET_LOGIN_CREDENTIAL_QUERY_ID = 'qauth_wallet_login';

/** Everything needed to build a wallet-login request, once the gate has passed. */
export interface WalletLoginCapability {
  /** The resolved active profile (#299). */
  readonly profile: VerifierProfile;
  /** Absolute `response_uri` the wallet posts to (OID4VP 1.0 §8.2, REQUIRED). */
  readonly responseUri: string;
  /** Wallet Authorization Endpoint the QR/deep link targets (§5). */
  readonly walletInvocationEndpoint: string;
  /** What the Verifier asks for — derived from `OID4VP_REQUESTED_VCT`. */
  readonly credentials: readonly CredentialRequestSpec[];
}

/** One built presentation request, plus everything the flow has to persist. */
export interface WalletLoginInvocation {
  /**
   * The wallet invocation URI — OPAQUE to the UI layer. Under
   * `oid4vp-1.0-base` it carries the request parameters inline; under HAIP it
   * would be a `request_uri` reference to a signed JAR (RFC 9101, #298). The
   * page renders whatever this is without interpreting it.
   */
  readonly invocationUri: string;
  /** The request as built, for persistence of its DCQL query. */
  readonly request: Oid4vpAuthorizationRequest;
  /** SHA-256 of the request `state` — the only form ever persisted to the DB. */
  readonly stateHash: string;
  /** The request `nonce`, stored in the clear for #234 to compare verbatim. */
  readonly nonce: string;
  /** Absolute expiry (epoch ms) of the request. */
  readonly expiresAt: number;
}

/**
 * Decide whether this deployment can serve a wallet login at all.
 *
 * @param fastify - server instance, for logging.
 * @returns the capability, or `undefined` when no wallet flow may be offered.
 * Never throws: a half-provisioned profile (`resolveVerifierProfile` throwing)
 * is an operator error that must not take down the password login page that
 * calls this to decide whether to render one extra link.
 */
export function resolveWalletLoginCapability(
  fastify: FastifyInstance
): WalletLoginCapability | undefined {
  if (!env.WALLET_FEDERATION_ENABLED) return undefined;

  let profile: VerifierProfile | undefined;
  try {
    // The realm argument is null because `realms.verifier_profile` does not
    // exist yet (#299) — the same call shape `routes/oid4vp/response.ts` uses,
    // so per-realm selection lands in both places at once.
    profile = resolveVerifierProfile(null, {
      OID4VP_VERIFIER_PROFILE: env.OID4VP_VERIFIER_PROFILE,
    });
  } catch (error) {
    fastify.log.error(
      { err: error },
      'wallet login unavailable: the selected VerifierProfile is not provisioned'
    );
    return undefined;
  }

  if (profile === undefined) return undefined;

  const vctValues = env.OID4VP_REQUESTED_VCT;
  if (vctValues === undefined || vctValues.length === 0) {
    fastify.log.debug('wallet login unavailable: OID4VP_REQUESTED_VCT is not configured');
    return undefined;
  }

  if (!profile.credentialFormats.includes(SD_JWT_VC_FORMAT)) return undefined;
  if (!profile.responseModes.includes(DIRECT_POST_RESPONSE_MODE)) return undefined;
  // Both wait on #298. Refused here rather than downgraded — a downgrade is the
  // "half-configured verifier" #299 forbids.
  if (profile.responseEncryption === 'required') return undefined;
  if (profile.requestSigning === 'required') return undefined;

  return {
    profile,
    responseUri: `${resolveIssuerIdentifier(env.JWT_ISSUER)}${OID4VP_RESPONSE_PATH}`,
    walletInvocationEndpoint: env.OID4VP_WALLET_INVOCATION_ENDPOINT,
    credentials: [
      {
        id: WALLET_LOGIN_CREDENTIAL_QUERY_ID,
        format: SD_JWT_VC_FORMAT,
        typeValues: [...vctValues],
      },
    ],
  };
}

/**
 * Build one presentation request and its wallet invocation URI.
 *
 * Pure apart from the CSPRNG: `state`/`nonce` are minted here and the caller
 * persists the row. Delegates every posture decision to
 * `buildOid4vpAuthorizationRequest`, which re-asks the profile about each
 * capability it exercises.
 *
 * @throws Error when the active profile forbids something the request needs.
 * The caller renders the uniform refusal — this is an operator misconfiguration,
 * and the user must not be told which one.
 */
export function buildWalletLoginInvocation(
  capability: WalletLoginCapability,
  clientName?: string
): WalletLoginInvocation {
  const secrets = generateOid4vpRequestSecrets();

  const request = buildOid4vpAuthorizationRequest({
    profile: capability.profile,
    responseUri: capability.responseUri,
    credentials: capability.credentials,
    state: secrets.state,
    nonce: secrets.nonce,
    ...(clientName === undefined ? {} : { clientName }),
  });

  return {
    invocationUri: encodeOid4vpRequestUri(capability.walletInvocationEndpoint, request),
    request,
    // Re-digested from the value that actually went into the request rather than
    // copied from `secrets`, so the stored key can only ever be the hash of the
    // `state` on the wire.
    stateHash: hashOid4vpState(request.state),
    nonce: request.nonce,
    expiresAt: resolveOid4vpExpiry(),
  };
}

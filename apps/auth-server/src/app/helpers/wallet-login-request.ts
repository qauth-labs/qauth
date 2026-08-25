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
  signOid4vpRequestObject,
  verifierMaterialProvisionedBy,
  type VerifierProfile,
  type VerifierSigningMaterial,
} from '@qauth-labs/fastify-plugin-federation';
import type { FastifyInstance } from 'fastify';

import { env } from '../../config/env';
import { resolveIssuerIdentifier } from './discovery';
import { verifierSigningMaterial } from './verifier-identity';
import { storeWalletRequestObject } from './wallet-login-flow';

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
 * Path PREFIX of the JAR Request Object Endpoint
 * (`routes/oid4vp/request-object.ts`, #377).
 *
 * A prefix rather than a whole path because the handle is minted per request.
 * Written here beside the response path so both wallet-facing URLs are built
 * from one place and neither can drift from the route that serves it.
 */
export const OID4VP_REQUEST_OBJECT_PATH_PREFIX = '/oid4vp/request/';

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
  /** Absolute base the `request_uri` reference is built on (#377). */
  readonly requestObjectBaseUri: string;
  /** Wallet Authorization Endpoint the QR/deep link targets (§5). */
  readonly walletInvocationEndpoint: string;
  /** What the Verifier asks for — derived from `OID4VP_REQUESTED_VCT`. */
  readonly credentials: readonly CredentialRequestSpec[];
  /**
   * The verifier's validated ES256 key and chain (#377), or `undefined` when
   * the deployment provisioned none.
   *
   * Carried on the CAPABILITY rather than looked up at build time so the gate
   * and the builder read one value: a page that offered a wallet login because
   * signing material existed must not then build a request without it.
   */
  readonly signingMaterial: VerifierSigningMaterial | undefined;
}

/** One built presentation request, plus everything the flow has to persist. */
export interface WalletLoginInvocation {
  /**
   * The wallet invocation URI — OPAQUE to the UI layer. Under
   * `oid4vp-1.0-base` it carries the request parameters inline; under a profile
   * that mandates signed requests it is a `request_uri` reference to a signed
   * JAR (RFC 9101, HAIP §5.1, #377). The page renders whatever this is without
   * interpreting it.
   */
  readonly invocationUri: string;
  /**
   * Handle addressing the parked request object, when the request was signed.
   *
   * Returned so the flow that owns it can delete it on a terminal outcome, the
   * way it already deletes its own record. `undefined` for an unsigned request,
   * where there is no request object at all.
   */
  readonly requestObjectHandle?: string;
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
  // Waits on Phase C of #377. Refused here rather than downgraded — a downgrade
  // is the "half-configured verifier" #299 forbids.
  if (profile.responseEncryption === 'required') return undefined;

  // Signed requests are no longer a blanket refusal (#377): a deployment that
  // provisioned an ES256 key and a chain can sign one. What is still refused is
  // a profile that MANDATES signing on a deployment that provisioned nothing to
  // sign with — the builder would throw at request time, and a login page must
  // not render a button whose only possible outcome is a 500.
  const signingMaterial = resolveSigningMaterial(fastify);

  if (profile.requestSigning === 'required' && signingMaterial === undefined) {
    fastify.log.debug(
      'wallet login unavailable: the selected VerifierProfile requires signed Authorization Requests and no OID4VP verifier signing material is provisioned'
    );
    return undefined;
  }

  const issuer = resolveIssuerIdentifier(env.JWT_ISSUER);

  return {
    profile,
    responseUri: `${issuer}${OID4VP_RESPONSE_PATH}`,
    requestObjectBaseUri: `${issuer}${OID4VP_REQUEST_OBJECT_PATH_PREFIX}`,
    walletInvocationEndpoint: env.OID4VP_WALLET_INVOCATION_ENDPOINT,
    credentials: [
      {
        id: WALLET_LOGIN_CREDENTIAL_QUERY_ID,
        format: SD_JWT_VC_FORMAT,
        typeValues: [...vctValues],
      },
    ],
    signingMaterial,
  };
}

/**
 * Read the deployment's verifier signing material without ever throwing.
 *
 * {@link verifierSigningMaterial} throws on a partial or invalid configuration,
 * and at BOOT that is exactly right — `app.ts` calls it during registration and
 * the deployment refuses to start. Reaching it again from this function means
 * the boot already accepted the configuration, so a throw here would be a
 * different process's problem; it is caught anyway because
 * {@link resolveWalletLoginCapability} promises never to throw, and the password
 * login page calls it to decide whether to render one extra link.
 */
function resolveSigningMaterial(fastify: FastifyInstance): VerifierSigningMaterial | undefined {
  try {
    return verifierSigningMaterial();
  } catch (error) {
    fastify.log.error(
      { err: error },
      'wallet login unavailable: the OID4VP verifier signing material is misconfigured'
    );
    return undefined;
  }
}

/**
 * Build one presentation request and its wallet invocation URI.
 *
 * Delegates every posture decision to `buildOid4vpAuthorizationRequest`, which
 * re-asks the profile about each capability it exercises — including WHETHER the
 * request is signed, which follows from the Client Identifier Prefix the profile
 * presents and is not decided here.
 *
 * Asynchronous since #377, and only for the signed path: producing a JWS needs a
 * key import, and parking it for the wallet to fetch needs the session store. An
 * unsigned request does neither and takes the same shape it always had.
 *
 * @param fastify - server instance; the signed path parks the request object on
 * the session store this owns.
 * @param capability - the resolved capability, carrying the signing material.
 * @param clientName - optional human-readable Verifier name.
 * @throws Error when the active profile forbids something the request needs, or
 * when the request object cannot be parked. The caller renders the uniform
 * refusal — an operator misconfiguration must not be spelled out to a user.
 */
export async function buildWalletLoginInvocation(
  fastify: FastifyInstance,
  capability: WalletLoginCapability,
  clientName?: string
): Promise<WalletLoginInvocation> {
  const secrets = generateOid4vpRequestSecrets();

  const request = buildOid4vpAuthorizationRequest({
    profile: capability.profile,
    responseUri: capability.responseUri,
    credentials: capability.credentials,
    state: secrets.state,
    nonce: secrets.nonce,
    provisioned: verifierMaterialProvisionedBy(capability.signingMaterial),
    ...(capability.signingMaterial === undefined
      ? {}
      : { signingMaterial: capability.signingMaterial }),
    ...(clientName === undefined ? {} : { clientName }),
  });

  const delivery = await deliverRequest(fastify, capability, request);

  return {
    invocationUri: delivery.invocationUri,
    ...(delivery.requestObjectHandle === undefined
      ? {}
      : { requestObjectHandle: delivery.requestObjectHandle }),
    request,
    // Re-digested from the value that actually went into the request rather than
    // copied from `secrets`, so the stored key can only ever be the hash of the
    // `state` on the wire.
    stateHash: hashOid4vpState(request.state),
    nonce: request.nonce,
    expiresAt: resolveOid4vpExpiry(),
  };
}

/** What {@link deliverRequest} produced. */
interface RequestDelivery {
  readonly invocationUri: string;
  readonly requestObjectHandle: string | undefined;
}

/**
 * Put the built request where the wallet can reach it (#377).
 *
 * Which form is used is NOT decided here: `encodeOid4vpRequestUri` reads the
 * Client Identifier Prefix out of `client_id` and refuses the form that
 * contradicts it. This function only does the WORK each form needs — signing and
 * parking for the reference form, nothing for the inline one — and the presence
 * of signing material is what tells it which one it is about to be asked for.
 *
 * The request object is signed and parked BEFORE the URI is rendered, so a
 * failure to store is a failed sign-in attempt rather than a QR code pointing at
 * a handle that was never written.
 */
async function deliverRequest(
  fastify: FastifyInstance,
  capability: WalletLoginCapability,
  request: Oid4vpAuthorizationRequest
): Promise<RequestDelivery> {
  if (capability.signingMaterial === undefined) {
    return {
      invocationUri: encodeOid4vpRequestUri(capability.walletInvocationEndpoint, request),
      requestObjectHandle: undefined,
    };
  }

  const requestObject = await signOid4vpRequestObject({
    request,
    material: capability.signingMaterial,
  });

  const handle = await storeWalletRequestObject(fastify, requestObject);

  return {
    invocationUri: encodeOid4vpRequestUri(capability.walletInvocationEndpoint, request, {
      mode: 'request-uri',
      requestUri: `${capability.requestObjectBaseUri}${handle}`,
    }),
    requestObjectHandle: handle,
  };
}

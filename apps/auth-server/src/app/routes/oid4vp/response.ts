import {
  assertEncryptedResponseStateMatches,
  assertProfileUnchanged,
  assertResponseModeUnchanged,
  type DcqlQuery,
  decryptOid4vpAuthorizationResponse,
  DIRECT_POST_JWT_RESPONSE_MODE,
  DIRECT_POST_RESPONSE_MODE,
  type EncryptedAuthorizationResponse,
  hashOid4vpState,
  type Oid4vpDirectPostOutcome,
  Oid4vpTransportRejection,
  parseStoredDcqlQuery,
  parseVpToken,
  readEncryptedResponseKid,
  type RedeemedOid4vpRequestState,
  resolveVerifierProfile,
} from '@qauth-labs/fastify-plugin-federation';
import type { FastifyInstance } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';
import type { JWK } from 'jose';

import { env } from '../../../config/env';
import { unprotectOid4vpResponseKey } from '../../helpers/oid4vp-response-key';
import { provisionedVerifierMaterial } from '../../helpers/verifier-identity';
import {
  publishWalletPresentationSignal,
  stashWalletPresentation,
} from '../../helpers/wallet-login-flow';
import {
  isEncryptedDirectPostRequest,
  type Oid4vpDirectPostRequest,
  oid4vpDirectPostRequestSchema,
  oid4vpDirectPostResponseSchema,
} from '../../schemas/oid4vp';

/**
 * `POST /oid4vp/response` — the OID4VP 1.0 `direct_post` Response Endpoint
 * (ADR-004, issue #233, Phase A).
 *
 * This is the `response_uri` QAuth-as-Verifier puts in every presentation
 * request. A wallet POSTs the Authorization Response here as
 * `application/x-www-form-urlencoded` (OID4VP 1.0 §8.1–§8.2) — in the clear
 * under `direct_post`, or as ONE `response` parameter carrying a JWE under
 * `direct_post.jwt` (§8.3; HAIP 1.0 §5.1, #377 Phase C).
 *
 * ## THIS ENDPOINT AUTHENTICATES NOBODY
 *
 * It does exactly three things:
 *
 *   1. Redeems the request — ATOMICALLY and exactly once — by whichever
 *      correlator the submission carries: the cleartext `state`, or the JWE
 *      `kid` read out of the protected header without decrypting anything.
 *   2. Confirms the deployment's verifier posture still matches the one the
 *      request was built under — the profile, and the Response Mode.
 *   3. Opens the response if it is encrypted, binds it to the row by the
 *      `state` inside it, and STRUCTURALLY parses `vp_token` against the DCQL
 *      query that was sent.
 *
 * It performs NO signature, credential, issuer, revocation or key-binding
 * validation, and it creates no user, no session and no token. `WalletProvider`
 * is never resolved from here and its `verify()` still throws — deliberately:
 * under ADR-003 the auth engine mints a QAuth token for whatever `externalSub` a
 * provider returns, so a transport round-trip that yielded a subject would let
 * anyone who can POST here self-register as a user. Credential validation is
 * #234, issuer trust is #236, and there is no protocol-guaranteed stable wallet
 * subject identifier at all (ADR-009 / #300) — so nothing here derives or
 * persists an `external_sub`.
 *
 * ## Fail-closed gating
 *
 * The route is not registered unless `WALLET_FEDERATION_ENABLED` is on, so a
 * default deployment answers 404 — the endpoint does not exist rather than
 * existing-and-refusing. Turning that flag on additionally requires a
 * `VerifierProfile` (#299) or the app refuses to boot, and the handler resolves
 * the profile again per request so a deployment that ends up with none refuses
 * wallet flows instead of falling back to a permissive posture (#296, LOCKED).
 *
 * ## Non-enumerating rejections
 *
 * Unknown `state`, expired `state`, already-redeemed `state`, changed posture,
 * an unusable stored `dcql_query` and a malformed `vp_token` all produce the
 * SAME 400 `invalid_request` with the same description. The specific reason is
 * logged server-side only. An attacker holding a candidate `state` therefore
 * learns nothing about whether it exists, is still alive, or was already
 * consumed — including from a deployment whose stored state is corrupt, since
 * that failure is only reachable AFTER redemption and would otherwise be the one
 * response shape a real `state` uniquely produces.
 *
 * The encrypted path adds unknown `kid`, undecryptable ciphertext, an unreadable
 * stored key and a `state` that does not match the row to that list, and every
 * one of them renders the same refusal — with the same ordering discipline:
 * the row is CONSUMED by its `kid` before a single byte of ciphertext is
 * touched, so a failed decrypt cannot be retried against a still-live row, and
 * a caller who can choose the ciphertext learns nothing from which byte it
 * failed on.
 *
 * ## The `kid` is an index, not a proof (OID4VP 1.0 §14.5)
 *
 * An encrypted Authorization Response carries no integrity protection tying it
 * to a request, so the `kid` — the only thing outside the ciphertext — is
 * attacker-controlled and is used ONLY to find a row. What binds the response
 * to the request is the `state` INSIDE the decrypted payload, compared against
 * the row's digest (§5.3). Nothing between finding the row and that comparison
 * trusts anything.
 */
export default async function (fastify: FastifyInstance) {
  // Flag gate (#232 / #299). Checked at REGISTRATION, not per request: an
  // endpoint that does not exist cannot be probed, and a deployment that never
  // opted into wallet federation should not grow an unauthenticated POST
  // surface. `createConfiguredProviders` has already refused the boot if this
  // flag is on without a profile, so reaching the handler implies both.
  if (!env.WALLET_FEDERATION_ENABLED) {
    fastify.log.debug(
      'OID4VP direct_post response endpoint not registered (WALLET_FEDERATION_ENABLED is off)'
    );
    return;
  }

  fastify.withTypeProvider<ZodTypeProvider>().post(
    '/response',
    {
      schema: {
        description:
          'OID4VP 1.0 direct_post Response Endpoint. Accepts a wallet Authorization Response as application/x-www-form-urlencoded: in the clear (vp_token + state, or error + state) under response_mode=direct_post, or as a single `response` parameter carrying a JWE (ECDH-ES P-256, A128GCM/A256GCM) encrypted to the per-request key published in client_metadata under response_mode=direct_post.jwt. TRANSPORT ONLY: the response is correlated against a single-use presentation request and structurally parsed. No signature, credential or issuer validation is performed and no user is authenticated (that is #234/#236).',
        tags: ['OID4VP'],
        body: oid4vpDirectPostRequestSchema,
        response: { 200: oid4vpDirectPostResponseSchema },
      },
      config: {
        // IP-scoped rate limit, in the shape every other unauthenticated surface
        // in this app uses (/oauth/token, /oauth/register, /auth/login).
        // Mandatory here for the same reason the rejections are uniform: the
        // endpoint is unauthenticated by construction, so this cap is what bounds
        // how fast an anonymous caller can throw candidate `state` values — and
        // DB round-trips — at it. Defaults to /oauth/token's 30 per 60s; a real
        // wallet posts once per presentation request.
        rateLimit: {
          max: env.OID4VP_RESPONSE_RATE_LIMIT,
          timeWindow: env.OID4VP_RESPONSE_RATE_WINDOW * 1000,
          keyGenerator: (request) => request.ip || 'unknown',
        },
      },
    },
    async (request, reply) => {
      const body = request.body as Oid4vpDirectPostRequest;

      // Which Response Mode this submission ARRIVED in, decided by its shape
      // and by nothing the caller says about itself: one `response` parameter
      // is the encrypted mode (§8.3), a cleartext `state` is the plain one.
      // Compared against the mode the request ASKED for once the row is read.
      const arrivedMode = isEncryptedDirectPostRequest(body)
        ? DIRECT_POST_JWT_RESPONSE_MODE
        : DIRECT_POST_RESPONSE_MODE;

      try {
        // (1) Single-use redemption. One guarded UPDATE — see the repository.
        // Deliberately the FIRST thing that happens: a replayed or expired state
        // must be rejected before any work is done on attacker-supplied bytes.
        //
        // The ENCRYPTED submission is redeemed by the JWE `kid` (#377 Phase C),
        // read out of the protected header alone — a base64 decode and a JSON
        // parse, no key operation — so the ordering discipline survives the
        // ciphertext: the row is consumed before anything is decrypted, and a
        // decrypt that fails has already spent the request. Redeeming AFTER a
        // failed decrypt would leave the row live for the next attempt, which
        // turns an unauthenticated POST into a retry oracle against a key QAuth
        // itself published.
        const redeemed = isEncryptedDirectPostRequest(body)
          ? await fastify.repositories.oid4vpRequestStates.redeemByEncryptionKid(
              readEncryptedResponseKid(body.response)
            )
          : await fastify.repositories.oid4vpRequestStates.redeem(hashOid4vpState(body.state));

        if (redeemed === undefined) {
          throw new Oid4vpTransportRejection(
            `${arrivedMode === DIRECT_POST_JWT_RESPONSE_MODE ? 'encryption kid' : 'state'} did not redeem (unknown, expired, or already consumed)`
          );
        }

        // The digest the flow record and the parked presentation are addressed
        // by. On the cleartext path it is what the row was just found BY; on
        // the encrypted path it is what the decrypted `state` is held to below
        // — either way, the stored column and never a value the caller chose.
        const stateHash = redeemed.stateHash;

        // (2) Posture. The realm argument is null because `realms.verifier_profile`
        // does not exist yet (#299); when it does, the redeemed row already
        // carries the `realm_id` this resolves for, with no change to the call
        // shape. `undefined` means no profile is selected → wallet flows are
        // refused outright, never served under a fallback posture.
        //
        // The provisioned material is threaded for the reason
        // `helpers/wallet-login-request.ts` gives at its own call site (#377):
        // `resolveVerifierProfile` folds in `assertVerifierIdentityProvisioned`,
        // and the default `NO_VERIFIER_MATERIAL` would make a profile requiring
        // an X.509 verifier identity throw on a deployment that provisioned one
        // and booted on it — every presentation refused, on the endpoint whose
        // refusals are deliberately indistinguishable from a forgery. Read from
        // the one helper `app.ts`'s boot gate reads.
        const profile = resolveVerifierProfile(
          null,
          { OID4VP_VERIFIER_PROFILE: env.OID4VP_VERIFIER_PROFILE },
          provisionedVerifierMaterial()
        );

        if (profile === undefined) {
          throw new Oid4vpTransportRejection('no VerifierProfile is selected for this deployment');
        }

        assertProfileUnchanged(redeemed.verifierProfile, profile.id);

        // The mode is posture too (#377 Phase C). A request built under a
        // profile that REQUIRES encryption asked for `direct_post.jwt`, and a
        // cleartext post holding its `state` — which anyone who read the signed
        // request object has — must not consume it; the reverse mismatch cannot
        // correlate at all, but the check is stated symmetrically anyway.
        assertResponseModeUnchanged(redeemed.responseMode, arrivedMode);

        // (2b) The response parameters — decrypted, or as posted (#377 Phase C).
        //
        // For the encrypted mode this is where the ciphertext is finally
        // touched: the row's private half is read back by the marker the ROW
        // carries, the JWE is opened under the crypto layer's pinned
        // algorithms, and the `state` inside is held to the row's digest. That
        // last step is the ONLY thing binding this response to this request —
        // the `kid` that found the row proves nothing (§14.5) — and it is a
        // time-safe digest comparison because the caller could choose the
        // plaintext. The cleartext mode's parameters need no such step: the row
        // was found by the digest of the `state` they carry.
        const parameters: EncryptedAuthorizationResponse = isEncryptedDirectPostRequest(body)
          ? await openEncryptedResponse(fastify, body.response, redeemed)
          : { state: body.state, vpToken: body.vp_token, error: body.error };

        // A stored `dcql_query` that no longer parses is a SERVER data-integrity
        // failure — the column is written by QAuth when the request is built, so
        // no caller can influence it — and a 500 would be the semantically honest
        // status for it in isolation. It is nevertheless rendered as the one
        // uniform refusal, because of WHERE it is detectable: the state has
        // ALREADY been redeemed by the time the row can be inspected, so a
        // distinct status here would be a response shape that ONLY a real, live,
        // unconsumed `state` can produce. That is precisely the oracle every other
        // path on this endpoint is built to deny — an attacker sweeping candidate
        // states would get "this one existed" for free, from a deployment already
        // in a degraded state.
        //
        // The integrity failure is not swallowed: it is logged at `error` with the
        // row that carries the bad column and the underlying parse message, which
        // is the channel an operator can actually act on. The wire is not.
        let dcqlQuery: DcqlQuery;

        try {
          dcqlQuery = parseStoredDcqlQuery(redeemed.dcqlQuery);
        } catch (error) {
          fastify.log.error(
            {
              err: error,
              requestStateId: redeemed.id,
              realmId: redeemed.realmId,
            },
            'OID4VP request state carries an unusable stored dcql_query — server data integrity failure, not a client error'
          );

          throw new Oid4vpTransportRejection(
            'stored dcql_query failed structural validation (server data integrity)'
          );
        }

        // The DB row projected onto the transport view. An EXPLICIT projection,
        // not a cast: it is the contract #234 will consume, and writing it out
        // means a column added to the table cannot silently become part of it.
        // Note what is copied — an id, a realm, a nonce, a posture and a query.
        // Nothing that names a person, because nothing here knows one.
        const correlated: RedeemedOid4vpRequestState = {
          id: redeemed.id,
          realmId: redeemed.realmId,
          nonce: redeemed.nonce,
          verifierProfile: redeemed.verifierProfile,
          dcqlQuery,
        };

        // (3) A wallet-reported error (§8.2). The state is already consumed
        // above, which is the correct outcome: the exchange is over. The wallet's
        // error code is logged, never echoed — it is attacker-controllable text.
        if (parameters.error !== undefined) {
          fastify.log.info(
            { requestStateId: correlated.id, walletError: parameters.error },
            'OID4VP wallet returned an error response'
          );
          // Wake a browser waiting on this request (#239) so it shows a refusal
          // instead of spinning until the request expires. The wallet's own
          // error code is NOT carried across — it is attacker-controllable text
          // and every failure renders the same refusal anyway.
          await publishWalletPresentationSignal(fastify, stateHash, 'wallet_error');
          return reply.code(200).send({});
        }

        if (parameters.vpToken === undefined) {
          throw new Oid4vpTransportRejection('response carries neither vp_token nor error');
        }

        // (4) Structural parse against the DCQL query we actually sent.
        //
        // STILL only a structural parse. #238 picks the outcome up from exactly
        // here and PARKS it for the cookie-bound browser that is waiting on this
        // request; validation (#234), issuer trust (#236), subject resolution
        // (#300) and enrolment (#235) all happen on that side, where the session
        // and the asserted identifier exist. Nothing about this endpoint's
        // posture changed: it still authenticates nobody, still creates nothing,
        // and still cannot name a browser, a user or an account.
        const outcome: Oid4vpDirectPostOutcome = {
          state: correlated,
          presentations: parseVpToken(
            parameters.vpToken,
            correlated.dcqlQuery,
            profile.credentialFormats
          ),
        };

        // Audited only on the accepted path. A failed submission is logged but
        // NOT audited: the endpoint is unauthenticated by construction, so
        // auditing failures would hand any anonymous POST an unbounded DB-write
        // primitive. Reaching here requires holding an unconsumed `state`, which
        // an attacker cannot manufacture.
        await fastify.repositories.auditLogs.create({
          userId: null,
          oauthClientId: null,
          event: 'oid4vp.response.received',
          eventType: 'auth',
          success: true,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'] ?? null,
          metadata: {
            requestStateId: outcome.state.id,
            realmId: outcome.state.realmId,
            verifierProfile: outcome.state.verifierProfile,
            presentationCount: outcome.presentations.length,
            // Recorded so an audit reader cannot mistake this row for a login.
            authenticated: false,
          },
        });

        // Park the presented bytes for the browser waiting on this request
        // (#238). Attacker-controlled text, addressed by the digest of a `state`
        // the caller had to redeem to get here at all, and read by nothing
        // except the verification seam — which checks it against a `nonce`, a
        // `client_id` and a DCQL query that come from the BROWSER's flow record,
        // never from this stash. Written BEFORE the signal so a browser that
        // sees `received` always finds the bytes it names.
        await stashWalletPresentation(fastify, stateHash, outcome.presentations);

        // Wake the browser waiting on this request, if there is one (#239).
        //
        // This is a TRANSPORT signal and nothing else: it says a structurally
        // valid `vp_token` came back for a `state` we issued. It carries no
        // subject, no claims and no verdict, and the UI cannot turn it into a
        // session on its own — `helpers/wallet-presentation.ts` is the seam that
        // does that, under a cookie-bound request. Deliberately AFTER the audit
        // entry and best-effort: a wallet's acknowledgement must not depend on a
        // store the wallet has no relationship with.
        await publishWalletPresentationSignal(fastify, stateHash, 'received');

        // OID4VP 1.0 §8.3 — a transport-level acknowledgement, nothing more.
        return reply.code(200).send({});
      } catch (error) {
        if (error instanceof Oid4vpTransportRejection) {
          // The detailed reason stays here. The wire gets one fixed sentence.
          fastify.log.warn(
            { reason: error.logReason, ip: request.ip },
            'OID4VP direct_post response rejected'
          );
          throw error.toClientError();
        }

        throw error;
      }
    }
  );
}

/**
 * A redeemed request-state row, as the repository returns it.
 *
 * Derived from the decorated repository rather than imported: `apps/auth-server`
 * is `scope:app` and may not reach `@qauth-labs/infra-db`, and the DB plugin
 * re-exports the repository interfaces but not the row types. Naming it off the
 * method this handler actually calls also means the helper below can never be
 * handed a row shape the redemption did not produce.
 */
type RedeemedRequestStateRow = NonNullable<
  Awaited<
    ReturnType<FastifyInstance['repositories']['oid4vpRequestStates']['redeemByEncryptionKid']>
  >
>;

/**
 * Open an encrypted Authorization Response with the key its redeemed row holds
 * (#377 Phase C).
 *
 * Three steps, each of which can only fail AFTER the row has been consumed —
 * which is why every failure renders the uniform transport refusal, whatever
 * its cause:
 *
 *  1. Read the private half back. A row with no key, an unrecognised
 *     protection marker, or an envelope the configured secret cannot open is a
 *     SERVER data or configuration failure, and would be a 500 in isolation.
 *     It is rendered as the one refusal for the reason the stored `dcql_query`
 *     case gives in the handler: it is reachable only through a real, live,
 *     unconsumed row, so a distinct status would be the one response shape
 *     only a genuine `kid` can produce. Logged at `error` with the row, which
 *     is the channel an operator can act on.
 *  2. Decrypt under the crypto layer's pinned `alg`/`enc`. Wrong key, tampered
 *     ciphertext, refused algorithm, `zip`, non-JSON plaintext — all one
 *     refusal, with the cause carried for the log.
 *  3. Bind the `state` inside to the row's digest (§5.3). Until this passes,
 *     all that is known is that SOMEONE encrypted something to a key QAuth
 *     published — which anyone who read `client_metadata` could do.
 *
 * @throws Oid4vpTransportRejection on any failure.
 */
async function openEncryptedResponse(
  fastify: FastifyInstance,
  response: string,
  redeemed: RedeemedRequestStateRow
): Promise<EncryptedAuthorizationResponse> {
  let privateJwk: JWK;

  try {
    if (redeemed.responseEncryptionKid === null || redeemed.responseEncryptionPrivateJwk === null) {
      // Unreachable through the repository — the row was found BY its kid, and
      // the schema's CHECK makes the three columns all-or-nothing — but the
      // types say nullable, and a narrowing cast here would be the thing that
      // hid a future row written around the constraint.
      throw new Error('redeemed row carries no ephemeral encryption key');
    }

    privateJwk = unprotectOid4vpResponseKey(
      redeemed.responseEncryptionPrivateJwk,
      redeemed.responseEncryptionKeyProtection,
      redeemed.responseEncryptionKid
    );
  } catch (error) {
    fastify.log.error(
      { err: error, requestStateId: redeemed.id, realmId: redeemed.realmId },
      'OID4VP request state carries an unusable ephemeral encryption key — server data or configuration failure, not a client error'
    );

    throw new Oid4vpTransportRejection(
      'stored ephemeral encryption key could not be read (server data or configuration)'
    );
  }

  const parameters = await decryptOid4vpAuthorizationResponse(response, privateJwk);

  assertEncryptedResponseStateMatches(parameters.state, redeemed.stateHash);

  return parameters;
}

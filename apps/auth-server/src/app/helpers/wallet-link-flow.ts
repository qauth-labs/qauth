import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

import { WALLET_RETURN_CODE_TTL_MS } from '../constants';
import { getOrCreateDefaultRealm } from './realm';
import {
  csrfTokensEqual,
  dropWalletFlowBinding,
  findWalletFlowBinder,
  readCookie,
  readWalletFlowBindings,
  setWalletFlowCookie,
  WALLET_FLOW_COOKIE_NAME,
} from './session-cookie';
import {
  createWalletLoginFlow,
  deleteWalletFlowDoneMarker,
  deleteWalletLoginFlow,
  deleteWalletPresentationSignal,
  deleteWalletPresentationStash,
  generateWalletFlowSecret,
  readWalletFlowDoneMarker,
  readWalletLoginFlow,
  readWalletPresentationSignalRecord,
  type WalletLoginFlow,
  writeWalletFlowDoneMarker,
} from './wallet-login-flow';
import { buildWalletLoginInvocation, resolveWalletLoginCapability } from './wallet-login-request';
import { linkWalletPresentation } from './wallet-presentation';

/**
 * The ACCOUNT-LINKING wallet flow (issue #238, ADR-004 / ADR-009 §5).
 *
 * Structurally the wallet-login flow (#239) with one difference that changes
 * everything about it: the account is not resolved from the presentation, it is
 * the one the caller is **already authenticated as**. ADR-009 §5 calls
 * `session-binding` *"the only correct path for attaching a wallet credential to
 * a pre-existing account"*, and ADR-009 §1's second bootstrap case is why —
 * `asserted-lookup` REFUSES an existing account that carries no wallet binding,
 * because letting a presentation create one *"would let any holder of any
 * trusted credential claim an existing account by asserting its email"*.
 *
 * ## Three independent things must hold at completion
 *
 * 1. **The browser binder cookie** matches the flow — the same defence the login
 *    flow applies, and for the same reason: without it an attacker starts a
 *    flow, presents their own credential, and hands the victim the URL.
 * 2. **A live session**, re-read at completion time.
 * 3. **That session is the SAME user the flow was started by.** Not merely "some
 *    session": a handle captured from a shared screen must not be completable by
 *    a different signed-in user, which would attach the attacker's wallet to the
 *    victim's flow (or the victim's account to the attacker's session).
 *
 * The mode discriminator is the fourth: `advanceWalletLoginFlow` refuses a
 * `link` flow and this refuses a `login` one, so neither path can complete the
 * other's handle.
 *
 * ## No identifier field, deliberately
 *
 * The login flow needs one (ADR-009 §1 — there is no usernameless wallet login).
 * Linking does not: the account is the session's, and asking the user to name it
 * would introduce an input that could disagree with the session. The identifier
 * written to `external_sub` is read from the ACCOUNT, in
 * `linkWalletPresentation`.
 *
 * ## Same device or another device (#405, ADR-013)
 *
 * A link can be started for a wallet on THIS device, exactly as a login can,
 * and then it ends the way a same-device login ends: the Response Endpoint
 * hands the wallet a `redirect_uri` carrying a Response Code (OID4VP 1.0 §8.2,
 * §14.2; HAIP 1.0 §5.1), the wallet brings the browser to
 * `/ui/wallet-login/return`, and the link completes THERE — never by polling.
 * The return route dispatches on `mode` and, for a link flow, re-resolves the
 * browser session before calling {@link advanceWalletLinkFlow} with
 * `via: 'return'`, so the three things above must hold on that leg exactly as
 * on the poll. The device choice is recorded at start, in both records at
 * once ({@link startWalletLinkFlow}); the gate that keeps the poll from
 * completing a same-device link, the deadline that rejects one whose redirect
 * was never followed, and the done-marker that lets the ORIGINAL tab render
 * the outcome after the wallet completed the link in a new one all mirror the
 * login state machine's, and are documented on {@link advanceWalletLinkFlow}.
 */

/** How a linking flow ended, as far as the browser is concerned. */
export type WalletLinkFlowOutcome =
  | { status: 'pending'; flow: WalletLoginFlow }
  | { status: 'linked'; rebound: boolean }
  | { status: 'conflict' }
  | { status: 'expired' }
  | { status: 'rejected' };

/** A started linking flow, ready to render or return. */
export interface StartedWalletLinkFlow {
  readonly handle: string;
  readonly invocationUri: string;
  readonly expiresAt: number;
  /**
   * Whether the flow was started for a wallet on this device (#405). Reported
   * back from what was RECORDED rather than left to the caller's memory of
   * what it asked for, so the pending page renders the affordance the flow
   * will actually complete through.
   */
  readonly sameDevice: boolean;
}

/**
 * Options for {@link startWalletLinkFlow} (#405).
 *
 * `device` is the user's own choice from the linking form (or the JSON body):
 * `this` for a wallet installed on the device the browser runs on, `other`
 * for a wallet that will scan a QR code. Absent means `other` — the
 * cross-device path every link took before #405 — and so does any value that
 * is not exactly `'this'`, so a caller that reached this helper around its
 * schema still gets the path that cannot strand a device with no wallet.
 */
export interface StartWalletLinkFlowOptions {
  device?: 'this' | 'other';
}

/**
 * Which surface is asking the state machine to advance (#405).
 *
 * - `poll` — the JSON status endpoint or the page re-render: the ORIGINAL tab,
 *   holding the binder cookie and a session.
 * - `return` — the same-device return leg: a tab holding the binder cookie
 *   and a session AND having just spent a Response Code that named this flow.
 *
 * A same-device flow's positive outcome is reserved for `return` (OID4VP 1.0
 * §14.2: "MUST require the frontend to pass the respective Response Code");
 * every negative outcome is reachable either way. Optional with `poll` as the
 * default so a caller that predates #405 keeps its meaning.
 */
export interface AdvanceWalletLinkFlowOptions {
  via?: 'poll' | 'return';
}

/** The word the done-marker carries for a completed link (#405). */
type WalletLinkDoneOutcome = 'linked' | 'rebound';

/** Copy the linking surfaces share. One sentence per outcome. */
export const WALLET_LINK_REFUSAL = 'We could not link that credential. Please try again.';
export const WALLET_LINK_EXPIRED = 'This linking request has expired. Please start again.';
export const WALLET_LINK_CONFLICT =
  'That credential is already linked to a different account. Sign in to that account to manage it.';
export const WALLET_LINK_UNAVAILABLE = 'This server is not currently accepting wallet credentials.';

/**
 * Start a linking flow for an authenticated user.
 *
 * @param fastify - server instance.
 * @param request - the authenticated request (for its existing flow cookie).
 * @param reply - the reply, for the browser-binder cookie.
 * @param userId - `users.id` from a VERIFIED session.
 * @param options - the user's device choice (#405); see
 * {@link StartWalletLinkFlowOptions}.
 * @returns the handle and invocation URI, or `undefined` when this deployment
 * serves no wallet flows.
 * @throws whatever the presentation-request build or the store throws — the
 * caller renders a uniform failure. Never partially started: the DB row and the
 * flow record are written before the cookie is set.
 */
export async function startWalletLinkFlow(
  fastify: FastifyInstance,
  request: FastifyRequest,
  reply: FastifyReply,
  userId: string,
  options: StartWalletLinkFlowOptions = {}
): Promise<StartedWalletLinkFlow | undefined> {
  const capability = resolveWalletLoginCapability(fastify);
  if (capability === undefined) return undefined;

  // The user's device choice (#405). Compared against the one value that
  // means same-device rather than trusting a schema default, so a body that
  // reached this helper without validation is still cross-device.
  const sameDevice = options.device === 'this';

  const realm = await getOrCreateDefaultRealm(fastify);
  const invocation = await buildWalletLoginInvocation(fastify, capability);

  await fastify.repositories.oid4vpRequestStates.create({
    realmId: realm.id,
    stateHash: invocation.stateHash,
    nonce: invocation.nonce,
    verifierProfile: capability.profile.id,
    // Written on the ROW because the Response Endpoint decides from the row
    // alone whether to hand the wallet a `redirect_uri` (#405); it cannot
    // read the flow record and must not be able to. A boolean names no
    // browser. See `WalletLoginFlow.sameDevice`.
    sameDevice,
    // Read off the built request, as the login route does (#377 Phase C).
    responseMode: invocation.request.response_mode,
    dcqlQuery: { ...invocation.request.dcql_query },
    expiresAt: invocation.expiresAt,
    // The per-request decryption key under direct_post.jwt — the same three
    // columns the login route writes, for the same reason. See there.
    ...(invocation.responseEncryption === undefined
      ? {}
      : {
          responseEncryptionKid: invocation.responseEncryption.kid,
          responseEncryptionPrivateJwk: invocation.responseEncryption.privateJwk,
          responseEncryptionKeyProtection: invocation.responseEncryption.protection,
        }),
  });

  const binder = generateWalletFlowSecret();
  const handle = await createWalletLoginFlow(fastify, {
    stateHash: invocation.stateHash,
    // Linking asserts no identifier — the account is the session's. Stored empty
    // rather than omitted so a reader cannot mistake an absent field for a lost
    // one, and so nothing downstream can treat it as an account to resolve.
    assertedIdentifier: '',
    mode: 'link',
    linkUserId: userId,
    invocationUri: invocation.invocationUri,
    // Carried so the terminal outcome that ends this flow also removes the
    // parked request object (#377). Absent for an unsigned request.
    ...(invocation.requestObjectHandle === undefined
      ? {}
      : { requestObjectHandle: invocation.requestObjectHandle }),
    nonce: invocation.nonce,
    clientId: invocation.request.client_id,
    dcqlQuery: { ...invocation.request.dcql_query },
    // The same choice, on the record the poll reads (#405): this is what makes
    // the state machine refuse to complete the link by polling and wait for
    // the return leg instead. Written only when true so a cross-device record
    // looks exactly as it did before #405.
    ...(sameDevice ? { sameDevice } : {}),
    returnTo: '/',
    binder,
    realmId: realm.id,
    verifierProfile: capability.profile.id,
    expiresAt: invocation.expiresAt,
    createdAt: Date.now(),
  });

  // ADDED to whatever this browser already holds: a user may have a wallet
  // login and a wallet link in flight at once, and replacing the cookie would
  // strand one of them.
  setWalletFlowCookie(reply, [
    ...readWalletFlowBindings(readCookie(request, WALLET_FLOW_COOKIE_NAME)),
    { handle, binder, expiresAt: invocation.expiresAt },
  ]);

  return {
    handle,
    invocationUri: invocation.invocationUri,
    expiresAt: invocation.expiresAt,
    sameDevice,
  };
}

/** Drop every trace of a finished linking flow. */
async function terminate(
  fastify: FastifyInstance,
  handle: string,
  flow: WalletLoginFlow
): Promise<void> {
  await deleteWalletLoginFlow(fastify, handle);
  await deleteWalletPresentationSignal(fastify, flow.stateHash);
  await deleteWalletPresentationStash(fastify, flow.stateHash);
}

async function auditWalletLink(
  fastify: FastifyInstance,
  request: FastifyRequest,
  entry: { userId: string; success: boolean; metadata: Record<string, unknown> }
): Promise<void> {
  await fastify.repositories.auditLogs.create({
    userId: entry.userId,
    oauthClientId: null,
    event: entry.success ? 'auth.wallet_link.success' : 'auth.wallet_link.failure',
    eventType: 'auth',
    success: entry.success,
    ipAddress: request.ip,
    userAgent: request.headers['user-agent'] || null,
    metadata: entry.metadata,
  });
}

/**
 * Read a linking flow, apply every gate, and advance it as far as it can go.
 *
 * The ONE place a linking flow changes state, shared by the JSON status
 * endpoint, the server-rendered page and — for a same-device link — the return
 * route (#405). Two surfaces observing one flow through two implementations is
 * how one of them ends up skipping the binder check; three would make it
 * certain.
 *
 * Missing flow, wrong binder, wrong user, expired flow and a login-mode flow all
 * return `expired`: indistinguishable by design, so a handle harvested from a
 * screen share or a log cannot be probed for whether it was ever real.
 *
 * ## The same-device gate (#405, ADR-013 D7)
 *
 * After the mode, binder, same-user and expiry gates, the signal record
 * decides:
 *
 * - `wallet_error` or `return_rejected` → terminate, `rejected` — on EVERY
 *   flow, via either surface. An error carries no presentation and surfacing
 *   it links nothing, so gating it would only leave a user who tapped
 *   "Decline" in their wallet watching a spinner.
 * - `received` on a same-device flow, via `poll` → `pending` while the
 *   redirect could still arrive (`now <= at + WALLET_RETURN_CODE_TTL_MS`, the
 *   same window the database gives the code), and once it cannot →
 *   terminate, `rejected`, logged. That is HAIP 1.0 §5.1's "MUST reject
 *   presentations if Wallets do not follow the redirect back", enforced
 *   ACTIVELY at the deadline rather than left to the flow's expiry.
 * - `received` via `return` → resolve, terminate, link: the leg the code was
 *   minted for.
 * - `received` on a cross-device flow → link by polling, exactly as before
 *   #405. A return can never reach such a flow, because the Response Endpoint
 *   emits no `redirect_uri` for a cross-device row and the repository refuses
 *   to redeem a code for one.
 *
 * ## Completion differs by surface (D6, D8)
 *
 * Both surfaces link identically and audit identically. The poll then burns
 * this flow's cookie binding on every terminal outcome, as it always has. The
 * return leg does NOT touch the binder cookie — the wallet opened it in a NEW
 * tab, and the original tab's next poll must still be able to prove it holds
 * the flow — and on `linked` leaves a done-marker under the handle carrying
 * the word its page should show. When that poll finds the flow gone, it
 * consults the marker: binder matches, mode is `link`, and the session is the
 * user the flow was started by → marker deleted, binding burned, `linked`
 * answered exactly once, and no second write. Anything else about a missing
 * flow is `expired`, as it always was. `conflict` and `rejected` on the return
 * leg leave no marker: the original tab then reports `expired`, which is the
 * refusal the login state machine gives its original tab for the same case,
 * and the return tab has already shown the specific outcome.
 *
 * @param fastify - server instance.
 * @param request - the authenticated request.
 * @param reply - the reply, for burning this flow's cookie binding.
 * @param handle - the flow handle.
 * @param userId - `users.id` from a session verified by the CALLER, now.
 * @param options - which surface is asking (#405); see
 * {@link AdvanceWalletLinkFlowOptions}.
 */
export async function advanceWalletLinkFlow(
  fastify: FastifyInstance,
  request: FastifyRequest,
  reply: FastifyReply,
  handle: string,
  userId: string,
  options: AdvanceWalletLinkFlowOptions = {}
): Promise<WalletLinkFlowOutcome> {
  const via = options.via ?? 'poll';

  // Read before the flow because the done-marker path below needs it too.
  const binder = findWalletFlowBinder(readCookie(request, WALLET_FLOW_COOKIE_NAME), handle);

  const flow = await readWalletLoginFlow(fastify, handle);
  if (flow === null) return resolveDoneMarker(fastify, request, reply, handle, binder, userId);

  // A LOGIN flow may never be completed here. It carries no `linkUserId`, so
  // the check below would refuse it anyway — refused explicitly so the reason is
  // in the log and so the property survives a future change to that field.
  if (flow.mode !== 'link') {
    fastify.log.warn({ ip: request.ip }, 'a wallet LOGIN flow was submitted to the linking path');
    return { status: 'expired' };
  }

  if (!binder || !csrfTokensEqual(flow.binder, binder)) {
    fastify.log.warn({ ip: request.ip }, 'wallet-link flow accessed without its browser binder');
    return { status: 'expired' };
  }

  // The session is re-checked against the user the flow was STARTED by. A
  // different signed-in user holding this handle must not be able to finish it.
  if (typeof flow.linkUserId !== 'string' || !csrfTokensEqual(flow.linkUserId, userId)) {
    fastify.log.warn(
      { ip: request.ip },
      'wallet-link flow completed by a different session than started it'
    );
    return { status: 'expired' };
  }

  if (Date.now() >= flow.expiresAt) {
    await terminate(fastify, handle, flow);
    return { status: 'expired' };
  }

  const record = await readWalletPresentationSignalRecord(fastify, flow.stateHash);
  if (record === null) return { status: 'pending', flow };

  if (record.signal === 'wallet_error' || record.signal === 'return_rejected') {
    if (record.signal === 'return_rejected') {
      fastify.log.warn(
        { ip: request.ip },
        'same-device presentation rejected: redirect landed in a foreign session'
      );
    }
    await terminate(fastify, handle, flow);
    return { status: 'rejected' };
  }

  // A same-device presentation links ONLY on the return leg (OID4VP 1.0
  // §14.2). By polling, it is pending while the wallet could still bring the
  // browser back, and rejected once the code it was handed can no longer be
  // redeemed — HAIP 1.0 §5.1, "do not follow the redirect back". The deadline
  // is measured from the signal's own timestamp, so a poll that arrives late
  // cannot restart it, and it is the SAME constant the database applies to the
  // code, so the two edges cannot disagree.
  if (flow.sameDevice === true && via === 'poll') {
    if (Date.now() <= record.at + WALLET_RETURN_CODE_TTL_MS) return { status: 'pending', flow };
    fastify.log.warn(
      { ip: request.ip },
      'same-device presentation rejected: redirect not followed'
    );
    await terminate(fastify, handle, flow);
    return { status: 'rejected' };
  }

  const resolution = await linkWalletPresentation(fastify, {
    realmId: flow.realmId,
    stateHash: flow.stateHash,
    authenticatedUserId: userId,
    nonce: flow.nonce ?? '',
    clientId: flow.clientId ?? '',
    dcqlQuery: flow.dcqlQuery ?? {},
  });

  await terminate(fastify, handle, flow);

  if (via === 'poll') {
    // Burn only THIS flow's binding: another flow may still be pending in the
    // same browser, and clearing the whole cookie would strand it. The return
    // leg leaves the binding alone — see the JSDoc — so the original tab can
    // still prove it holds the flow when it comes looking for the marker.
    dropWalletFlowBinding(request, reply, handle);
  }

  if (resolution.status === 'linked') {
    await auditWalletLink(fastify, request, {
      userId,
      success: true,
      metadata: {
        credentialId: resolution.credentialId,
        subjectSource: resolution.subjectSource,
        rebound: resolution.rebound,
        verifierProfile: flow.verifierProfile,
      },
    });

    if (via === 'return') {
      // The wallet opened this leg in a NEW tab; the marker is what the
      // original tab's poll will find where the flow was. Written AFTER the
      // credential row and the audit row, so a marker exists only for a link
      // that happened, and it writes nothing when consumed. The user the
      // outcome belongs to rides on the marker's open index signature — the
      // marker type is deliberately mode-agnostic and lives with the login
      // flow — so the replay can apply the same-user gate the live flow did.
      const outcome: WalletLinkDoneOutcome = resolution.rebound ? 'rebound' : 'linked';
      await writeWalletFlowDoneMarker(fastify, handle, {
        binder: flow.binder,
        mode: 'link',
        outcome,
        linkUserId: userId,
      });
    }

    return { status: 'linked', rebound: resolution.rebound };
  }

  await auditWalletLink(fastify, request, {
    userId,
    success: false,
    metadata: { reason: resolution.status, verifierProfile: flow.verifierProfile },
  });

  return resolution.status === 'conflict' ? { status: 'conflict' } : { status: 'rejected' };
}

/**
 * What a poll finds where a linking flow used to be (#405, ADR-013 D8).
 *
 * A same-device link completed on the return leg — in the tab the wallet
 * opened — has been terminated like any other, and the tab that started it is
 * still polling `/auth/link/wallet/:handle`. Before answering `expired` for a
 * missing flow, look for the done-marker the return leg left under this
 * handle. It is honoured only when this browser presents the flow's binder
 * (timing-safe, as the flow itself was gated), only for a marker of THIS
 * state machine's mode (a link poll must not eat a login flow's marker, whose
 * page is waiting to navigate), only for the session of the user the link was
 * made for (the same-user gate the live flow applied, so a browser whose
 * session changed hands underneath the original tab reads nothing), and only
 * once: the marker is deleted and the cookie binding burned in the same
 * breath, so a second poll is `expired` again. Nothing is written to the
 * account — the credential row has existed since the return leg — and the
 * word answered is the one the marker recorded.
 *
 * A poll that fails any gate learns nothing and burns nothing: the read and
 * the delete are separate on purpose (see `readWalletFlowDoneMarker`), so a
 * handle harvested from a screen share cannot strand the rightful tab.
 */
async function resolveDoneMarker(
  fastify: FastifyInstance,
  request: FastifyRequest,
  reply: FastifyReply,
  handle: string,
  binder: string | null,
  userId: string
): Promise<WalletLinkFlowOutcome> {
  const marker = await readWalletFlowDoneMarker(fastify, handle);
  if (marker === null || !binder || !csrfTokensEqual(marker.binder, binder)) {
    return { status: 'expired' };
  }
  if (marker.mode !== 'link') return { status: 'expired' };

  const markerUserId = marker['linkUserId'];
  if (typeof markerUserId !== 'string' || !csrfTokensEqual(markerUserId, userId)) {
    fastify.log.warn(
      { ip: request.ip },
      'wallet-link done-marker read by a different session than the link was made for'
    );
    return { status: 'expired' };
  }

  await deleteWalletFlowDoneMarker(fastify, handle);
  dropWalletFlowBinding(request, reply, handle);

  return { status: 'linked', rebound: marker.outcome === 'rebound' };
}

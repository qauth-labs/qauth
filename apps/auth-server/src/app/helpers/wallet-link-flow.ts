import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

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
  decideSignalGate,
  deleteWalletFlowDoneMarker,
  deleteWalletLoginFlow,
  deleteWalletPresentationSignal,
  deleteWalletPresentationStash,
  generateWalletFlowSecret,
  readWalletFlowDoneMarker,
  readWalletLoginFlow,
  readWalletPresentationSignalRecord,
  type WalletFlowSurface,
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
 * Which surface is asking the state machine to advance (#405); see
 * `WalletFlowSurface`. Optional with `poll` as the default so a caller that
 * predates #405 keeps its meaning.
 */
export interface AdvanceWalletLinkFlowOptions {
  via?: WalletFlowSurface;
}

/**
 * The word the done-marker carries for a link that ended on the return leg
 * (#405): the two completions the linking page has a sentence for, and the
 * two refusals the return tab rendered, so the original tab renders the
 * same one. Any other word on a link marker is read as `rejected` — the
 * marker is QAuth-authored and cannot carry one, but nothing unrecognised
 * may read as a completion.
 */
type WalletLinkDoneOutcome = 'linked' | 'rebound' | 'conflict' | 'rejected';

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

/**
 * End a linking flow on the RETURN leg (#405, ADR-013 D8): the done-marker
 * first, the flow second.
 *
 * The order is the point, and `WalletFlowDoneMarker` says why at length: the
 * original tab is answered from the flow record while one exists and from
 * the marker once there is not, so the marker must exist before the flow
 * stops existing or a poll in between finds neither and reports "expired".
 * Safe on this leg specifically, because nothing can complete a same-device
 * link while it stays addressable for these two writes — the poll is gated
 * and the code is spent. The user the outcome belongs to rides on the
 * marker's open index signature — the marker type is deliberately
 * mode-agnostic and lives with the login flow — so the replay can apply the
 * same-user gate the live flow did.
 */
async function concludeReturnLeg(
  fastify: FastifyInstance,
  handle: string,
  flow: WalletLoginFlow,
  userId: string,
  outcome: WalletLinkDoneOutcome
): Promise<void> {
  await writeWalletFlowDoneMarker(fastify, handle, {
    binder: flow.binder,
    mode: 'link',
    outcome,
    linkUserId: userId,
  });
  await terminate(fastify, handle, flow);
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
 * decides — in `decideSignalGate`, the ONE function both this machine and
 * the login machine call, documented there: a wallet error or a foreign
 * landing is `rejected` on every flow via either surface; `received` on a
 * same-device flow is `pending` by poll until the Response Code deadline and
 * `rejected` after it; `received` via the return leg, or on a cross-device
 * flow by poll, proceeds to the link. This machine does what the verdict
 * says — logs the reason, terminates, answers — so the flow still changes
 * state in one place while the rule lives in one place.
 *
 * ## Completion differs by surface (D6, D8)
 *
 * Both surfaces link identically and audit identically. The poll then burns
 * this flow's cookie binding on every terminal outcome, as it always has. The
 * return leg does NOT touch the binder cookie — the wallet opened it in a NEW
 * tab, and the original tab's next poll must still be able to prove it holds
 * the flow — and on EVERY terminal outcome leaves a done-marker under the
 * handle carrying the word its page should show: `linked` or `rebound` for a
 * completion, `conflict` or `rejected` for a refusal, so the original tab
 * renders exactly what the return tab did instead of an "expired" that would
 * depend on whether its poll or the redirect got there first. The marker is
 * written BEFORE the flow is terminated (`concludeReturnLeg`; the poll never
 * completes a same-device link, so a poll that lands mid-completion is
 * `pending`, never a second write). When that poll finds the flow gone, it
 * consults the marker: binder matches, mode is `link`, and the session is
 * the user the flow was started by → marker deleted, binding burned, the
 * word answered exactly once, and no second write. Anything else about a
 * missing flow is `expired`, as it always was.
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

  // The same-device gate, shared with the login machine (D7). A same-device
  // presentation links ONLY on the return leg (OID4VP 1.0 §14.2); by polling
  // it is pending while the wallet could still bring the browser back, and
  // rejected once the code it was handed can no longer be redeemed (HAIP
  // 1.0 §5.1, "do not follow the redirect back").
  const gate = decideSignalGate(record, flow, via);
  if (gate.verdict === 'pending') return { status: 'pending', flow };
  if (gate.verdict === 'rejected') {
    if (gate.warn !== undefined) fastify.log.warn({ ip: request.ip }, gate.warn);
    if (via === 'return') {
      await concludeReturnLeg(fastify, handle, flow, userId, 'rejected');
    } else {
      await terminate(fastify, handle, flow);
    }
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

  if (via === 'poll') {
    // By POLL the flow ends here, before the audit row, as it always has: a
    // cross-device link CAN be reached by a concurrent poll, so the window in
    // which two of them read the same presentation stays as narrow as it
    // was. By RETURN it ends in `concludeReturnLeg` below, AFTER the marker
    // for the original tab is written.
    await terminate(fastify, handle, flow);
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
      // credential row and the audit row, so a completion marker exists only
      // for a link that happened, and BEFORE the flow is deleted, so that
      // poll never finds neither. It writes nothing when consumed.
      await concludeReturnLeg(
        fastify,
        handle,
        flow,
        userId,
        resolution.rebound ? 'rebound' : 'linked'
      );
    }

    return { status: 'linked', rebound: resolution.rebound };
  }

  await auditWalletLink(fastify, request, {
    userId,
    success: false,
    metadata: { reason: resolution.status, verifierProfile: flow.verifierProfile },
  });

  const refused: WalletLinkDoneOutcome = resolution.status === 'conflict' ? 'conflict' : 'rejected';
  if (via === 'return') await concludeReturnLeg(fastify, handle, flow, userId, refused);

  return refused === 'conflict' ? { status: 'conflict' } : { status: 'rejected' };
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
 * word answered is the one the marker recorded: `linked` / `rebound` for a
 * completion, `conflict` / `rejected` for a refusal the return tab already
 * showed, and `rejected` for any word this machine does not know, because
 * nothing unrecognised may read as a completion.
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

  switch (marker.outcome) {
    case 'linked':
      return { status: 'linked', rebound: false };
    case 'rebound':
      return { status: 'linked', rebound: true };
    case 'conflict':
      return { status: 'conflict' };
    default:
      return { status: 'rejected' };
  }
}

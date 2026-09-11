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
  deleteWalletLoginFlow,
  deleteWalletPresentationSignal,
  deleteWalletPresentationStash,
  generateWalletFlowSecret,
  readWalletLoginFlow,
  readWalletPresentationSignal,
  type WalletLoginFlow,
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
}

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
  userId: string
): Promise<StartedWalletLinkFlow | undefined> {
  const capability = resolveWalletLoginCapability(fastify);
  if (capability === undefined) return undefined;

  const realm = await getOrCreateDefaultRealm(fastify);
  const invocation = await buildWalletLoginInvocation(fastify, capability);

  await fastify.repositories.oid4vpRequestStates.create({
    realmId: realm.id,
    stateHash: invocation.stateHash,
    nonce: invocation.nonce,
    verifierProfile: capability.profile.id,
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

  return { handle, invocationUri: invocation.invocationUri, expiresAt: invocation.expiresAt };
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
 * The ONE place a linking flow changes state, shared by the JSON status endpoint
 * and the server-rendered page. Two surfaces observing one flow through two
 * implementations is how one of them ends up skipping the binder check.
 *
 * Missing flow, wrong binder, wrong user, expired flow and a login-mode flow all
 * return `expired`: indistinguishable by design, so a handle harvested from a
 * screen share or a log cannot be probed for whether it was ever real.
 *
 * @param fastify - server instance.
 * @param request - the authenticated request.
 * @param reply - the reply, for burning this flow's cookie binding.
 * @param handle - the flow handle.
 * @param userId - `users.id` from a session verified by the CALLER, now.
 */
export async function advanceWalletLinkFlow(
  fastify: FastifyInstance,
  request: FastifyRequest,
  reply: FastifyReply,
  handle: string,
  userId: string
): Promise<WalletLinkFlowOutcome> {
  const flow = await readWalletLoginFlow(fastify, handle);
  if (flow === null) return { status: 'expired' };

  // A LOGIN flow may never be completed here. It carries no `linkUserId`, so
  // the check below would refuse it anyway — refused explicitly so the reason is
  // in the log and so the property survives a future change to that field.
  if (flow.mode !== 'link') {
    fastify.log.warn({ ip: request.ip }, 'a wallet LOGIN flow was submitted to the linking path');
    return { status: 'expired' };
  }

  const binder = findWalletFlowBinder(readCookie(request, WALLET_FLOW_COOKIE_NAME), handle);
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

  const signal = await readWalletPresentationSignal(fastify, flow.stateHash);
  if (signal === null) return { status: 'pending', flow };

  if (signal === 'wallet_error') {
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
  // Burn only THIS flow's binding: another flow may still be pending in the same
  // browser, and clearing the whole cookie would strand it.
  dropWalletFlowBinding(request, reply, handle);

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
    return { status: 'linked', rebound: resolution.rebound };
  }

  await auditWalletLink(fastify, request, {
    userId,
    success: false,
    metadata: { reason: resolution.status, verifierProfile: flow.verifierProfile },
  });

  return resolution.status === 'conflict' ? { status: 'conflict' } : { status: 'rejected' };
}

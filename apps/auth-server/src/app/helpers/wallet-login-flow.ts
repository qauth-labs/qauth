import { randomBytes } from 'node:crypto';

import type { FastifyInstance } from 'fastify';

import { WALLET_LOGIN_FLOW_TTL_MS } from '../constants';

/**
 * Wallet-login flow state (issue #239, ADR-004 / ADR-009).
 *
 * Two server-side records live here, and keeping them SEPARATE is the point:
 *
 * 1. **The flow record** — what the BROWSER is doing. Keyed by an unguessable
 *    handle the browser carries in its URL, bound to that browser by a signed
 *    cookie, and holding the identifier the user asserted (ADR-009 §1), the
 *    opaque wallet invocation URI to render, and where to go afterwards.
 * 2. **The presentation signal** — what the WALLET did. Keyed by the request
 *    `state` digest, written by the unauthenticated `direct_post` endpoint, and
 *    carrying nothing but "a response arrived, of this shape".
 *
 * The two are joined only by the `state` digest the flow record stores. That
 * asymmetry is deliberate: the wallet side of the exchange is unauthenticated by
 * construction (OID4VP 1.0 §8.2 — a wallet has no client credentials), so it
 * must not be able to name a browser, a user, or an account. It can only say
 * that the request it was given came back.
 *
 * ## What the signal is NOT
 *
 * `'received'` means a `vp_token` round-tripped a live `state` and parsed
 * STRUCTURALLY. It is not a validated presentation, not a trusted issuer, and
 * not an identity — those are #234, #236 and #300. Everything downstream of this
 * module must treat the signal as "the transport step finished" and nothing
 * more; see `helpers/wallet-presentation.ts` for the boundary that turns it into
 * an authentication decision, and for why that boundary refuses today.
 *
 * ## Why Redis, and what is stored in it
 *
 * The same store that already holds live browser sessions and the
 * pending-authorization stash. The flow record holds the invocation URI, which
 * embeds the request `state` — a bearer value: whoever holds it can consume the
 * pending presentation request exactly once. That is a real property and it is
 * accepted deliberately. The DATABASE stores only `sha256(state)` so a read-only
 * DB leak yields nothing redeemable (see `schema/oid4vp.ts`); Redis is a
 * different trust domain that already holds session identifiers, the record
 * lives for minutes, and consuming a presentation request authenticates nobody
 * on its own. Storing the URI is what makes the page refresh-safe and lets the
 * QR be re-rendered without re-issuing a second request to the same wallet.
 */

/** Redis namespace for browser-side flow records. */
const WALLET_FLOW_KEY_PREFIX = 'wallet-login:';

/**
 * Redis namespace for the wallet-side signal.
 *
 * Distinct from the flow namespace because the two are written by different
 * parties: an authenticated-by-cookie browser writes the first, an
 * unauthenticated wallet POST causes the second. Sharing a namespace would make
 * a key-shape mistake in one path a way of writing into the other.
 */
const WALLET_SIGNAL_KEY_PREFIX = 'wallet-login-signal:';

/** CSPRNG bytes per handle and per binder; 32 bytes → 43 base64url characters. */
const HANDLE_BYTES = 32;

/** Exactly what `randomBytes(32).toString('base64url')` produces. */
const HANDLE_PATTERN = /^[A-Za-z0-9_-]{43}$/;

/** Path prefix of the wallet-login flow pages. */
export const WALLET_LOGIN_PATH_PREFIX = '/ui/wallet-login/';

/**
 * What the wallet-side POST reports back to the waiting browser.
 *
 * Only two values, and neither is an identity claim:
 *
 * - `received` — a structurally-valid `vp_token` redeemed the request `state`.
 * - `wallet_error` — the wallet returned an OAuth-style error instead (§8.2).
 *   The wallet's own error code is NOT propagated: it is attacker-controllable
 *   text, and the UI shows one refusal for every failure anyway.
 */
export type WalletPresentationSignal = 'received' | 'wallet_error';

/** Browser-side flow record. Auth-flow state, never user state. */
export interface WalletLoginFlow {
  /**
   * SHA-256 of the request `state`, hex — the join key to both the database row
   * and the wallet signal. The raw `state` is never stored under this field; it
   * exists only inside {@link invocationUri}, which has to carry it on the wire.
   */
  stateHash: string;
  /**
   * The account the user ASSERTED (normalized). ADR-009 §1: `asserted-lookup` is
   * the default strategy because no protocol-guaranteed stable wallet subject
   * identifier exists, so the user names the account and the presentation proves
   * entitlement to it. This value is an input to that decision, never its
   * output — nothing here may treat it as authenticated.
   */
  assertedIdentifier: string;
  /**
   * The wallet invocation URI, OPAQUE to this layer. Under the base profile it
   * carries the request parameters inline; under HAIP it is a `request_uri`
   * reference to a signed JAR (#298). The UI renders whichever it is given.
   */
  invocationUri: string;
  /** Relative path to redirect to after a completed sign-in. */
  returnTo: string;
  /** Binder mirrored in the signed `__Host-` wallet-flow cookie. */
  binder: string;
  /** Realm the presentation request was created in. */
  realmId: string;
  /** `VerifierProfile` id in force when the request was built (#299). */
  verifierProfile: string;
  /** Absolute expiry (epoch ms) of the underlying presentation request. */
  expiresAt: number;
  createdAt: number;
  [key: string]: unknown;
}

/** Cheap shape guard so a junk path segment never reaches Redis. */
export function isWalletLoginHandle(value: unknown): value is string {
  return typeof value === 'string' && HANDLE_PATTERN.test(value);
}

/** Mint an unguessable handle or binder. */
export function generateWalletFlowSecret(): string {
  return randomBytes(HANDLE_BYTES).toString('base64url');
}

/**
 * Store a flow record and return the handle addressing it.
 *
 * @throws whatever the session store throws — unlike the pending-authorization
 * stash, a failed write here CANNOT degrade to an inline fallback (there is no
 * URL to inline), so the caller must surface it as a failed sign-in attempt
 * rather than render a page that will never advance.
 */
export async function createWalletLoginFlow(
  fastify: FastifyInstance,
  flow: WalletLoginFlow
): Promise<string> {
  const handle = generateWalletFlowSecret();
  await fastify.sessionUtils.setSession<WalletLoginFlow>(
    `${WALLET_FLOW_KEY_PREFIX}${handle}`,
    flow,
    Math.floor(WALLET_LOGIN_FLOW_TTL_MS / 1000)
  );
  return handle;
}

/**
 * Read a flow record, or null when the handle is malformed, unknown or expired.
 *
 * A store failure is a MISS rather than a throw: to the user standing in front
 * of the page, an unreachable Redis and an expired flow are the same event, and
 * the page must degrade to "this expired" instead of 500-ing mid-sign-in.
 */
export async function readWalletLoginFlow(
  fastify: FastifyInstance,
  handle: unknown
): Promise<WalletLoginFlow | null> {
  if (!isWalletLoginHandle(handle)) return null;
  try {
    return await fastify.sessionUtils.getSession<WalletLoginFlow>(
      `${WALLET_FLOW_KEY_PREFIX}${handle}`
    );
  } catch (error) {
    fastify.log.warn({ err: error }, 'wallet-login flow store unavailable; treating as expired');
    return null;
  }
}

/**
 * Delete a flow record. Called on EVERY terminal outcome — success, refusal and
 * expiry alike — so a completed or refused flow cannot be polled again.
 */
export async function deleteWalletLoginFlow(
  fastify: FastifyInstance,
  handle: string
): Promise<void> {
  try {
    await fastify.sessionUtils.deleteSession(`${WALLET_FLOW_KEY_PREFIX}${handle}`);
  } catch (error) {
    fastify.log.warn({ err: error }, 'failed to delete a wallet-login flow record');
  }
}

/**
 * Record that a wallet responded to the presentation request behind `stateHash`.
 *
 * Called from the `direct_post` endpoint, which is UNAUTHENTICATED. Three
 * properties follow from that and none of them is optional:
 *
 * - It is called only AFTER the `state` redeemed, so an anonymous caller cannot
 *   use it as an unbounded write primitive — reaching it requires holding an
 *   unconsumed `state`.
 * - It stores a fixed-shape marker, never wallet-supplied text.
 * - It never throws. The wallet's transport acknowledgement (§8.3) must not
 *   depend on a store the wallet has no relationship with; a failed write
 *   degrades to the browser timing out, which is the same outcome as a wallet
 *   that never answered.
 */
export async function publishWalletPresentationSignal(
  fastify: FastifyInstance,
  stateHash: string,
  signal: WalletPresentationSignal
): Promise<void> {
  try {
    await fastify.sessionUtils.setSession<{ signal: WalletPresentationSignal; at: number }>(
      `${WALLET_SIGNAL_KEY_PREFIX}${stateHash}`,
      { signal, at: Date.now() },
      Math.floor(WALLET_LOGIN_FLOW_TTL_MS / 1000)
    );
  } catch (error) {
    fastify.log.warn(
      { err: error },
      'failed to publish a wallet presentation signal; the waiting browser will time out'
    );
  }
}

/** Read the wallet-side signal for a request, or null while none has arrived. */
export async function readWalletPresentationSignal(
  fastify: FastifyInstance,
  stateHash: string
): Promise<WalletPresentationSignal | null> {
  try {
    const record = await fastify.sessionUtils.getSession<{ signal: WalletPresentationSignal }>(
      `${WALLET_SIGNAL_KEY_PREFIX}${stateHash}`
    );
    if (record?.signal === 'received' || record?.signal === 'wallet_error') return record.signal;
    return null;
  } catch (error) {
    fastify.log.warn({ err: error }, 'wallet presentation signal store unavailable');
    return null;
  }
}

/** Delete a consumed signal so a terminal flow cannot be replayed. */
export async function deleteWalletPresentationSignal(
  fastify: FastifyInstance,
  stateHash: string
): Promise<void> {
  try {
    await fastify.sessionUtils.deleteSession(`${WALLET_SIGNAL_KEY_PREFIX}${stateHash}`);
  } catch (error) {
    fastify.log.warn({ err: error }, 'failed to delete a wallet presentation signal');
  }
}

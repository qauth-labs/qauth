import { randomBytes } from 'node:crypto';

import type { PresentedCredential } from '@qauth-labs/fastify-plugin-federation';
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
 * Redis namespace for the PRESENTED BYTES a wallet posted.
 *
 * Separate from the signal namespace below, and the separation is the point: the
 * signal is a fixed-shape marker QAuth writes about itself, this is
 * attacker-controlled text QAuth is merely holding. Sharing a key would make a
 * shape mistake in one a way of writing the other, and would quietly turn the
 * signal — which several code paths treat as trustworthy because QAuth authored
 * it — into a channel a wallet can put content into.
 */
const WALLET_PRESENTATION_KEY_PREFIX = 'wallet-presentation:';

/**
 * Redis namespace for the wallet-side signal.
 *
 * Distinct from the flow namespace because the two are written by different
 * parties: an authenticated-by-cookie browser writes the first, an
 * unauthenticated wallet POST causes the second. Sharing a namespace would make
 * a key-shape mistake in one path a way of writing into the other.
 */
const WALLET_SIGNAL_KEY_PREFIX = 'wallet-login-signal:';

/**
 * Redis namespace for the SIGNED REQUEST OBJECT a wallet fetches (#377).
 *
 * A fourth namespace rather than a field on the flow record, and the separation
 * carries the same weight as the three above: this is the one value an
 * UNAUTHENTICATED party reads by handle, and it must not be addressable by
 * anything that also names a browser. A shape mistake in the flow record must
 * not become a way to read one, and a handle leaked from a wallet must not
 * become a way to read the flow.
 */
const WALLET_REQUEST_OBJECT_KEY_PREFIX = 'wallet-request-object:';

/** CSPRNG bytes per handle and per binder; 32 bytes → 43 base64url characters. */
const HANDLE_BYTES = 32;

/** Exactly what `randomBytes(32).toString('base64url')` produces. */
const HANDLE_PATTERN = /^[A-Za-z0-9_-]{43}$/;

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

/**
 * What a wallet flow is FOR (issue #238).
 *
 * A hard discriminator, not a hint. `login` mints a session for whichever
 * account the presentation resolves to; `link` attaches a credential to an
 * account that is ALREADY authenticated. Feeding a `link` flow to the login
 * completion path would sign a browser in as the linking user without ever
 * checking a password — so each path REFUSES the other's mode rather than
 * tolerating it, and both refusals are tested.
 */
export type WalletFlowMode = 'login' | 'link';

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
   * What this flow is for. See {@link WalletFlowMode}.
   *
   * Optional in the TYPE only, because Redis holds records written by the
   * previous binary. Readers treat an absent value as `'login'` — the mode that
   * existed before #238 — and the linking path requires an explicit `'link'`,
   * so an old record can never be advanced into a link.
   */
  mode?: WalletFlowMode;
  /**
   * `users.id` this flow will link a credential to. Present ONLY when
   * {@link mode} is `'link'`, and written from a VERIFIED session — never from a
   * request parameter. The completion path re-checks that the session at
   * completion time is still this user, so a captured handle cannot be finished
   * by someone else's browser even if they also hold the binder.
   */
  linkUserId?: string;
  /**
   * The wallet invocation URI, OPAQUE to this layer. Under the base profile it
   * carries the request parameters inline; under HAIP it is a `request_uri`
   * reference to a signed JAR (#298). The UI renders whichever it is given.
   */
  invocationUri: string;
  /**
   * The request `nonce`, as sent. The Key Binding JWT is compared against it
   * verbatim (#234), which is what makes a presentation answer THIS request and
   * not a replay of an earlier one.
   *
   * Held on the BROWSER-side record rather than read back from the wallet-side
   * stash: the wallet already holds this value (it is in the request it was
   * given), but it must never be able to CHOOSE the value it is checked against.
   * It is no more exposed here than in {@link invocationUri}, which embeds it.
   */
  nonce?: string;
  /**
   * The `client_id` the request carried (OID4VP 1.0 §5.9). Compared against the
   * Key Binding JWT's `aud`, which is what binds the presentation to THIS
   * Verifier. Same reasoning as {@link nonce} for why it lives here.
   */
  clientId?: string;
  /**
   * The DCQL query that was sent, as an object. `vp_token` is keyed by its
   * Credential Query ids, so validation cannot proceed without it.
   */
  dcqlQuery?: Record<string, unknown>;
  /**
   * Handle of the parked signed request object, when the request was signed
   * (#377). Absent under a profile whose requests are unsigned, and absent on
   * records written by a binary that predates #377.
   *
   * Held here so {@link deleteWalletLoginFlow} can clean the request object up
   * on the SAME terminal outcome that ends the flow — the two have the same
   * lifetime and there is no path that ends one and not the other.
   */
  requestObjectHandle?: string;
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
 *
 * Also deletes the signed request object the flow parked, when it parked one
 * (#377). Read first rather than passed in: every caller already has the handle
 * and none of them has the record, and one extra store read on a path that runs
 * once per flow is cheaper than a parameter every call site could forget. The
 * request object would expire on its own TTL regardless — this is hygiene, not a
 * control, which is why a failure to read it is not a failure to end the flow.
 */
export async function deleteWalletLoginFlow(
  fastify: FastifyInstance,
  handle: string
): Promise<void> {
  const flow = await readWalletLoginFlow(fastify, handle);

  if (typeof flow?.requestObjectHandle === 'string') {
    await deleteWalletRequestObject(fastify, flow.requestObjectHandle);
  }

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

/**
 * The presented credentials a wallet posted, parked for the waiting browser
 * (issue #238).
 *
 * ## Why the bytes are parked instead of validated on arrival
 *
 * The `direct_post` endpoint is UNAUTHENTICATED by construction (OID4VP 1.0
 * §8.2 — a wallet has no client credentials), and it holds only half of what a
 * decision needs: the request, but not the browser, the session or the asserted
 * identifier. Validation also costs signature verification per Disclosure, so
 * running it there would put the expensive part of the flow on the anonymous
 * surface. So the endpoint stays what its own module JSDoc says it is —
 * transport — and the cookie-bound browser poll does the validating.
 *
 * ## What this is, in trust terms
 *
 * Attacker-controlled bytes, held for minutes, addressed by the digest of a
 * `state` the attacker had to redeem to write here at all. Nothing may read
 * this record except the verification seam, and nothing in it is trusted: the
 * `nonce`, the `client_id` and the DCQL query it is checked against all come
 * from the BROWSER-side flow record, never from here.
 */
export interface StashedWalletPresentation {
  /** What `parseVpToken` structurally parsed. Unvalidated. */
  presentations: readonly PresentedCredential[];
  at: number;
  [key: string]: unknown;
}

/**
 * Park the presented credentials for the browser that is waiting on this
 * request.
 *
 * Never throws, for the same reason `publishWalletPresentationSignal` does not:
 * the wallet's transport acknowledgement (§8.3) must not depend on a store the
 * wallet has no relationship with. A failed write degrades to the browser timing
 * out, which is what a wallet that never answered looks like.
 */
export async function stashWalletPresentation(
  fastify: FastifyInstance,
  stateHash: string,
  presentations: StashedWalletPresentation['presentations']
): Promise<void> {
  try {
    await fastify.sessionUtils.setSession<StashedWalletPresentation>(
      `${WALLET_PRESENTATION_KEY_PREFIX}${stateHash}`,
      { presentations, at: Date.now() },
      Math.floor(WALLET_LOGIN_FLOW_TTL_MS / 1000)
    );
  } catch (error) {
    fastify.log.warn(
      { err: error },
      'failed to stash a wallet presentation; the waiting browser will time out'
    );
  }
}

/** Read the parked presentations, or null when none arrived or the store failed. */
export async function readWalletPresentationStash(
  fastify: FastifyInstance,
  stateHash: string
): Promise<StashedWalletPresentation['presentations'] | null> {
  try {
    const record = await fastify.sessionUtils.getSession<StashedWalletPresentation>(
      `${WALLET_PRESENTATION_KEY_PREFIX}${stateHash}`
    );
    if (!record || !Array.isArray(record.presentations)) return null;
    return record.presentations;
  } catch (error) {
    fastify.log.warn({ err: error }, 'wallet presentation stash unavailable');
    return null;
  }
}

/** Delete parked presentations. Called on EVERY terminal outcome. */
export async function deleteWalletPresentationStash(
  fastify: FastifyInstance,
  stateHash: string
): Promise<void> {
  try {
    await fastify.sessionUtils.deleteSession(`${WALLET_PRESENTATION_KEY_PREFIX}${stateHash}`);
  } catch (error) {
    fastify.log.warn({ err: error }, 'failed to delete a stashed wallet presentation');
  }
}

/**
 * A signed JAR request object, parked for the wallet that will fetch it (#377).
 *
 * An object rather than a bare string because `sessionUtils` stores
 * `SessionData` — an index-signature type — and a bare JWT would not typecheck.
 * The wrapper is not decoration: it is also where a future member (a per-request
 * encryption key id, Phase C) lands without changing the key shape.
 */
export interface StoredWalletRequestObject {
  /** The compact JWS, exactly as it goes on the wire. */
  requestObject: string;
  [key: string]: unknown;
}

/**
 * Park a signed request object and return the handle addressing it (#377).
 *
 * ## What the handle is, and what holding one gets you
 *
 * 32 CSPRNG bytes, the same shape as a flow handle, minted per Authorization
 * Request. It goes on the wire inside `request_uri`, which is exactly where a
 * wallet needs it, so it is a BEARER value by construction — and the value it
 * bears is a request object QAuth signed, which carries `state`, `nonce`,
 * `client_id` and the DCQL query.
 *
 * That is the same exposure the invocation URI already carries under the base
 * profile: it embeds `state` and `nonce` as query parameters. Whoever holds
 * either can consume the pending presentation request exactly once. The handle
 * therefore adds no reachability that the unsigned form did not already have,
 * and it is accepted for the same reason — see the module JSDoc on why the
 * invocation URI lives in Redis at all.
 *
 * @throws whatever the session store throws. A failed write CANNOT degrade to a
 * fallback: under a profile that mandates `request_uri` there is no other way to
 * deliver the request, so the caller must surface it as a failed sign-in attempt
 * rather than render a QR code pointing at nothing.
 */
export async function storeWalletRequestObject(
  fastify: FastifyInstance,
  requestObject: string
): Promise<string> {
  const handle = generateWalletFlowSecret();

  await fastify.sessionUtils.setSession<StoredWalletRequestObject>(
    `${WALLET_REQUEST_OBJECT_KEY_PREFIX}${handle}`,
    { requestObject },
    Math.floor(WALLET_LOGIN_FLOW_TTL_MS / 1000)
  );

  return handle;
}

/**
 * Read a parked request object, or null (#377).
 *
 * A malformed handle, an unknown one, an expired one and an unreachable store
 * are ALL null, and they must stay indistinguishable: this is read by an
 * unauthenticated endpoint, so any difference between them is an oracle telling
 * a caller sweeping handles which ones exist. That is the same reasoning
 * {@link readWalletLoginFlow} gives, applied to a surface with no cookie at all.
 */
export async function readWalletRequestObject(
  fastify: FastifyInstance,
  handle: unknown
): Promise<string | null> {
  if (!isWalletLoginHandle(handle)) return null;

  try {
    const record = await fastify.sessionUtils.getSession<StoredWalletRequestObject>(
      `${WALLET_REQUEST_OBJECT_KEY_PREFIX}${handle}`
    );

    return typeof record?.requestObject === 'string' && record.requestObject.length > 0
      ? record.requestObject
      : null;
  } catch (error) {
    fastify.log.warn(
      { err: error },
      'wallet request-object store unavailable; treating as expired'
    );
    return null;
  }
}

/**
 * Delete a parked request object.
 *
 * Called on every TERMINAL outcome of the flow that owns it, never on the fetch:
 * a wallet may legitimately retry the `request_uri` GET — a dropped connection,
 * a backgrounded app — and deleting on first read would turn a retry into a
 * failed login. The TTL and the single-use `state` are what bound it.
 */
export async function deleteWalletRequestObject(
  fastify: FastifyInstance,
  handle: string
): Promise<void> {
  try {
    await fastify.sessionUtils.deleteSession(`${WALLET_REQUEST_OBJECT_KEY_PREFIX}${handle}`);
  } catch (error) {
    fastify.log.warn({ err: error }, 'failed to delete a wallet request object');
  }
}

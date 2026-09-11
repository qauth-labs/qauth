import { randomBytes } from 'node:crypto';

import type { PresentedCredential } from '@qauth-labs/fastify-plugin-federation';
import type { FastifyInstance } from 'fastify';

import {
  WALLET_LOGIN_DONE_MARKER_TTL_MS,
  WALLET_LOGIN_FLOW_TTL_MS,
  WALLET_RETURN_CODE_TTL_MS,
} from '../constants';

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
 * ## The same-device return leg (#405, ADR-013)
 *
 * A third record joins the two above when a flow was started on the device the
 * wallet lives on: **the done-marker** (`wallet-login-done:<handle>`). On a
 * same-device flow the wallet does not merely post its response — it is handed
 * a `redirect_uri` carrying a fresh Response Code (OID4VP 1.0 §8.2, §14.2;
 * HAIP 1.0 §5.1) and brings the user's browser back to
 * `/ui/wallet-login/return`, which is where the flow completes. Wallets open
 * that URL in a NEW tab, and the tab that started the flow is still polling; the
 * marker is how the return leg tells that tab how the flow ended. It is
 * browser-side state like the flow record (keyed by handle, gated by the same
 * binder), never something the wallet can write, and it mints nothing — see
 * {@link writeWalletFlowDoneMarker}.
 *
 * The signal grows a third value for the same leg, `'return_rejected'`, and the
 * flow record grows `sameDevice`; both are documented where they are declared.
 * The decision the two state machines take on a signal record — wait for the
 * return leg, reject, or go on — lives here too, in ONE function,
 * {@link decideSignalGate}, so the login and link flows cannot drift apart on
 * the one piece of security-relevant timing logic they share.
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

/**
 * Redis namespace for the DONE-MARKER a same-device return leg leaves for the
 * tab that started the flow (#405).
 *
 * A fifth namespace, keyed by the flow HANDLE like the flow record — it is
 * about the browser, not the wallet — but kept apart from the flow record
 * rather than folded into it as a field: the flow record is deleted on every
 * terminal outcome (`deleteWalletLoginFlow`, "so a completed or refused flow
 * cannot be polled again"), and the marker exists precisely to outlive that
 * deletion by one read. Writing "done" INTO the flow record would mean keeping
 * a finished flow addressable, which is the property the deletion exists to
 * deny.
 */
const WALLET_DONE_MARKER_KEY_PREFIX = 'wallet-login-done:';

/** CSPRNG bytes per handle and per binder; 32 bytes → 43 base64url characters. */
const HANDLE_BYTES = 32;

/** Exactly what `randomBytes(32).toString('base64url')` produces. */
const HANDLE_PATTERN = /^[A-Za-z0-9_-]{43}$/;

/**
 * What arrived for the waiting browser, and from whom.
 *
 * Three values, and none is an identity claim:
 *
 * - `received` — a structurally-valid `vp_token` redeemed the request `state`.
 *   Written by the wallet-side POST.
 * - `wallet_error` — the wallet returned an OAuth-style error instead (§8.2).
 *   Written by the wallet-side POST. The wallet's own error code is NOT
 *   propagated: it is attacker-controllable text, and the UI shows one refusal
 *   for every failure anyway.
 * - `return_rejected` — a same-device `redirect_uri` was followed into a
 *   browser that does not hold the flow, or that holds a LINK flow but not
 *   the user session it was started in (#405). Written by the RETURN ROUTE,
 *   never by a wallet: it is QAuth's own record that the redirect "arrives in a
 *   different user session to the one the request was initiated in", the case
 *   HAIP 1.0 §5.1 says the Verifier MUST reject (and OID4VP 1.0 §14.2 names —
 *   "the Wallet uses a browser different from the one used on the presentation
 *   request"). Consumers treat it exactly like `wallet_error`: the flow ends as
 *   refused, nothing is minted, and the presented bytes are already gone (see
 *   {@link discardWalletPresentation}). It overwrites the `received` the wallet
 *   wrote moments earlier, which is the point — the hard guarantee is that the
 *   Response Code was spent on the foreign landing and the initiating flow can
 *   never complete; this value is what lets that flow's poll SAY so instead of
 *   waiting for the deadline.
 */
export type WalletPresentationSignal = 'received' | 'wallet_error' | 'return_rejected';

/** The signal as stored: which one, and when it was written (epoch ms). */
export interface WalletPresentationSignalRecord {
  signal: WalletPresentationSignal;
  /**
   * When the signal was published. Read by exactly one consumer — the
   * same-device rejection deadline in {@link decideSignalGate}, which both
   * state machines call — and carried on the record rather than recomputed so
   * the deadline is measured from the moment the wallet answered, not from
   * whenever a poll happened to look.
   */
  at: number;
  [key: string]: unknown;
}

const KNOWN_SIGNALS: ReadonlySet<string> = new Set<WalletPresentationSignal>([
  'received',
  'wallet_error',
  'return_rejected',
]);

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
  /**
   * Whether the user chose to open a wallet on THIS device (#405, ADR-013).
   *
   * Decided by the user's own form submission at flow start (HAIP 1.0 §5.1
   * "If same-device flow is used") and written in TWO places atomically with
   * each record: here, and as `same_device` on the `oid4vp_request_states`
   * row. Neither copy can stand in for the other, because each side of the
   * exchange reads only its own record. The ROW is what the wallet's POST
   * redeems, so it is the row the Response Endpoint reads to decide whether to
   * hand the wallet a `redirect_uri` at all (OID4VP 1.0 §14.2: the technique
   * "is not applicable to cross-device scenarios") — the endpoint cannot name
   * a browser and must not be able to read a flow record. The FLOW is what the
   * browser's poll reads, so it is the flow the login state machine consults to
   * refuse completion by polling ("MUST require the frontend to pass the
   * respective Response Code") and to reject a presentation whose redirect was
   * never followed. A boolean names no browser, so the row-side copy keeps the
   * "wallet side cannot name a browser" invariant intact.
   *
   * Optional in the TYPE only, for the reason {@link mode} is: Redis holds
   * records written by the previous binary, and every reader treats an absent
   * value as `false` — the cross-device path that existed before #405, which
   * is the only path such a record could ever have been on. The same default
   * makes the form's absent `device` field mean cross-device, so the E2E
   * harness and older clients keep completing by polling exactly as before.
   */
  sameDevice?: boolean;
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
    await fastify.sessionUtils.setSession<WalletPresentationSignalRecord>(
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

/**
 * Read the whole signal record for a request — which signal, and when — or
 * null while none has arrived.
 *
 * The timestamp matters to exactly one reader: the same-device deadline in
 * {@link decideSignalGate} (#405), which rejects a `received` presentation
 * whose `redirect_uri` was never followed once `at` is older than
 * `WALLET_RETURN_CODE_TTL_MS`. A stored record whose `at` is not a finite
 * number — nothing this module writes, but the store is shared — reads as
 * arbitrarily OLD (`0`) rather than as "now": the only decision that looks at
 * the field is a rejection deadline, and an unreadable timestamp must fail
 * closed into the rejection it guards, not restart the clock.
 *
 * A stored `signal` outside the known set is a MISS, as before: the value is
 * trusted downstream because QAuth authored it, so anything that is not one of
 * QAuth's three markers is treated as nothing having been written.
 */
export async function readWalletPresentationSignalRecord(
  fastify: FastifyInstance,
  stateHash: string
): Promise<WalletPresentationSignalRecord | null> {
  try {
    const record = await fastify.sessionUtils.getSession<WalletPresentationSignalRecord>(
      `${WALLET_SIGNAL_KEY_PREFIX}${stateHash}`
    );
    if (typeof record?.signal !== 'string' || !KNOWN_SIGNALS.has(record.signal)) return null;
    const at = typeof record.at === 'number' && Number.isFinite(record.at) ? record.at : 0;
    return { signal: record.signal, at };
  } catch (error) {
    fastify.log.warn({ err: error }, 'wallet presentation signal store unavailable');
    return null;
  }
}

/**
 * Which surface is asking a state machine to advance a flow (#405).
 *
 * - `poll` — the status endpoint or the page re-render: the ORIGINAL tab,
 *   holding the binder cookie (and, for a link, a session) and nothing else.
 * - `return` — the same-device return leg: a tab holding the binder cookie
 *   AND having just spent a Response Code that named this flow.
 *
 * A same-device flow's positive outcome is reserved for `return` (OID4VP 1.0
 * §14.2: "MUST require the frontend to pass the respective Response Code");
 * every negative outcome is reachable either way. Shared by both state
 * machines so the word means one thing.
 */
export type WalletFlowSurface = 'poll' | 'return';

/** The log line for a same-device presentation refused on the foreign-landing signal. */
export const SAME_DEVICE_FOREIGN_SESSION_WARNING =
  'same-device presentation rejected: redirect landed in a foreign session';

/** The log line for a same-device presentation refused at the Response Code deadline. */
export const SAME_DEVICE_NOT_FOLLOWED_WARNING =
  'same-device presentation rejected: redirect not followed';

/**
 * What {@link decideSignalGate} tells a state machine to do with a flow whose
 * signal record has arrived.
 *
 * - `pending` — answer pending and touch nothing; the return leg may still
 *   arrive.
 * - `rejected` — terminate and refuse. `warn` is the reason for the log when
 *   the refusal is one the log should carry (a foreign landing, a deadline);
 *   a wallet-reported error carries none, as it never did.
 * - `proceed` — the presentation may be resolved on this surface.
 */
export type WalletSignalGateDecision =
  { verdict: 'pending' } | { verdict: 'rejected'; warn?: string } | { verdict: 'proceed' };

/**
 * The same-device gate (#405, ADR-013 D7) — ONE decision for both state
 * machines, taken on the signal record after the binder, expiry and mode
 * gates each machine applies for itself.
 *
 * - `wallet_error` or `return_rejected` → `rejected`, on EVERY flow, via
 *   either surface. An error carries no presentation and surfacing it mints
 *   nothing, so gating it would only leave a user who tapped "Decline" in
 *   their wallet watching a spinner. `return_rejected` is logged: it is the
 *   record that a redirect landed in a foreign session.
 * - `received` on a same-device flow, via `poll` → `pending` while the
 *   redirect could still arrive (`now <= at + WALLET_RETURN_CODE_TTL_MS`, the
 *   same window the database gives the code), and once it cannot →
 *   `rejected`, logged. That is HAIP 1.0 §5.1's "MUST reject presentations
 *   if Wallets do not follow the redirect back", enforced ACTIVELY at the
 *   deadline rather than left to the flow's expiry, so the wait is capped at
 *   three minutes and the rejection is a logged event rather than a silence.
 *   The deadline is measured from the signal's own timestamp, so a poll that
 *   arrives late cannot restart it, and it is the SAME constant the database
 *   applies to the code, so the two edges cannot disagree.
 * - `received` via `return` → `proceed`: the leg the code was minted for.
 * - `received` on a cross-device flow → `proceed` by polling, exactly as
 *   before #405. A return can never reach such a flow, because the Response
 *   Endpoint emits no `redirect_uri` for a cross-device row and the
 *   repository refuses to redeem a code for one.
 *
 * Pure: it reads the clock only through `now`, writes nothing and logs
 * nothing, so the caller — which holds the request, the flow and the
 * terminate routine — does the terminating and the logging. That is what
 * keeps this the one place the rule lives and each machine the one place its
 * flow changes state.
 *
 * @param record - the signal record the flow's `stateHash` resolved to.
 * @param flow - the flow, for its `sameDevice` flag.
 * @param via - which surface is asking.
 * @param now - the clock, epoch ms; a parameter so the deadline is testable.
 */
export function decideSignalGate(
  record: WalletPresentationSignalRecord,
  flow: Pick<WalletLoginFlow, 'sameDevice'>,
  via: WalletFlowSurface,
  now: number = Date.now()
): WalletSignalGateDecision {
  if (record.signal === 'wallet_error') return { verdict: 'rejected' };
  if (record.signal === 'return_rejected') {
    return { verdict: 'rejected', warn: SAME_DEVICE_FOREIGN_SESSION_WARNING };
  }

  if (flow.sameDevice === true && via === 'poll') {
    if (now <= record.at + WALLET_RETURN_CODE_TTL_MS) return { verdict: 'pending' };
    return { verdict: 'rejected', warn: SAME_DEVICE_NOT_FOLLOWED_WARNING };
  }

  return { verdict: 'proceed' };
}

/**
 * Reject a presentation whose same-device redirect landed in a browser that
 * does not hold the flow (#405; HAIP 1.0 §5.1, third bullet: "Verifiers MUST
 * reject presentations if […] the redirect back arrives in a different user
 * session to the one the request was initiated in").
 *
 * Called by the return route AFTER it has spent the Response Code and found no
 * flow of this browser's that the code names — or found a LINK flow, but no
 * session, or another user's, where the one that started it should be. Two
 * writes, best-effort and in this order: the parked presentation is deleted
 * (attacker-reachable text that no surface will ever validate now has no
 * business staying addressable for the rest of its TTL), then the signal is
 * overwritten with `'return_rejected'` so the initiating flow's poll answers
 * `rejected` on its next tick instead of spinning to the deadline.
 *
 * Neither write is the guarantee. The guarantee is the spent code: the
 * initiating flow is same-device (a code redeems only for a `same_device`
 * row), a same-device flow never completes by polling, and the one code that
 * could have completed it on the return leg is gone. So this never throws and
 * a failed write costs nothing but a slower refusal — the same posture as
 * {@link publishWalletPresentationSignal}, for the same reason: it runs on a
 * response to an unauthenticated landing, and that response must not depend
 * on the store.
 */
export async function discardWalletPresentation(
  fastify: FastifyInstance,
  stateHash: string
): Promise<void> {
  await deleteWalletPresentationStash(fastify, stateHash);
  await publishWalletPresentationSignal(fastify, stateHash, 'return_rejected');
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

/**
 * What a same-device return leg leaves for the tab that started the flow
 * (#405, ADR-013).
 *
 * ## Why it exists
 *
 * Wallets open the `redirect_uri` in a NEW tab (`UIApplication.open` on iOS, an
 * `ACTION_VIEW` intent on Android), while the OAuth client's `state` and PKCE
 * verifier live in the ORIGINAL tab's `sessionStorage` — so the tab that
 * completes the sign-in is not the tab that can continue it. The return leg
 * therefore mints the browser session in the shared cookie jar, renders a
 * "you're signed in, go back" page, and leaves THIS record for the original
 * tab's poll to find where the flow record used to be. The poll answers
 * `complete` with `redirectTo` once, the original tab navigates, and the
 * client's callback runs in the tab that holds its verifier.
 *
 * ## What it is, in trust terms
 *
 * Nothing that confers anything. It carries a COPY of the flow's binder — the
 * secret the browser proves with its `__Host-` cookie — so only the browser
 * that started the flow can read it (the state machine compares with
 * `csrfTokensEqual` before honouring it), an already-validated relative
 * `redirectTo`, and the WORD the flow ended on. It is written by every
 * terminal outcome of the return leg, completed or refused, so the original
 * tab is told the same thing the return tab was told: a marker for a refusal
 * carries `outcome: 'rejected'` (or `'conflict'`) and consuming it answers
 * exactly that, never a completion. Consuming a completed login's marker
 * mints nothing — the session it names was minted by the return leg — but it
 * does re-issue that session's cookie, see {@link sessionId}. A marker read
 * with the wrong binder, or by a poll that arrives after the TTL, is an
 * `expired`, exactly what a missing flow answered before #405.
 *
 * ## Written before the flow is deleted
 *
 * The return leg writes the marker while the flow record still exists and
 * deletes the flow afterwards. The tab that started the flow is polling on a
 * three-second clock, and the state machine answers it from the flow record
 * while there is one and from the marker once there is not; the other order
 * leaves a window, a few store round trips wide, in which that poll finds
 * neither, answers `expired`, and the pending page stops polling for good
 * while the return tab says "You're signed in". With the marker first, a poll
 * that lands mid-completion finds the live flow and answers `pending` (the
 * same-device gate never lets a poll complete it), and the first poll after
 * the deletion finds the marker.
 *
 * ## Single read
 *
 * Deleted the moment the rightful poll consumes it (the state machine's job,
 * not this module's — see {@link deleteWalletFlowDoneMarker}), for the reason
 * the flow record is deleted on every terminal outcome: a finished flow must
 * not stay addressable. The TTL, `WALLET_LOGIN_DONE_MARKER_TTL_MS`, equals the
 * flow TTL and not less: a backgrounded phone tab polls only when it is
 * brought back, and a marker gone by then would strand the very tab the leg
 * exists to continue.
 */
export interface WalletFlowDoneMarker {
  /** The flow's binder, copied so the marker is gated the way the flow was. */
  binder: string;
  /** Which state machine may consume it; a login poll must not eat a link's. */
  mode: WalletFlowMode;
  /** Where the original tab should continue (login mode); already validated. */
  redirectTo?: string;
  /**
   * How the flow ended, when it did not complete — or, in link mode, the
   * word the linking page shows for a completion too (`'linked'` /
   * `'rebound'`). A login marker carries this ONLY for a refusal
   * (`'rejected'`): its one completed outcome is "continue to `redirectTo`",
   * and it is recorded by the absence of a word, so nothing that carries one
   * can be read as a completion.
   */
  outcome?: string;
  /**
   * The browser session the return leg minted, for a COMPLETED login (#405).
   *
   * Consuming the marker re-issues this session's cookie. The return tab's
   * response already carried it, but that response and the original tab's
   * poll are two requests on two connections, and nothing orders them: a
   * poll that consumes the marker before the return tab's `Set-Cookie` has
   * landed would navigate to `redirectTo` without a session and bounce the
   * user back to the login screen. Re-setting the cookie from the marker
   * removes the dependency, and it confers nothing new: the marker is
   * readable only with the flow's binder, the binder is proven by an
   * HMAC-signed `__Host-` cookie that only the browser which started the
   * flow holds, and the session was minted for exactly that flow — so the
   * browser the cookie is set on is the browser the session belongs to.
   * The value is a session id, not a secret in its own right (the cookie is
   * the signed form), held in a store that already holds the session.
   */
  sessionId?: string;
  [key: string]: unknown;
}

/**
 * Leave a done-marker for the tab that started `handle`'s flow (#405).
 *
 * Called by the return leg on every terminal outcome, AFTER the outcome
 * happened — the session minted, the credential linked, the refusal audited
 * — and BEFORE the flow is terminated (see {@link WalletFlowDoneMarker} on
 * why that order). Writing it after the outcome is what makes it safe to
 * write best-effort: by the time this runs the user IS signed in (or IS
 * refused), and the worst a failed write can do is leave the original tab on
 * "expired" while the return tab has already shown the truth and, for a
 * completed sign-in, its "Continue here instead" link still works. Never
 * throws, for that reason; a completed sign-in must not turn into a 500
 * because a courtesy record for another tab could not be stored.
 */
export async function writeWalletFlowDoneMarker(
  fastify: FastifyInstance,
  handle: string,
  marker: WalletFlowDoneMarker
): Promise<void> {
  try {
    await fastify.sessionUtils.setSession<WalletFlowDoneMarker>(
      `${WALLET_DONE_MARKER_KEY_PREFIX}${handle}`,
      marker,
      Math.floor(WALLET_LOGIN_DONE_MARKER_TTL_MS / 1000)
    );
  } catch (error) {
    fastify.log.warn(
      { err: error },
      'failed to write a wallet-login done-marker; the original tab will report expired'
    );
  }
}

/**
 * Read the done-marker for `handle`, or null (#405).
 *
 * A malformed handle, no marker, a marker without a binder and an unreachable
 * store are ONE null, for the reason {@link readWalletLoginFlow} gives: to the
 * poll, each of them is "this flow is gone", and the answer must not vary
 * with which. The caller — the state machine, which holds the browser's
 * cookie — compares `binder` timing-safely and only then calls
 * {@link deleteWalletFlowDoneMarker}. That ordering is deliberate: a poll that
 * arrives WITHOUT the binder (a handle harvested from a screen share) must
 * learn nothing and must not burn the marker the rightful tab is about to
 * consume, so the read and the delete are separate primitives rather than one
 * "consume".
 */
export async function readWalletFlowDoneMarker(
  fastify: FastifyInstance,
  handle: unknown
): Promise<WalletFlowDoneMarker | null> {
  if (!isWalletLoginHandle(handle)) return null;
  try {
    const record = await fastify.sessionUtils.getSession<WalletFlowDoneMarker>(
      `${WALLET_DONE_MARKER_KEY_PREFIX}${handle}`
    );
    if (typeof record?.binder !== 'string' || record.binder.length === 0) return null;
    return record;
  } catch (error) {
    fastify.log.warn({ err: error }, 'wallet-login done-marker store unavailable');
    return null;
  }
}

/**
 * Delete the done-marker for `handle` once the rightful tab has consumed it
 * (#405). Best-effort: the TTL bounds it regardless, and a marker that
 * lingers is readable only by the browser that already acted on it.
 */
export async function deleteWalletFlowDoneMarker(
  fastify: FastifyInstance,
  handle: string
): Promise<void> {
  try {
    await fastify.sessionUtils.deleteSession(`${WALLET_DONE_MARKER_KEY_PREFIX}${handle}`);
  } catch (error) {
    fastify.log.warn({ err: error }, 'failed to delete a wallet-login done-marker');
  }
}

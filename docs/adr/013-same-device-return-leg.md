# ADR-013: Same-Device Return Leg — the OID4VP Response Code on Both Verifier Profiles

**Status:** Accepted
**Date:** 2026-09-11
**Authors:** QAuth Team

## Context

Until #405 every wallet sign-in ended the same way whatever device the wallet
was on: the wallet posted its Authorization Response to `POST /oid4vp/response`,
the endpoint answered `200 {}`, and the browser that started the flow polled
`GET /ui/wallet-login/:handle/status` until the presentation was there. That is
the cross-device model OID4VP 1.0 §13.3 describes — step (6) with no
`redirect_uri`, the Verifier fetching the result on its own — and it is the only
model a phone wallet scanning a desktop QR code can use.

It is not the model HAIP 1.0 §5.1 makes mandatory for a wallet on the same
device: "Verifiers MUST include `redirect_uri` in the HTTP response to the
Wallet's HTTP POST to the `response_uri`", "Wallets MUST follow the redirect",
and "Verifiers MUST reject presentations if Wallets do not follow the redirect
back or the redirect back arrives in a different user session to the one the
request was initiated in". The mechanism it points at is OID4VP 1.0 §14.2: a
fresh secret — the Response Code — in the redirect URI, which the frontend
must present before the Verifier hands over the Authorization Response. That is
what binds the presentation to the browser session that asked for it, and it
is the one session-fixation defence `direct_post` has.

Issue #405 asked for the Response Code on both profiles. The design went
through one full critique; this record is what survived it, and why the first
draft did not.

## Decision

### 1. The user says which device the wallet is on, at flow start

The identifier form (`GET /ui/wallet-login`) has two submit buttons on the one
form — `device=this` ("Use a wallet on this device") and `device=other` ("Scan
with a wallet on another device"). The same field is on the link form
(`POST /ui/wallet-link`) and in the JSON body of `POST /auth/link/wallet`. An
absent field is cross-device, so every caller built before #405 keeps the path
it had.

The choice is written in two places, atomically with each record:
`oid4vp_request_states.same_device` (a boolean — the wallet-side row still names
no browser) and `sameDevice` on the Redis flow record. The pending page then
renders **exactly one** affordance: the "Open my wallet" anchor for `this`, the
QR code for `other`. Both carry a "Start again" link to a fresh, unmarked flow.

There is no server-side "bounce" that marks a flow same-device on a click. See
[Alternatives](#alternatives-considered) for why that shape cannot work.

### 2. One shape on both profiles

`oid4vp-1.0-base` and `haip-1.0`, `direct_post` and `direct_post.jwt`, behave
identically. There is no profile field and no environment variable: a mandate
no code reads is decoration, and response encryption already set the precedent
of "built in, no variable". HAIP's RECOMMENDED same-device-only posture is a
recorded deviation (below), not a switch.

### 3. The Response Code is minted at the Response Endpoint and written in the same UPDATE that redeems the row

`POST /oid4vp/response` mints 32 CSPRNG bytes (43 base64url characters; §8.2
RECOMMENDS at least 128 bits) **before** redemption and passes the SHA-256
digest and a deadline into the one guarded `UPDATE` that already consumed the
row: `redeem(stateHash, { codeHash, codeExpiresAt })` and its
`redeemByEncryptionKid` twin add two columns to their existing `SET`; the guard
predicates and the erasure of the encryption key are untouched. Only the digest
is ever stored, mirroring `state_hash`.

The digest is written for every redeemed row — the repository has one shape —
but the `redirect_uri` is **emitted only when the returning row carries
`same_device = true`**. A cross-device row's code never leaves the server, and
`redeemResponseCode` additionally requires `same_device = true`, so it cannot be
redeemed even in theory. Both 200 paths — the accepted presentation and the
wallet-reported error — answer `{ redirect_uri }` for a same-device row and
`{}` for a cross-device one, `Cache-Control: no-store`. §8.2 permits the member
"for Error Responses", and HAIP's MUST has no success qualifier: the user who
declined on this device is looking at the tab that waits, and the redirect is
how it learns to stop. Every refusal throws before `send`, so a code is never
returned for an exchange that was not accepted.

`WALLET_RETURN_CODE_TTL_MS` is 180 s, a constant rather than a setting: policy,
not tuning. Long enough for wallets that require a "Done" tap; short because
the code is a bearer secret in a URL. The same constant is the poll's rejection
deadline (decision 7), so feedback and expiry cannot disagree.

### 4. The `redirect_uri` is absolute, built from the issuer, with the code as a query parameter

`redirect_uri = <JWT_ISSUER>/ui/wallet-login/return?response_code=<code>` —
never from `Host` or `X-Forwarded-*` (there is no `trustProxy`), and carrying
nothing but the code: no state, no handle, no realm. The Authorization Request
still carries no `redirect_uri` parameter (`assertNoRedirectUriParameter` stays;
see [Three meanings](#three-meanings-of-redirect_uri) below).

§8.2 allows the value "as a path component, as a fragment or as a parameter",
and its non-normative example uses a fragment. QAuth uses a query parameter
because every wallet surface here has a `<noscript>` twin, and a fragment never
reaches the server — the landing would be JavaScript-only. The cost is that the
secret transits a URL that logs, caches and referrers can see, so it is fenced:

- single-use, spent in one guarded `UPDATE` before the browser is asked anything;
- 180 s deadline in the database;
- `Cache-Control: no-store` and `Referrer-Policy: no-referrer` on every response
  of the return route;
- a nonced `history.replaceState(null, '', '/ui/wallet-login/return')` on the
  refusal page and the completed pages, scrubbing the (already spent) code from
  the address bar and history entry — a browser without scripts loses only that
  hygiene. The 401/409 terminal pages the return route renders for a refusal
  after the code was spent (a wallet-reported error, an unresolvable
  presentation, a link conflict) carry **no** scrub, by design: they are the
  linking and login surfaces' existing pages, and the tests hold them
  byte-identical to what the page GET renders for the same outcome. The trade
  is a spent code left in the address bar of a page that says "not completed";
  step 2 below has already burned it before any page renders;
- pino request logging redacts the `response_code` query value from `req.url`
  (`config/logger.ts`), because §14.2 names the code the secret and Fastify's
  default request line would otherwise write it at `info`. The global error
  handler's own `url` field is redacted the same way, so a 429 from the rate
  limiter, a 5xx from the store, or a validation 400 on the return route logs
  `response_code=[Redacted]` too — those are precisely the paths on which the
  code is still unspent.

### 5. The return route burns first, then binds

`GET /ui/wallet-login/return?response_code=…` lives in `routes/ui/wallet-login.ts`
beside the one login state machine; it is flag-gated and rate-limited like its
sibling GET routes, and every response is `no-store` / `no-referrer`. Its order
of operations is the security property:

1. **Shape.** Not 43 base64url characters → the refusal page, nothing touched.
2. **Burn.** `redeemResponseCode(sha256(code))` — one `UPDATE` guarded on the
   digest, unspent, unexpired, row redeemed and `same_device = true`, returning
   only `state_hash`. `undefined` (unknown, expired, replayed, cross-device) →
   the refusal page. Whatever happens next, the code is spent.
3. **Bind.** Read this browser's `__Host-qauth_wallet_flow` bindings (at most
   three), read each flow, select the one whose `stateHash` matches the returned
   one and whose stored binder equals the cookie's, timing-safely. **None** is a
   foreign landing — a different browser, an in-app browser with its own jar, a
   private window, an attacker replaying a code from a log: the parked
   presentation is discarded, the signal becomes `return_rejected`, the log says
   "same-device return arrived in a foreign session", and the refusal page
   renders. This is HAIP §5.1's "arrives in a different user session" clause,
   enforced.
4. **Advance.** `login` → `advanceWalletLoginFlow(…, { via: 'return' })`;
   `link` → resolve the browser session and compare it, timing-safely, with the
   user the flow was started by (a link flow was initiated in a user session,
   so a return without one — or in a _different_ user's session, the jar
   having changed hands while the wallet was open — is a foreign landing too,
   handled exactly as step 3: discard, warn, refuse), then
   `advanceWalletLinkFlow(…, { via: 'return' })`. Both re-apply the binder,
   expiry and mode gates they always applied.

Every refusal in steps 1–3, and `expired`/`pending` from step 4, render **one
byte-identical page**: HTTP 200 (in-app browsers decorate non-2xx navigations),
titled "Finish signing in where you started", with no "Try again" — a new flow
started in the wrong cookie jar is a trap — and the password footer kept. The
reason is logged server-side only; nothing is audited on refusal; no
wallet-supplied text is echoed. A `rejected` outcome after a spent code (the
wallet declined; the presentation did not resolve; the user is unavailable)
renders the existing 401 refusal terminal page, byte-for-byte what the page GET
renders for the same outcome — and leaves a `rejected` done-marker (decision 8)
so the original tab reports the same word.

### 6. Completion on the return leg — the original tab continues

Wallets open the `redirect_uri` in a **new** tab (iOS `UIApplication.open`,
Android `ACTION_VIEW`), and the OAuth client's `state` and PKCE verifier live in
the **original** tab's `sessionStorage`. So the return leg mints the session
exactly as the poll does — fresh session id, `updateLastLogin`, the
`ui.wallet_login.success` audit row, the session cookie into the shared jar — but
does **not** drop the flow's cookie binding, writes the done-marker (decision 8)
**before** deleting the flow, and renders a 200 terminal page: "You're signed
in — go back to the tab or window where you started; it's continuing there on
its own", with `returnTo` offered only as a secondary "Continue here instead"
link for a purged original tab. Redirecting here would hand a server-side client two authorization codes
for one login and an SPA client a "state mismatch" error in the foreground tab.
Link mode renders its own linked page. The status endpoints' JSON shapes are
unchanged.

### 7. Same-device gating inside the one state machine

`advanceWalletLoginFlow` and `advanceWalletLinkFlow` take `via: 'poll' | 'return'`.
After the binder, expiry and mode gates, on the signal record `{ signal, at }`,
the decision is taken by one shared, pure function — `decideSignalGate` in
`helpers/wallet-login-flow.ts` — that both machines call and act on, so the
one piece of security-relevant timing logic the two flows share cannot drift
between them:

- `wallet_error` or `return_rejected` → terminate, `rejected` — on every flow,
  via poll or return. An error carries no presentation; surfacing it mints
  nothing, and hiding it would leave a user who tapped "Decline" watching a
  spinner for six minutes.
- `received` on a same-device flow **via poll** → `pending` while
  `now ≤ at + WALLET_RETURN_CODE_TTL_MS` (the poll never completes a same-device
  flow — §14.2's "MUST require the frontend to pass the respective Response
  Code"); past it → terminate, `rejected`, log "same-device presentation
  rejected: redirect not followed". That is HAIP §5.1's "do not follow the
  redirect back" clause enforced **actively**, and it caps the wait at three
  minutes instead of leaving the flow to expire.
- `received` via return → resolve, terminate, complete.
- `received` on a cross-device flow → complete via poll exactly as before. A
  return can never reach a cross-device flow, because no code is emitted for one.
- No flow → consult the done-marker before answering `expired`.

Because the poll never completes a same-device flow, the poll and the return
leg cannot both complete it: there is no race to lose. There is one edge the
two surfaces can disagree on, and it is accepted rather than closed: neither
consumes the signal atomically, so a return that spends its code in the last
few hundred milliseconds of the window can still be resolving the presentation
when a poll fires past `at + WALLET_RETURN_CODE_TTL_MS`, terminates the flow as
`rejected`, and the return then completes anyway — session minted, success
audited, marker written — while the original tab has already rendered the
refusal and will not read the marker. Sub-second, the rightful user, a
legitimate code, and no bypass: the code was redeemable, the browser held the
binder, and the return tab shows "You're signed in" with its "Continue here
instead" link. It is an inconsistent pair of pages, not a security outcome.
What would close it is making the signal read a consume (a `GETDEL`-style
helper) or taking a `SETNX` "completing" marker keyed by `stateHash` before
`resolveWalletPresentation` on both surfaces, so exactly one caller can proceed
past the signal; neither is worth a second Redis write on every poll for a
window this narrow.

### 8. The done-marker for the original tab

`wallet-login-done:<handle>` = `{ binder, mode, redirectTo?, outcome?, sessionId? }`,
TTL equal to the flow's (six minutes — a backgrounded phone tab's poll gap
routinely exceeds a minute). Written by **every** terminal outcome of the return
leg — a completion, and a refusal with `outcome: 'rejected'` (or `'conflict'`
for a link) — so the original tab reports the word the return tab showed rather
than an "expired" that would depend on whether its poll or the redirect got
there first. Written **before** the flow record is deleted: the state machines
answer the original tab from the flow while one exists and from the marker once
there is not, and the other order left a window, a few store round trips wide,
in which that tab found neither, reported `expired`, and stopped polling for
good. Consulted inside the state machines when the flow is missing, and consumed
**once** by a poll that presents the binder: marker deleted, binding dropped,
`{ status: 'complete', redirect_to }` / `{ status: 'rejected' }` (or the link
outcome). It never mints a session — but a completed login's marker carries the
`sessionId` the return leg minted, and consuming it re-issues that session's
cookie on the poll's own response, so the original tab's navigation does not
depend on the return tab's `Set-Cookie` having landed first (two requests on two
connections, unordered). That is safe because the binder that unlocks the
marker is proven by an HMAC-signed `__Host-` cookie only the browser which
started the flow holds, and the session was minted for exactly that flow. A
poll without the binder, or with the wrong mode, learns nothing and burns
nothing.

## Alternatives considered

| Alternative                                                                                          | Why not                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| ---------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| A `POST /ui/wallet-login/:handle/open` bounce that marks the flow same-device and 302s to the wallet | Three independent failures. The global CSP sets `form-action 'self'`, and Chromium and WebKit re-check it on the redirect target, so a form POST answered with `302 openid4vp://…` is refused — the wallet never opens, and the flow is already marked. iOS does not open an app for a universal link reached through a server-side 3xx, so a deployment with an `https://` invocation endpoint loses the same-device path entirely. Android renders `ERR_UNKNOWN_URL_SCHEME` into the polling tab when no wallet is installed. The anchor the page already had — a plain user-gesture `href` — has none of these problems, so the choice moved to flow start and the anchor stayed. |
| The Response Code as a URL fragment (the spec's example)                                             | A fragment never reaches the server; the landing would need JavaScript to read it, and every wallet surface here has a `<noscript>` twin. The query parameter's exposure is fenced instead (decision 4).                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| Keep the code in Redis rather than on the request-state row                                          | The signal and stash writes are best-effort and never throw; the code's single-use guarantee has to be an atomic, guarded statement against the same row the presentation was correlated with. The repository already had exactly that idiom.                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| A `sameDevicePosture` field on `VerifierProfile`, or an env knob                                     | The issue asked for the code on both profiles. A posture nothing reads is decoration; a knob that turns session binding off is a knob someone will turn. A per-profile `crossDevice` posture is the honest follow-up (below), and it would gate the QR path, not the code.                                                                                                                                                                                                                                                                                                                                                                                                           |
| A `flow_handle` column on the request-state row                                                      | The row is inserted before the flow handle is minted, and the invariant that the wallet-side row cannot name a browser is worth more than the join it would buy. The natural join is code → row → `state_hash`, matched against the at-most-three flows the browser's own cookie names.                                                                                                                                                                                                                                                                                                                                                                                              |
| Redeem the code only `WHERE state_hash IN (<this browser's flows>)`                                  | A landing with no binding would then issue no query, the code would stay live for its whole deadline, and the presentation would stay completable by whoever holds the binder — exactly the "arrives in a different user session" case HAIP says to reject. Burning unconditionally and binding afterwards is the MUST.                                                                                                                                                                                                                                                                                                                                                              |
| Return `redirect_uri` on every 200, including cross-device                                           | §8.2 obliges a wallet given a `redirect_uri` to follow it, so every phone that scanned a desktop QR would land on a refusal page while the desktop succeeded — with a live code in its address bar. §14.2 says the technique "is not applicable to cross-device scenarios"; §13.3 draws the cross-device model as no `redirect_uri` plus polling; HAIP's MUST sits under "If same-device flow is used". Emitting it only for a same-device row is what the specs describe.                                                                                                                                                                                                           |

## Residual cross-device risk

The QR flow keeps completing by polling on both profiles, and OID4VP §14.2 is
explicit that the Response Code "is not applicable to cross-device scenarios
because the browser used by the Wallet will not have the original session".
That flow therefore relies on the mitigations §14.2 RECOMMENDS a Verifier add
when running `direct_post` without a redirect:

- the signed `__Host-qauth_wallet_flow` binder cookie required on every poll —
  only the browser that started the flow can fetch its outcome
  (`routes/ui/wallet-login.test.ts`, "CSRF and the browser binder");
- the asserted identifier the presentation must match ([ADR-009](./009-wallet-account-resolution.md)
  §1) — a request relayed to a victim whose credential carries a different
  identifier is refused ("the asserted identifier");
- the six-minute flow lifetime and one uniform refusal.

They narrow the attack; they do not close it the way the Response Code does.
HAIP 1.0 §5.1's "Verifiers are RECOMMENDED to use only the same-device flow" is
therefore a **waived** row in the conformance matrix, not n/a — it applied and
QAuth chose the QR flow anyway, because a desktop browser signing in with a
phone wallet is the primary journey the product ships. Revisit **2027-03-31**
(`docs/conformance/requirements/haip-1_0.json`). The follow-up that would let a
deployment take the recommendation is a per-profile `crossDevice` posture on
`VerifierProfile` — `permitted` today, `forbidden` for a deployment that relies
on session binding for phishing resistance — which would remove the
`device=other` affordance rather than touch the Response Code. It is noted, not
built.

## In-app browsers and a different browser on the same device

§14.2 concedes the technique "is also not applicable in same-device scenarios
if the Wallet uses a browser different from the one used on the presentation
request". `SFSafariViewController` shares nothing with Safari; an Android intent
opens the default browser whatever the flow started in; a private window has
its own jar. In every one of those the return lands with no binding for the
flow. The behaviour is **burn and reject**: the code is spent, the presentation
discarded, the initiating tab's next poll answers `rejected`, and the refusal
page says to go back to where the sign-in began. That is the outcome both specs
name for the case, and it is deliberately not softened — a code that lands
anywhere is dead everywhere, and a "Try again" in the wrong jar would start a
second flow the user cannot finish either.

## Conformance

The join lives in `docs/conformance/requirements/oid4vp-1_0.json` and
`haip-1_0.json`, registered under version-qualified aliases only so the
suite's pre-existing bare `OID4VP §…` / `HAIP §…` citations neither prove nor
orphan against the new rows. Two readings from the issue were corrected while
writing them:

- **§14.2's MUSTs apply when a `redirect_uri` is returned; the issue's
  "unconditional" reading is narrowed accordingly.** The section's own text
  scopes the technique to a redirect that reaches the original session.
- **HAIP's same-device-only RECOMMENDED is waived, with a revisit date**, not
  treated as satisfied by a "proximity scenario" exemption that a desktop QR
  flow does not meet.

## Three meanings of `redirect_uri`

The word now occurs in three unrelated places in this codebase, and
[ADR-004](./004-wallet-agnostic-federation.md) already records the first two:

1. The OID4VP **Authorization Request parameter** `redirect_uri`, which §8.2
   forbids beside `response_uri` — QAuth never sends it, and the request tests
   pin that.
2. The `redirect_uri:` **Client Identifier Prefix** (§5.9.3), the certificate-free
   prefix `oid4vp-1.0-base` presents, which cannot be signed.
3. The **response-body member** `redirect_uri` that #405 adds — the JSON object
   the Response Endpoint returns to the wallet, carrying the Response Code.

Only the third is this record's subject.

## Consequences

- A same-device sign-in or link on either profile is session-bound: the
  presentation is released only to the browser that started the flow, on
  presentation of a single-use secret that browser could only have received
  from its own wallet.
- A same-device flow whose wallet never returns fails in three minutes, with a
  reason in the log, instead of spinning for six.
- The tab that started a same-device flow and the tab the wallet opened end on
  the same word, completed or refused; the one sub-second edge on which they
  can differ is recorded under decision 7.
- The cross-device journey is byte-for-byte what it was: `device` absent, QR
  only, `200 {}`, completion by polling, status JSON unchanged.
- The new surfaces to keep uniform are the return route's one refusal page and
  the two terminal pages; the invariants in the route's JSDoc (burn before bind,
  nothing audited on refusal, no request text echoed) are pinned by
  `routes/ui/wallet-login.test.ts` and `routes/ui/wallet-link.test.ts`.
- `WalletProvider.verify()` is untouched and still throws; the return leg runs
  on the same dedicated seam as the poll.

## Related

- Issue #405 — the request this record settles; epic #231
- [ADR-004](./004-wallet-agnostic-federation.md) — OID4VP federation; the request-side `redirect_uri` rules
- [ADR-009](./009-wallet-account-resolution.md) — the asserted identifier the cross-device flow relies on
- [OpenID for Verifiable Presentations 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) §8.2, §13.3, §14.2, §14.3
- [OpenID4VC High Assurance Interoperability Profile 1.0](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html) §5.1
- `docs/conformance/requirements/oid4vp-1_0.json`, `docs/conformance/requirements/haip-1_0.json` — the rows and their evidence

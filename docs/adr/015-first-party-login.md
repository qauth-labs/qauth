# ADR-015: First-Party Login — Headless Sign-In on the Authorization Challenge Endpoint

**Status:** Proposed
**Date:** 2026-09-26
**Authors:** QAuth Team

> **Proposed 2026-09-26.** Nothing below is implemented. Every fork takes the fail-closed option.
> The authorization challenge endpoint sits behind `FIRST_PARTY_LOGIN_ENABLED` (default `false`):
> with the switch off, the route is not registered and discovery does not mention it. F0 makes a few
> flag-free changes before the endpoint exists; each is a listed delta with its own test
> ([Phasing](#phasing)). The client profile this record adds is inert for every client an operator
> has not flagged, so for those clients nothing else changes.

## Context

Many first-party apps want native sign-in and sign-up: the user types credentials into the app's own
screen, the app's backend talks to the identity provider (IdP), and no browser opens. The common way
to get that is the resource owner password credentials grant (ROPC): an app that calls a password
grant at another IdP sends a username and a password and receives tokens. RFC 9700 §2.4 "Resource
Owner Password Credentials Grant" says the grant "MUST NOT be used". ROPC also drops the IdP's own
controls (MFA, step-up, brute-force defence, email verification), so each app rebuilds them on its
own. QAuth should offer the same experience without ROPC and without a browser, as a headless,
standards-based first-party login, and give apps that use a password grant a clear path off it.

### What exists and what this record adds (verified 2026-09-26)

| Concern                           | As of 2026-09-26                                                                                                                                                                                                                                         | This record adds                                                                                                                                                                                                          |
| --------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Password-to-token route           | `POST /auth/login` (`routes/auth/login.ts`) exchanges `{ email, password }` for tokens of the internal `system` client (`getOrCreateSystemClient`, `helpers/oauth-client.ts`), without client authentication. `/oauth/token` offers no `password` grant. | Frozen in F1, removed in F1c; the authorization challenge endpoint replaces it (Decision 12)                                                                                                                              |
| QAuth's own app                   | The developer portal (`apps/developer-portal/src/server/auth-server-client.ts`) calls `/auth/login`, `/auth/register`, `/auth/verify`, `/auth/resend-verification` and `/auth/logout` server-to-server                                                   | The portal signs in through `/oauth/authorize` in F0 (Decision 12)                                                                                                                                                        |
| Headless hand-off                 | `/oauth/authorize` accepts `Authorization: Bearer` with a `system`-client access token in place of a browser session                                                                                                                                     | Follows the consent rule from F0; frozen in F1; removed in F1c (Decision 9)                                                                                                                                               |
| Client authentication             | `private_key_jwt` at `/oauth/token` ([ADR-011 §7](./011-enterprise-managed-authorization.md) "`private_key_jwt` (#384) — additive, no flag"); `/oauth/revoke` and `/oauth/introspect` accept `client_secret_basic` and `client_secret_post`              | `private_key_jwt` at both in F0 (Decision 14)                                                                                                                                                                             |
| First-party marking               | No client attribute marks a client as first-party. Operator-set attributes such as `max_agent_mode` are written only by the seed manifest (`clientSpecSchema`)                                                                                           | An operator-set `first_party_profile`, seed-only and CHECK-constrained (Decision 2)                                                                                                                                       |
| Consent                           | Skipped when an active consent row covers the requested scopes (`canSkipConsent`, `helpers/consent.ts`)                                                                                                                                                  | Audited administrative consent for flagged clients (Decision 9)                                                                                                                                                           |
| Authorization codes               | Two mint sites; every code is S256 PKCE-bound; `authorization_codes.redirect_uri` is NOT NULL and the token endpoint requires `redirect_uri`                                                                                                             | One mint helper, an `issued_via` marker, and codes without a redirect URI (Decision 10)                                                                                                                                   |
| Sender constraint                 | No DPoP                                                                                                                                                                                                                                                  | DPoP in F3, one verifier shared with ADR-014 (Decision 14)                                                                                                                                                                |
| `acr` and `amr`                   | `acr` only from wallet sign-in ([ADR-010](./010-acr-assurance-mapping.md)); no `amr`                                                                                                                                                                     | `amr` and `auth_time` on tokens from challenge-issued codes (Decision 10)                                                                                                                                                 |
| Password policy                   | zxcvbn score ≥ `PASSWORD_MIN_SCORE` (default 2), with `PASSWORD_MAX_LENGTH` (256) checked first, applied by `/auth/register` (`libs/shared/validation/src/lib/password.ts`)                                                                              | One policy for every newly set password, per NIST SP 800-63B-4 §3.1.1.2 "Password Verifiers" (Decision 8)                                                                                                                 |
| Registration, verification, reset | `/auth/register`, `/auth/verify` and `/auth/resend-verification` JSON routes; no password-reset route                                                                                                                                                    | All three inside the authorization challenge endpoint (F1); hosted pages (F2a) (Decision 8)                                                                                                                               |
| Factors and challenges            | Password; wallet sign-in behind `WALLET_FEDERATION_ENABLED`; no TOTP, passkey, emailed code or bot challenge                                                                                                                                             | Passkeys (F2b, Decision 14) and TOTP (F5) as factors; emailed codes for verification, recovery and an optional per-client check after the password, never as a factor (F1, Decision 5); a bot challenge (F1b, Decision 7) |
| Abuse controls                    | `@fastify/rate-limit` keyed on the TCP peer (`request.ip`); failed-login counters in `helpers/failed-login.ts`; `TRUST_PROXY` as an address or CIDR list                                                                                                 | A layered limiter, a failure ladder per NIST SP 800-63B-4 §3.2.2 "Rate Limiting (Throttling)", and an asserted end-user IP (Decision 7)                                                                                   |
| Client SDK                        | None; the README lists `@qauth-labs/node` as planned                                                                                                                                                                                                     | `@qauth-labs/node` in F1 (Decision 13)                                                                                                                                                                                    |
| Discovery                         | `authorization_response_iss_parameter_supported: true`; no `authorization_challenge_endpoint`                                                                                                                                                            | Members that appear only while the endpoint accepts them (Decision 11)                                                                                                                                                    |

### The draft this record builds on

[draft-ietf-oauth-first-party-apps-04](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-first-party-apps-04)
("OAuth 2.0 for First-Party Applications", here "FiPA") is dated 2026-07-01 and expires 2027-01-02.
The Working Group Last Call (WGLC) on -03 ran from 2026-06-25 to 2026-07-13. The chairs' IETF 126
slides, uploaded 2026-07-22, list the draft as "Waiting for Shepherd Write-up". The IETF
Internet-Draft index generated 2026-09-26 gives its IESG state as "I-D Exists". No text newer than
-04 existed on 2026-09-26.

FiPA defines the authorization challenge endpoint at the authorization server (AS). A client posts
what it collected from the user and receives an authorization code or an error. The error asks for
more (`insufficient_authorization`, HTTP 403), sends the user to a browser (`redirect_to_web`, HTTP
403), or ends the attempt (`invalid_session`). An opaque `auth_session` handle links the rounds, and
the code is redeemed at the ordinary token endpoint. FiPA does not define the steps. FiPA §1.2
"Limitations of this specification": "The precise client–server interactions used to authenticate
the user (e.g., prompts, challenges, and step sequencing) are intentionally left to individual
deployments and are out of scope for this specification", and "This specification is intended to be
profiled to standardize specific interaction patterns enabling a complete interoperable solution."
OpenID for Verifiable Credential Issuance 1.1, an OpenID Foundation (OIDF) editor's draft, profiles
-04 in its section "Interactive Authorization". Four Working Group (WG) issues about the wire are
open as of 2026-09-26:
[WG issue #171](https://github.com/oauth-wg/oauth-first-party-apps/issues/171) (collisions),
[WG issue #173](https://github.com/oauth-wg/oauth-first-party-apps/issues/173) (negotiation),
[WG issue #177](https://github.com/oauth-wg/oauth-first-party-apps/issues/177) (status codes) and
[WG issue #179](https://github.com/oauth-wg/oauth-first-party-apps/issues/179) (`redirect_uri`).

### Four readings this record corrects

1. Web front-ends behind a backend. A natural reading of the heading of FiPA §9.8 "Single Page
   Applications" suggests that it does not reach a web app whose OAuth work runs in a backend (a
   BFF). The text says "it is NOT RECOMMENDED to use this specification in browser-based
   applications". RFC 10017 ("OAuth 2.0 for Browser-Based Applications", a BCP of August 2026) §3
   "Terminology" defines a browser-based application as one "dynamically downloaded and executed in
   a web browser", and §6.1 "Backend for Frontend (BFF)" describes "a browser-based application that
   relies on a backend component". RFC 10017 §7.3 "Resource Owner Password Credentials Grant" says
   "browser-based applications using OAuth or OpenID Connect MUST use a redirect-based flow", and
   §6.1.3.1 "The Authorization Code Grant" says the BFF "MUST use the OAuth 2.0 Authorization Code
   grant". A backend that serves a native app is not a browser-based application in that sense, and
   FiPA §1.1 "Usage and Applicability" says the draft "is designed to be used by first-party native
   applications, which includes both mobile and desktop applications". So this record serves native
   front-ends only (Decision 1; parked question 1).
2. PKCE (RFC 7636). A natural reading suggests that FiPA requires PKCE, as OAuth 2.1 does. The text
   of FiPA §5.1 "Authorization Challenge Request" makes `code_challenge` and `code_challenge_method`
   OPTIONAL. QAuth requires S256, a stricter choice (Decision 3).
3. FiPA §1.1. A natural reading suggests that §1.1 obliges every deployment to describe how it
   avoids third-party risks. The text binds only "Profiles of this specification that extend the
   usage to non-first-party use cases"; for other uses its sentence is descriptive ("Using this
   specification in scenarios other than those described may lead to unintended security and privacy
   problems for users and service providers."). So QAuth states its profile rules as its own
   requirements (Decision 1).
4. Email codes. A natural first design would use email codes as a sign-in factor. NIST SP 800-63B-4
   §3.1.3.1 "Out-of-Band Authenticators" says "Email SHALL NOT be used for out-of-band
   authentication", and "Confirmation codes that are sent to validate email addresses or are issued
   as recovery codes (see Sec. 4.2.1.2) are not authentication processes and not affected by the
   above prohibition." So QAuth uses emailed codes to verify addresses and to recover, never as a
   sign-in factor (Decision 5).

### Threat model

| Threat                                                                | Control                                                                                                                                                                                                                                                              | Residual                                                                                                                                                                                                                                                                                                                                                                |
| --------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Credential stuffing and spraying through a first-party backend        | Per-account ladder (delay, bot challenge from F1b, disable at 100), per-end-user-IP limits, per-client failure-ratio breaker, per-session budget, dummy Argon2id verify and a timing floor, optional post-password email check, attestation as a bot signal (F4)     | A correct password is learned when a second step appears. A distributed campaign below per-IP thresholds trips the per-client breaker only if it lifts the client's failure ratio above 50 %. A campaign diluted by successful sign-ins, including the client's own traffic, is bounded only by the per-client cap of 600 rounds per minute and the per-account ladder. |
| Phishing by a look-alike app                                          | Only operator-flagged confidential backends reach the endpoint; public clients refused until attestation and DPoP (F4); passkey-first (F2b); `redirect_to_web` on a risk rule (none in F1)                                                                           | A look-alike app can collect a password and relay an email code; from F2b a password alone no longer completes a login on a passkey-bound account; manually entered codes are not phishing-resistant (NIST SP 800-63B-4 §3.2.5 "Phishing Resistance")                                                                                                                   |
| Client impersonation and assertion misuse                             | `private_key_jwt` on every round at the authorization challenge endpoint, with `aud` = the issuer as sole value, a life of at most 60 s and a burned `jti`; public clients refused until F4                                                                          | A stolen backend key impersonates the backend until the operator rotates its keys                                                                                                                                                                                                                                                                                       |
| Scripts calling the vendor's backend                                  | Asserted end-user IP, per-client breaker, per-account ladder; app attestation between app and backend is the vendor's job until F4                                                                                                                                   | QAuth cannot tell a real app from a script behind a real backend before F4                                                                                                                                                                                                                                                                                              |
| `auth_session` theft or replay                                        | 256-bit handle, hashed at rest, consumed atomically, rotated every round, bound to client authentication, 10-minute absolute life, dead at the code, never logged; a replay ends the live transaction                                                                | A backend that mixes its own users' transactions (the SDK enforces one per app session)                                                                                                                                                                                                                                                                                 |
| Account enumeration                                                   | Uniform first response; identical registration and reset bodies; counters keyed on an identifier HMAC for known and unknown addresses; send caps met by quiet suppression; dummy hash; timing floor on every identifier-resolving round                              | Email content differs; only the mailbox owner sees it                                                                                                                                                                                                                                                                                                                   |
| Lockout as denial of service                                          | Soft ladder first, consulted by every surface before it verifies; known-IP exemption from the wait; disable only at 100 counted failures and only while a self-service rebind path exists; notice to the user                                                        | A per-account wait also delays the real user from an unknown IP. An attacker who knows an address can wait out the delays (or solve bot challenges from F1b) and disable its password after 100 counted failures, in under a day with the default waits. The user then needs a reset. The per-client hard cap and per-IPv4 limits affect every user behind them.        |
| Forged end-user IP                                                    | IP inside the signed, single-use assertion; derived by the backend from its peer or a listed proxy chain (the SDK does it); audit rows mark it `asserted`; TCP peer and `client_id` keep their own caps                                                              | QAuth verifies who asserted the value, not the value; a misconfigured backend skews per-IP limits and audit rows; a forged or shared IP that matches a known IP skips the per-account wait (it still counts toward the ceiling), which also shows that the account exists                                                                                               |
| Script on a web origin driving a backend                              | Web front-ends outside the profile; browser-origin guard; no CORS; a signed assertion on every request                                                                                                                                                               | An operator can flag a web backend as native. Script running in that web front-end could then drive the backend's login actions. RFC 10017 §5.1.4 "Proxying Requests via the User's Browser" says this scenario "cannot be stopped or prevented by application-level security measures"                                                                                 |
| Code interception, replay or AS mix-up                                | PKCE S256 required; 60-second single-use codes; a replay revokes the family; `iss` on every response; the SDK pins one issuer and its metadata                                                                                                                       | Raw-wire clients that ignore `iss`                                                                                                                                                                                                                                                                                                                                      |
| Downgrade and factor mixing                                           | A transaction completes only after the account's strongest bound factor; one subject per transaction; an email code never replaces an authenticator; `/auth/login` refuses passkey-bound accounts while it exists                                                    | Until the hosted `/ui/login` runs on the same engine (F2b), the browser path keeps its own rules                                                                                                                                                                                                                                                                        |
| Account takeover through a mailbox                                    | 8-digit recovery code, 10 minutes, 5 tries per code, a per-identifier wait ladder across codes (bot challenge from F1b), send caps; a stronger bound authenticator required; every refresh family revoked, live transactions and browser sessions ended; notice sent | Mailbox takeover of a password-only account is an account takeover; codes can be relayed in real time; an attacker who waits out the ladder can keep guessing slowly, and every code guessed at was also mailed to the user                                                                                                                                             |
| Registration abuse (squatting, pre-hijacking, mail bombing)           | Verify first, then create; the first mailbox proof on an unclaimed account removes every credential and consent bound before it; send caps per address, IP and client; per-client opt-in; bot challenge from F1b                                                     | Bot sign-ups with real mailboxes before F1b; state that downstream apps keep for the account's `sub` from before the proof survives                                                                                                                                                                                                                                     |
| Third-party, MCP or agent client; consent waived for the wrong client | CHECKs exclude DCR, CIMD and agent clients; the waiver covers only flagged clients and non-dangerous allowlisted scopes; a written reason per flag; removing a flag revokes families                                                                                 | Operator error in the seed manifest                                                                                                                                                                                                                                                                                                                                     |
| Browser-leg session swap                                              | App-claimed redirect URI; completion only over the originating app session with a matching `state`; a fresh login that QAuth requires for every `/oauth/authorize` request of a native profile                                                                       | The app-side half is vendor code until the mobile SDK (F4)                                                                                                                                                                                                                                                                                                              |
| Bearer access-token theft from a backend                              | Tokens stay on the backend; short access-token life; refresh tokens bound to the client                                                                                                                                                                              | The deviation from FiPA §9.5 "Sender-Constrained Tokens" until a client opts into DPoP (F3)                                                                                                                                                                                                                                                                             |

### The question this ADR settles

FiPA gives a frame: an endpoint, three error codes and an opaque handle. It leaves the steps, their
signalling, first-partyness and abuse controls to each deployment. This record settles which clients
may call the endpoint, what the wire carries, how steps are ordered and throttled, how registration
and reset fit in, how apps leave a password grant, and what QAuth does with its own
password-to-token route.

## Decision

One switch gates the endpoint: `FIRST_PARTY_LOGIN_ENABLED`, a boolean in the auth environment
schema, default `false`. Phases are named F0 to F5. Some have lettered sub-phases (F1b, F1c, F1d,
F2a, F2b), and [Phasing](#phasing) lists them all. These names are distinct from ADR-014's P0–P5.

### 1. Scope — a first-party-only endpoint for native front-ends, behind one switch

**QAuth adds the FiPA -04 authorization challenge endpoint at `POST /oauth/authorize-challenge`,
behind `FIRST_PARTY_LOGIN_ENABLED`, for one client shape in the first release: an operator-flagged
confidential backend (`private_key_jwt`) whose user-facing front-end is a native mobile or desktop
app.** Web front-ends use the redirect-based code flow.

With the switch off, the route is not registered (404), discovery omits every member this record
would add, and flagged rows do nothing at the endpoint. The profile is the confidential backend for
a native front-end, value `native_backend`; the value avoids the word BFF, because RFC 10017 §6.1
"Backend for Frontend (BFF)" makes a BFF part of a browser-based application.

QAuth's profile requirements, stated as QAuth's own rules:

1. The backend is a confidential client with `private_key_jwt`; its key stays server-side.
2. It keeps one `auth_session` per app-side session, server-side, never on the device, discarded at
   logout.
3. It puts the end-user IP in every client assertion (Decision 7), derived from the app connection's
   peer address or a proxy chain it operates and lists, never from a free-form header.
4. It exposes fixed login actions to its app, never a generic proxy to QAuth (by analogy with RFC
   10017 §6.1.3.6 "Proxy Restrictions").
5. For `redirect_to_web`, the app opens the system browser or an in-app browser tab, never a web
   view (RFC 8252 §8.12 "Embedded User-Agents").
6. The browser leg returns to the app and completes only over the originating app session. Its
   redirect URI is app-claimed `https` on mobile (RFC 8252 §7.2 "Claimed "https" Scheme URI
   Redirection") and private-use or loopback on desktop (§7.1 "Private-Use URI Scheme Redirection",
   §7.3 "Loopback Interface Redirection"), never a URL the backend serves. The app posts `code`,
   `state` and `iss` to its backend over the same app session that started the leg, and the backend
   redeems the code only if `state` was issued to that session (RFC 8252 §8.9 "Cross-App Request
   Forgery Protections"). That app session exists before the user signs in: the backend issues it to
   the app instance, and the SDK's `sessionKey` names it. The leg carries `prompt=login`, and QAuth
   applies it to every `/oauth/authorize` request of a native profile whatever the request says
   (Decision 9). A backend that completed from `state` alone could not tell which browser returned
   the code; with the consent waiver and a live QAuth browser session, a response could attach to
   the wrong app session.
7. It checks `iss` on every response and uses only endpoints from its pinned issuer's metadata.
8. Tokens stay on the backend; logout revokes the refresh token at `/oauth/revoke`.
9. Every first-party app renders the same steps; the SDK's step contract carries this.
10. Until attestation (F4), the genuineness of the app in front of the backend is the vendor's
    responsibility; QAuth does not see it.

QAuth enforces three things. A request that carries `Origin` or `Sec-Fetch-Site` is refused with 400
`invalid_request` and audited (`Sec-Fetch-Mode` is not a signal: Node's built-in `fetch` sends it
without either of the other two). The route has no CORS, by analogy with RFC 9700 §2.6 "Other
Recommendations": "CORS MUST NOT be supported at the authorization endpoint". Every request carries
a signed client assertion. Together they stop browser script from calling the endpoint; they cannot
stop a web backend's server.

Why. FiPA §9.8 and RFC 10017 §7.3 and §6.1.3.1, as in
[Four readings this record corrects](#four-readings-this-record-corrects). FiPA §1 "Introduction":
the draft "should be considered only when a redirect-based approach introduces usability issues",
which holds for a native app and not for a web page. FiPA §5 "Authorization Initiation" asks for
native-app best practice "for redirect URI selection and external user-agent usage".
[ADR-008 §3](./008-environment-aware-authorization.md) "Fail-safe defaults (the safe method)" sets
the default-off switch.

### 2. First-partyness — an operator-set client profile, never self-asserted

**First-partyness is an operator-set `oauth_clients.first_party_profile`, written only by the seed
manifest and tied by database CHECKs to `private_key_jwt`, non-DCR, non-CIMD, non-agent,
developer-less rows.** Public native clients are refused until attestation-based client
authentication and DPoP both exist. DPoP proves key continuity, not app identity.

FiPA §1.1 and §9.1 "First-Party Applications" define first-party apps as "controlled by the same
entity as the authorization server" and that "users understand as belonging to the same entity". An
operator may set a profile only for an app that the entity operating the AS controls and that users
see under that entity's brand; other entities' apps, including tenants of a shared deployment, use
`/oauth/authorize`. Each seed entry carries a required written `reason`, stored with the client and
audited.

```text
-- F0 migration on oauthClients (libs/infra/db/src/lib/schema/core.ts)
first_party_profile  enum('web_redirect','native_backend') NULL  -- 'native_attested' added in F4
first_party_policy   jsonb NULL      -- native profiles only: { flows, email_code_after_password }
CHECK (first_party_profile IS NULL OR (dynamic_registered_at IS NULL AND developer_id IS NULL
       AND is_agent = false AND coalesce(metadata->>'registrationType','') NOT IN ('dynamic','cimd')))
CHECK (first_party_profile IS NULL OR token_endpoint_auth_method = 'private_key_jwt')
CHECK ((first_party_profile = 'native_backend') = (first_party_policy IS NOT NULL))
CHECK (first_party_profile IS DISTINCT FROM 'native_backend' OR grant_types ? 'authorization_code')
-- F4 adds 'native_attested' and replaces the auth-method CHECK: 'web_redirect' and
-- 'native_backend' stay tied to private_key_jwt; 'native_attested' is tied to
-- attest_jwt_client_auth[_dpop]. F4 also widens the policy and grant CHECKs to
-- ('native_backend','native_attested').
```

`web_redirect` earns only the consent waiver on `/oauth/authorize` (Decision 9) and is refused at
the new endpoint; `native_backend` reaches it; `native_attested` (F4) is an attested native app. No
value admits a public (`none`) or secret-based client in any phase. `first_party_policy` is a strict
object: `flows` (a non-empty subset of `login`, `register`, `reset`; default `login`) and
`email_code_after_password` (default `false`); a policy that does not parse makes the client not
first-party. One new resolver, `resolveFirstPartyProfile(client)`, serves the endpoint gate and the
consent waiver. Write paths follow the pattern of `max_agent_mode`: the seed manifest
(`clientSpecSchema`, `buildInsert`, `buildUpdate` in
`libs/infra/db/src/scripts/seed-oauth-clients.ts`) is the only positive write path; DCR pins NULL;
CIMD omits the fields; the developer API (`createClientRequestSchema`, `updateClientRequestSchema`)
can read but not write them. For native profiles the seed requires `jwks` or `jwks_uri`,
`authorization_code`, a `reason`, and at least one browser-leg redirect URI that is `https`,
private-use or loopback. The seed cannot check that an `https` URI is app-claimed and never served
by the backend. That stays a profile requirement (Decision 1, requirement 6). Removing a profile
revokes every refresh family of the client, audited.

The runtime gate runs after client authentication on every round (client enabled, profile
`native_backend` or, from F4, `native_attested`, `authorization_code` granted, flow in `flows`);
failure is 400 `unauthorized_client`, audited. Client authentication uses
`authenticateClientRequest` and `authenticateClientAssertion` with three stricter rules. `aud` is
the issuer identifier as its sole value (a string or a one-element array), so the token endpoint URL
that `acceptedClientAssertionAudiences` also accepts at `/oauth/token` is refused here and, from F0,
at `/oauth/revoke` and `/oauth/introspect`. At `/oauth/token`, where challenge-issued codes are
redeemed, a client with a `first_party_profile` also needs the issuer as its sole `aud`. Flagged
rows exist only from F0, so no existing client is affected. For every other client, `/oauth/token`
keeps the rule of ADR-011 §7 (watch list). `iat` is required and `exp − iat` is at most 60 s; with
`CLIENT_ASSERTION_CLOCK_SKEW_LEEWAY_SECONDS` (60) on `exp`, an assertion is accepted up to about
120 s after `iat`, and the burned `jti` keeps it single-use. The assertion must carry
`qauth_end_user_ip` (Decision 7), or the answer is 400 `invalid_request`. The SDK always sets
`typ: client-authentication+jwt`; the server does not require it.

Public native clients get 400 `unauthorized_client` in every environment until F4, for three
reasons. RFC 8252 §8.5 "Client Authentication" says an AS must not accept a secret embedded in a
native app "as proof of the client's identity". FiPA §9.4 "Client Authentication" says "client
impersonation should be a concern of anyone deploying this pattern". A fake app can also generate a
DPoP key. From F4, `native_attested` uses attestation -11 in DPoP combined mode (§5.2 "Using DPoP as
the Proof of Possession"), with attester keys set per client by the operator (§10.8 "Trust
Management and Key Resolution").

Why. FiPA §5 "Authorization Initiation": the AS "MUST verify the "first-partyness" of the client
before continuing with the authentication flow". FiPA §9.1 is "not prescriptive" on how and names
DCR only as a possible tool, so refusing DCR and CIMD clients is QAuth's stricter choice.
[ADR-008 §4](./008-environment-aware-authorization.md) "Relaxation is operator-controlled, never
self-asserted"; [ADR-011 §5](./011-enterprise-managed-authorization.md) "Why an allowlist, and not
the alternatives"; [ADR-012 §4](./012-dynamic-client-ownership.md) "The developer-scoped predicate
is never widened". RFC 9700 §2.5 "Client Authentication" recommends asymmetric methods, and
draft-ietf-oauth-rfc7523bis-11 §4 "Updates to RFC 7523" requires the issuer as the sole audience of
a client assertion.

### 3. The wire — FiPA -04, OpenID4VCI negotiation and namespaced QAuth steps

**QAuth signals every next step as FiPA's HTTP 403 `insufficient_authorization` plus OpenID4VCI
1.1's `interaction_type_required`.** The step is negotiated from the client's
`interaction_types_supported`. QAuth step identifiers sit under `urn:qauth:ia:`, and every
QAuth-defined member is prefixed `qauth_`. No QAuth value ever appears in `error`. No prose goes on
the wire. Every response carries `iss`.

The envelope. `POST {issuer}/oauth/authorize-challenge`, `https` only. Every request, initial and
intermediate, is `application/x-www-form-urlencoded`, UTF-8; a JSON-valued answer (a WebAuthn
response) travels as a JSON string in one form parameter. Every response is `application/json` with
`Cache-Control: no-store`, sets no cookie, and carries `iss` (RFC 9207 §2 "Response Parameter iss").
`iss` on the 200 is a QAuth addition: FiPA §5.2.1 "Authorization Code Response" defines only
`authorization_code`, and [OpenID4VCI issue #595](https://github.com/openid/OpenID4VCI/issues/595)
describes an AS mix-up against these endpoints. Every request carries client authentication;
`client_id` is optional and must match if sent. No prose: `error_description` is never sent for end
users, and the AS never says why it asked for a step, how many tries remain, whether an identifier
exists, or which factors an account has.

| Initial-request parameter                 | Handling                                                                                                                                                                                                                                                                                                                  |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `response_type`                           | `code` required; otherwise 400 `unsupported_response_type`                                                                                                                                                                                                                                                                |
| `code_challenge`, `code_challenge_method` | required, `S256`, bounds as in `authorizeQuerySchema`; stricter than FiPA §5.1, where both are OPTIONAL; keeps a future `request_uri` legal (FiPA §5.2.2.1.1 "Redirect to Web Error Response")                                                                                                                            |
| `scope`, `resource`, `nonce`              | as at `/oauth/authorize`                                                                                                                                                                                                                                                                                                  |
| `state`                                   | accepted and bounded as at `/oauth/authorize`, as FiPA §4.1 "Authorization Challenge Endpoint" requires ("MUST accept the authorization request parameters"); otherwise unused: the authorization challenge endpoint never redirects, so no response carries it; the browser leg sends the app's own `state` (Decision 1) |
| `login_hint`                              | at most 254 bytes, email syntax, then `normalizeEmail`; the identifier answer; new handling (`authorizeQuerySchema` has no `login_hint` as of 2026-09-26)                                                                                                                                                                 |
| `max_age`                                 | satisfied, because every sign-in is a fresh authentication; `auth_time` is when the last authenticator succeeded; reset and registration are not offered (403 `redirect_to_web` if selected)                                                                                                                              |
| `prompt`                                  | `login` a no-op (and, like `max_age`, rules out reset and registration); `consent` 403 `redirect_to_web`; `none` 400 `login_required` (OpenID Connect Core 1.0 §3.1.2.6 "Authentication Error Response"); `create` refused until F2a (Decision 8); others 400 `invalid_request`                                           |
| `acr_values`                              | 400 `unmet_authentication_requirements` (Decision 4)                                                                                                                                                                                                                                                                      |
| `redirect_uri`                            | accepted if `redirectUriMatchesRegistered` agrees; used for the browser leg and stored for the token-endpoint rule (Decision 10)                                                                                                                                                                                          |
| `interaction_types_supported`             | comma-separated step URNs, at most 1024 bytes and 16 entries; unknown URNs ignored; if absent, 403 `redirect_to_web`, FiPA's own continuation, so a generic FiPA client never dead-ends                                                                                                                                   |
| any repeated parameter                    | 400 `invalid_request` (RFC 6749 §3.1 "Authorization Endpoint")                                                                                                                                                                                                                                                            |

The authorization-request parameters are frozen at round 0: an intermediate request that carries one
gets 400 `invalid_request`, and the transaction stays live. A `DPoP` header is refused with 400
`invalid_request` until the endpoint implements FiPA §9.5.1 "DPoP: Demonstrating
Proof-of-Possession" code binding and §9.6.1 "Auth Session DPoP Binding" (F3), and
`OAuth-Client-Attestation` headers until F4, so no client believes its code is bound when it is not.

| QAuth member                      | Where       | Meaning                                                                                                                                                                                                                                                                |
| --------------------------------- | ----------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `qauth_interaction_type`          | any request | the step URN this request answers or selects; required when several were offered; with no answer field other than `login_hint` it selects a path (reset, registration, resend)                                                                                         |
| `interaction_type_required`       | 403 body    | always a value the client listed                                                                                                                                                                                                                                       |
| `qauth_interaction_types_offered` | 403 body    | every step the AS accepts next, preferred first; the first equals `interaction_type_required`                                                                                                                                                                          |
| `qauth_interaction_params`        | 403 body    | one object keyed by step URN with only what each offered step's screen needs                                                                                                                                                                                           |
| `qauth_interaction_error`         | 403 body    | closed set: `invalid_credentials` (any rejected password, code or passkey, for any account state), `code_expired`, `password_rejected` (with `reasons`), `captcha_failed` (F1b); a rejected answer is still 403 `insufficient_authorization` with a new `auth_session` |
| answer fields                     | request     | unprefixed, scoped by step: `login_hint`, `password`, `otp` (the name of FiPA Appendix B.1 "Authorization Challenge Request Parameters"), `new_password`, `captcha_token`, `webauthn_response`                                                                         |

| Step (`urn:qauth:ia:` + name) | Phase | `qauth_interaction_params` entry                                                                             | Answer fields                                 | `amr`         |
| ----------------------------- | ----- | ------------------------------------------------------------------------------------------------------------ | --------------------------------------------- | ------------- |
| `identifier`                  | F1    | `{}`                                                                                                         | `login_hint`                                  | —             |
| `password`                    | F1    | `{}`                                                                                                         | `password` (+ `login_hint` if none was given) | `pwd`         |
| `email_code`                  | F1    | `purpose` (`verify_address`, `recovery`, `confirm_sign_in`), `length` (6 or 8), `expires_in`, `resend_after` | `otp`; none = resend                          | —             |
| `new_password`                | F1    | `min_length`, `max_length`, optional `reasons`                                                               | `new_password`                                | —             |
| `password_reset`, `register`  | F1    | path markers, no data                                                                                        | — (+ `login_hint`)                            | —             |
| `captcha`                     | F1b   | `provider`, `site_key`                                                                                       | `captcha_token`                               | —             |
| `webauthn_get`                | F2b   | WebAuthn Level 3 request options JSON                                                                        | `webauthn_response`                           | `pop`, `mfa`  |
| `webauthn_create`             | F2b   | WebAuthn Level 3 creation options JSON, `optional`                                                           | `webauthn_response`                           | — (enrolment) |
| `totp`                        | F5    | `digits`                                                                                                     | `otp`                                         | `otp`         |

| Situation (every body carries `iss`)                                                                                                          | HTTP                      | `error`                                      | Notes                                                                                                                        |
| --------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------- | -------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| Code issued                                                                                                                                   | 200                       | —                                            | `authorization_code`; no `auth_session` (FiPA §5.2.1)                                                                        |
| Next step, or a rejected answer                                                                                                               | 403                       | `insufficient_authorization`                 | new `auth_session`, `interaction_type_required`, `qauth_*` (FiPA §5.2.2.1 "Error Codes")                                     |
| Continue in a browser                                                                                                                         | 403                       | `redirect_to_web`                            | no `request_uri` before F5 (FiPA §5.2.2.1.1)                                                                                 |
| Handle unknown, expired, completed, replayed, bound elsewhere; budget spent                                                                   | 400                       | `invalid_session`                            | one body for every reason                                                                                                    |
| Malformed or oversized input, PKCE missing, repeated or frozen parameter, browser origin, IP claim missing, a header the endpoint cannot bind | 400                       | `invalid_request`                            | —                                                                                                                            |
| Client authentication failed                                                                                                                  | 401, as at `/oauth/token` | `invalid_client`                             | RFC 6749 §5.2 "Error Response"                                                                                               |
| Not first-party, wrong profile, flow not allowed                                                                                              | 400                       | `unauthorized_client`                        | code from RFC 6749 §4.1.2.1 "Error Response"                                                                                 |
| Scope refused; `response_type` not `code`                                                                                                     | 400                       | `invalid_scope`; `unsupported_response_type` | RFC 6749 §4.1.2.1                                                                                                            |
| `acr_values` present                                                                                                                          | 400                       | `unmet_authentication_requirements`          | RFC 9470 §5 "Authorization Response"; code defined by OpenID Connect Core Error Code `unmet_authentication_requirements` 1.0 |
| `prompt=none`                                                                                                                                 | 400                       | `login_required`                             | OpenID Connect Core 1.0 §3.1.2.6                                                                                             |
| Throttled                                                                                                                                     | 429 + `Retry-After`       | `temporarily_unavailable`                    | new `auth_session` if the transaction may continue                                                                           |
| Counter, session or bot-challenge store unavailable                                                                                           | 503                       | `temporarily_unavailable`                    | fail closed (Decision 7)                                                                                                     |
| DPoP proof missing or invalid; nonce needed (F3)                                                                                              | 400                       | `invalid_dpop_proof`; `use_dpop_nonce`       | with `DPoP-Nonce`                                                                                                            |

Wire examples (`CA` stands for
`client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&client_assertion=eyJ…`).
The eager password, which is the one-call path:

```http
POST /oauth/authorize-challenge HTTP/1.1
Content-Type: application/x-www-form-urlencoded

response_type=code&CA&scope=openid%20profile%20offline_access
&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256
&interaction_types_supported=urn%3Aqauth%3Aia%3Apassword%2Curn%3Aqauth%3Aia%3Aemail_code%2Curn%3Aqauth%3Aia%3Anew_password%2Curn%3Aqauth%3Aia%3Apassword_reset
&qauth_interaction_type=urn%3Aqauth%3Aia%3Apassword
&login_hint=alice%40example.com&password=correct%20horse%20battery%20staple%20x

HTTP/1.1 200 OK
{ "authorization_code": "uY29tL2F1dGhlbnRpY2F0aW9u", "iss": "https://auth.acme.example" }
```

The next block shows two exchanges. The first is the uniform 403 returned when the request carries
no credential. It is the same for every account and for none. A wrong password, an unknown account
and a disabled account add only `"qauth_interaction_error": "invalid_credentials"`, after the same
timing floor. The second is an email-code verify step after a correct password on an unverified
address, followed by its answer:

```text
← 403 { "error": "insufficient_authorization", "iss": "https://auth.acme.example",
        "auth_session": "Qm9vbGVhbi1ub3QtYS1yZWFsLWhhbmRsZS0yNTYtYml0cw",
        "interaction_type_required": "urn:qauth:ia:password",
        "qauth_interaction_types_offered": ["urn:qauth:ia:password", "urn:qauth:ia:password_reset"] }

← 403 { "error": "insufficient_authorization", "iss": "https://auth.acme.example", "auth_session": "p0Lr…",
        "interaction_type_required": "urn:qauth:ia:email_code", "qauth_interaction_types_offered": ["urn:qauth:ia:email_code"],
        "qauth_interaction_params": { "urn:qauth:ia:email_code":
            { "purpose": "verify_address", "length": 6, "expires_in": 600, "resend_after": 60 } } }
→ auth_session=p0Lr…&qauth_interaction_type=urn%3Aqauth%3Aia%3Aemail_code&otp=482913&CA
← 200 { "authorization_code": "…", "iss": "https://auth.acme.example" }
```

The fallbacks and the token request follow. The token request carries no `redirect_uri` (FiPA §6
"Token Request"). Its response is ordinary. The ID token and the JWT access token carry `auth_time`
and `"amr": ["pwd"]`. F3 and F4 add headers only (`DPoP`; `OAuth-Client-Attestation`).

```http
HTTP/1.1 403 Forbidden
{ "error": "redirect_to_web", "iss": "https://auth.acme.example" }
HTTP/1.1 400 Bad Request
{ "error": "invalid_session", "iss": "https://auth.acme.example" }

POST /oauth/token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=uY29tL2F1dGhlbnRpY2F0aW9u
&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk&CA
```

Why. FiPA §1.2 leaves the steps to deployments; FiPA §5.1 and §5.2.2 "Error Response" allow
additional parameters and members. On
[WG issue #133](https://github.com/oauth-wg/oauth-first-party-apps/issues/133) an editor wrote that
the draft's `otp_required` example "should have been an additional response parameter rather than a
different `error` value"; on
[WG issue #177](https://github.com/oauth-wg/oauth-first-party-apps/issues/177) the editors held that
"4xx are the right codes". OpenID4VCI 1.1 "Interactive Authorization" already answers
[WG issue #173](https://github.com/oauth-wg/oauth-first-party-apps/issues/173)'s negotiation
question; QAuth borrows its two member names, and if the WG settles these issues differently it
emits the core equivalent beside its own members.

### 4. Step order — a uniform first response, a downgrade rule, and step-up as a fresh transaction

**One engine decides every step in a fixed order, and before a factor succeeds every response is the
same whatever the account's state.** A transaction completes only if it proved the account's
strongest bound factor. Step-up is a fresh transaction. `acr_values` is refused with the
`unmet_authentication_requirements` error that RFC 9470 §5 names.

The engine evaluates these rules in order on every round. The first unmet rule produces the
response.

1. Transport: per-peer cap, 16 KiB body, repeated parameters, schema bounds, origin guard.
2. Client authentication, the first-partyness gate and the IP claim.
3. Per-client limits; the `auth_session` lookup, binding and budgets; per-end-user-IP limits; the
   per-account ladder for credential rounds.
4. Request checks: `response_type`, PKCE, `acr_values`, `prompt`, scope, negotiation, frozen
   parameters.
5. A bot challenge, if a soft threshold requires one (F1b). If the client listed `captcha`, the
   `captcha` step comes next, and the pending step then resumes. Otherwise only the delay and 429 of
   step 3 apply (Decision 7).
6. The identifier: `login_hint`, or a discoverable passkey from F2b.
7. The first factor: passkey (F2b) before password.
8. After a first factor only: the downgrade rule, address verification, the per-client post-password
   email check, TOTP (F5), and from F2b an optional passkey enrolment offer.
9. Mint the code.

Any other rule that needs a step the client did not list answers `redirect_to_web`.

- Anti-enumeration. For a given client, request and configuration, every response before a factor
  succeeds is the same for an unknown, password-only, passkey-only, disabled or locked account.
  `login_hint` never changes a response before the first factor, and timing follows the same rule.
- One subject per transaction. The first identifier given and the first user proven are fixed; every
  later factor is verified only against that user's password, passkeys and address. A different
  `login_hint`, or an assertion or code of another user, ends the transaction with 400
  `invalid_session`, audited as `subject_mismatch`.
- Passkey-first (F2b). With no `login_hint`, the first response requires a discoverable
  `webauthn_get` and offers `password` and `identifier`; with one, it is the same password-required
  shape for every account, with `webauthn_get` offered. A passkey is always one tap away, and the
  response never says who holds one.
- Downgrade rule (defined in F1 so the wire does not change; binding from F2b). A login completes
  only if the transaction proved the account's strongest bound authenticator (passkey above
  password). After a correct password on a passkey-bound account the next step is `webauthn_get`, or
  `redirect_to_web` if the client did not list it. An email code never replaces an authenticator.
  Wallet credentials are outside the ranking ([ADR-009 §6](./009-wallet-account-resolution.md)
  "Wallet presentation is onboarding and assurance-raising, not session authentication").
- Eager answers. An initial request may carry the answer to the step it expects. The AS verifies it
  only if that step is the one it would ask for next; otherwise it ignores the value, with no
  verification and no failure counted. This keeps the happy path at two calls: one to the
  authorization challenge endpoint and one to the token endpoint. It also gives no password oracle
  when a bot challenge is due.
- Step-up. For resource-server step-up (RFC 9470 §3 "Authentication Requirements Challenge"; FiPA §7
  "Resource Server Error Response"), the client starts a new transaction. It sends the returned
  `max_age` and `scope` and a new PKCE pair. There is no post-code `auth_session` before F5.
  AS-initiated step-up at the token endpoint (FiPA §6.2 "Token Endpoint Error Response") is F5.
  `acr_values` answers 400 `unmet_authentication_requirements`: RFC 9470 §5 says an AS "SHOULD
  consider the requested acr value as necessary" and that the error "will help prevent clients
  getting stuck in a loop". No factor here produces `acr`
  ([ADR-010 §2](./010-acr-assurance-mapping.md) "`'low'` emits no `acr` claim"), and
  `acr_values_supported` is not published (RFC 9470 §7 "Authorization Server Metadata").
- Dangerous scopes. `isDangerousScope` (`helpers/step-up.ts`) classifies `write:*`, `agent:admin`
  and `agent:exec`. A first-party client's administrative consent set is its allowlisted requested
  scopes minus dangerous ones, passed to `evaluateStepUp` as its prior-consent scopes at both
  endpoints. A dangerous scope answers `redirect_to_web` in every environment, so the browser's
  consent screen and fresh login apply.

`redirect_to_web` answers a step the client did not list (except a bot challenge), a missing
negotiation, a dangerous scope, `prompt=consent`, a passkey-bound account whose client cannot do
passkeys, reset or registration under `max_age` or `prompt=login`, and a risk decision (FiPA §9.2
"Phishing": the AS "MAY decide to require that the user go through a redirect-based flow at any
stage"). In F1 no automatic rule makes a risk decision, so no step in the order above produces this
trigger. A risk rule added later is named in the phase that adds it and has its own audit reason.
`redirect_to_web` never answers a throttle: a throttle is 429, so an attacker is not moved to a path
with other controls.

Why. FiPA §9.2 and §9.3 "Credential Stuffing Attacks"; RFC 9470 §4 "Authorization Request" and §5.
An email code never replaces an authenticator because email is not one: NIST SP 800-63B-4 §3.1.3.1
"Out-of-Band Authenticators", as in
[Four readings this record corrects](#four-readings-this-record-corrects). NIST SP 800-63B-4 §4.2
"Account Recovery" adds a second point. Replacing a forgotten password when the subscriber "can
authenticate with one or more other authenticators" is "the binding of a new authenticator", not
account recovery.

### 5. Email codes verify and recover; they are never a sign-in factor

**An emailed code proves control of a mailbox and is never a sign-in factor.** It is used for
address verification, recovery and an optional per-client check after the password. It never adds an
`amr` value, never counts toward `mfa`, never raises `acr` and carries no NIST AAL claim.
Passwordless email-code sign-in is not offered.

One exception is stated openly: a headless reset of a password-only account ends in a code after a
mailbox proof alone. That is an email-recovery sign-in at mailbox assurance (Decision 8); it carries
no `amr` or `auth_time`, and it cannot satisfy `max_age` or `prompt=login`.

- Codes come from a CSPRNG, are stored hashed in the `auth_session` state and are compared in
  constant time. They have 6 digits after a password and 8 digits for recovery and registration,
  where the code alone creates a verified binding or unlocks a reset. They are valid 10 minutes,
  single use, bound to the `auth_session` that asked for them, and burned after 5 wrong answers. A
  resend never resets a failure counter.
- An account-level counter of wrong codes applies per normalised identifier (a keyed HMAC), across
  transactions, for existing and unknown addresses alike. From 5 consecutive wrong codes the soft
  ladder of Decision 7 applies, with a bot challenge from F1b. It has no hard stop. It never
  suppresses mail, and a correct code answered outside a wait is accepted. So this counter cannot
  close the reset that Decision 7's disable relies on, and it cannot block a sign-up.
- Send limits count every request that would send if the account existed, unknown addresses
  included: 3 per 15 minutes and 10 per 24 hours per address, 10 per hour per end-user IP, and
  per-client caps. At a cap the response is the same step, and the mail is quietly suppressed. Mail
  is dispatched after the response is built and every identifier-resolving round meets the timing
  floor, so "sent", "not sent" and "capped" look alike.
- New templates: the code (verify, confirm, recovery), "an account already exists", "your password
  was changed" and "your password was disabled after too many attempts". As of 2026-09-26
  `createEmailService` has one method, `sendVerificationEmail`.

Why. NIST SP 800-63B-4 §3.1.3.1, as in
[Four readings this record corrects](#four-readings-this-record-corrects); §3.2.5 "Phishing
Resistance": manually entered outputs "SHALL NOT be considered phishing-resistant". §4.2.1.2 "Issued
Recovery Codes": the code "SHALL include at least six decimal digits", lives at most "24 hours when
sent to an email address", and its verification "SHALL be subject to the throttling requirements in
Sec. 3.2.2". Each code is disabled after 5 wrong answers, well inside §3.2.2's limit of 100. Across
codes, the per-identifier counter uses the techniques §3.2.2 says "MAY be used to reduce the
likelihood that an attacker will lock the legitimate claimant out due to rate limiting": increasing
waits and a bot challenge. A stop there would let an attacker close the reset that a disabled
password needs. §3.1.3.2 "Out-of-Band Verifiers" (a new secret does not reset the failure count)
governs authenticators, so it applies here by analogy only. RFC 8176 §2 "Authentication Method
Reference Values" has no value for an emailed code.

### 6. `auth_session` — hashed, single-use per round, bound to client authentication, dead at the code

**The `auth_session` is a 256-bit handle, stored only as its hash, consumed atomically and rotated
on every response, bound on every round to the authenticated client, and ended when the code is
issued.** It is valid at most 10 minutes. From F3 it is also bound to the DPoP key, and from F4 to
the attested instance key. A burned handle of a live transaction, presented by its own client, ends
that transaction and is audited as a replay.

- Value and storage: 32 CSPRNG bytes, base64url (43 characters), kept in Redis in the pattern of
  `helpers/pending-authorization.ts`, keyed by the handle's hash, with a burn marker until the
  absolute expiry and a per-user index of live transactions so a reset can end them all.
- Consumption: each round takes the state atomically (`GETDEL`, which F0 adds to the cache
  utilities) and binds a new handle, burn first, then bind
  ([ADR-013 §5](./013-same-device-return-leg.md) "The return route burns first, then binds"). Of two
  concurrent answers with one handle, only the first to take the state is processed. The other
  presents a burned handle and follows the next bullet. While the transaction is live, that is a
  replay: it ends the transaction, and a round still in flight then binds no new handle and issues
  no code. Once the first answer has issued the code, the other gets `invalid_session` with no
  replay alarm. The SDK sends one round at a time per `sessionKey`, so a double submit from an SDK
  client never reaches this path.
- A burned handle: the client binding is checked first, so a handle from another client gets
  `invalid_session` (audited `client_mismatch`) and never ends the owner's transaction. From the
  owning client, while the transaction is live, the state is deleted and the replay audited. After
  completion or expiry the answer is `invalid_session` with no replay alarm, so a client that keeps
  its last handle, as FiPA §5.3.1 "Auth Session" requires, pays one round trip. The SDK never
  retries a round; after a network failure it starts a new transaction that keeps the user's visible
  state.
- Binding: the authenticated client must equal the recorded client on every round. From F3 a session
  with a DPoP key needs a valid proof for it on every round (FiPA §9.6.1 "Auth Session DPoP
  Binding"); from F4 it is bound to the attested instance key. An end-user IP change within a
  transaction is a risk signal, not a failure. It is audited and never ends the transaction. In F1
  it changes no response. From F1b it counts as a soft threshold for the bot challenge (step 5 of
  the order in Decision 4).
- Lifetime and budgets: `FIRST_PARTY_AUTH_SESSION_TTL` (new), default 600 s, maximum 900 s, absolute
  from round 0; at most 3 failed answers per step (5 per email code) and 10 rounds; the 200 and the
  token response carry no `auth_session`.
- Carriage: form body only, never in a URL, a header, a log line or an audit row; `LOG_REDACT_PATHS`
  gains `auth_session`, `password`, `new_password`, `otp`, `captcha_token` and `webauthn_response`.
  The backend keeps one transaction per app-side session, never shared across end users and never
  sent to the device (SDK-enforced): client binding stops other clients, and this rule stops other
  users of the same backend.

Why. FiPA §5.3.1: the value is opaque, "unique to the session", "SHOULD have a minimum of 256 bits
of entropy", and "SHOULD be bound to the device" (for a backend, the presenting device is the
backend). FiPA §9.6 "Auth Session" allows other binding methods; §9.6.2 "Auth Session Lifetime"
leaves the lifetime to the AS; FiPA §9.3 asks implementors to rate-limit per `auth_session`. RFC
9449 §5 "DPoP Access Token Request": refresh tokens of confidential clients "are not bound to the
DPoP proof public key because they are already sender-constrained".

### 7. Abuse controls live at QAuth

**QAuth, not the app, enforces every abuse control.** A layered limiter is keyed on TCP peer,
authenticated client, `auth_session`, end-user IP and account. A NIST SP 800-63B-4 §3.2.2 ladder
counts failures across every password surface. The end-user IP travels as a claim inside the
backend's signed, single-use client assertion. The limiter and ladder stores fail closed. Every
credential round runs a dummy Argon2id verify and meets a timing floor. Input bounds are checked
before any expensive work.

The end-user IP. The `qauth_end_user_ip` claim is required for `native_backend`: an IPv4 or IPv6
literal of at most 45 characters. QAuth canonicalises it, and turns an IPv4-mapped IPv6 address into
IPv4, before any check or key. Outside `development` it refuses private, loopback, link-local,
unique-local, shared (100.64.0.0/10), unspecified and multicast addresses. No IETF standard carries
this value, so the claim is QAuth-defined. The signature proves who asserted the value and binds it
to one request; it does not prove the value is right. RFC 9700 §4.13 "TLS Terminating Reverse
Proxies" puts that duty on the component that receives the original request: "A reverse proxy MUST
therefore sanitize any inbound requests to ensure the authenticity and integrity of all header
values relevant for the security of the application servers". That is the vendor's ingress, so QAuth
makes it a profile requirement: the backend derives the value from its peer address or a proxy chain
it operates and lists, as QAuth's own `TRUST_PROXY` does, and the SDK derives it from typed inputs.
The SDK canonicalises each address the same way. It takes the peer address unless that address is in
`trustedProxies`. Otherwise it reads the forwarded chain from the right and takes the first address
not in `trustedProxies`, the same walk Fastify's `trustProxy` makes for `TRUST_PROXY`. QAuth never
reads `X-Forwarded-For` for this, `TRUST_PROXY` is unchanged, and audit rows record
`ip_source: asserted`. The TCP peer and `client_id` keep their own caps, so a lying backend evades
only the per-IP limits.

Limits (configurable; `development` may relax them per
[ADR-008 §5](./008-environment-aware-authorization.md) "The profiles"; `staging` keeps production
values):

| Dimension             | Key                                                                                                                       | Soft action                                                                                                                                                             | Hard action                                                                                                                                                                           |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| TCP peer              | `request.ip`                                                                                                              | —                                                                                                                                                                       | a per-route `@fastify/rate-limit` cap, tiered by `resolveRealmRateLimitMax`; a listed backend address gets `FIRST_PARTY_BACKEND_PEER_RATE_LIMIT` instead (see "Backend volume" below) |
| Client                | authenticated `client_id`                                                                                                 | failure ratio above 50 % over at least 200 credential rounds in 5 min: delay (bot challenge from F1b) and an alert                                                      | above `FIRST_PARTY_CLIENT_MAX_ROUNDS` (new, 600) rounds per minute: 429                                                                                                               |
| `auth_session`        | transaction                                                                                                               | —                                                                                                                                                                       | 3 failures per step (5 per email code), 10 rounds: `invalid_session`                                                                                                                  |
| End-user IP           | the claim; IPv6 keyed on /64                                                                                              | 10 failed credential rounds in 15 min: delay (bot challenge from F1b)                                                                                                   | 30: 429 for 15 min                                                                                                                                                                    |
| Account (password)    | HMAC(server key, realm, normalised identifier), whether or not the account exists; one counter for every password surface | from 5 consecutive failures, the next attempt waits 2^(n−5) s, capped at 15 min (bot challenge from F1b); an early attempt gets 429 and is neither verified nor counted | 100 consecutive counted failures: the password is disabled until a reset, and the user is notified                                                                                    |
| Account (email codes) | the same key, a separate counter                                                                                          | the same ladder from 5 wrong codes (bot challenge from F1b)                                                                                                             | none: it never suppresses mail or refuses a correct code outside a wait (Decision 5)                                                                                                  |
| Registration starts   | end-user IP; client                                                                                                       | —                                                                                                                                                                       | 3 per hour per IP (the `REGISTRATION_RATE_LIMIT` default); a per-client cap                                                                                                           |

- Backend volume. Every user of a `native_backend` client reaches QAuth from the backend's
  addresses. As of 2026-09-26, `/oauth/token` allows `TOKEN_RATE_LIMIT` (30) requests per
  `TOKEN_RATE_WINDOW` (60 s) per TCP peer in the strict tier. `/oauth/revoke` allows
  `INTROSPECT_RATE_LIMIT` (30) per `INTROSPECT_RATE_WINDOW` (60 s). A route with no cap of its own
  gets `RATE_LIMIT_MAX` (100) per `RATE_LIMIT_WINDOW` (3600 s). The design therefore requires an
  operator-set list of the flagged backends' egress addresses, `FIRST_PARTY_BACKEND_PEERS` (new; an
  address or CIDR list, as `TRUST_PROXY` takes; empty by default). A listed address gets its own
  per-peer cap, `FIRST_PARTY_BACKEND_PEER_RATE_LIMIT` (new; requests per minute, set together with
  the list), at the authorization challenge endpoint, `/oauth/token` and `/oauth/revoke`. The list
  changes only that cap. QAuth reads no forwarded header for it, and the client, `auth_session`,
  end-user IP and account rows still apply. It takes effect only while `FIRST_PARTY_LOGIN_ENABLED`
  is on.
- Known-IP exemption: an end-user IP with a successful sign-in to the account in the last 30 days
  skips the wait but still counts toward the ceiling. A wrongly asserted IP, or one shared through a
  carrier NAT, that matches a known IP skips the wait too.
- One counter across surfaces, while the switch is on: the new endpoint, `/ui/login` and
  `/auth/login` all increment the engine's per-account counter, and a success on any clears it.
  Every surface consults the ladder before verifying; an attempt inside a wait is refused with that
  surface's existing lockout answer, unverified and uncounted. The new endpoint writes nothing under
  the identifiers of `helpers/failed-login.ts`, so an asserted IP never sets or clears a lock on
  another surface; the legacy routes keep their own lock as well.
- The disabled mark is a typed, authenticator-generic column, `user_credentials.disabled_at`. While
  the hard action is armed, the repository's credential lookup returns a disabled credential as
  unusable, so no verifier can miss it. Every password surface then refuses it with its ordinary
  invalid-credentials answer.
- The hard action is armed only while every account it can reach has a self-service rebind path.
  Web-only users have one only through F2a's hosted reset, so the rule is checked at run time
  against that page's switch, not per release. While the hosted reset is off, no password is
  disabled, and the lookup ignores any mark set earlier. Every surface keeps its other throttling. A
  successful sign-in clears an ignored mark, as a reset does. The default ships F2a in the F1
  release train (parked question 7).
- Fail closed: at the new endpoint, an error from any counter, session or bot-challenge store
  answers 503 `temporarily_unavailable`. That answer comes before any credential is checked.
- Timing: an unknown identifier runs one Argon2id verify against a fixed dummy hash, and every round
  that resolves an identifier or carries a credential (sign-in, reset start, registration start,
  code rounds) returns no earlier than `MIN_RESPONSE_TIME_MS.LOGIN` (500 ms), through
  `ensureMinimumResponseTime`, success or failure.
- Input bounds, in the route schema before any handler work: a 16 KiB body (64 KiB only for a
  `webauthn_create` answer); `password` and `new_password` at 1–256 UTF-16 code units
  (`PASSWORD_MAX_LENGTH`) on the raw input, before normalisation, strength estimation or hashing,
  with zxcvbn seeing at most 100 characters (`ZXCVBN_MAX_INPUT_LENGTH`); `login_hint` 1–254 bytes;
  `otp` exactly `length` digits; `auth_session` exactly 43 characters; `captcha_token` 4096 bytes;
  `webauthn_response` 16 KiB; `client_assertion` 8192 characters (`ASSERTION_MAX_LENGTH`); the other
  parameters as at `/oauth/authorize`.
- Bot challenge (F1b): a provider-neutral verifier, called through a new SSRF-safe POST helper built
  like `ssrfSafeGet` (`https` only, no redirects, DNS pinning, time and size caps) to one
  operator-configured host. A required challenge with no provider, or an unreachable provider,
  refuses the gated action; it is never waved through and never replaced by `redirect_to_web`. A
  client that did not list `captcha` still gets the soft action's delay and the hard action's
  answer, a 429. It is not exempt, and it is not sent to `redirect_to_web`.

Why. FiPA §9.3 "Credential Stuffing Attacks": "Implementors SHOULD consider similar security
measures to reduce this risk in the authorization challenge endpoint." NIST SP 800-63B-4 §3.2.2
"Rate Limiting (Throttling)": failures are limited "to no more than 100 by disabling that
authenticator", which "is an upper bound"; disabled authenticators "SHALL be required to rebind to
the subscriber account"; on success the verifier "SHOULD disregard any previous failed attempts";
and the claimant's IP address is a listed risk signal. RFC 6749 §4.3.2 "Access Token Request" asks a
password-grant AS to protect its endpoint against brute force, which applies here by analogy.

### 8. Registration, verification and reset in the same flow; one password policy

**Registration, address verification and password reset run inside the authorization challenge
endpoint as operator-enabled flows that end in an authorization code.** No account exists until the
mailbox is proven and the password passes policy. Every response is identical whether or not the
address exists. A reset never unlocks an account whose strongest authenticator is stronger than
email. One password policy module sets every password QAuth stores.

Registration. In F1 the signal is the path marker `urn:qauth:ia:register`, allowed when the client's
`flows` contains `register`; `realms.registration_allowed` is not read, since nothing writes it as
of 2026-09-26. From F2a, `prompt=create` becomes the standard signal at both endpoints, the marker
stays as an alias, and discovery publishes `prompt_values_supported` listing every prompt value
QAuth supports: `create` and the values `/oauth/authorize` accepts (`none`, `login` and `consent` as
of 2026-09-26). It waits for F2a for two reasons. Initiating User Registration via OpenID Connect
1.0, an OIDF specification, says an OpenID Provider that supports it "MUST define this metadata
element in the openid-configuration file" (§4.2 "Discovery Metadata"). And `/oauth/authorize` cannot
honour `create` before hosted registration pages exist. §4.2 also says the provider "must also
specify all other prompt values which it supports". With `prompt=create`, `openid` is required: the
flow "MUST NOT be considered successful without the return of a valid id_token" (§4.1 "Authorization
Request").

- The first answer is always 403 `email_code` (`verify_address`, 8 digits), identical for new and
  existing addresses; an existing address receives a code with an "account exists" notice. After the
  code, a new address gets `new_password` (and, from F2b, an offered `webauthn_create`). An existing
  account whose address is verified is helped to sign in (`password`, `webauthn_get` from F2b, or
  `redirect_to_web` without a password), as the OIDF text allows: "Whether the AS creates a brand
  new identity or helps the user authenticate an identity they already have is out of scope for this
  specification". An unclaimed account (defined below) follows the unclaimed-account rule.
- Creation happens in one transaction after the policy passes: `users`, the verified `password`
  `user_credentials` row with the NFC marker, and the verified `email` `user_attributes` row.
  ADR-002's tables and claim rules are unchanged; only the order differs from ADR-002 "Phase 1 Flow
  Mapping". A unique-constraint race answers `invalid_session`. The code carries no `amr` or
  `auth_time` (Decision 10). FiPA Appendix A.8 "Registration" (non-normative) also runs registration
  inside the flow.
- Unclaimed accounts. An account is unclaimed when it holds a password credential and its address
  was never verified. An account that a wallet presentation created is never unclaimed. The first
  successful mailbox proof (registration or reset) on an unclaimed account runs one transaction. It
  removes every credential of the user: the password, any wallet binding, any passkey (from F2b) and
  any TOTP secret (from F5). It revokes every active `oauth_consents` row and every refresh family
  of the user. It also advances the user's browser-session epoch and ends every live `auth_session`
  of the user. Then the address is marked verified and `new_password` comes next. No other
  authenticator is asked for, so step 3 of the reset finds none. From F2b, the hosted enrolment and
  management page refuses an account whose address was never verified. The post-password
  verification step keeps every credential, because there the same person proved both the password
  and the mailbox.
- The browser-session epoch is a per-user Redis value whose TTL is at least the browser-session TTL;
  `resolveBrowserSession` (`helpers/browser-session.ts`) treats a session created before it as
  absent and clears its cookie. A reset, an unclaimed-account verification and an explicit "sign out
  everywhere" advance it. It lives in Redis because ADR-002 keeps `users` a pure identity anchor,
  and with the switch off nothing advances it.
- Verification. At this endpoint an unverified address is always verified after a correct password,
  whatever `REQUIRE_EMAIL_VERIFIED` says, so no code from this endpoint belongs to an unverified
  address. This replaces `/auth/verify` for native clients.

Reset is a QAuth extension. FiPA Appendix A.2 "Redirect to Authorization Server" and §5.2.2.1.1
"Redirect to Web Error Response" route recovery to the browser instead.

1. The client selects `urn:qauth:ia:password_reset`. The client's `flows` must contain `reset`.
2. QAuth answers 403 `email_code` (`recovery`, 8 digits) for every address. Mail goes only to a
   known address with a password.
3. If the account has another bound authenticator (a passkey from F2b, TOTP from F5), that
   authenticator is required next. If the client cannot render it, the answer is `redirect_to_web`.
4. The `new_password` answer must pass the policy.
5. One transaction replaces the hash through a new password-update method on the credential
   repository. It also marks the address verified and clears the counters and the disabled mark. It
   revokes every refresh family, ends every live `auth_session`, advances the epoch and sends a
   notice. QAuth then answers 200 with a code that carries no `amr` or `auth_time` (Decision 10).

For a password-only account, the reset proves only the mailbox and then signs the user in. That is
an email-recovery sign-in at mailbox assurance, with no `amr`, `acr` or `auth_time` (Decision 10).
It is never offered under `max_age` or `prompt=login`, so it never satisfies a step-up.

On the wire, both paths start with `qauth_interaction_type` set to the path marker. `login_hint`
carries the address unless the transaction already has one. Registration starts on the initial
request. Its `interaction_types_supported` lists `urn:qauth:ia:register`, `urn:qauth:ia:email_code`
and `urn:qauth:ia:new_password`, plus `urn:qauth:ia:password` so that an existing account can sign
in. Reset starts on the initial request, or from any 403 that offers `urn:qauth:ia:password_reset`.
Its initial `interaction_types_supported` lists `urn:qauth:ia:password_reset`,
`urn:qauth:ia:email_code` and `urn:qauth:ia:new_password`, because the list is frozen at round 0.
For a new address, or for a password-only account, the answers are 403 `email_code` (8 digits), then
403 `new_password`, then 200 with the code. A step the client did not list answers `redirect_to_web`
(Decision 4).

Disabled users. These flows never change a user whose `users.enabled` is false, and never give that
user a code. Registration and reset send that address no mail, as at a send cap (Decision 5), so the
step looks the same. Every answer for that user gets the ordinary `invalid_credentials` answer. This
includes a code mailed before the user was disabled. No hash, mark, counter, refresh family or
address state changes, and no notice is sent. Each round re-reads the flag before it writes anything
or mints a code.

One password policy, in `libs/shared/validation/src/lib/password.ts`, used by this endpoint and,
while it exists, by `/auth/register`. Any future admin or SCIM API creates users without a password
or through this module; the F1d import tool only carries existing hashes. The raw length (at most
256 UTF-16 code units) is checked first, then NFC normalisation, then `PASSWORD_MIN_LENGTH` (new),
which defaults to 15 code points. An operator may lower it to no fewer than 8. While any account can
sign in with a password alone, a minimum below 15 is a knowing deviation from NIST SP 800-63B-4
§3.1.1.2 "Password Verifiers". The blocklist is zxcvbn's dictionaries plus context words passed as
zxcvbn user inputs (the address's local part and domain; service, realm and client names). A
password is blocklisted only when the whole password matches an entry; the same section says "The
entire password SHALL be subject to comparison, not substrings or words". Separately, a zxcvbn score
below `PASSWORD_MIN_SCORE` (default 2) rejects the password. This score floor is a QAuth rule beyond
the NIST blocklist. It requires no mix of character types, so QAuth does not count it as a
composition rule. A breached-password corpus is F5. There are no composition rules and no periodic
change. Rejection reasons are returned (`too_short`, `too_long`, `blocklisted`, `too_weak`), and
fields are marked for password managers. New and changed passwords are hashed after NFC
normalisation, and the credential records a marker, declared as an optional field of
`passwordCredentialDataSchema`. Every verifier honours it: `verifyPasswordCredential`
(`helpers/credential-auth.ts`, which serves `/auth/login`, `/ui/login` and the new endpoint) and the
direct `verifyPassword` call in `routes/auth/verify.ts`; a credential without the marker is verified
on the raw input. Applying the minimum to `/auth/register` is an announced, listed F1 change on
every deployment, with a release note and the portal form showing the new reasons (parked question
3). Existing passwords are grandfathered.

Why. NIST SP 800-63B-4 §3.1.1.2 "Password Verifiers": single-factor passwords must be "a minimum of
15 characters in length"; only passwords used solely within multi-factor processes may be shorter,
and never below eight; the CSP "SHALL provide the reason for rejection"; verifiers "SHALL allow the
use of password managers" and "SHALL NOT impose other composition rules". §4.2 "Account Recovery":
"Replacement of a forgotten password where the subscriber can authenticate with one or more other
authenticators is considered to be the binding of a new authenticator". §4.2.3 "Account Recovery
Notification": recovery "SHALL cause a notification". RFC 9700 §4.14.2 "Recommendations" allows
revoking refresh tokens after a password change.

### 9. Consent — audited administrative consent for operator-flagged first-party clients

**Consent may be skipped only for an operator-flagged first-party client, and only for non-dangerous
scopes in its registered allowlist; the decision is still made and audited on every request, and
every other path requires consent.**

- The waiver applies at the new endpoint for `native_backend` (and `native_attested`), and at
  `/oauth/authorize` for any client whose profile resolves, so the portal (`web_redirect`) needs no
  consent screen. `canSkipConsent` gains that one operator-set condition, through
  `resolveFirstPartyProfile`, and no other. No `oauth_consents` row is written; it would list apps
  the user cannot meaningfully revoke.
- The waiver covers the administrative consent set of Decision 4. Dangerous scopes and
  `prompt=consent` always get the consent screen (`redirect_to_web` at the new endpoint). Every
  waiver is audited as `oauth.consent.administrative` (basis, client, scopes, path).
- The waiver needs no switch: it is inert until an operator sets a profile, as with
  [ADR-011 §7](./011-enterprise-managed-authorization.md) "`private_key_jwt` (#384) — additive, no
  flag". So the portal can move in F0 without enabling headless login. At `/oauth/authorize`, QAuth
  treats every request from a client whose profile is `native_backend` (or, from F4,
  `native_attested`) as carrying `prompt=login`, whatever the request says. A `prompt=none` request
  from such a client answers `login_required` (OpenID Connect Core 1.0 §3.1.2.6 "Authentication
  Error Response"). Before F5 the client builds the browser-leg URL, so QAuth does not rely on the
  parameter arriving intact. So the waiver never lets a native app's browser leg complete without a
  visible login.
- From F0, the headless hand-off on `/oauth/authorize` follows this decision. F1 freezes it; F1c
  removes it with `/auth/login`.

Why. FiPA says nothing about consent. OpenID Connect Core 1.0 §3.1.2.4 "Authorization Server Obtains
End-User Consent/Authorization": the AS "MUST obtain an authorization decision", and may establish
consent "via conditions for processing the request or other means (for example, via previous
administrative consent)".

### 10. Codes, tokens, `amr` and sender-constraint phasing

**Challenge-issued codes carry no `redirect_uri`, live 60 s, stay PKCE-bound, and yield tokens with
`auth_time` and RFC 8176 `amr` (neither after registration or reset).** Each code is marked
`issued_via = 'authorization_challenge'`, and a CHECK enforces the missing `redirect_uri`. Each code
is linked to the refresh family it creates, so a replay revokes that family. `amr` and `auth_time`
stay fixed across refreshes, and no new `acr` is added. Access tokens stay Bearer until DPoP (F3).
This is a knowing deviation from FiPA §9.5's SHOULD.

```text
-- F0
authorization_codes.issued_via   enum('authorize','authorization_challenge') NOT NULL DEFAULT 'authorize'
authorization_codes.redirect_uri text NULL                          -- was NOT NULL
CHECK ((issued_via = 'authorization_challenge') = (redirect_uri IS NULL))
authorization_codes.challenge_redirect_uri text NULL  -- a redirect_uri sent on the challenge request
CHECK (challenge_redirect_uri IS NULL OR issued_via = 'authorization_challenge')
authorization_codes.amr jsonb NULL;  refresh_tokens.auth_time bigint NULL;  refresh_tokens.amr jsonb NULL
refresh_tokens.authorization_code_id uuid NULL → authorization_codes(id) ON DELETE SET NULL
-- F3: authorization_codes.dpop_jkt, refresh_tokens.cnf_jkt, oauth_clients.dpop_bound_access_tokens
```

- One new helper, `mintAuthorizationCode`, replaces the two mint sites (`createCode` in
  `routes/oauth/authorize.ts` and the consent POST in `routes/ui/consent.ts`) and serves the new
  endpoint. It refuses to mint without an S256 challenge of 43–128 characters, in every environment,
  so every authorization code QAuth mints is PKCE-bound by construction.
- The token endpoint's `redirect_uri` rule (optional in `tokenExchangeAuthCodeBodySchema`, applied
  in `handleAuthorizationCode`): a browser code needs it, equal to the stored value; a challenge
  code with a `challenge_redirect_uri` accepts it absent or identical; a challenge code without one
  accepts it absent. A browser code without it, or any code with a different value, is
  `invalid_grant`. RFC 6749 §5.2 "Error Response" gives that code to a grant that "does not match
  the redirection URI used in the authorization request". Whether the parameter is required depends
  on the code, so a missing value counts as a mismatch, not as a missing parameter
  (`invalid_request`).
- Challenge codes live 60 s; browser codes keep `AUTHORIZATION_CODE_TTL_MS`. A second redemption of
  any code is denied and revokes the family issued from it, audited as `oauth.token.code_replay`.
- `amr` and `auth_time` appear in the ID token and the JWT access token for challenge-issued codes,
  fixed across refreshes. Browser-flow tokens are unchanged in F1; `amr` on browser logins is F5.
- A registration or reset code carries neither `amr` nor `auth_time`, and neither do the tokens it
  yields. RFC 9470 §6.1 "JWT Access Tokens" uses `auth_time` to tell a resource server when the user
  authenticated, and §3 "Authentication Requirements Challenge" measures `max_age` from that event.
  So a token from a transaction that proved only a mailbox never passes a resource server's
  `max_age` check. OpenID Connect Core 1.0 §2 "ID Token" requires `auth_time` when `max_age` is
  requested, and these paths are never offered under `max_age`.

| Transaction                                              | `amr` (RFC 8176 §2 and the IANA-registered `pop`) |
| -------------------------------------------------------- | ------------------------------------------------- |
| Password (with or without the post-password email check) | `["pwd"]`                                         |
| Passkey with user verification (F2b)                     | `["pop","mfa"]`                                   |
| Password, then passkey (downgrade rule, F2b)             | `["pwd","pop","mfa"]`                             |
| Password and TOTP (F5)                                   | `["pwd","otp","mfa"]`                             |
| Registration, reset                                      | `amr` and `auth_time` omitted                     |

`hwk` and `swk` are never claimed: QAuth requests `attestation: "none"` and cannot know the key
store. The server verifies the user verification (UV) flag in the signed authenticator data of every
assertion and refuses an assertion without it, so `["pop","mfa"]` means a possession factor whose
authenticator reported a local verification, not an attested multi-factor authenticator. No factor
here produces `acr`; an authenticator-strength `acr` is an ADR-010 amendment.

| Client                                                        | Access token                                                                                                  | Refresh token                                                                | Phase |
| ------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- | ----- |
| `native_backend`                                              | Bearer, kept on the backend; the FiPA §9.5 "Sender-Constrained Tokens" SHOULD is not met, a knowing deviation | bound to the client (the ownership check in `handleRefreshToken`), rotated   | F1    |
| `native_backend` with operator-set `dpop_bound_access_tokens` | `cnf.jkt`, `token_type: DPoP`                                                                                 | bound to the client                                                          | F3    |
| `native_attested`                                             | DPoP-bound                                                                                                    | bound to the client instance (attestation -11 §10.3 "Refresh token binding") | F4    |

Why. RFC 6749 §4.1.3 "Access Token Request" requires `redirect_uri`, identical, when the
authorization request included it. OAuth 2.1 -16 §10.2 "Redirect URI Parameter in Token Request": an
AS serving both versions "MUST allow clients to send the redirect_uri parameter in the token request
(Section 4.1.3), and MUST enforce the parameter as described in [RFC6749]". FiPA §6 "Token Request":
the parameter "will not be included in this request, because no redirect_uri parameter was included
in the authorization request". RFC 6749 §4.1.3 ties its presence rule to a `redirect_uri` sent in a
Section 4.1.1 authorization request, which is where a browser code comes from. A challenge code
comes from the authorization challenge endpoint instead. For it QAuth applies the OAuth 2.1 rule,
not RFC 6749's presence rule. OAuth 2.1 -16 §10.2 says PKCE prevents code injection, which makes the
parameter "serve no purpose in the token request". So a value sent on the authorization challenge
request may be omitted at the token endpoint. If it is repeated, it must be identical. OAuth 2.1 -16
§4.1.3 "Token Endpoint Extension": for a replayed code the AS "MUST deny the request and SHOULD
revoke (when possible)" its tokens. RFC 9068 §2.2.1 "Authentication Information Claims": the values
"are fixed and remain the same across all access tokens that derive from a given authorization
response".

### 11. Discovery and audit

**Discovery advertises exactly what the endpoint accepts, and only while the switch is on; every
accept and every reject writes an `audit_logs` row without secrets, with identifiers as keyed
HMACs.**

| Discovery member (`buildAuthorizationServerMetadata`, `helpers/discovery.ts`)                                                                                                                                                                                                                                                                     | When                                                                                                                                                                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `authorization_challenge_endpoint`                                                                                                                                                                                                                                                                                                                | `FIRST_PARTY_LOGIN_ENABLED` (FiPA §8 "Authorization Server Metadata")                                                                                                                             |
| `private_key_jwt` in `revocation_endpoint_auth_methods_supported` and `introspection_endpoint_auth_methods_supported`, with `revocation_endpoint_auth_signing_alg_values_supported` and `introspection_endpoint_auth_signing_alg_values_supported` from the same constant as the token endpoint's list (`ASSERTION_SIGNING_ALG_VALUES_SUPPORTED`) | F0, when those endpoints accept it (RFC 8414 §2 "Authorization Server Metadata": MUST when `private_key_jwt` is listed)                                                                           |
| `end_session_endpoint`                                                                                                                                                                                                                                                                                                                            | F0, once the browser end-session route exists (OpenID Connect RP-Initiated Logout 1.0 §2.1 "OpenID Provider Discovery Metadata")                                                                  |
| `amr` in `claims_supported`                                                                                                                                                                                                                                                                                                                       | F1, switch on                                                                                                                                                                                     |
| `prompt_values_supported` listing every supported prompt value, `create` included                                                                                                                                                                                                                                                                 | F2a, when both endpoints honour it                                                                                                                                                                |
| `dpop_signing_alg_values_supported`                                                                                                                                                                                                                                                                                                               | `DPOP_ENABLED` (RFC 9449 §5.1 "Authorization Server Metadata"); its algorithms apply at the token endpoint and, from F3, at the authorization challenge endpoint, which refuses `DPoP` until then |
| `attest_jwt_client_auth_dpop` in `token_endpoint_auth_methods_supported`; the attestation algorithm members                                                                                                                                                                                                                                       | F4 (attestation -11 §8 "Authorization Server and Resource Server Metadata")                                                                                                                       |
| `acr_values_supported`                                                                                                                                                                                                                                                                                                                            | not published; an ADR-010 amendment that makes both endpoints honour `acr_values` would add it (RFC 9470 §7 "Authorization Server Metadata")                                                      |
| `challenge_endpoint` of attestation -11 §6.3 "Providing Challenges through the Challenge Endpoint"                                                                                                                                                                                                                                                | never: combined mode takes freshness from DPoP nonces, and the name collides                                                                                                                      |

Audit goes through `fastify.repositories.auditLogs.create` under the rule of
[ADR-011 §8](./011-enterprise-managed-authorization.md) "Audit": never a password, code, `otp`,
`auth_session`, assertion, key, WebAuthn signature or bot-challenge token. The identifier appears
only as the throttle HMAC while no user is resolved, and `userId` is set only after a factor
succeeds. `ip_address` holds the end-user IP, `metadata.ip_source` says where it came from, and
`metadata.peer_ip` holds the TCP peer. The events cover client rejections by reason
(`oauth.authorize_challenge.client_rejected`), every step and outcome
(`oauth.authorize_challenge.*`, with session rejections by reason, including `subject_mismatch`, and
throttling aggregated per key and window), administrative consent, code replay, profile changes
(`oauth.client.first_party_changed`), browser sign-out, registration, verification, reset,
unclaimed-account resets (with the credentials and consents removed), epoch advances, disabled
authenticators, notifications, passkey binding (F2b) and imports (F1d). A Prometheus counter,
`qauth_first_party_steps_total`, sits beside them. The rows form the dated authenticator life-cycle
record NIST SP 800-63B-4 §4.1 "Authenticator Binding" asks for.

Why. The house rule that discovery advertises only what an endpoint accepts
([ADR-008 §3](./008-environment-aware-authorization.md) "Fail-safe defaults (the safe method)").
[RFC 8414](https://www.rfc-editor.org/rfc/rfc8414.html) §2 "Authorization Server Metadata": each
`…_auth_signing_alg_values_supported` member "MUST be present" when `private_key_jwt` is listed for
that endpoint. FiPA §4.1 "Authorization Challenge Endpoint": servers "SHOULD include the URL of
their authorization challenge endpoint in their authorization server metadata document".

### 12. No password grant, not even for compatibility — and the migration path

**QAuth offers no password grant in any form.** An app that calls a password grant moves to one
authorization challenge call plus one token call, with the same happy-path shape. An app leaving
another IdP also needs its users imported, as a separate step. QAuth applies the rule to itself. Its
portal moves to the redirect flow in F0. `/auth/login` and the headless hand-off are removed in F1c,
after a supported replacement for scripted management tokens exists.

Why no compatibility mode. RFC 9700 §2.4 says the grant "MUST NOT be used", with no first-party
exception; OAuth 2.1 -16 §10 "Differences from OAuth 2.0" omits it "as per Section 2.4 of
[RFC9700]"; RFC 10017 §7.3 repeats the rule for browser apps. A compatibility grant has two options.
If it runs the engine's steps, it may answer that an email code is needed. Then it is no longer
ROPC. If it skips them, verification, the ladder, the session budget and the downgrade rule no
longer protect any account. It cannot be compatible and safe at once. It would also put `password`
in `grant_types_supported` and invite third parties to use it. And it buys nothing: with eager
answers, the happy path already takes credentials and returns a code.

One limit remains. FiPA fixes ROPC's protocol problems: the AS signals each step, controls every
factor and limits the flow to first-party apps. But a password step still shows the password to the
app. RFC 9700 §2.4 objects that the grant exposes credentials to the client and trains users to type
them outside the AS. Both objections still apply to a password step. FiPA §9.2 "Phishing" says the
same. A passkey sign-in (F2b) avoids them, because the app never sees a password. They still apply
whenever a user types a password.

Before, a password grant at another IdP; after, the SDK of Decision 13 (on the wire, the
eager-password request and the token request of Decision 3):

```text
POST /token   Authorization: Basic <client_id:client_secret>
grant_type=password&username=alice%40example.com&password=…&scope=openid%20offline_access
```

```ts
// before: const tokens = await idp.passwordGrant({ username, password });
// once, at startup (discovers metadata and checks the issuer):
const qauth = await createFirstPartyClient({ issuer, clientId, signingKey, steps, store });
// per sign-in request:
const r = await qauth.signInWithPassword({
  sessionKey: appSession.id,
  identifier: username,
  password,
  scope,
  endUser: {
    peerAddress: req.socket.remoteAddress,
    forwardedFor: req.headers['x-forwarded-for'],
    trustedProxies: ['10.0.0.0/8'],
  },
});
// r.kind is one of four values:
// - 'tokens': iss checked, PKCE redeemed.
// - 'step': step view JSON for the app. A wrong password is a 'step'
//   whose error is 'invalid_credentials', never a 'failed'.
// - 'redirect_to_web': a URL for the system browser. The app returns through its
//   redirect URI, and the backend calls qauth.redirectToWeb.complete with the same
//   sessionKey (Decision 1, requirement 6).
// - 'failed': the reason is 'session_expired', 'throttled' (with retryAfter) or 'unavailable'.
```

| Password grant                              | QAuth first-party profile                                                                                                                                                                                    |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `grant_type=password` at the token endpoint | `response_type=code` at the authorization challenge endpoint, then `grant_type=authorization_code` at `/oauth/token`                                                                                         |
| `username`                                  | `login_hint`, which must be an email address                                                                                                                                                                 |
| `password`                                  | `password`, eager with `qauth_interaction_type=urn:qauth:ia:password`, or as a step answer                                                                                                                   |
| `client_secret`                             | `private_key_jwt` (`aud` = issuer as sole value, `typ: client-authentication+jwt`, at most 60 s, `qauth_end_user_ip`)                                                                                        |
| `scope`                                     | `scope`. A dangerous scope (`write:*`, `agent:admin`, `agent:exec`; Decision 4) is never granted headlessly. A request that includes one answers `redirect_to_web`, and the sign-in continues in the browser |
| 400 `invalid_grant` for bad credentials     | 403 `insufficient_authorization`, same step, `qauth_interaction_error: "invalid_credentials"`                                                                                                                |
| —                                           | `code_challenge` (S256) and `interaction_types_supported`, filled by the SDK                                                                                                                                 |
| Refresh; logout                             | the same refresh with `private_key_jwt`; `/oauth/revoke` with `private_key_jwt` (F0)                                                                                                                         |
| User creation or reset through an admin API | the `register` and `reset` flows                                                                                                                                                                             |

What an app with a backend changes, beyond the wire mapping:

- The operator seeds the backend as `native_backend` with its JWKS, a written `reason`, its
  browser-leg redirect URI and the `flows` it needs (Decision 2). `flows` defaults to `login`, so an
  app that registers or resets users also lists `register` and `reset`.
- The backend signs a fresh client assertion for every request, carrying the derived end-user IP
  (Decision 1, requirement 3).
- The backend keeps one `auth_session` per app-side session in a server-side store (Decision 1,
  requirement 2). That app-side session exists before the user signs in.
- The app renders `email_code`, `new_password` and `redirect_to_web` from `StepView` (Decision 13).
  For `redirect_to_web` it opens the system browser and returns through its registered redirect URI,
  app-claimed `https` on mobile (Decision 1, requirements 5 and 6).
- Registration and reset move from `/auth/register` or any admin API into the `register` and `reset`
  flows.
- Tokens stay on the backend, and logout revokes the refresh token at `/oauth/revoke` (Decision 1,
  requirement 8).
- A user whose address was never verified enters an email code after the first correct password
  (Decision 8).
- Passkey screens come in F2b.

Two populations migrate. QAuth's `/oauth/token` has never offered `grant_type=password` (the enum
comment in `libs/infra/db/src/lib/schema/enums.ts` reads "OAuth 2.1 removed deprecated grant types
(password, implicit)"). Apps on QAuth's own `/auth/login` keep their users and their Argon2id
hashes, so they need only the protocol change and the app changes above. Such an app whose front-end
is a web app takes the redirect flow instead (table below). Apps on another IdP's password grant are
the main population. As of 2026-09-26 QAuth has no user import path (password users are created only
by `routes/auth/register.ts`), so these apps need the protocol change and a user migration. The
default is an operator import tool in F1d for Argon2id PHC hashes (parked question 5). If that
default is declined, no migrated user exists in QAuth. The migration guide says so in its first
paragraph and names the bulk path: every user goes through `register` with the same address, because
`reset` mails a code only to an existing account with a password (Decision 8). The client's `flows`
must then contain `register`. Sign-in and reset answer an unknown address the same way as a known
one, so the app points returning users to registration. Registration is safe for a user who already
has an account: a verified address is helped to sign in (Decision 8). The same path serves users
whose source hash is not Argon2id PHC, because F1d does not import them.

Both paths need an email address for each user. The sign-in identifier is an email address:
`login_hint` must have email syntax, and a password credential is keyed by the normalised address
([ADR-002](./002-identifier-abstraction.md)). An app whose users sign in with a user name or a phone
number gives each user an email address before it moves.

| Migrating app                                                                       | Path                                                                                                                                                                                                                                                                                                                                                                       |
| ----------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Native app whose backend calls a password grant and keeps the tokens                | The authorization challenge endpoint (above)                                                                                                                                                                                                                                                                                                                               |
| Native app whose backend calls a password grant and passes the tokens to the device | The authorization challenge endpoint, with the tokens kept on the backend (Decision 1, requirement 8). The device holds only its session with the backend. The backend calls the APIs itself, or forwards the app's calls only to an allowlist of APIs (by analogy with RFC 10017 §6.1.3.6 "Proxy Restrictions"). Tokens held on the device arrive with attested apps (F4) |
| Native app whose device calls a password grant directly (a public client)           | The RFC 8252 browser flow, or add a backend; headless public clients arrive with attestation (F4)                                                                                                                                                                                                                                                                          |
| Web app (SPA with a BFF, or server-rendered)                                        | The redirect flow at `/oauth/authorize`; hosted registration and reset in F2a                                                                                                                                                                                                                                                                                              |
| Scripts that obtain a developer token from `/auth/login`                            | The replacement of parked question 8, shipped before F1c                                                                                                                                                                                                                                                                                                                   |

QAuth's own surfaces move in these steps. In F0 the portal moves first: its `SYSTEM_CLIENT_ID` row
becomes a `private_key_jwt` `web_redirect` client (`assertManagementToken` keeps working because it
pins that row), and portal login moves to `/oauth/authorize` (Phasing, F0). In F1, `/auth/login` and
the hand-off are frozen and marked deprecated with a named version and date. Before F2b ships,
`/auth/login` starts refusing any account with a bound passkey, with its ordinary
invalid-credentials answer. The refusal holds until `/auth/login` is removed. In F1c, `/auth/login`,
`/auth/logout` and the hand-off are removed, at least one minor release after F1's release, once the
replacement for scripted management tokens has shipped. `/auth/register`, `/auth/verify` and
`/auth/resend-verification` issue no tokens; they adopt the one password policy in F1 and stay until
hosted pages are on for the portal (F2a), because a legacy route is never removed while its
replacement is off by default.

### 13. SDK scope — a server-side Node SDK and a language-neutral kit

**The first client SDK is the server-side `@qauth-labs/node` (in `libs/sdk/node`), with a typed step
union, a published step-view JSON Schema and message catalogue, and every safety check built in.**
F1 also publishes a language-neutral kit for other backends. Mobile SDKs come with attested public
clients in F4. There is no browser SDK.

- `@qauth-labs/node` (F1) depends only on `jose`. It targets Node 22 and later (Node 22 is the
  oldest Node release line still in support on 2026-09-26) and runtimes with WebCrypto and `fetch`.
  `createFirstPartyClient` discovers metadata, checks `issuer`, and refuses to start without
  `authorization_challenge_endpoint`. It offers `signIn.start`, `signIn.continue`,
  `signInWithPassword` (the eager path), `register.start`, `reset.start`, `tokens.refresh()`,
  `signOut()` (revoke, then drop state), and `redirectToWeb.start` and `.complete`, which refuses a
  `state` stored under another `sessionKey` and is called only over the app session that started the
  leg.
- Results are values; only programmer or infrastructure faults throw. `StepView` is a discriminated
  union with one variant per step of the catalogue, carrying only what a screen needs (for example
  `purpose`, `length` and `resendAfter` for a code, or `minLength`, `maxLength` and `reasons` for a
  new password), plus `alternatives` and an optional `error`.
- Built-in checks:
  - Assertions carry `aud` = the issuer as sole value, `typ`, `iat`, a fresh `jti`, a 60 s life and
    the IP claim.
  - `endUser` is a required typed field from which the SDK derives the IP claim. Forgetting the
    abuse control is a compile error, and a free-form string is not accepted.
  - PKCE.
  - Handle rotation goes through a store keyed one-to-one by `sessionKey` (a Redis adapter in F1).
    The last handle is kept until logout and is not presented for a new transaction before F5 (a
    knowing deviation from FiPA §5.3.1 "Auth Session").
  - No automatic retry, and one round in flight per `sessionKey`.
  - Errors are classified by `error`, not by status.
  - `iss` is compared with the pinned issuer before redemption.
- The AS sends no text. The SDK ships a `StepView` JSON Schema and an English message catalogue. In
  F1 a native app renders step-view JSON relayed by its backend. It needs its own screens for the
  steps and its own code for the browser leg, but no QAuth SDK in Dart, Swift or Kotlin. For
  backends in Java, Go, Python or .NET, F1 publishes a JSON Schema of the whole wire, request and
  response test vectors, and a raw-HTTP guide.
- As of 2026-09-26 nothing in the workspace publishes an npm package. F1 adds npm publishing for
  `@qauth-labs/node` (the scope, an `nx release` configuration, a pre-1.0 versioning rule,
  provenance, a release workflow), and a package installable from npm is an F1 exit criterion. The
  README's "Planned SDK Usage (Phase 3)" section shows a browser-side `auth.signInWithPassword` and
  a `@qauth-labs/react` package; after this record no browser-side `signInWithPassword` ships, and
  any `@qauth-labs/react` stays redirect-only.
- Flutter and Dart come in F4, in a separate repository: attestation evidence to the vendor's
  attester, DPoP combined mode with keys in platform secure storage, platform passkeys,
  `redirect_to_web` through ASWebAuthenticationSession or Custom Tabs, and the same `StepView`.
  Until then the F1 guide shows the app-side half of the browser leg as vendor code.

Why. FiPA §9.7.3 "Mitigation": "it is RECOMMENDED that a client-side SDK be used" when several
first-party apps exist. FiPA §9.7.1 "User Experience Risk": "the implementation MUST ensure the
native experience is identical across all the first-party applications."

### 14. One DPoP verifier, one WebAuthn provider — fit with ADR-007 and ADR-014

**ADR-015 adds a human-login product line beside ADR-007's near-term identity without changing it.**
It shares one DPoP verifier and one WebAuthn `CredentialProvider` with ADR-014. The DPoP verifier is
flag-neutral, under `DPOP_ENABLED`, which `AGENT_TREE_ENABLED` requires. The WebAuthn provider sits
under `WEBAUTHN_ENABLED`. This record pulls `private_key_jwt` at revocation and introspection
forward into its F0. A first-party client never uses the MCP or agent door, and an MCP or agent
client never uses the first-party door.

- Positioning. [ADR-007](./007-mcp-first-positioning.md) "Decision" sets "The open-source,
  self-hostable OAuth 2.1 authorization server for MCP servers and AI agents" and does not exclude
  human login. This record feeds no agent path in any phase: a challenge code never roots an agent
  tree, MCP, DCR and CIMD clients are refused, and there is no SSO carry-over into the browser.
- DPoP. [ADR-014](./014-agent-authority-tree.md) "Phasing" plans DPoP at the token endpoint in P1a,
  behind `AGENT_TREE_ENABLED`. The proposed amendment (parked question 10): the verifier (RFC 9449
  §4.3 "Checking DPoP Proofs", a `jti` burn, nonces per §8 "Authorization Server-Provided Nonce"
  with §11.3 "DPoP Nonce Downgrade", `cnf.jkt`) lands once in a flag-neutral library behind
  `DPOP_ENABLED`; `AGENT_TREE_ENABLED` requires `DPOP_ENABLED`; the operator-set
  `dpop_bound_access_tokens` column is shared; whichever phase lands first builds it.
  `private_key_jwt` at `/oauth/revoke` and `/oauth/introspect`, also in P1a, needs no DPoP and is
  opt-in per client, so it moves to ADR-015 F0: a backend cannot log out without it.
- WebAuthn. ADR-014 §14 "Remote approval — a refused request the owner approves out of band" makes a
  passkey the default factor, and its phase P5 needs "A WebAuthn credential provider — passkey
  registration and assertion in the portal". F2b builds it once, as an
  [ADR-003](./003-credential-provider-interface.md) `CredentialProvider` (`provider_type` of
  `webauthn`, `external_sub` = credential id), with step verifiers above the single-shot `verify()`
  for second-factor use, optional enrolment after sign-in, the NIST SP 800-63B-4 §4.1.2.1 "Binding
  an Additional Authenticator" notice, and a hosted enrolment and management page that ADR-014's P5
  reuses; the amendment makes `AGENT_APPROVAL_ENABLED` require `WEBAUTHN_ENABLED`. The RP ID
  (`WEBAUTHN_RP_ID`, a registrable suffix of the issuer host) and per-client origins are
  operator-set; when the RP ID is the issuer host, QAuth serves the platform association files
  (`apple-app-site-association`, `assetlinks.json`) from operator-set app identifiers, so one
  passkey works across every first-party app and the hosted `/ui/login`. F2b also clears the first
  gate of [ADR-009 §3](./009-wallet-account-resolution.md) "`rp-pseudonym` is the intended endpoint,
  and is gated" ("a WebAuthn workstream").
- Wallet, agents and MCP. `WalletProvider.verify()` keeps throwing; wallet login is never a
  challenge step, only a `redirect_to_web` target. `first_party_profile` excludes `is_agent` by
  CHECK, so a challenge-issued code never roots an agent tree
  ([ADR-014 §1](./014-agent-authority-tree.md) "Session root — `sid` on agent access tokens"). DCR
  and CIMD clients cannot be first-party, so MCP clients reach the endpoint only as
  `unauthorized_client`. draft-embesozzi-oauth-agent-native-authorization-00 binds MCP Elicitation
  to FiPA; it would have a third-party agent collect a user's credentials, the case FiPA §1.1's MUST
  covers, so it stays a watch item. OpenID Connect Native SSO for Mobile Apps (Second Implementer's
  Draft) is F5, for several first-party apps on one device.

Why. ADR-007 keeps its identity; ADR-014's P1a and P5 need the same two components, and two
verifiers or two providers would have to be kept in step.

## Alternatives considered

| Alternative                                                                                           | Why not                                                                                                                                                                                                                                                              |
| ----------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Web front-ends as a per-client operator opt-in with compensating controls                             | A knowing breach of RFC 10017 §7.3 (MUST) and FiPA §9.8 (NOT RECOMMENDED) in the first release; §9.8's user-experience reason does not hold on the web. Parked (question 1) with its mitigation list.                                                                |
| Argue that a server-rendered web app is not a browser-based application                               | RFC 10017 §3 turns on "dynamically downloaded and executed in a web browser"; a framework app with server actions, such as QAuth's own portal, is one.                                                                                                               |
| Only attested native apps, no backends                                                                | Blocks the first release on a draft whose WGLC ended 2026-09-22, and leaves the main case, an app backend, unserved.                                                                                                                                                 |
| Keep extending the `/auth/*` JSON routes                                                              | A proprietary surface with no client authentication and no step signalling; FiPA Appendix C "Design Goals" puts the answer in an endpoint that returns a code.                                                                                                       |
| One boolean `first_party`, or two booleans                                                            | Cannot separate the redirect-flow consent waiver from headless access, and cannot state the front-end scope.                                                                                                                                                         |
| Infer first-partyness from `dynamic_registered_at IS NULL`, or a client-id allowlist in configuration | Self-service `/api/clients` rows are NULL there too; a configuration list has no CHECK tying it to auth method, agent flag or registration type.                                                                                                                     |
| DCR with a software statement                                                                         | A trust edge created by the party being trusted is not a trust edge (ADR-011 §5).                                                                                                                                                                                    |
| Public native clients on DPoP alone before attestation                                                | DPoP proves key continuity, not app identity; it cannot meet the FiPA §5 MUST for such a client.                                                                                                                                                                     |
| QAuth-defined `error` values per step or per rejection                                                | Against the editors' position on [WG issue #133](https://github.com/oauth-wg/oauth-first-party-apps/issues/133); custom values collide ([WG issue #171](https://github.com/oauth-wg/oauth-first-party-apps/issues/171)); a generic client stops on an unknown error. |
| `interaction_types_supported` required, 400 when absent                                               | Dead-ends a generic FiPA client; `redirect_to_web` is the draft's own escape.                                                                                                                                                                                        |
| Pick the first step from the account's strongest method after `login_hint`                            | Discloses account existence and passkey holders before any factor.                                                                                                                                                                                                   |
| Accept and ignore `acr_values`                                                                        | Drops an RFC 9470 §5 SHOULD and invites the loop it warns about.                                                                                                                                                                                                     |
| Email code after every password sign-in in F1                                                         | Removes the one-call happy path apps rely on; kept as a per-client option.                                                                                                                                                                                           |
| Passwordless email-code sign-in                                                                       | NIST SP 800-63B-4 §3.1.3.1; contradicts the downgrade rule while every account has a password.                                                                                                                                                                       |
| A 429 when a per-address send cap is reached                                                          | A different answer at the cap is an enumeration signal; quiet suppression keeps one shape.                                                                                                                                                                           |
| DPoP for every client in the first release                                                            | Blocks F1 on a verifier QAuth does not have as of 2026-09-26, and adds little for a confidential backend.                                                                                                                                                            |
| Long-lived post-code sessions for step-up (FiPA §6.1 "Token Endpoint Successful Response") in F1      | The right later design, but long-lived state in a first release; deferred to F5.                                                                                                                                                                                     |
| A form parameter or `TRUST_PROXY` for the end-user IP                                                 | A form parameter is workable (parked question 4); `TRUST_PROXY` makes every route believe `X-Forwarded-For` from a backend on the public internet.                                                                                                                   |
| Bot challenge mandatory for registration in the first release                                         | Makes F1 depend on a third-party provider and an unbuilt egress helper; F1b, per client.                                                                                                                                                                             |
| `prompt=create` in F1, or gating registration on `realms.registration_allowed`                        | Would breach the OIDF §4.2 MUST or over-advertise `/oauth/authorize`; the realm column has no write path.                                                                                                                                                            |
| `amr: ["pwd"]` after a reset                                                                          | The user set a password; they did not prove one.                                                                                                                                                                                                                     |
| A flag-gated `grant_type=password` for compatibility                                                  | Either not ROPC or not safe (Decision 12); RFC 9700 §2.4.                                                                                                                                                                                                            |
| A backend callback URL for the browser leg                                                            | A backend that completes from `state` alone cannot tell which browser returned the code.                                                                                                                                                                             |
| Fold ADR-015 into ADR-014, or wait for it                                                             | Puts human login behind `AGENT_TREE_ENABLED`, or loses the window for apps leaving ROPC.                                                                                                                                                                             |

## Standards position

Positions: Conformant, Stricter (QAuth requires more), QAuth-defined (an extension the text allows),
Knowing deviation (recorded, with an end or a parked question), Partial (part of the text is met;
the row names that part, and the phase or parked question for the rest), Shared responsibility
(QAuth meets its part; the rest is a profile requirement on the vendor's app), Not claimed (QAuth
makes no claim the text governs), Deferred.

| Piece                                                                             | Position                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | Hook                                                                                                                                                                                                       |
| --------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `https` endpoint; client authentication at the endpoint                           | Conformant                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | FiPA §4.1 MUSTs                                                                                                                                                                                            |
| Accept authorization-request parameters                                           | Conformant: `state` accepted and unused; `login_hint` new handling; `prompt=create` from F2a                                                                                                                                                                                                                                                                                                                                                                                                                                                 | FiPA §4.1 "Authorization Challenge Endpoint" MUST                                                                                                                                                          |
| Verify first-partyness                                                            | Conformant (operator profile and `private_key_jwt`; attestation for native apps in F4)                                                                                                                                                                                                                                                                                                                                                                                                                                                       | FiPA §5 MUST; §9.1                                                                                                                                                                                         |
| Browser leg: external user agent                                                  | Shared responsibility until F4: a profile requirement, shown in the guide; the app code is the vendor's                                                                                                                                                                                                                                                                                                                                                                                                                                      | FiPA §5 SHOULD; RFC 8252 §8.12                                                                                                                                                                             |
| Browser leg: redirect URI and completion                                          | Conformant as a profile requirement                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | FiPA §5 SHOULD; RFC 8252 §7.1–§7.3, §8.9                                                                                                                                                                   |
| PKCE                                                                              | Stricter: S256 required; FiPA makes it OPTIONAL                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | FiPA §5.1; RFC 9700 §4.8.2 "Countermeasures"                                                                                                                                                               |
| Next-step signal                                                                  | QAuth-defined members inside `insufficient_authorization`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | FiPA §5.2.2 MAY; [WG issue #133](https://github.com/oauth-wg/oauth-first-party-apps/issues/133)                                                                                                            |
| 403 for `insufficient_authorization` and `redirect_to_web`; 400 `invalid_session` | Conformant ([WG issue #177](https://github.com/oauth-wg/oauth-first-party-apps/issues/177) open)                                                                                                                                                                                                                                                                                                                                                                                                                                             | FiPA §5.2.2.1 MUST; §5.2.2 default                                                                                                                                                                         |
| 429 for throttling, 503 for store outages                                         | QAuth-defined: outside §5.2.2's default of 400, which applies "unless specified otherwise by a particular error code"                                                                                                                                                                                                                                                                                                                                                                                                                        | FiPA §5.2.2                                                                                                                                                                                                |
| `error` values                                                                    | Stricter: only values that a specification defines, within the character set that FiPA §5.2.2 sets as a MUST NOT. FiPA §5.2.2 lets the AS "extend these error codes"; QAuth defines no values of its own. The same section "requires the authorization server to define new error codes" for the client's next actions. QAuth carries those as members, as FiPA Appendix B.2 "Authorization Challenge Response Parameters" does and as an editor preferred on [WG issue #133](https://github.com/oauth-wg/oauth-first-party-apps/issues/133) | FiPA §5.2.2 "Error Response"; Appendix B.2; [WG issue #133](https://github.com/oauth-wg/oauth-first-party-apps/issues/133); [WG issue #171](https://github.com/oauth-wg/oauth-first-party-apps/issues/171) |
| `iss` on every response                                                           | QAuth-defined on the 200                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | FiPA §5.2.2.1.1 SHOULD (RFC 9207) for the browser leg                                                                                                                                                      |
| `auth_session` device binding                                                     | Partial for backends (bound to client authentication); DPoP F3; instance key F4                                                                                                                                                                                                                                                                                                                                                                                                                                                              | FiPA §5.3.1 SHOULD; §9.6                                                                                                                                                                                   |
| Client keeps `auth_session` beyond the code                                       | Conformant in the SDK: the last handle is kept per `sessionKey` until logout                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | FiPA §5.3.1 "Auth Session" MUST                                                                                                                                                                            |
| Client includes a stored `auth_session` in later requests                         | Knowing deviation in the SDK until F5 (parked question 17): the SDK does not present the last handle on a new transaction, because QAuth ends every `auth_session` at the code; a client that presents it gets `invalid_session` and pays one round trip (Decision 6)                                                                                                                                                                                                                                                                        | FiPA §5.3.1 "Auth Session" MUST; §9.6.2 "Auth Session Lifetime"                                                                                                                                            |
| `redirect_uri` at the token endpoint                                              | Conformant. Browser codes: required and identical (RFC 6749 §4.1.3). Challenge codes: the OAuth 2.1 -16 rule, absent or identical to a value sent on the authorization challenge request; RFC 6749 §4.1.3's presence rule is not applied to them ([WG issue #179](https://github.com/oauth-wg/oauth-first-party-apps/issues/179) open as of 2026-09-26)                                                                                                                                                                                      | FiPA §6; RFC 6749 §4.1.3; OAuth 2.1 -16 §4.1.3, §10.2                                                                                                                                                      |
| Client assertion `aud`                                                            | Conformant for every client with a `first_party_profile` at every endpoint it uses, and for every client at `/oauth/revoke` and `/oauth/introspect`: the issuer as sole value. For other clients at `/oauth/token`, the rule of ADR-011 §7 is unchanged by this record (watch list). The SDK sends the issuer as sole value at every endpoint                                                                                                                                                                                                | draft-ietf-oauth-rfc7523bis-11 §4 "Updates to RFC 7523" MUST, MUST NOT                                                                                                                                     |
| `acr_values`                                                                      | Conformant: refused with `unmet_authentication_requirements`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | RFC 9470 §5 SHOULD; §7                                                                                                                                                                                     |
| Attestation for native apps                                                       | Deferred to F4 (not applicable to backends)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | FiPA §9.3, §9.4 SHOULD                                                                                                                                                                                     |
| Sender-constrained tokens                                                         | Knowing deviation for `native_backend` without operator-set DPoP; F3 option, F4 DPoP for attested apps                                                                                                                                                                                                                                                                                                                                                                                                                                       | FiPA §9.5 SHOULD                                                                                                                                                                                           |
| Identical experience across first-party apps                                      | Shared responsibility: AS behaviour, `StepView` and SDK; app UIs are the vendor's                                                                                                                                                                                                                                                                                                                                                                                                                                                            | FiPA §9.7.1 MUST; §9.7.3 RECOMMENDED                                                                                                                                                                       |
| Browser-based applications                                                        | Conformant (native front-ends only; web variant parked)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | FiPA §9.8 NOT RECOMMENDED; RFC 10017 §7.3, §6.1.3.1 MUSTs                                                                                                                                                  |
| Registration inside the flow                                                      | QAuth-defined, following the non-normative example with verify-first                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | FiPA Appendix A.8                                                                                                                                                                                          |
| Headless reset                                                                    | QAuth-defined: an email-recovery sign-in at mailbox assurance, with no `amr` or `auth_time`                                                                                                                                                                                                                                                                                                                                                                                                                                                  | FiPA Appendix A.2, §5.2.2.1.1; NIST SP 800-63B-4 §4.2                                                                                                                                                      |
| No ROPC                                                                           | Conformant at `/oauth/token`, which has never offered `grant_type=password`; QAuth's own password-to-token route, `/auth/login`, is removed in F1c (Decision 12)                                                                                                                                                                                                                                                                                                                                                                             | RFC 9700 §2.4 "Resource Owner Password Credentials Grant" MUST NOT; OAuth 2.1 -16 §10 "Differences from OAuth 2.0"                                                                                         |
| Asymmetric client authentication                                                  | Stricter (`private_key_jwt` only)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | RFC 9700 §2.5 RECOMMENDED                                                                                                                                                                                  |
| Forwarded end-user IP                                                             | QAuth-defined signed claim; the sanitising duty falls on the backend's ingress and is a profile requirement                                                                                                                                                                                                                                                                                                                                                                                                                                  | RFC 9700 §4.13                                                                                                                                                                                             |
| Code replay                                                                       | Conformant (deny and revoke the family)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | OAuth 2.1 -16 §4.1.3 MUST, SHOULD                                                                                                                                                                          |
| `invalid_dpop_proof`, `use_dpop_nonce` at this endpoint (F3)                      | QAuth-defined use beyond the registered locations                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | RFC 9449 §12.2 "OAuth Extensions Error Registration"                                                                                                                                                       |
| `interaction_types_supported`, `interaction_type_required`                        | Knowing deviation: the names are borrowed and the rules differ. OpenID4VCI requires the list and says an AS that cannot serve it "MUST reject the request"; QAuth answers `redirect_to_web`, as FiPA allows (Decision 3)                                                                                                                                                                                                                                                                                                                     | OpenID4VCI 1.1 "Initial Request"; "Interaction Required Response"; "Authorization Challenge Error Response"                                                                                                |
| Step values "MUST be valid URNs"                                                  | Knowing deviation: `urn:qauth:` is not a registered namespace (parked question 18)                                                                                                                                                                                                                                                                                                                                                                                                                                                           | OpenID4VCI 1.1 "Initial Request"                                                                                                                                                                           |
| `prompt=create` metadata and ID token                                             | Conformant from F2a                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | OIDF prompt=create §4.1, §4.2 MUSTs                                                                                                                                                                        |
| Administrative consent                                                            | Conformant                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | OpenID Connect Core 1.0 §3.1.2.4                                                                                                                                                                           |
| `amr` vocabulary                                                                  | Conformant (RFC 8176 and IANA `pop`; no email value)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | RFC 8176 §2; RFC 9068 §2.2.1                                                                                                                                                                               |
| Password verifiers                                                                | Conformant for new and changed passwords at the default minimum of 15 (whole-password blocklist); an operator-set minimum below 15 is a knowing deviation while a password can be the only factor; Stricter by a zxcvbn score floor, which requires no character mix and so is not read as a composition rule; blocklist partial until a breach corpus (F5)                                                                                                                                                                                  | NIST SP 800-63B-4 §3.1.1.2                                                                                                                                                                                 |
| Email as an authenticator                                                         | Not claimed: no `amr`, `acr`, `mfa` or AAL                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | NIST SP 800-63B-4 §3.1.3.1 SHALL NOT                                                                                                                                                                       |
| Email code parameters                                                             | Conformant as address-verification and issued recovery codes: each code is disabled after 5 wrong answers; across codes, a per-identifier wait ladder, not a stop, so the recovery path stays open. The optional per-client `confirm_sign_in` check is outside the §3.1.3.1 carve-out and claims no authenticator status (no `amr`, `acr`, `mfa` or AAL)                                                                                                                                                                                     | NIST SP 800-63B-4 §4.2.1.2 "Issued Recovery Codes"; §3.2.2; §3.1.3.1                                                                                                                                       |
| Throttling                                                                        | Conformant while the hard action is armed; partial in a deployment where it is not (parked question 7)                                                                                                                                                                                                                                                                                                                                                                                                                                       | NIST SP 800-63B-4 §3.2.2                                                                                                                                                                                   |

### Watch list

| Document                                                         | Revision · date                                                                              | Expires    | Why watched                                                                                                                  |
| ---------------------------------------------------------------- | -------------------------------------------------------------------------------------------- | ---------- | ---------------------------------------------------------------------------------------------------------------------------- |
| draft-ietf-oauth-first-party-apps (WG)                           | `-04` · 2026-07-01                                                                           | 2027-01-02 | the profile's base; the four WG issues named in [The draft this record builds on](#the-draft-this-record-builds-on) are open |
| draft-ietf-oauth-attestation-based-client-auth (WG)              | `-11` · 2026-09-03                                                                           | 2027-03-07 | F4; WGLC ended 2026-09-22; F4 builds on its post-WGLC revision                                                               |
| OpenID4VCI 1.1 "Interactive Authorization" (OIDF editor's draft) | `openid-4-verifiable-credential-issuance-1_1-01` · repository commit `8cb80d2` of 2026-09-25 | —          | negotiation names; [OpenID4VCI issue #595](https://github.com/openid/OpenID4VCI/issues/595)                                  |
| draft-ietf-oauth-v2-1 (WG)                                       | `-16` · 2026-09-03                                                                           | 2027-03-07 | token request without `redirect_uri`; replay rule; ROPC omitted                                                              |
| draft-ietf-oauth-rfc7523bis (WG)                                 | `-11`, in the RFC Editor queue per the IETF index of 2026-09-26                              | —          | `aud` = issuer as sole value; the token endpoint's accepted values; also watched by ADR-014                                  |
| draft-embesozzi-oauth-agent-native-authorization (individual)    | `-00` · 2026-04-03                                                                           | 2026-10-05 | MCP elicitation over FiPA                                                                                                    |
| OpenID Connect Native SSO for Mobile Apps                        | draft 07 · 2025-01-16 (Second Implementer's Draft)                                           | —          | F5                                                                                                                           |
| OIDF Initiating User Registration via OpenID Connect 1.0         | Final · 2022-12-02                                                                           | —          | `prompt=create` in F2a                                                                                                       |

Rows for these documents go into `docs/spec-pin-log.md` in a follow-up change, not in this record.

## Explicitly out of scope

A password grant in any form. Headless login for web front-ends, unless parked question 1 changes.
Password-hash import in formats other than Argon2id PHC (bcrypt and PBKDF2 later, and only after the
dependency and advisory check of parked question 5). All import if parked question 5 is declined.
SMS and phone steps. User-name and phone-number identifiers. Social or wallet steps inside the flow
(they are `redirect_to_web` targets). An admin user API or an operator role. OpenID Connect Native
SSO and an MCP-elicitation binding (later), and TOTP before F5. SSO carry-over from a headless login
into the browser: FiPA is silent on it, and the user meets `/ui/login` fresh.

## Phasing

The rule for every phase: with the phase's switch off (for F0, for every client an operator has not
flagged), nothing changes except the deltas listed for that phase. Each listed delta has its own
test, and every other response, token and discovery document stays byte-identical to the previous
release. The switch is usable only when F1 is complete. F1 lands as several changes. Until the
change that completes F1 (its end-to-end suite), the environment schema refuses
`FIRST_PARTY_LOGIN_ENABLED=true` with a clear boot error. That change removes the refusal, so the
route can never be switched on before its abuse controls exist. `WEBAUTHN_ENABLED` follows the same
pattern in F2b.

The F1 release train is the run of releases in which F1's changes land. It ends with F1's release:
the release that removes the refusal, so an operator can first switch `FIRST_PARTY_LOGIN_ENABLED`
on. A phase whose target is the train ships no later than F1's release.

- F0 — prerequisites, no new endpoint, no switch.
  - Contents: Decision 10's data model, `mintAuthorizationCode`, the token-endpoint `redirect_uri`
    rule and replay revocation; Decision 2's profile, CHECKs, resolver, seed fields and pins;
    `private_key_jwt` at revocation and introspection; administrative consent at `/oauth/authorize`
    and the limited hand-off (Decision 9); a fresh login at `/oauth/authorize` for native profiles
    (Decision 9); an atomic `GETDEL`; a browser end-session route (`id_token_hint`, a registered
    `post_logout_redirect_uri`; it clears `__Host-qauth_session`) per OpenID Connect RP-Initiated
    Logout 1.0 §2 "RP-Initiated Logout" and §3.1 "Client Registration Metadata"; the portal's move.
    The `SYSTEM_CLIENT_ID` row is re-provisioned as a `private_key_jwt` `web_redirect` client with
    the portal's callback. The `migration-runner` job and the seed provisioner do this from operator
    configuration. The portal refuses to start on any other row shape and takes
    `authorization_endpoint` from discovery. It signs out by revoking its refresh token and calling
    the end-session route. It keeps "sign out everywhere" as an explicit action (parked question 9)
    and keeps its "Create account" link until F2a.
  - Listed deltas: (1) a replayed code revokes its family, for every client; (2) discovery gains
    `private_key_jwt` for revocation and introspection, the matching
    `revocation_endpoint_auth_signing_alg_values_supported` and
    `introspection_endpoint_auth_signing_alg_values_supported` members, and `end_session_endpoint`;
    (3) the headless hand-off follows Decision 9; (4) a browser-code token request without
    `redirect_uri` answers `invalid_grant` (Decision 10) instead of a schema `VALIDATION_ERROR`; (5)
    a new end-session route; (6) the portal signs in through the redirect flow.
  - Exit criteria:
    - Byte identity except the listed deltas.
    - The CHECKs hold: no browser code without `redirect_uri`; no profile from DCR, CIMD or
      `/api/clients`, or with `is_agent`, a developer or another auth method.
    - A `private_key_jwt` client revokes its own refresh token, and a token-URL `aud` is refused
      there. A flagged client's token-URL `aud` is also refused at `/oauth/token`.
    - Management tokens from the re-provisioned row pass `assertManagementToken`.
    - A `native_backend` client at `/oauth/authorize` with a live browser session and no `prompt`
      meets the login page, and with `prompt=none` gets `login_required`.
    - Sign-out then sign-in asks for a password.
  - Dependencies: none on ADR-014; the revocation and introspection work waits only for the text of
    the ADR-014 amendment, so the two records never disagree.
- F1 — first release, behind `FIRST_PARTY_LOGIN_ENABLED=false`.
  - Contents: Decisions 1–11 for `native_backend` with the F1 steps; flows per client, inline
    verification, the unclaimed-account rule and the session epoch; the one password policy;
    `@qauth-labs/node`, published to npm with provenance, and the language-neutral kit; the guide,
    API reference and migration guide; an operate checklist line to pass 400 and 403 bodies through
    unchanged on the endpoint; an example in the repository: a Node backend and a minimal desktop or
    command-line app that renders `StepView`.
  - Listed delta with the switch off: `/auth/register` applies the new password policy.
  - Exit criteria:
    - The example app signs up, verifies, signs in, resets and signs out with no browser.
    - A listed backend at its expected volume is not throttled at the authorization challenge
      endpoint, `/oauth/token` or `/oauth/revoke`, and an unlisted peer keeps the route caps.
    - A fallback case works with the example app: no negotiation, `redirect_to_web`, system browser,
      loopback return, the app posts to its backend, tokens. The guide shows the app-claimed `https`
      return for mobile apps.
    - Every row of the status table has a test.
    - The anti-enumeration invariant holds in bodies and timing, including reset and registration
      starts.
    - With the switch off, discovery is byte-identical except the listed deltas.
    - `@qauth-labs/node` installs from npm.
    - The disable ceiling is armed only while F2a's hosted reset is on, and a test shows that a mark
      set before that switch goes off is ignored and no longer blocks sign-in.
  - Dependencies: F0. None on ADR-014. No third-party provider.
- F1b — bot challenge (same switch): the provider-neutral verifier, the SSRF-safe POST helper,
  `urn:qauth:ia:captcha`, and a per-client requirement for registration. Depends on F1.
- F1c — removal of `/auth/login`, `/auth/logout` and the headless hand-off, at least one minor
  release after F1's release, on the version and date F1's deprecation notice names. Depends on F0's
  portal move and on the replacement for scripted management tokens (parked question 8).
- F1d — user import, a switch-free operator tool (parked question 5): `db:import-users` in the
  seed-script pattern; records carry the address, whether it is verified, and an Argon2id PHC hash,
  which QAuth's hasher already verifies; each import writes `user.imported`. A record in any other
  hash format is not imported. The tool lists it in its report, and that user takes the `register`
  path (Decision 12). A record may also carry the source IdP's subject identifier. The tool then
  writes a report that maps it to the new `sub`, and the `user.imported` row records it. An app that
  keys its data by the old issuer and subject re-keys from that report, not by address (OpenID
  Connect Core 1.0 §5.7 "Claim Stability and Uniqueness"). Depends on F0. Target: the F1 release
  train, so the migration guide that ships with F1 can name the tool.
- F2a — hosted account pages with no WebAuthn dependency, behind their own default-off switch
  (parked question 6): server-rendered `/ui/register` and `/ui/reset` on the F1 engine, "Create
  account" and "Forgot password" links on `/ui/login`, `prompt=create` at both endpoints with
  `prompt_values_supported`, and the portal's sign-up. The legacy registration routes are removed
  only once the hosted pages are on for the portal in a default deployment. Depends on F1's
  registration and reset flows. A hosted reset or registration sets no `auth_time`. It ends without
  a browser session that could satisfy `max_age` or `prompt=login` (Decision 10). Target: the F1
  release train.
- F2b — passkeys, behind `WEBAUTHN_ENABLED=false`: the shared WebAuthn `CredentialProvider`;
  `webauthn_get` and `webauthn_create`; passkey-first; the downgrade rule binding; UV verified
  server-side; optional enrolment; the hosted enrolment and management page shared with ADR-014's
  P5; an operator-set RP ID, per-client origins and the association files, after re-reading the
  platform rules; passkeys on the hosted `/ui/login` on the same engine. Depends on F1, and on F2a
  for hosted passkey login.
- F3 — DPoP, behind `DPOP_ENABLED=false`: the shared verifier; FiPA §9.5.1 code binding and §9.6.1
  session binding at the endpoint, which ends its `DPoP` refusal; `cnf.jkt`, `token_type: DPoP` and
  nonces at the token endpoint; the shared `dpop_bound_access_tokens` column. Depends on F1; shares
  the verifier with ADR-014's P1a.
- F4 — attested native apps, behind `CLIENT_ATTESTATION_ENABLED=false` (which requires
  `DPOP_ENABLED`): attestation -11, or its post-WGLC revision, in DPoP combined mode; the
  `native_attested` profile, with the auth-method CHECK replaced so that `native_attested` is tied
  to `attest_jwt_client_auth[_dpop]` and the other profiles stay on `private_key_jwt`; attester keys
  per client (`CLIENT_ATTESTATION_TRUSTED_ATTESTERS`, in the pattern of `ID_JAG_TRUSTED_ISSUERS`);
  instance-bound refresh tokens; the attestation metadata; public native clients may become
  first-party only here; the Flutter SDK in a separate repository.
- F5 — later, unscheduled: TOTP; an established post-code `auth_session` and FiPA §6.2 refresh-time
  step-up; a pushed-request `request_uri` (RFC 9126 §2.2 "Successful Response") in `redirect_to_web`
  once [WG issue #179](https://github.com/oauth-wg/oauth-first-party-apps/issues/179) settles; the
  FiPA Appendix A.4 "Email Confirmation Code" link variant; `amr` on browser logins; a
  breached-password corpus; an authenticator-strength `acr`; OpenID Connect Native SSO.

| What the first release refuses                                           | Answer                                                 | Lifted in                             |
| ------------------------------------------------------------------------ | ------------------------------------------------------ | ------------------------------------- |
| Public client (`none`)                                                   | 400 `unauthorized_client`                              | F4                                    |
| Secret-based client; DCR, CIMD or agent client; `web_redirect` profile   | 400 `unauthorized_client`                              | never                                 |
| `DPoP` or `OAuth-Client-Attestation` headers                             | 400 `invalid_request`                                  | when the endpoint binds them (F3, F4) |
| Browser-originated request (`Origin`, `Sec-Fetch-Site`)                  | 400 `invalid_request`                                  | never                                 |
| Missing `qauth_end_user_ip` claim                                        | 400 `invalid_request`                                  | never for `native_backend`            |
| A frozen authorization-request parameter on a later round                | 400 `invalid_request`                                  | never                                 |
| `acr_values`                                                             | 400 `unmet_authentication_requirements`                | with an ADR-010 amendment             |
| `prompt=none`                                                            | 400 `login_required`                                   | F5, with established sessions         |
| `prompt=consent`, dangerous scopes                                       | 403 `redirect_to_web`                                  | not planned                           |
| Reset or registration under `max_age` or `prompt=login`                  | 403 `redirect_to_web`                                  | never                                 |
| `prompt=create`                                                          | 400 `invalid_request` (use the `register` path marker) | F2a                                   |
| No `interaction_types_supported`                                         | 403 `redirect_to_web`                                  | never                                 |
| Passkey, TOTP and bot-challenge steps                                    | not offered                                            | F2b, F5, F1b                          |
| Passwordless email-code sign-in                                          | not offered                                            | parked question 2                     |
| `request_uri` in `redirect_to_web`                                       | never returned                                         | F5                                    |
| `auth_session` after a code; token-endpoint `insufficient_authorization` | `invalid_session`; never emitted                       | F5                                    |

## Consequences

### Positive

- Apps get native sign-in, sign-up and reset with no browser and no password grant, on a WG draft's
  endpoint rather than a proprietary one.
- QAuth, not each app, owns throttling, verification, recovery, step-up and the password policy.
- The happy path keeps a password grant's shape: one call to the authorization challenge endpoint
  and one token call.
- Passkeys (F2b) arrive on the same wire with no new endpoint. A user who signs in with a passkey
  gives the app no password.
- QAuth applies the rule to itself: its portal moves to the redirect flow in F0, and its
  password-to-token route retires in F1c.
- Every authorization code QAuth mints is PKCE-bound by construction, and every code replay revokes
  its family, for every client. Revocation and introspection gain `private_key_jwt`, which ADR-014
  also needs.

### Negative

- A new endpoint with a step engine, a session store, a layered limiter and an SDK is a large
  surface, and the most branch-heavy login path QAuth has.
- A password step shows the password to the app. Passkeys (F2b) avoid this only for users who sign
  in with one. `native_backend` access tokens stay Bearer until a client opts into DPoP (F3), a
  recorded deviation from FiPA §9.5 "Sender-Constrained Tokens".
- QAuth cannot verify the asserted end-user IP, only who asserted it.
- Headless login is unavailable while Redis is unavailable, by design.
- Two registration paths coexist until F2a, and `/auth/login` stays, frozen, until F1c.
- The app changes too, not only its backend. It renders the `email_code`, `new_password` and
  `redirect_to_web` steps. After a correct password, a user whose address is unverified is asked for
  an email code; this includes an imported record the source did not mark verified. New passwords
  need 15 code points. An app build that cannot render these steps cannot complete them, so the
  build that renders them ships before its backend switches.
- An app whose backend passed password-grant tokens to its device must route its API calls through
  the backend until attested apps (F4).
- The one password policy changes `/auth/register` on every deployment in F1 (15 code points), and
  integrations must show the new rejection reasons.
- QAuth ships and versions an npm package for the first time, with its release process; the README's
  planned browser-side `signInWithPassword` will not ship.

### Neutral

- FiPA is a WG draft. The profile absorbs likely changes (status codes, negotiation, custom members)
  by emitting core equivalents beside its own members and classifying by `error`.
- ADR-007's positioning is unchanged; human login is a product line beside it and feeds no agent
  path. `acr` semantics are unchanged (ADR-010); `amr` appears only on tokens from challenge-issued
  codes until F5.
- `WalletProvider.verify()` keeps throwing; wallet login stays on its own seam.
- The ADR-014 amendment is a separate, dated change after this record is accepted.

## Decisions parked for the maintainer

Each question carries the default this record proceeds on until the maintainer decides otherwise.
Questions 1–10 are true forks; questions 11–29 record defaults that are unlikely to change.

1. Web front-ends behind a backend. FiPA §9.8 and RFC 10017 §7.3 and §6.1.3.1 reach them. Should
   QAuth offer them as a per-client, operator-set, recorded deviation? The minimum would be an
   operator value `web_backend` with a written reason; RFC 10017 §6.1.3.2 "Cookie Security" and
   §6.1.3.3 "Cross-Site Request Forgery Protections"; a content security policy without
   `unsafe-inline` and no third-party script on credential pages; passkey-first with the web origin
   as the WebAuthn origin; a mandatory end-user IP and a bot challenge at thresholds; lower
   per-client limits; `redirect_to_web` on any risk signal; dangerous scopes always refused; audit
   rows tagged as web; and the ADR naming the deviation. _Default: no. Web front-ends use
   `/oauth/authorize`, and hosted pages (F2a) are the web answer._
2. Email codes: a sign-in factor, a check after every password, or passwordless sign-in? _Default:
   address verification and recovery, plus an optional per-client check after the password
   (`email_code_after_password: false`). They never produce `amr`, `acr`, `mfa` or an AAL claim.
   Passwordless email-code sign-in is not offered. A reset of a password-only account is labelled an
   email-recovery sign-in._
3. Password minimum on `/auth/register`. _Default: the 15-code-point minimum applies to every newly
   set password, including `/auth/register`, as an announced F1 change on every deployment, with a
   release note and the portal form showing the new reasons. An operator may lower it to 8, a
   knowing deviation while a password can be the only factor. Alternatives: gate it behind the
   switch, or keep the legacy route on its old rule until F2a._
4. End-user IP carriage. _Default: the `qauth_end_user_ip` claim inside the signed assertion,
   derived by the backend from its peer or a listed proxy chain. Alternatives: a form parameter from
   an authenticated first-party client; accepting either carrier is not recommended (two parsers and
   a precedence rule for one security input)._
5. Users migrating from another IdP. _Default: an operator import tool in F1d, in the seed-script
   pattern (the only operator surface; ADR-012 §4); Argon2id PHC hashes only, with bcrypt and PBKDF2
   only after the dependency and advisory check; addresses verified only if the source says so; a
   source subject identifier, when given, is mapped to the new `sub` in the tool's report; audited
   as `user.imported`. Alternative: no import, with the migration guide saying so and naming the
   `register` flow as the bulk path, since `reset` mails only an existing account. Lazy migration
   against the old IdP is rejected, because it keeps a password grant alive there._
6. Hosted account pages: timing and switch. _Default: `/ui/register` and `/ui/reset` ship in the F1
   release train, independent of WebAuthn, behind their own default-off switch, because opening
   hosted registration is an operator decision._
7. Arming the disable ceiling. NIST SP 800-63B-4 §3.2.2 says disabled authenticators "SHALL be
   required to rebind". _Default: the disable at 100 is armed only while every account it can reach
   has a self-service rebind path, checked at run time. The headless reset serves native users only,
   so in practice the ceiling is armed only while F2a's hosted reset is on. Otherwise the soft
   ladder runs alone, marks set earlier are ignored, and the standards position records §3.2.2 as
   partial._
8. Scripted management tokens after F1c. The public API reference names `/auth/login` as the source
   of the developer token. _Default: before F1c, ship an operator-listed public CLI client with no
   `first_party_profile`, so the CHECKs of Decision 2 stay unchanged and the ordinary consent rules
   of Decision 9 apply. It uses the code flow with a loopback redirect (RFC 8252 §7.3 "Loopback
   Interface Redirection"); as of 2026-09-26 `redirectUriMatchesRegistered` accepts any loopback
   port. `assertManagementToken` accepts its tokens through an operator-set, seed-only allowlist
   field. Alternative: record that scripted management ends at F1c._
9. "Sign out everywhere". As of 2026-09-26 `/auth/logout` revokes every refresh token of the user.
   _Default: the portal keeps that action after F0, through a management-API call guarded by
   `assertManagementToken`; it revokes every refresh family and advances the browser-session epoch.
   The ordinary sign-out ends only the current session._
10. ADR-014 amendment. _Default: yes, as a separate dated change after this record is accepted: DPoP
    under `DPOP_ENABLED`, which `AGENT_TREE_ENABLED` requires; a shared `dpop_bound_access_tokens`;
    one flag-neutral WebAuthn provider with one hosted enrolment and management page;
    `AGENT_APPROVAL_ENABLED` requires `WEBAUTHN_ENABLED`; revocation and introspection
    `private_key_jwt` moved to ADR-015 F0._

Other recorded defaults:

| #   | Question                                               | Default                                                                                                                |
| --- | ------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------- |
| 11  | PKCE                                                   | S256 required, recorded as Stricter; `mintAuthorizationCode` refuses to mint without it                                |
| 12  | FiPA §1.1                                              | the profile's rules are stated as QAuth's own requirements                                                             |
| 13  | Registration gate                                      | per-client `flows`; `realms.registration_allowed` stays unread; F2a extends the per-client list to hosted registration |
| 14  | `prompt=create`                                        | the path marker in F1; `prompt=create` with its metadata in F2a                                                        |
| 15  | Bot challenge for registration                         | not required in F1; per client from F1b                                                                                |
| 16  | Consecutive-failure ceiling                            | 100 with the soft ladder; lower values make lockout cheaper                                                            |
| 17  | Established post-code `auth_session` (FiPA §6.1, §6.2) | none before F5; step-up is a fresh transaction                                                                         |
| 18  | Step identifier namespace                              | `urn:qauth:ia:`, recorded as a deviation; revisit if a WG type registry appears                                        |
| 19  | Hand-off and legacy removal                            | limited in F0, frozen in F1, removed in F1c; `/auth/login` refuses passkey-bound accounts until then                   |
| 20  | Attestation revision                                   | wait for the post-WGLC revision of -11, re-pin, then build F4                                                          |
| 21  | Pre-attestation native clients                         | refused in every environment until F4; no value exempts a public client                                                |
| 22  | `amr` for passkeys                                     | `["pop","mfa"]` when the server verified the UV flag, never `hwk`; no ADR-010 change here                              |
| 23  | Absolute refresh-family lifetime                       | none; the sliding `REFRESH_TOKEN_LIFESPAN` is unchanged                                                                |
| 24  | DPoP for `native_backend` in F3                        | operator opt-in per client; the FiPA §9.5 deviation stays recorded for the rest                                        |
| 25  | Recovery after losing the only passkey                 | `redirect_to_web`; F2b designs the hosted policy (NIST SP 800-63B-4 §4.2.2.1 "Recovery Without Identity Proofing")     |
| 26  | Browser-origin guard                                   | on, keyed on `Origin` and `Sec-Fetch-Site` only                                                                        |
| 27  | Dangerous scopes at the endpoint                       | `redirect_to_web` in every environment                                                                                 |
| 28  | Endpoint path                                          | `/oauth/authorize-challenge`                                                                                           |
| 29  | Known-IP exemption from the per-account wait           | on; the attempt still counts toward the ceiling                                                                        |

## Related

- [ADR-007](./007-mcp-first-positioning.md) — the near-term identity this record sits beside.
- [ADR-008](./008-environment-aware-authorization.md) — fail-safe defaults, operator-controlled
  relaxation and the environment profiles the limits follow.
- [ADR-010](./010-acr-assurance-mapping.md) — why no factor here emits `acr`.
- [ADR-011](./011-enterprise-managed-authorization.md) — `private_key_jwt`, the allowlist trust
  posture and the audit rule.
- [ADR-012](./012-dynamic-client-ownership.md) — why no operator role or widened predicate exists,
  and why the seed manifest is the operator surface.
- [ADR-013](./013-same-device-return-leg.md) — the burn-then-bind idiom of the `auth_session`.
- [ADR-014](./014-agent-authority-tree.md) — the DPoP verifier and WebAuthn provider this record
  shares, and the amendment of parked question 10.
- [ADR-002](./002-identifier-abstraction.md), [ADR-003](./003-credential-provider-interface.md)
  and [ADR-009](./009-wallet-account-resolution.md) — the identity tables, the `CredentialProvider`
  a passkey plugs into, and the wallet boundary.
- [draft-ietf-oauth-first-party-apps-04](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-first-party-apps-04)
  · [the WG repository](https://github.com/oauth-wg/oauth-first-party-apps)
  · [draft-ietf-oauth-attestation-based-client-auth-11](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth-11)
  · [draft-ietf-oauth-v2-1-16](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16)
  · [draft-ietf-oauth-rfc7523bis-11](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rfc7523bis-11)
  · [draft-embesozzi-oauth-agent-native-authorization-00](https://datatracker.ietf.org/doc/html/draft-embesozzi-oauth-agent-native-authorization-00)
- [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html) · [RFC 10017](https://www.rfc-editor.org/rfc/rfc10017.html)
  · [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html) · [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252.html)
  · [RFC 9470](https://www.rfc-editor.org/rfc/rfc9470.html) · [RFC 8176](https://www.rfc-editor.org/rfc/rfc8176.html)
  · [RFC 9207](https://www.rfc-editor.org/rfc/rfc9207.html) · [RFC 9126](https://www.rfc-editor.org/rfc/rfc9126.html)
  · [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html) · [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html)
  · [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068.html)
- [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html)
  · [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
  · [OpenID Connect Core Error Code unmet_authentication_requirements 1.0](https://openid.net/specs/openid-connect-unmet-authentication-requirements-1_0.html)
  · [OpenID Connect RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)
  · [Initiating User Registration via OpenID Connect 1.0](https://openid.net/specs/openid-connect-prompt-create-1_0.html)
  · [OpenID4VCI 1.1 editor's draft `-01`, repository commit of 2026-09-25](https://github.com/openid/OpenID4VCI/blob/8cb80d2b82171e5e7ed81c42ca97103ef75d11cd/1.1/openid-4-verifiable-credential-issuance-1_1.md)
  · [OpenID4VCI issue #595](https://github.com/openid/OpenID4VCI/issues/595)

# Changelog

All notable changes to QAuth are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Linking an upstream account to an existing one** ([#670], ADR-020 §3).
  On the Interaction API's ceremony page, the first upstream sign-in of an
  identity no account holds now asks at the new `upstream_link` step: "I
  already have an account", or a new account when the realm allows one. A
  signed-in person links one from an operator-flagged first-party client
  with `qauth_link=<type>` on the authorization request. Either way the
  identity joins the account only after a fresh sign-in to it with its own
  factors and its MFA policy, in the same browser and interaction; a session
  is not enough, and nothing is matched by email. An identity another account
  holds, or a second one of the same provider, is refused on its own page
  (`/ui/upstream-link-refused`). The account API lists the linked accounts
  (`GET /account/v1-rc.0/linked-accounts`) and unlinks one
  (`DELETE /account/v1-rc.0/linked-accounts/{linkedAccountId}`) after a fresh
  sign-in with the strongest factor, refusing the last way to sign in with
  `409 last_credential`. A link and an unlink mail the owner and record
  `user.upstream_linked` and `user.upstream_unlinked`, which the security
  log shows; a refused link records `user.upstream_link_failed`. With the
  server-rendered pages an unknown identity still creates its account at
  once.
- **Design tokens and theming in `libs/ui`** ([#472], ADR-020 §5). QAuth's
  own UIs now share the design system of the qauth.dev website: square corners,
  flat surfaces with hairline edges, DM Sans, Instrument Serif and JetBrains
  Mono, self-hosted. The values live in one token file in the Design Tokens
  Community Group format (`libs/ui/src/tokens/tokens.json`), and the CSS
  custom properties and the Tailwind v4 theme are generated from it. The
  theme follows the system's light or dark setting; `data-theme` on the root
  overrides it. Every text colour declares the backgrounds it is drawn on, and
  a test checks each pair against WCAG AA (4.5:1 for text, 3:1 for a field's
  edge and the focus ring) in both modes. This raised the default button,
  placeholder, muted text and field edges to AA. `applyBrand` checks a realm's
  brand settings (primary and accent colours, a font from a fixed list, dark
  mode on or off) and returns its theme stylesheet; it refuses a colour below
  AA, a font outside the list, and any value containing `url(`, `;`, `{` or
  `}`. The five primitives use the tokens, and the developer portal loads the
  design system.
- **Preset plugins on the generic upstream OpenID Connect client,
  experimental** ([#951], ADR-019 Decisions 9 and 12). A preset is a plugin
  for one named provider that runs the generic client's code (discovery, PKCE
  with S256, the ID token and callback checks) under its own id, type and
  config: `createUpstreamOidcPresetMethod` of
  `@qauth-labs/server-upstream-oidc` builds its `authMethod`, so the plugin
  loader takes it as any plugin, from the first-party list with
  `PLUGIN_API_ENABLED` off too. Its client secret is a `writeOnly` member of
  its own config, sealed under the plugin's context like any plugin secret;
  a config whose client secret is not such a member's value is refused, as
  it would be stored in the clear. The preset names the `https` origins its
  provider answers on: a config whose issuer or an endpoint set by hand
  leaves them is refused at the configure and at every use, and a discovery
  document that names an endpoint off them is refused before any call to it,
  so a realm's admin cannot send the stored secret to another host. Within
  those origins the secret is not bound to a tenant, unlike the generic
  client's. A config that carries a secret member's value anywhere but in the
  client secret is refused too. The plugin runtime's
  secret-member reader now takes a `writeOnly` mark inside a union of objects,
  such as a discriminated union of client authentication methods, when every
  branch with a member at that path marks it; the generic client's own
  config reads as one secret member, `clientAuthentication.clientSecret`.

- **Scopes for the account and developer APIs** ([#933], ADR-019 Decision 7).
  Each family has a read and a write scope in QAuth's reserved `qauth:`
  namespace: `qauth:developer:read` and `qauth:developer:write`,
  `qauth:account:read` and `qauth:account:write`. An operation needs its
  family's scope of its `x-qauth-class`, which is the class of its
  `x-qauth-permission`; the two scopes are independent. A token without it is
  refused with 403 `forbidden` and an `insufficient_scope` challenge naming
  the scope, so a developer token with only the read scope lists and reads
  clients, API keys and consents, and cannot create, update, delete or
  regenerate a client's secret, mint or revoke an API key, or revoke a
  consent. Every operation of both families now lists 403 in its OpenAPI
  responses. The token endpoint issues a family's scopes only to a client
  whose `audience` an operator set to that family's audience, for a token
  that names a user (never `client_credentials`, an ID-JAG or the jwt-bearer
  grant; a delegated token of token exchange keeps one its subject token
  carried when the agent's own registration lists the scope), with no admin
  grant and no DPoP proof; a refresh carries them
  forward. The developer portal's token from `POST /auth/login` carries both
  developer scopes. The deprecated `/api/clients` and `/api/consents` routes
  need the scope of the operation each aliases, and `POST /oauth/register`
  attributes a client to a developer only with `qauth:developer:write`. For
  this release only, a portal token that names no scope, minted by a node of
  the previous release, counts as carrying both developer scopes, so portal
  sessions survive the rolling upgrade. The account API contract states the
  rule and publishes `ACCOUNT_API_SCOPES`.
- **Fresh authentication with the strongest factor for account changes**
  ([#663], ADR-017 Decision 8, ADR-019 Decision 7, ADR-020 §3). One guard
  stands in front of every account API operation (`/account/v1-rc.0`) and
  applies the rules the contract gives it. An operation that changes a
  credential, an identifier, the contact address or a linked account, or
  deletes the account, needs a sign-in at most 5 minutes old (`auth_time`)
  whose `amr` holds the account's strongest bound factor: `pop` with a
  passkey, else `otp` with an authenticator app, else `pwd`. Otherwise it
  answers 401 `insufficient_user_authentication` with the RFC 9470 §3
  challenge, `Bearer error="insufficient_user_authentication",
  max_age="300"` for a sign-in too old or `max_age="0"` for one without the
  factor (the `DPoP` scheme for a DPoP-bound token), and `max_age` in the
  problem document. An act-chain token (RFC 8693 `act`) is refused with 403
  `delegated_token_refused` on those operations, before any challenge. A
  sign-in that used a recovery code in place of a lost factor passes only
  on the rebind operations (removing a passkey or the authenticator app,
  binding a new one): the browser session records it (new column
  `sessions.recovery_code_used`, migration 0067), and the account API's
  access token from the code exchange names that session in a new `sid`
  claim, which no other access token carries. A failed read of the
  account's factors or of the session refuses the call with 503. Every
  refusal is recorded as the new `request.account_operation_refused` event,
  which the security log leaves out. The two account operations served
  today, `account.consents.list` and `account.consents.delete`, run behind
  the guard with the contract's rules (neither asks for fresh
  authentication) and now publish `x-qauth-fresh-authentication` and
  `x-qauth-act-chain`. The new guide `integrate/account-api-backend` tells a
  backend for frontend how to answer the challenge.
- **Sign-up with a passkey alone, and `WEBAUTHN_ENABLED` switched on**
  ([#655], ADR-017 Decision 8 and phase F2b, ADR-018 §3;
  `graphs/flows/core/passkey-sign-up`). `WEBAUTHN_ENABLED=true` now boots:
  the environment schema no longer refuses it, and it turns on passkey
  sign-in, the offer to add a passkey after a password sign-in, and a new
  registration path. Where the realm and the client allow sign-up, the hosted
  pages offer a passkey first at registration, with the email address beside
  it: the ceremony (user verification required, no account named, the
  passkey named `account-` and the start of its user handle) creates a
  `users` row and a `webauthn` credential with no email attribute and no
  password, in one transaction with `user.registered` (method `passkey`).
  The account counts as verified by the ceremony; the registration carries
  no `amr` or `auth_time`. A recovery set is shown at once, and no code is
  issued until the person confirms the codes are saved. No mail is ever sent
  to such an account: its notices are its security log. It has no password
  reset; on the hosted pages a recovery code is offered beside the first
  sign-in step, for every account alike, and finds an account whose
  credentials are all passkeys by the code alone, through a per-realm
  Argon2id lookup digest of each code of its set (new column
  `user_recovery_codes.lookup_digest`, migration 0066). The code then binds
  a new passkey within 5 minutes in place of the lost one (the account's
  other passkeys are disabled in the same write), which the next round signs
  in with; a code alone never signs in. A registration by passkey counts against the realm's
  registration cap, and each answer is a credential round on the sign-in
  limiters.
- **TOTP as a second factor, with its own failure ladder** ([#653], ADR-017
  Decisions 7 and 8, ADR-020 §3; `graphs/flows/core/totp`). The sign-in
  engine gains the `totp` step (answered with `otp`) after the first factor of
  an account that holds an authenticator app, and the `totp_setup` step, which
  an MFA policy needing a second factor the account lacks asks for instead of
  sending a code. The parameters are fixed: SHA-1, six digits, a 30-second
  step, one step of tolerance either way. The secret is stored in
  `user_credentials`, sealed under the realm's `data_at_rest` key with a
  context bound to the account (only the `api` signer role may open it), and
  an accepted time step, or any earlier one, is never accepted again. The
  interaction record keeps no secret during the set-up: each read of the
  step opens the sign-in's ciphertext again. A secret
  is bound only after a first valid code, within 5 minutes of the
  transaction's strongest factor, for a claimed account only, after a mailed
  code for the first second factor of a password-only account whose mailbox
  this sign-in did not prove, and the first binding issues a recovery set.
  Password then code gives `amr` `["pwd","otp","mfa"]`. Wrong codes count per
  account across transactions, clients and IP addresses, with no known-IP
  exemption, and a password never clears them; from 5 failures the ladder
  makes each attempt wait, and an early one gets `429` unchecked and
  uncounted. Three mails no realm can switch off: `totp_added`,
  `second_factor_failed` (a wrong code after a right password, at most once a
  day) and `second_factor_disabled` (100 wrong codes in a row, only while the
  hosted pages are on and the account keeps an unused code of a recovery set
  it confirmed, or another usable second factor). A recovery code that stands
  in for a disabled app leads to its set-up before the sign-in completes,
  whatever the MFA policy. Two server-rendered pages serve the steps:
  `GET /ui/totp/{interactionId}` and `GET /ui/totp-setup/{interactionId}`,
  with a QR code and the text secret. No MFA policy is stored yet, so a first
  set-up is reachable only once its storage exists.

- **Passkey sign-in steps, passkey-first order and the downgrade rule**
  ([#651], ADR-017 Decisions 4 and 10; `graphs/flows/core/passkey`). The
  sign-in engine gains the `webauthn_get` step (request options with user
  verification required and no `allowCredentials`, answered with
  `webauthn_response`) and the optional `webauthn_create` enrolment step.
  With no `login_hint` the first response asks for a discoverable passkey and
  offers the password and the identifier; with one, it asks for the password
  and offers the passkey, the same for every account. On the hosted pages
  `/oauth/authorize` starts a sign-in with no `login_hint` at the passkey. A login completes only
  after the account's strongest bound factor, a disabled passkey included:
  after a right password a passkey-bound account is asked for the passkey,
  and an email code never stands in for it. An assertion without the UV flag
  in its signed authenticator data is refused. `amr` is `["pop","mfa"]` for
  a passkey and `["pwd","pop","mfa"]` for a password then a passkey. After a
  password sign-in on the hosted pages the engine offers to add a passkey: a
  fresh password (5 minutes), a mailbox proved by an 8-digit code when this
  sign-in did not prove it, then a recovery set shown once; the new
  `passkey_added` mail tells the owner, and `user.signed_in` and
  `user.sign_in_failed` name the new `passkey` method. `/auth/login` and
  `/ui/login` refuse a right password of a passkey-bound account as a wrong
  one. The FiPA mapper answers `redirect_to_web` for a client that did not
  list `webauthn_get`. Two pages in the current `/ui` style run the
  ceremonies: `GET /ui/passkey/{id}` and `GET /ui/passkey-enrolment/{id}`.
  Passkey sign-in is on while `WEBAUTHN_ENABLED` is (#655).
- **`amr` and `auth_time` on the tokens of browser sign-ins** ([#662],
  ADR-017 Decision 10 as amended 2026-11-06, ADR-020 §3; RFC 9068 §2.2.1,
  RFC 8176). A browser session now stores the methods its sign-in proved
  (`["pwd"]` for a password, on the hosted pages and on `/ui/login`). The
  code copies them and the session's authentication time at mint time, the
  refresh family at the code exchange (new columns `authorization_codes.amr`,
  `refresh_tokens.auth_time` and `refresh_tokens.amr`, migration 0065), and
  the ID token and the JWT access token carry `amr` and `auth_time`, unchanged
  across every refresh of the family. The access token carried neither
  before; the ID token already carried `auth_time`. A registration or reset
  code still yields neither claim, and a session created before this release
  (or by a wallet or upstream sign-in) yields no `amr`. Discovery lists `amr`
  and `auth_time` in `claims_supported`. During a rolling upgrade, a refresh
  served by a node of the previous release drops both claims from that family
  for good.
- **Recovery codes for a lost second factor** ([#649], ADR-017 Decisions 7
  and 8, ADR-018 §3; `graphs/flows/core/recovery-code`). A set is 10 codes of
  80 bits each from the CSPRNG, shown once as `xxxx-xxxx-xxxx-xxxx` and
  stored only as salted Argon2id hashes from the password hasher in the new
  `user_recovery_codes` table (migration 0064). A code is checked against
  every unused hash of the set, padded to 10, and taken in one conditional
  write, so it works once; a new set replaces the old one, every code of
  which stops working. On the hosted pages alone, two Interaction-API-only
  steps serve them: `recovery_codes` shows a new set once and needs the
  person's confirmation that it is saved, when a sign-in proved a factor
  beyond the password of an account with no confirmed set (one nobody
  confirmed is replaced); `recovery_code` redeems a
  code in place of the factor rule 8 asks for after the password. A code
  adds no `amr` value and never `mfa`, so an MFA policy still asks for a
  second factor after it; the FiPA endpoint answers `redirect_to_web`. Wrong
  codes count on a new `recovery_code` counter of the failure ladder keyed
  on the account (`sign-in-ladder:{<realm>:user:<user>}:recovery_code`),
  shared by every transaction and end-user IP and never cleared by a right
  password: from 5 failures the bot challenge comes first and each attempt
  waits up to 15 minutes, with no known-IP exemption. At 100 in a row the
  operator is alerted (`an account's wrong recovery codes reached the
  ceiling`) and the account mailed, once a day. Three new engine mails, none
  of which a realm can switch off: `recovery_code_used` (with the codes
  left), `recovery_codes_regenerated` and `recovery_codes_failed`; two new
  events, `user.recovery_code_used` and `user.recovery_codes_failed`. The
  pages are server-rendered in the current `/ui` style,
  `GET /ui/recovery-code/{id}` and `GET /ui/recovery-codes/{id}`, posting to
  the Interaction API's answer endpoint. Regenerating a set from the
  account API (ACC-02) and redemption for a passkey-only account follow in
  their own issues.
- **A provider-neutral bot challenge in the sign-in engine** ([#643], ADR-017
  Decisions 4 and 7, ADR-019 Decision 5). The engine's rule 5 asks for the
  `captcha` step while a soft threshold holds: of the round limits (an
  end-user IP, its bucket or a client past its free failures) or of the
  failure ladder (the round's identifier past the password's or the email
  code's free failures), in addition to the delay; and before a registration
  when the realm's new `botChallenge.requiredAtSignUp` policy or the client's
  new operator-set `registration_challenge` (migration 0063, the seed
  manifest's `registration_challenge`) requires it. A right answer resumes the
  pending step; a wrong one is refused with `captcha_failed` and counted as a
  failed round on the limiters. No provider, or one that cannot be reached,
  refuses the round as unavailable: the challenge is never waved through, and
  never answered with a redirect. A transport that does not serve the step (a
  FiPA client that did not list it) still meets the delay and the 429. The
  default provider is a built-in proof of work (SHA-256, the realm's
  `botChallenge.difficulty`, 18 leading zero bits by default) whose solver the
  interaction client ships, so the strict CSP needs no exception.
  `BOT_CHALLENGE_PROVIDER=hosted` checks a hosted provider's token instead,
  with one form POST to `BOT_CHALLENGE_HOSTED_VERIFY_URL` through the egress
  client (no redirect, 5 seconds, 16 KiB), for sign-in and registration; a
  password reset still gets the proof of work. A `success: false` whose
  `error-codes` blame the secret, the site key or the provider refuses the
  round instead of counting the visitor. The reference proxy's new
  `site/bot-challenge.conf` names such a provider's script hosts per realm
  host, empty by default; they are added to `script-src` and `frame-src` of
  the interaction page alone (`/ui/interaction/*`, which a password reset,
  consent and the logout confirmation share). `captcha_token` is redacted
  from the logs and
  never audited.
- **Password reset inside the sign-in engine, and the session epoch** ([#642],
  ADR-017 Decisions 7, 8 and 10, ADR-019 Decision 3). With
  `INTERACTION_UI_ENABLED` on, the Interaction API's password step offers
  `password_reset` beside the password, to every usable client; a request with
  `prompt=login` or `max_age` offers none. The reset asks for an 8-digit
  `recovery` code with the same step and timing for every address (only an
  enabled account with a password and a verified address is mailed; an
  unclaimed account, whose address was never verified, gets no mail and no
  change until [#641] ends such an account at the first mailbox proof), then
  for any other authenticator
  the account holds (a disabled one included; email never stands in for it),
  then `new_password` with `purpose: "reset"` under the realm's password policy
  and breach list. One database transaction then replaces the password
  through the credential repository's new `updatePassword`, marks the address
  verified, clears the password's disabled mark and a pending
  `update_password`, revokes every refresh token of the user, invalidates
  every authorization code of the user not yet exchanged, advances the user's
  session epoch and records `user.password_reset` (sent over SSF as a
  CAEP credential change). After it the password's failure counter is cleared
  (a second factor's is not), every browser session of the user ends, and the
  owner gets a "password changed" mail. The session epoch is the new
  `user_session_epochs` table (migration 0062; the `web` role's database user
  is granted it), cached in Redis for up to 60 seconds: a browser session
  created before it (or within a second after it, the margin for the clocks of
  two nodes) is treated as absent and its cookie cleared, and a sign-in that
  began before it ends. A reset signs nobody in: no browser session, and the
  code and the ID token carry no `auth_time` and no `amr`. A registration or a
  reset that waits at its consent screen is no longer decided for the account
  once a later reset has advanced its epoch: it asks for a sign-in instead. Until the
  passkey and TOTP steps are served, an account that holds one cannot finish a
  reset on these pages. The flow is graphed in
  `graphs/flows/core/password-reset`.
- **Registration with `prompt=create`** ([#640], ADR-017 Decisions 3, 8 and
  10, ADR-020 §3, OpenID Connect Prompt Create 1.0). `/oauth/authorize`
  accepts `prompt=create`, which starts a registration interaction in the
  Interaction API instead of a sign-in. It is off unless both the realm and the
  client allow it: the realm's `accounts.allowSignUp` (seeded by
  `ALLOW_SIGN_UP`, off by default; the same switch upstream sign-up reads) and
  the client's new `hosted_flows` list naming `register`. `hosted_flows` is the
  nullable column `oauth_clients.hosted_flows` (migration 0061), which only
  the `db:seed-oauth-clients` manifest writes; no client can set its own. The
  request needs the `openid` scope and no `max_age`, else `invalid_request`; a
  client not allowed gets `unauthorized_client`, a realm that does not allow
  sign-up `invalid_request`; each refusal is recorded as `authorization.failed`.
  The sign-in engine registers the account in this order: the address, then an
  8-digit `verify_account` code with the same step and timing for every
  address (a new address gets the code, an existing account's address the
  code and an "account exists" notice, a disabled user's address no mail), then
  `new_password` with `purpose: "register"` under the realm's password policy
  and breach list. Only then is the account created, in one database
  transaction with its verified password credential, its verified email
  attribute and `user.registered`; an address taken meanwhile ends the
  transaction. An address an account already holds is helped to sign in to it
  instead (an unclaimed account too, until [#641]). A registration signs nobody
  in: no browser session, and the code and the ID token carry no `auth_time`,
  no `amr` and no session. Discovery's OpenID Provider metadata gains
  `prompt_values_supported` (`none`, `login`, `consent`, and `create` only while
  the realm allows sign-up and the Interaction API is on). The flow is graphed
  in `graphs/flows/core/sign-up`, and `graphs/flows/core/authorization` gains
  the `prompt=create` checks.
- **Breached-password check and the forced password update** ([#635],
  ADR-020 §3, ADR-017 Decisions 4 and 8, NIST SP 800-63B-4 §3.1.1.2). A realm
  chooses in the new policy `password.breachListSource` which breach list
  passwords are checked against: `off` (the default, seeded from
  `PASSWORD_BREACH_LIST_SOURCE`; nothing changes), `local` (the operator's
  file of SHA-1 digests at `BREACHED_PASSWORD_LIST_PATH`, at most 5,000,000,
  loaded at boot and again within 30 seconds of the file changing) or `k_anonymity` (a range lookup at
  `BREACHED_PASSWORD_RANGE_URL`, such as Have I Been Pwned's, that sends only
  the first five hex characters of the password's SHA-1, padded, through the
  egress client, with no redirect and a three-second limit). `POST
  /auth/register` refuses a listed password as `blocklisted`. In the
  Interaction API, a correct password on the list, or an account holding the
  new `update_password` required action (table `user_required_actions`,
  migration 0059: `update_password`, `setup_mfa`, `setup_passkey`,
  `complete_profile`), does not complete the sign-in: an account with a second
  factor proves it first, a password-only account an 8-digit `recovery` code
  to its address (a `verify_account` code the sign-in already took counts),
  and then the `new_password` step with `purpose: "update_required"` asks for
  a new password that meets the realm's policy and is not on the list. Until
  it is set, no code or session is issued. A check that fails (a list that
  did not load, a lookup that failed or was refused) never blocks a sign-in, a
  password update or a registration: it is counted on
  `qauth_breached_password_checks_total` with its reason and written as the
  new `user.password_breach_check_failed` event. The check at sign-in and the
  forced update run only in the Interaction API, which `/oauth/authorize`
  uses while `INTERACTION_UI_ENABLED` is on; the legacy `/auth/login` and
  `/ui/login`, the default browser path, check neither the list nor
  `update_password` until they move onto the sign-in engine ([#709]). No route
  writes `update_password` yet: the admin API ([#700]) and the account's
  "this wasn't me" ([#689]) will.
- **Back-channel logout** ([#624], OpenID Connect Back-Channel Logout 1.0,
  ADR-019 Decisions 4, 8 and 9, ADR-017 F0). A client may register
  `backchannel_logout_uri` and `backchannel_logout_session_required` through
  dynamic registration, a client metadata document or the seed manifest
  (migration 0058). The URI must be an absolute `https` URI without a fragment
  or user information, and a URI the client registers must resolve only to
  public addresses: the egress client checks it at registration, and a
  refused one is `invalid_client_metadata` (a document drops it; a check that
  failed rather than refused, such as a name that did not resolve now, keeps a
  document's URI, since delivery checks again). Only a URI an admin sets, through the seed manifest, may
  use the egress allowlist. Whenever a session ends (RP-initiated logout,
  `POST /auth/logout`, sign out everywhere, a password reset, an admin, a
  retired key, the session limit or the session lapsing), the session
  revocation writes one `user.client_session_ended` event for each client the
  session served that has a URI, in its own transaction. The `delivery` role
  turns each into a logout token for that client (`typ: logout+jwt`; `iss`,
  `aud` = `client_id`, `iat`, `exp` two minutes later, `jti` = the delivery id,
  `events`, `sub` and `sid`; no `nonce`), signed by the signer with the
  key and in the algorithm of the realm's ID tokens (§2.4: `RS256` while the realm holds an RS256
  token key, else `EdDSA`), and POSTs it as the `logout_token` form
  parameter through the egress client, which checks the address again at
  every attempt. The signer holds every event token, a Security Event Token or a logout token,
  to its kind: no
  `scope`, `client_id`, `nonce` or other grant claim, an `events` object, no
  `sub` or `exp` in a Security Event Token, and for a logout token the
  back-channel logout event alone, an `aud`, a `jti`, a `sub` or `sid`, at most two
  minutes of life and no claim but `aud`, `iat`, `exp`, `jti`, `events`, `sub` and `sid`
  (`LOGOUT_TOKEN_CLAIMS`); anything else is refused (`INVALID_CLAIMS`). A delivery
  route may now ask the delivery role to start a realm's first fan-out a set
  time back rather than at the horizon (`DeliveryRoute.backfillMs`, at most 30
  days); back-channel logout starts a day back, so a notice committed before
  the role first listed the realm is sent late rather than lost. A `5xx`, `408`, `429`, timeout or network failure is retried
  on the delivery schedule with the same `jti`; any other answer is final. A
  failed delivery never holds a sign-out back: it is recorded on the delivery
  row and counted in `qauth_events_delivery_attempts_total` under the kind
  `backchannel_logout`. A client that needs `sid` gets no token without one.
  Discovery lists `backchannel_logout_supported` and
  `backchannel_logout_session_supported`. `logout+jwt` is now a `token_signing` type
  (`JWS_TYP_BY_PURPOSE`), so a relying party verifies a logout token at `jwks_uri` with the keys
  it verifies ID tokens with; the realm JWKS and `/ssf/jwks.json` are unchanged. The signer's
  grants name token types (`SIGNER_POLICY`): the `delivery` role may have a `logout+jwt` signed
  with the token key and a `secevent+jwt` with the event key, and no access token, ID token or
  ID-JAG; the `api` role signs no logout token, and `signHybrid` none at all. ADR-019 Decision 9
  is amended for this. The `delivery` role's database user reads the client
  columns the route needs, and the role loads the egress plugin. New
  libraries `@qauth-labs/server-backchannel-logout` and
  `@qauth-labs/fastify-plugin-backchannel-logout`; conformance rows in
  `docs/conformance/requirements/oidc-backchannel-1_0.json`.

- **RP-initiated logout** ([#675], OpenID Connect RP-Initiated Logout 1.0,
  ADR-017 phase F0, ADR-019 Decision 4). `GET` and `POST /oauth/end-session`,
  listed in discovery as `end_session_endpoint`, sign the browser out at an
  app's request. An `id_token_hint` must verify with the realm's token keys and
  issuer; an expired one is accepted. `client_id` must be the hint's audience.
  `post_logout_redirect_uri` must be one of the client's new
  `post_logout_redirect_uris` (migration 0057; the seed manifest, dynamic
  registration and CIMD documents take it), matched exactly; any other value
  gets an information page and never a redirect. Only a valid hint that names
  the signed-in account and, by its `sid`, the session ends the session at
  once; any other signed-in browser gets the `logout_confirm` step (an
  interaction of purpose `logout`, or a plain form while
  `INTERACTION_UI_ENABLED` is off), so a cross-site request ends nothing. A
  client the operator did not set up is not redirected to before the browser
  has seen a QAuth page: the signed-out page links to its return URI instead.
  The session ends through the session service, which tells its listeners for
  back-channel logout (#624); no refresh token is revoked. Request logs censor
  `id_token_hint` and `logout_hint`.
  `GET /oauth/end-session/status` says whether the browser is still signed in.
  `user.signed_out` gains `sid`, and its CAEP `session-revoked` SET then names
  the user and the session as a complex subject; `interaction.created` gains the
  `logout` purpose. The `web` role now loads the JWT plugin to verify the hint.

- **A database user for each service role** ([#498], ADR-019 Decisions 8 and
  9). A declarative grants map
  (`libs/infra/db/src/lib/database-users/grants-map.ts`) says which role may
  `SELECT`, `INSERT`, `UPDATE` or `DELETE` each table, the columns `delivery`
  reads of tables it may not read whole, and the definer functions each role
  may execute. `realm_keys` is the signer's alone; every role reads
  `realm_public_keys` and only the signer writes it; no role writes
  `audit_logs`; no role user holds `TRUNCATE`, `REFERENCES` or `TRIGGER`,
  creates a table in the schema, or alters or drops one. The new `nx run infra-db:db:grants` command,
  and the migration runner after its migrations, apply it to the users named by
  `DB_USER_WEB`, `DB_USER_API`, `DB_USER_ADMIN`, `DB_USER_SIGNER` and
  `DB_USER_DELIVERY`, as the owner of the tables, in one transaction under the
  migration lock: each user's grants on the schema are revoked, the map's
  granted, and the run commits only once every user holds exactly them, through
  `PUBLIC` and every role the user can reach (`SET ROLE` included) counted. A
  superuser, the owner, a member of the owner, a missing user, and a user with
  `REPLICATION`, `CREATEROLE`, `BYPASSRLS`, a predefined role that reads past
  the grants or `CREATE` on the database are refused, as is a `SECURITY
  DEFINER` function `PUBLIC` may execute. It creates no user and sets no password,
  and with no `DB_USER_*` set (a single deployment) it does nothing. A partial
  set exits `2`; grants the runner could not apply exit `5` with the
  migrations applied. `--check` reports drift; `--print` prints the SQL.
  Migration 0055 adds `ssf_subject_events_pending`, a `SECURITY DEFINER`
  function the SSF subject sweep calls instead of reading `events`, granted to
  `api` alone.
- **Published container images** (ADR-018 §6). A release tag now publishes
  `ghcr.io/qauth-labs/qauth/auth-server` and
  `ghcr.io/qauth-labs/qauth/migration-runner` for `linux/amd64`, pushed by
  digest, signed with cosign (keyless) and carrying build-provenance and SPDX
  SBOM attestations (the new `release-images.yml` workflow). A stable `vX.Y.Z`
  is tagged `X.Y.Z` and `X.Y`, a release candidate only its own version, and
  there is no `latest` before 1.0. The publish jobs wait for a maintainer in the
  `release` environment. The developer portal is not published: its build bakes
  in the auth server's public URL. The docs site's new **Published images**
  page (`operate/images`) shows how to pin the digests and verify them.
- The auth-server image installs `tsx` at the exact version the lockfile
  resolves (4.23.15), not the floating `tsx@4`.
- **npm releases of the SDK packages** ([#596], ADR-018 §6). The SDK packages
  carry QAuth's own version: the release tag `vX.Y.Z` or `vX.Y.Z-rc.N` that
  publishes the images also packs every SDK in `libs/sdk/` at that version (the
  workspace `package.json` files stay at `0.0.0`; the job writes the version in
  before packing). Each tarball is checked: it may hold only `package.json`,
  `README.md`, `LICENSE` and compiled `dist/`, with no environment, test,
  source-map or source file, no private key or build-machine path, and complete
  metadata. It is then installed into an empty project, where every entry point
  must import and type-check. Last, it is staged on npm through trusted
  publishing, with no stored token and with provenance, in the `npm`
  environment, and goes live only when a maintainer approves it with 2FA. A
  release candidate goes to the `next` dist-tag and a release to `latest`;
  before 1.0 the versions are `0.x`. The SDK release notes are QAuth's CHANGELOG
  section, attached to the draft release as `release-notes-<version>.md`; the
  release body only links that section, so a long CHANGELOG cannot exceed the
  repository host's 125,000-character limit on a release body ([#1012]). Every
  pull request runs the same stamp, pack, check and install as a dry run, and
  builds the release body and notes. `@qauth-labs/resource-guard` is the first package: ESM with type
  declarations, an `exports` map, `engines` and its licence. `RELEASING.md` is
  the maintainer guide for both the images and the packages: release, rollback
  (deprecate, never unpublish) and the version rule.
- **`@qauth-labs/plugin-sdk`: write a plugin in its own repository** ([#1009],
  ADR-018 §4 and §6). The AuthMethod contract, the experimental item
  `plugin-api`, is now the SDK package `@qauth-labs/plugin-sdk`, which depends
  on no other QAuth package and takes Zod as a peer. Its main entry point holds
  what a plugin imports: the `AuthMethod` interface and the types it uses (the
  context, the egress client and the `CredentialProvider` half), the contract's
  constants with `AUTH_METHOD_PLUGIN_EXPORT`, its errors and its static checks.
  `/testing` holds the contract test kit, `checkAuthMethod`, and `/host` the
  engine and context the server builds around a method. The server imports the
  contract from the SDK and declares none of it again; a test fails on a
  second copy. Like `resource-guard`, the package has an `api-report.md` that
  CI checks and an Experimental README, and it is released through the npm
  release workflow: the first publish is `0.2.0-rc.1`, on the `next` dist-tag.
  The release dry run now builds and tests the SDK's example plugin
  (`libs/sdk/plugin-sdk/examples/minimal-plugin`) against the packed tarball in
  an empty project. The AuthMethod contract page gains _Write a plugin in your
  own repository_. The `testing` entry point of
  `@qauth-labs/server-federation`, a workspace package that was never
  published, is gone: import the kit from `@qauth-labs/plugin-sdk/testing`.
  The container image now deploys workspace packages with all their files
  (`deployAllFiles`), since the image runs the server from source.
- **First-party plugins in their own repositories, and a plugin added to the
  server image** ([#672], ADR-018 §3). ADR-018 §3 is amended: a first-party
  plugin is one QAuth makes and releases, and it may live in its own
  repository, on its own version line, depending only on the published plugin
  SDK. The GitHub provider plugin, `@qauth-labs/plugin-github`, is the first,
  built and released from `qauth-labs/plugin-github`; it is not on
  `FIRST_PARTY_AUTH_METHOD_PLUGINS`, so it loads only with
  `PLUGIN_API_ENABLED=true`, like any package the operator installs. The
  _Published images_ page gains _Add a plugin to the image_: a Dockerfile that
  installs a plugin package with npm from a lockfile the operator has read
  (nested, without its peer dependencies, so it takes the server's Zod) and
  copies it into `/app/node_modules` of the
  published `auth-server` image. The AuthMethod contract page names the plugin
  as its example of a plugin in its own repository. The server itself is
  unchanged: it loads such a package as it is.
- **A registry of configuration keys** ([#449], ADR-018 §5). Every environment
  key the auth server and the developer portal read has one entry in
  `libs/server/config/src/lib/registry/`: a tier (stable, advanced or
  experimental), a role (deployment or realm seed), a default and one sentence.
  The docs site's new **Configuration** page (`operate/configuration`) is
  generated from it, and tests fail when the registry, the env schemas, the page
  and `.env.example` disagree. Stable keys follow the deprecation policy, an
  advanced key may change in a minor release, and an experimental key may change
  at any time.
- **A typed, versioned schema for realm policies** ([#514], ADR-019 Decisions 7
  and 10, ADR-018 §5). The new library `libs/server/realm-policy` defines the
  realm policies once, at schema version `1-rc.0`, as groups of fields made with
  `policyField`: each field carries the environment key that seeds it, its
  default, which way is stricter (`lower-is-stricter` to `opaque`), when a change
  is a security operation (`never`, `loosening` or `any-change`) and with which
  effects, whether it is a secret or environment-bound, and one sentence with a
  docs link. Eight groups ship: `tokens`, `accounts`, `password`, `bruteForce`,
  `registration`, `mail`, `posture` and `admin`; other areas add theirs with
  `registerPolicyGroup`, and a name is taken once. `diffPolicies` marks each
  changed field as tightening, loosening or neutral with its class and effects,
  and a change it cannot place counts as a loosening. `defaultsFromEnv` gives a
  new realm's policies, and `toJsonSchema` the JSON Schema of the stored
  document, a write and the realm representation, where a secret such as the
  SMTP password appears only as `passwordSet`. The docs site's new **Realm
  policies** page (`reference/realm-policies`) is generated from the schema.
  Nothing reads the policies from the realm row yet.
- **Realm policies on the realm row** ([#516], ADR-019 Decision 10, ADR-020
  §2). Migration 0046 adds `realms.policies` (jsonb), `policy_schema_version`
  and `policies_version`, the counter the admin API will use as `ETag` and
  `If-Match`. Four existing columns stay the storage of their fields
  (`access_token_lifespan`, `refresh_token_lifespan`,
  `dynamic_registration_allowed_scopes`, `max_environment_laxity`); every other
  field is in the document, and a secret field never is. A new realm stores
  `defaultsFromEnv` of the environment the server runs with. At the first boot
  after the upgrade the default realm's boot step fills each realm that has no
  policies yet with the environment's values, keeping the environment ceiling
  and a non-empty dynamic registration allowlist its row held, with an
  `UPDATE ... WHERE policies_version = 0`, so the first node wins; from then on
  an environment key changes no existing realm. Each boot names every seed key
  still set, once: a warning ("only seeds new realms and is ignored") for a
  policy the server reads from the row (the dynamic registration allowlist, the
  environment ceiling), and an info line for any other: the server still
  applies the key, a change of it never reaches the stored value, and the
  stored value applies once that area reads the row. `/oauth/register` and the
  clients API no longer write `DEFAULT_DYNAMIC_REGISTRATION_SCOPES` into a
  realm's allowlist: they read the realm's list, or for a realm with no
  policies yet the list its fill will hold. A plain realm create or update
  writes no policy, the four column-backed fields included. The new
  `fastify.policyStore` (`@qauth-labs/fastify-plugin-realm-policy`) reads a
  realm's policies off its row with no query and updates them only with the
  expected `policies_version`; the trigger `realms_policies_version` raises the
  counter on every change of the policies, whoever writes them. The interface
  `RealmSecretStore` names where secret fields go; the store itself comes with
  [#529], and until then a write that sets a secret is refused. The flows still
  read the environment until they move to the row ([#527], [#528], [#529],
  [#534]); the token lifetimes moved with [#527], the sign-in policy with [#528],
  the mail transport and sender with [#529] and CIMD with [#534] (below). See
  **Realm policies move onto the realm row** in `operate/upgrades`.
- **Stored realm policies of an earlier schema version are upgraded** ([#908],
  ADR-018 §5). A release that changes `REALM_POLICY_SCHEMA_VERSION` ships an
  upgrade from the version before it in `REALM_POLICY_UPGRADES` (none yet: the
  version is still `1-rc.0`). The policy store reads a document stored under an
  older `policy_schema_version` through those upgrades, an update stores the
  upgraded document under the current version, and the boot writes it once
  (`realm policies of an earlier schema version upgraded to this release's`).
  A document of an older version that no upgrade reaches is refused on read
  and on write rather than read with the new schema, where a renamed field
  would read as its possibly looser seed, and the boot warns about it. A document of a
  later version, during a rolling upgrade, is still read and never written.
  `version.ts` lists what a version change ships, and a contract test fails
  while the upgrades do not lead from `1-rc.0` to the current version.
- **Each realm sends its mail through its own transport and sender** ([#529],
  ADR-019 Decisions 7, 9 and 10). The mail sender reads a realm's `mail.*`
  policies (transport, sender address and name, SMTP host, port, TLS and user)
  from its row for every mail, and builds the realm's provider on its first
  mail after a change, keyed by realm id and `policies_version`, so a change
  reaches the next mail without a restart; app.ts no longer builds one provider
  for the process. The SMTP password and the Resend API key go to the new
  realm secret store: migration 0049 adds `realm_secrets`, which holds each
  value encrypted with the realm's data-at-rest key by the signer, under a
  context that names the field, and CHECKs refuse anything but that ciphertext.
  The representation (`policyStore.representation`) shows only `passwordSet`
  and `apiKeySet`; logs, errors and the audit diff never carry a value. Only
  the mail sender is handed the store's reader of a value (no decorator holds
  one), and the signer lets the `api` role decrypt only a context under
  `realm_secrets:mail.`. The first boot that can encrypt stores
  `SMTP_PASSWORD` or `RESEND_API_KEY` in the default realm, once, and records
  an unset one, unless the realm's stored transport needs it: then a later
  boot whose environment sets it still stores it. Every other realm whose
  stored transport is the environment's and needs the secret (as the
  upgrade's fill leaves each realm) gets it too, and nothing is recorded
  there; `SMTP_PASSWORD` goes to no realm whose stored SMTP host, port or user
  is not `SMTP_HOST`, `SMTP_PORT` and `SMTP_USER`, which is logged as an error.
  Later boots ignore both keys for a realm that has the secret and warn while
  they are set. A policy update that selects `smtp` without its host, port,
  user, sender address and password, or `resend` without its sender address
  and API key, is refused (422 `unprocessable_content`, with a JSON Pointer
  per refused field in `errors`), and so is one that selects `smtp` or changes
  its host, port or TLS mode without giving the password again; an update
  that changes nothing of `mail` is not checked, and a gap the realm already
  had does not refuse an update. The boot no longer refuses an incomplete
  environment, and warns for each setting or secret the default realm's
  stored transport lacks. Until the admin API's policy update ([#517]) ships, a mail secret is
  replaced by deleting its `realm_secrets` row and restarting with the new
  value, as `operate/upgrades` describes. Mail is
  sent from `EMAIL_FROM_NAME <EMAIL_FROM_ADDRESS>`, as the realm stores them.
  Each boot also warns when a seed key of a policy the server reads from the row
  is stricter than the stored value, or, for a policy with no order, differs
  from it. See **Mail secrets move into the realm** in `operate/upgrades`.
- The auth-server logs a warning at boot for each experimental key or value that
  is set. A key or value that switches on an experimental feature warns through
  that feature instead (below).
- **The experimental-feature registry** ([#476], ADR-018 §4 and §5).
  `libs/shared/stability` lists the six experimental items of ADR-018 §4, each
  with its switch, the spec it implements and the four conditions it must meet
  to become stable, with their evidence. Only the `oid4vp-1.0-base` verifier
  profile is built today. The docs site's new **Experimental features** page
  (`reference/experimental-features`) is generated from it, and
  `node scripts/experimental-status.mjs` prints each item's conditions;
  `--check-stable` fails when an item marked stable lacks evidence.
- The auth-server logs one warning at boot for each experimental feature that is
  on, with the feature's id, "may change in a minor release" and its docs link:
  `oid4vp-1.0-base` with `WALLET_FEDERATION_ENABLED=true` and
  `OID4VP_VERIFIER_PROFILE=oid4vp-1.0-base`, which ADR-018 §4 marks
  experimental; the setting works as before. With wallet sign-in off the base
  profile does not run, and nothing is logged for it.
- **Experimental items stay out of discovery and the default API** ([#477],
  ADR-018 §5). Each registry item lists the discovery members it adds, and the
  discovery documents carry them only while the item is on: absent, never
  `null` or `false`, while it is off. Each built item names the docs page that
  documents it; a page whose frontmatter sets `experimental: true` shows an
  "Experimental" banner, and the registry's tests hold flagged pages and items
  one to one (the wallet sign-in page is the base profile's). The stable-surface
  check now fails on an experimental operation in the default-flag OpenAPI
  export, and the exporter refuses a default surface with an experimental item
  on or a maximal one that leaves a built item off. The wire suite checks that a
  default deployment answers every experimental operation as a route that does
  not exist and lists no experimental discovery member.
- **Background jobs** ([#452], ADR-019 Decision 8). The auth-server runs
  periodic jobs in-process. A Postgres advisory lock keeps each job to one node
  per interval when several nodes share the database, and a job whose node dies
  moves to another node at the next interval. Runs are logged and counted in
  `qauth_job_runs_total`, and on `SIGTERM` a running job is told to stop and
  given up to 5 seconds. The first job, `purge-expired`, runs hourly and deletes expired
  authorization codes, refresh tokens, email verification tokens and OID4VP
  request states, which nothing removed before. Refresh tokens are deleted by
  family, once the family's newest token has expired, so replaying a rotated
  token still revokes its family for as long as the family has a live token.
  The docs site's observability page (`operate/observability`) describes the
  jobs.

- **Schema**: migration 0024 adds the tables that will hold each realm's keys
  ([#461], ADR-019 Decision 9). `realm_keys` stores a key per realm and
  purpose, envelope-encrypted, with its lifecycle status (`next`, `active`,
  `retired`, `compromised`) and times; one `active` key per realm, purpose,
  scope and algorithm, and `kid` unique per realm. `realm_public_keys` holds
  the public JWK of each published key, so roles that may not read
  `realm_keys` can still serve the JWKS and verify tokens. The migration is
  additive and needs no special deploy ordering. Nothing writes the tables
  yet: keys are still read from the environment until key generation lands.

- **Envelope encryption for stored keys** ([#462], ADR-019 Decision 9). The new
  library `@qauth-labs/server-keys` encrypts key material with a random 256-bit
  data key and AES-256-GCM, and wraps the data key with a key-encryption key
  (KEK) from a pluggable provider. The associated data binds each key to its
  realm, purpose, scope, `kid` and algorithm, so a row copied to another realm
  does not open. The default provider (`KEK_PROVIDER=local`) reads `KEK` or
  `KEK_PATH`, plus `KEK_PREVIOUS` or `KEK_PREVIOUS_PATH` during a KEK rotation;
  any other `KEK_PROVIDER` value loads the optional package
  `@qauth-labs/keys-<name>`. The five keys are stable and listed on the
  configuration page. The auth-server reads them since the key import at
  first boot ([#485]): `NODE_ENV=production` refuses an unset KEK and the
  published development KEK.

- **The KEK in AWS KMS** ([#577], ADR-019 Decision 9). The optional package
  `@qauth-labs/keys-aws-kms` keeps the key-encryption key in a symmetric KMS key:
  `KEK_PROVIDER=aws-kms` makes the signer load it, and it sends data keys to KMS
  `Encrypt` and `Decrypt` with the key's associated data as the encryption
  context. Signing stays local. `KEK_AWS_KMS_KEY_ID` names the key by its ARN
  (an alias is refused) and `KEK_AWS_REGION`, optional, must match it;
  credentials come only from the default AWS credential chain. `kekRef` is the
  key ARN and the key material that wrapped the row. KMS calls are tried at most
  3 times, with connection and request timeouts. The auth server does not depend
  on the package and its image does not carry it; the package's README shows
  how to add it, the IAM policy of the signer role (`kms:Encrypt` and
  `kms:Decrypt` on the one key) and what happens during a KMS outage.

- **The KEK in a Vault Transit key** ([#578], ADR-019 Decision 9). The optional
  package `@qauth-labs/keys-vault` keeps the key-encryption key in a key of
  Vault's Transit engine: `KEK_PROVIDER=vault` makes the signer load it, and it
  sends data keys to Transit `encrypt` and `decrypt` with the key's associated
  data as the Transit `context`. Signing stays local. The key must be created
  with `derived=true`: Vault ignores the context of a key that is not derived,
  so the provider refuses one, and every wrap is decrypted once more under
  another context, which Vault must refuse. A key that can leave Vault
  (`exportable`, `allow_plaintext_backup`) or be deleted (`deletion_allowed`)
  wraps nothing; unwraps go on with a warning, so the stored keys still open
  until the KEK rotation ([#545]) moves them. An imported key only warns.
  `kekRef` is the key's path and version (`vault:transit/keys/qauth-kek#v2`), so
  a Transit key rotation shows which rows to re-wrap. Settings are
  `KEK_VAULT_ADDR` (`https` only), `KEK_VAULT_TRANSIT_KEY`, and optionally
  `KEK_VAULT_TRANSIT_MOUNT`, `KEK_VAULT_NAMESPACE` and `KEK_VAULT_CA_CERT_FILE`;
  the provider logs in with a token from `KEK_VAULT_TOKEN_FILE` or with AppRole
  (`KEK_VAULT_ROLE_ID`, `KEK_VAULT_SECRET_ID_FILE`), never with a credential in
  a variable. It renews the token before it expires and logs in again at its
  maximum TTL, revoking the AppRole token it replaces; a revoked token fails
  with `KEK_ACCESS_DENIED`, and a root token or one that never expires logs a
  warning. `KekProvider` gains an optional `close()`, which the signer calls
  when the server closes, so the token stops renewing. The auth server does not
  depend on the package and its image does not carry it; the package's README
  gives the exact Vault policy of the signer role, which the new container suite
  applies to a Vault dev server.

- **Schema**: migration 0025 gives every realm an issuer and hosts ([#470],
  ADR-019 Decision 1). `realms.issuer` holds the realm's issuer: an `https`
  URL (plain `http` only on `localhost`, for development) without a trailing
  slash, white space, control characters or a backslash. `realms.is_operator`
  marks the operator realm, of which
  there is at most one. The new `realm_hosts` table maps each host to one
  realm, as its `primary` host (at most one per realm, never an IP literal) or
  as an `endpoint` host for server-to-server callers. A host exists once across
  every realm and both kinds. Once set, a realm's issuer and primary host
  cannot change: database triggers refuse it. Existing realms keep a NULL
  issuer and no host, and nothing reads the new columns yet, so the upgrade
  changes no behaviour. A later boot step fills the default realm from
  `JWT_ISSUER`. `normaliseRealmHost()` in `@qauth-labs/shared-validation` is the
  one function that writes the stored form: lower case, punycode, no port and
  no trailing dot. It refuses wildcards, white space, empty labels and hosts
  over 253 characters.

- **The default realm at boot** ([#484], ADR-019 Decision 1). Before it
  listens, the auth-server finds the realm named by `DEFAULT_REALM_NAME`, or
  creates it, and gives it `JWT_ISSUER` as its issuer, without a trailing
  slash, and that URL's host as its primary host. When no realm is the
  operator realm, the default realm becomes it: in simple mode the two are one.
  The new stable key `DEFAULT_REALM_ENDPOINT_HOSTS` (comma-separated) adds
  endpoint hosts to the default realm, such as `auth-server`, the name the
  developer portal reaches the server by; the Compose file sets it, and a boot
  never removes one. The step runs in one transaction under a Postgres advisory
  lock, so nodes that start together create one realm. It logs one line,
  `default realm ready`, with the realm, issuer, host and operator flag, and
  warns when `JWT_ISSUER` has a trailing slash or a path. A realm from before
  migration 0025 keeps its id, users and clients, and only gains its issuer
  and host, so existing clients and tokens keep working. `DEFAULT_REALM_NAME`
  and `JWT_ISSUER` are documented as the single-realm settings.

- **Routing by host** ([#486], ADR-019 Decisions 1 and 8). A request belongs
  to the realm whose primary host or endpoint host equals the request's host,
  compared case-insensitively without the port or a trailing dot.
  `X-Forwarded-Host` counts only from a `TRUST_PROXY` address. Hosts are cached
  in-process: a known host for 30 seconds, an unknown one for at most 5. Every
  route names the hosts it answers on in `config.surface`: `browser` routes,
  which use the session cookie (`/oauth/authorize`, `/ui/*`, `/consents`,
  `/auth/link/wallet`), answer only on the realm host; `api` and `meta` routes
  also answer on its endpoint hosts; `/health` answers on any host. The server
  refuses to start when a route has no class. Every handler takes its realm
  from the one resolved ([#487], below). Problem documents gain the code
  `misdirected_request` (421).

- **Schema**: migration 0026 adds the admin audit log ([#448], ADR-019
  Decision 7, ADR-020 §3). `admin_audit_log` keeps one hash chain per target
  realm: each row carries a `seq` without a gap, the previous row's hash and
  its own, SHA-256 over the chain format's id (`qauth-admin-audit-chain/1-rc.0`,
  a release candidate until 1.0.0), that hash and the RFC 8785 canonical JSON
  of the row.
  A row records the actor and its kind (human admin, service account,
  break-glass operator or host operator), the full act chain when the actor
  acted for a user, the operation id, class, effects and outcome, the diff with
  every secret field masked, the approvals, the request digest and the trace
  id. Database triggers refuse `UPDATE` and `TRUNCATE`, accept a row only as
  the next link of its realm's chain, and accept a `DELETE` only of rows a
  checkpoint covers. `admin_audit_log_prune()` writes that checkpoint in
  `admin_audit_log_checkpoints` and removes a realm's oldest rows; a trigger
  accepts the checkpoint only over an unbroken run of rows at least 90 days
  old, so the chain still verifies after a prune. A table owner can still
  disable a trigger: the per-role database users (#498) are what keep the
  application from being one. In
  `@qauth-labs/infra-db`, `createAdminAuditLogRepository` gives
  `appendAdminAudit(tx, entry)`, which writes in the caller's transaction and
  calls an outbox hook after the insert, and `verifyAdminAuditChain(realmId)`,
  which reports the first row that breaks the chain;
  `adminAuditLogWriterGrantStatements()` grants a writing role `INSERT` and
  `SELECT` only. The migration is additive. Nothing writes the log yet: the
  admin API that will is still to come.

- **The event contract** ([#456], ADR-018 §3 and §5, ADR-019 Decision 8). The
  new library `@qauth-labs/shared-events` defines what an event looks like on
  every delivery route: an envelope (`id`, a UUIDv7 kept across routes and
  retries; `type`; `time`; `realm`; `category`, `user` or `admin`; `actor`;
  `subject`; `client`; `request`; `data`) and a registry of 33 event types,
  named `urn:qauth:event:<name>:v<N>-rc.<M>`, each with a payload schema, a category,
  a severity and the release it appeared in. Every event the auth server
  records today has a type, and a map from each earlier audit or log name to
  its type is ready for copying the audit log into the event store. A scanner
  enforces the payload rules of ADR-011 §8 and ADR-017 §11 (ids, not names or
  addresses; never a password, code, OTP, token, key, assertion or link;
  hidden identifiers as keyed HMACs) over every type's schema and every event.
  The JSON Schema of the envelope and of each type is published under
  `/schemas/events/` on the docs site and registered with the stable-surface
  guard, so a new required member fails CI and a new optional one passes. The
  docs site's new **Events** page (`reference/events`) is generated from the
  registry. Every type is a release candidate (`:v1-rc.0`) until QAuth 1.0.0:
  nothing about it is promised before then, a breaking change raises the
  candidate number, and 1.0.0 drops the suffix. The auth server emits them
  since [#458].

- **Admin events, with a diff, masked secrets and a hash chain** ([#459],
  ADR-020 §3, ADR-019 Decision 7). Every admin change becomes one
  `admin.change_applied` event, written in the transaction of the change with
  `emitAdminEvent(tx, { realm, actor, operation, target, before, after,
  approvals })` from `@qauth-labs/infra-db`. Its `data.diff` lists the changed
  fields by JSON Pointer with their old and new values: unchanged fields are
  left out, nested objects are diffed, arrays are shown whole. A secret field
  holds `***`: one the operation marks, and one whose name looks like a secret
  by the payload rules, marked or not; a token- or key-shaped string is masked
  wherever it sits. `data.approvals` records both approvals of a two-admin
  operation, each with the approver, the passkey credential id and who created
  the approver's account. A command-line tool on the server host records itself
  as an `operator_cli` actor with the operating-system user
  (`operatorCliActor()`). Admin events are always on: no environment key and no
  realm setting turns them off. Tests fail when a configuration key, a realm
  column or a member a realm `jsonb` column's type declares names events
  (`event`, `audit`, `log`, `sink`, …) and no allow list says why it turns
  nothing off ([#827]). Today only the client suspension
  command writes admin events, which now join the chain; the admin API that
  will write the rest is still to come.
- **Schema**: migration 0032 chains admin events by hash ([#459]). Each admin
  row of `events` stores the hash of the realm's admin row before it as
  `prev_hash`, and its own `hash` is SHA-256 over the chain format's id
  (`qauth-event-chain/1-rc.0`, a release candidate until 1.0.0), `prev_hash`,
  the row's `xid` and the RFC 8785 canonical JSON of the envelope. The `xid` decides where a
  reader of the stream finds the row, so a row whose `xid` was moved breaks the
  chain at that row ([#827]). Every event of an admin type joins the chain,
  through `emit` as well: the writer takes the realm's advisory transaction
  lock, and a unique index on `(realm_id, prev_hash)` keeps a writer that raced
  it from forking the chain. `verifyChain(realmId, from?)` and the command
  `pnpm --dir libs/infra/db exec tsx src/scripts/verify-event-chain.ts --realm=<name>`
  report the first
  admin event that was changed, or that follows one that was removed; run from
  a head kept outside the database, they also fail when the chain was cut back
  to before that head. The command exits 0 when the chain verifies, 1 when it
  breaks, 2 on a usage error and 3 when the check could not run, such as with
  the database unreachable or the realm not found, so a monitor does not report
  an outage as a tampered chain ([#827]). The Nx target
  `infra-db:events:verify-chain` runs the same script, but Nx reports every
  failure as 1. A second trigger refuses an admin row that does not
  follow the realm's head or sets its own `seq`. A trigger now refuses every
  `UPDATE` on `events`, the owner's included. The migration adds two nullable columns, checks, two indexes and the
  trigger; the check that admin rows are chained is added `NOT VALID`, so rows
  written before it, such as the client suspensions migration 0031 copied from
  `audit_logs`, are left as they are.
- **Schema**: migration 0033 adds the two functions a role that writes events
  reads through ([#827], ADR-019 Decision 7): `events_admin_chain_head`, the
  realm's chain head, and `events_own_row`, the row the calling transaction
  wrote. Both are `SECURITY DEFINER`, with `EXECUTE` revoked from `PUBLIC`.
  `eventsWriterGrantStatements()` grants a writing role `INSERT` on `events`
  and `EXECUTE` on the two functions, and no `SELECT`, so a writer cannot read
  any realm's events, request IPs, user agents or admin diffs. `verifyChain`
  and `events:verify-chain` run as a role that may read the table. A new
  trigger, `events_xid_from_transaction`, refuses any row whose `xid` is not
  the inserting transaction's, so a role that can insert cannot put a row,
  admin or user, behind a reader's position. The migration only creates the
  functions and the trigger.

- **Passkeys: the WebAuthn provider and the relying-party settings** ([#467],
  ADR-017 Decision 14, ADR-019 Decision 2). One WebAuthn `CredentialProvider`
  (`provider_type` `webauthn`, `external_sub` the credential id) that sign-in,
  account pages, admin sign-in and the Authority Tree approval will share. It
  asks for `attestation: "none"`, accepts EdDSA, ES256 and RS256 keys only,
  binds each single-use challenge to its transaction, requires user
  verification for sign-in and flags a sign counter that goes backwards.
  SimpleWebAuthn (`@simplewebauthn/server` 14.0.3, pinned) does the
  cryptography behind a `WebAuthnVerifier` port. Nothing calls the provider
  yet: `WEBAUTHN_ENABLED` is refused at boot until phase F2b is complete.
  `WEBAUTHN_RP_ID` defaults to the realm host; a parent domain needs
  `WEBAUTHN_RP_ID_ALLOW_PARENT_DOMAIN=true` and logs a warning at every boot.
  Migration 0028 adds `realms.webauthn_rp_id`, the RP ID lock that the realm's
  first passkey enrolment writes and a trigger keeps permanent, and the
  operator-set `oauth_clients.webauthn_allowed_origins` for native apps, set in
  the `db:seed-oauth-clients` manifest. While the RP ID is the realm host, the
  server serves `/.well-known/apple-app-site-association` and
  `/.well-known/assetlinks.json` from `WEBAUTHN_APPLE_APP_IDS` and
  `WEBAUTHN_ANDROID_APPS`; with neither set, both paths stay 404.

- **The DPoP proof verifier** ([#479], RFC 9449, ADR-014 §3, ADR-017
  Decision 14). `@qauth-labs/server-dpop` is the one verifier the token
  endpoint, the admin API, `resource-guard` and the Authority Tree will share.
  It takes the `DPoP` header, the request's method and URL and, at a protected
  resource, the access token, and returns the RFC 7638 thumbprint of the
  proof's key. It checks `typ` (`dpop+jwt`), an asymmetric algorithm from an
  allowlist (`none` and MAC algorithms can never be on it), a public `jwk`
  with no private members, `htm` and `htu` against the values the caller
  passes, `iat` within 60 seconds, `jti`, `ath` and, when an endpoint asks for
  one, a server-provided nonce, answered with `use_dpop_nonce`. Used proofs are
  recorded in Redis for the window; with Redis unavailable, every proof is
  refused. The library imports only `jose` and `node:crypto`, no Fastify.
  `test-vectors/dpop/proof.json` holds the RFC's example proofs and one
  failing case per check. The token endpoint uses it from [#480] (below).

- **DPoP-bound tokens at the token endpoint** ([#480], RFC 9449, ADR-014 §3,
  ADR-017 phase F3), behind `DPOP_ENABLED` (default `false`), which is no longer
  refused at boot. With it on:
  - a token request's `DPoP` proof binds the access token to the proof's key,
    whatever the grant: `cnf.jkt` in the token and `token_type: DPoP` in the
    response. The ID-JAG mint stays `N_A` and unbound.
  - `oauth_clients.dpop_bound_access_tokens` (migration 0037) marks a client
    that always uses DPoP; its token requests without a proof are refused with
    `invalid_dpop_proof`. Only the `db:seed-oauth-clients` manifest sets it
    (`dpop_bound_access_tokens: true`); dynamic registration, CIMD documents
    and `/api/clients` cannot.
  - `/oauth/authorize` reads `dpop_jkt` and binds the code to that key
    (`authorization_codes.dpop_jkt`), so the code is redeemed only with a proof
    under it. A public client's refresh token is bound to its proof key
    (`refresh_tokens.cnf_jkt`) and every rotation keeps it; a confidential
    client's refresh token is not bound. While DPoP is off, a code or refresh
    token bound while it was on is refused with `invalid_grant`.
  - discovery publishes `dpop_signing_alg_values_supported`, and introspection
    returns `cnf` and `token_type: DPoP` for a bound token.
  - `userinfo` and the other routes that read an access token from the
    `Authorization` header accept the `DPoP` scheme with a valid proof (its
    `ath` the token's hash), and refuse a DPoP-bound token sent as Bearer
    (`401 invalid_token`). A refusal under the `DPoP` scheme carries a
    `WWW-Authenticate: DPoP` challenge with the accepted algorithms.
  - a token exchange whose subject token is DPoP-bound needs a proof under
    that token's key; another key is refused with `invalid_request` until
    ADR-014's spawn assertion exists.
  - a proof's `htu` must name the endpoint URL discovery publishes, built from
    `JWT_ISSUER` (path included), also for a request sent to one of
    `DEFAULT_REALM_ENDPOINT_HOSTS`.

  With `DPOP_ENABLED` off the server reads no `DPoP` header and no `dpop_jkt`,
  and every response is the one it gave before. `token_type` in the token and
  introspection responses gains the value `DPoP`, an approved break of the
  stable surface.

- **The signer** ([#464], ADR-019 Decision 9). `@qauth-labs/server-keys`
  defines `Signer`, the one interface for private-key work: sign a JWS, sign
  the ADR-005 hybrid carrier, hand out the cookie HMAC secrets, encrypt and
  decrypt with the `data_at_rest` key, and read the verification keys and the
  realm JWKS. The signer sets `iss` from the realm row and `kid` from the
  active key; a caller can set neither. `token_signing` signs only `at+jwt`
  and ID tokens (and, since [#624], logout tokens), `event_signing` only
  `secevent+jwt`. Every
  call names its caller's role (`local`, `web`, `api`, `delivery`, `admin`),
  and a policy table decides what each may call. No operation returns a
  private key. The in-process signer unwraps a key on first use, keeps it in a
  bounded cache and re-reads the active key once a minute, so a signature with
  a warm cache runs no database query; a missing key is an error, never a new
  key. The KEK provider, envelope encryption and key factory move to the
  `@qauth-labs/server-keys/custody` entry point, and a lint rule lets only the
  signer's wiring, the new `@qauth-labs/fastify-plugin-signer`, import it.
  The auth-server registers the plugin for the key import at first boot
  ([#485]), and every token is signed through it ([#491]).

- **Schema**: migration 0029 adds the event store ([#457], ADR-019 Decision 8,
  ADR-018 §3). One append-only table, `events`, is both the transactional
  outbox and the event log: an event is written in the transaction of the
  change it records, so both commit or neither does. Each row is one envelope,
  plus `seq` and `xid`, the writing transaction's id. In
  `@qauth-labs/infra-db`, `createEventsRepository` gives `emit(tx, event)`,
  which checks the event against the registry and throws on an unknown type or
  a bad payload, and `emitInOwnTransaction(event)` for a caller without a
  transaction. `readAfter(realmId, position, limit, filters)` returns a realm's
  events in `(xid, seq)` order and only those older than every open
  transaction, so a reader never skips one that commits late; its position is
  opaque and names its realm. Every read needs a realm id. The price is lag: a
  transaction left open holds back the events written after it began, and the
  new gauge `qauth_events_oldest_unread_age_seconds` on `/metrics` shows how
  long. The migration only creates the table and its indexes. The auth server
  writes its events there since [#458]; the delivery role and the event API
  come next.

- **Events as OpenTelemetry logs** ([#541], ADR-018 §3, ADR-019 Decision 8).
  With `OTEL_EVENTS_ENABLED=true` (off by default) the auth-server sends every
  event it commits to the operator's OpenTelemetry collector as a log record,
  over OTLP/HTTP with JSON encoding. The body is the event envelope as JSON;
  the attributes are `qauth.event.id`, `qauth.event.type`,
  `qauth.event.category`, `qauth.realm`, `qauth.subject.id` and
  `qauth.client.id`; the severity is the type's; an active span gives the
  trace and span id, else the record carries `qauth.request.id`. The export
  reads `OTEL_SERVICE_NAME` and the standard `OTEL_EXPORTER_OTLP_*` variables
  of the logs signal, all advanced keys; with the export on, the boot refuses
  a malformed one.
  It is telemetry with no delivery guarantee: records wait in a bounded queue
  that drops the oldest when full, export never fails or slows a request, and
  `qauth_events_telemetry_dropped_total` on `/metrics` counts what was not
  sent. In `@qauth-labs/infra-db`, `createEventsRepository` takes a
  `telemetry` sink that it hands each event to once its transaction commits.
  The observability page (`operate/observability`) describes the setup.

- **The delivery role** ([#460], ADR-019 Decisions 8 and 9). A worker in the
  auth-server hands every event to every matching destination of a delivery
  route, at least once and with the event's own id, so a receiver drops a
  duplicate. Migration 0035 adds `event_deliveries`, one row per destination
  and event, and `event_delivery_positions`, the fan-out's place in each
  realm's stream per route kind; it is expand-only. The fan-out reads each
  realm below the event store's horizon, one node at a time per realm and
  kind, and a node moves only the positions of the kinds it has routes for. Workers claim
  deliveries with `FOR UPDATE SKIP LOCKED` and a lease, so a worker that dies
  leaves its deliveries to another, and a destination that is down holds only
  its own deliveries. A failed attempt is retried with exponential backoff and
  jitter (`EVENT_DELIVERY_MAX_ATTEMPTS`, `EVENT_DELIVERY_RETRY_INITIAL_DELAY`
  and `EVENT_DELIVERY_RETRY_MAX_DELAY`, advanced keys); after the last one the
  delivery ends `failed` and stays queryable. At shutdown the role waits for
  its attempts in flight and releases the rest. `/metrics` gains
  `qauth_events_pending`, `qauth_events_delivery_lag_seconds` and
  `qauth_events_delivery_attempts_total`. The new
  `@qauth-labs/server-event-delivery` exports `startDeliveryRole()` and the
  route interface the webhook and SSF routes will plug into; it holds no key,
  signs only through a signer handle, and an Nx constraint and a test keep
  every import path to key-loading code out of it.
  `@qauth-labs/fastify-plugin-event-delivery` runs it in-process, and
  `minOffered(realmId)` on the queue gives the retention job the lowest
  position every destination has finished. No route exists yet, so the role
  does nothing but publish its metrics.

- **Event retention** ([#536], ADR-020 §3, ADR-019 Decisions 7 and 10). A realm
  keeps its user events 90 days and its admin events 365 days by default, and
  never fewer than 90 days of admin events. Migration 0036 stores both on the
  realm row (`user_event_retention_days`, `admin_event_retention_days`, whose
  CHECKs refuse an admin value below 90), and `EVENT_RETENTION_USER_DAYS` and
  `EVENT_RETENTION_ADMIN_DAYS` seed a new realm's values; the realms
  repository applies the seeds to every realm it creates and refuses a value
  out of range. The hourly `event-retention` job, on one node at a time,
  deletes a realm's oldest events once they are past its retention and every
  enabled delivery destination has finished them, `delivered` or `failed`; a
  disabled destination holds nothing back, and cursor readers are not waited
  for. It deletes in batches of 1000, each a short transaction under the
  realm's lock, so two instances never delete a row twice. Admin events go
  only from the start of the chain, never its head, and only while each
  verifies; the last one deleted becomes the realm's anchor in the new
  `event_chain_anchors` table, written in the same transaction, and
  `verifyChain` starts from it. A changed old admin event stops the deletions
  and is logged. `eventRetentionGrantStatements()` gives the retention role
  the only `DELETE` on `events`. `/metrics` gains
  `qauth_events_retention_deleted_total` and
  `qauth_events_oldest_age_seconds`. The migration replaces
  `idx_events_time`, which no query used, with
  `idx_events_retention (realm_id, category, time)`.

- **The migration runner is one small command** ([#474], ADR-018 §5). The
  `migration-runner` image holds Node and one bundled program,
  `dist/apps/migration-runner/main.js`, with the migrations beside it, and no
  pnpm, nx or drizzle-kit; its build fails when one of them reaches the image.
  The runner takes a Postgres advisory lock, so a second runner waits and then
  finds nothing to do. It applies the pending migrations in one transaction,
  logs each with its duration, and exits `0` when the database is current, `1`
  when a migration failed (the run rolled back), `2` on a usage error and `3`
  when it could not start. `--check` lists the pending migrations, exits `1`
  when there are any and changes nothing. From a checkout,
  `pnpm nx run migration-runner:migrate` builds and runs it. The upgrade guide
  (`operate/upgrades`) now opens with the procedure every upgrade follows: back
  up, run the runner, start the new version.
- The auth server checks the schema at boot ([#474]). When the database lacks
  migrations of its release, it waits up to `DB_MIGRATION_WAIT_MS` (an advanced
  key, 60 seconds by default) for the migration runner, then exits non-zero
  naming them. A database ahead of the release is accepted with a warning, as
  during a rolling upgrade. `@qauth-labs/infra-db/migrations` exports the
  runner's work and the check; `awaitDatabaseMigrations` in
  `@qauth-labs/fastify-plugin-db` runs the check.

- **Schema**: migration 0030 reshapes the `sessions` table for browser sessions
  ([#468], ADR-019 Decision 3). Each row is one account signed in on one
  browser, tied to a realm and a user, and its `id` is the session's `sid`. It
  holds the authentication (`auth_time`, `amr`, `assurance_level`), the address
  and user agent at creation, `last_seen_at`, the absolute end `expires_at`, and
  `revoked_at` with a `revoked_reason`. A new unique constraint on
  `users (id, realm_id)` backs a composite foreign key, so the database refuses
  a session whose realm is not its user's. The token-session columns
  (`access_token_hash`, `refresh_token_hash`, `oauth_client_id`, `revoked`) and
  `last_activity_at` are dropped. The new `session_clients` table records which
  clients a session served, for back-channel logout. No code ever wrote the
  old table, so the migration deletes any rows it holds. Nothing reads or
  writes the new tables yet: browser sessions stay in Redis until the session
  service lands.

- **The browser session service** ([#469], ADR-019 Decision 3). The new
  `@qauth-labs/server-sessions` library creates, reads and ends browser
  sessions with Postgres as the source of truth and Redis as a cache in front
  of it, and the auth-server decorates it as `fastify.sessionService` through
  `@qauth-labs/fastify-plugin-sessions`. A read takes the realm and the `sid`,
  goes to Redis first and to Postgres on a miss, and fills Redis for at most
  60 seconds, never past the session's end. A session is absent when it is
  revoked, past its absolute end, past the realm's idle limit or in another
  realm. The realm row's `sso_max_lifespan` and `sso_idle_timeout` set the
  absolute end and the idle limit; without them the end is
  `SESSION_COOKIE_TTL` after creation and there is no idle limit.
  `last_seen_at` is written at most once per `SESSION_LAST_SEEN_INTERVAL`
  (a new advanced key, 60 seconds by default) per session, by one conditional
  `UPDATE`, so several nodes do not all write. A revocation updates Postgres
  and leaves a short Redis tombstone. With Redis down, reads go to Postgres,
  and a Redis call is given up after 250 ms; with Postgres down, a session
  that needs it is absent and a cached one is served no longer than the cache
  time. `/metrics` counts cache reads,
  Postgres reads and last-seen writes. The browser sign-in and the session
  lookup use it ([#488], under Changed).

- **`sid` on ID tokens** ([#549], ADR-019 Decisions 3 and 4). The ID token from
  the authorization code exchange carries `sid`, the id of the browser session
  the user signed in with (the `sessions` row the session cookie names), which
  back-channel logout will name. Migration 0042 adds
  `authorization_codes.session_id`, a nullable foreign key to `sessions` that a
  deleted session sets to null. `/oauth/authorize` and the consent form store
  it on the code and, in the same transaction, record the client in
  `session_clients`, once per session and client. The sessions repository
  looks that registry up by session, by user and by client, listing live
  sessions only, and revoking a session deletes its rows and returns them: the
  clients back-channel logout will notify. Revoking a session also spends the
  codes minted under it that are not yet redeemed, so none becomes an ID token
  naming an ended session; a later redemption of one is refused as a replay
  that revokes nothing. A code from the legacy Bearer path
  of `/oauth/authorize` has no browser session and its ID token no `sid`, nor
  does a code minted before the upgrade. Access tokens, introspection
  responses, refresh tokens and discovery are unchanged. If a sign-out commits
  while a code is being minted for that session, no code is issued: the
  browser goes back to the sign-in page, or the client gets `login_required`
  under `prompt=none`, and a consent the user asked to remember is not stored
  either: it commits with the code. The migration is additive; it locks
  `sessions` and then `authorization_codes` while it runs (see the upgrade
  guide). During a rolling upgrade the previous release writes codes without a
  session, and a session it revokes keeps its registry rows, which the lookups
  skip, and its codes unspent.
- **Session lists and revocations** ([#550], ADR-019 Decisions 3 and 4). The
  session service lists a user's sessions, or the sessions that served a
  client, newest first in cursor pages (a cursor of another list is refused),
  each with its clients, address, user agent, `auth_time`, `last_seen_at` and
  state (`live`, `idle`, `expired` or `revoked`). It ends one session (a second
  call reports `already_ended` and changes nothing), a user's sessions (but one,
  or only those created before a time, for a password reset), and a realm's
  sessions in batches of 500 (at most 5,000), each its own transaction, for key
  retirement and bulk revocation. Every revocation names its actor, returns the
  ended sessions with the clients they served, writes a cache tombstone for
  each, and then tells the listeners registered with `onSessionsEnded`, once
  per session, in the process that revoked, after the commit. Refresh-token
  families and Authority Trees are left to the caller. Two jobs run on the
  `web` role. `session-expiry`, every five minutes, marks the sessions past
  their absolute end or their realm's idle limit (which no read accepted
  already) as `expired` or `idle`, so their clients leave the registry and the
  listeners hear of the end. `session-purge`, hourly, deletes the rows that
  ended or expired more than `SESSION_RETENTION_DAYS` ago (a new advanced key,
  30 by default). The single revocation now passes on the clients the session
  served, which the store adapter used to drop. No HTTP route is added; the
  account and admin APIs will add them.

- **The key variables move into the key store at first boot** ([#485],
  ADR-019 Decision 9 and its answer on existing issuers). At every boot, after
  the default realm's step and under an advisory lock on the realm, the
  auth-server imports each key variable the default realm's encrypted key
  store lacks: `JWT_PRIVATE_KEY` as the Ed25519 signing key,
  `JWT_RS256_PRIVATE_KEY` as the RS256 one, `JWT_MLDSA_PRIVATE_KEY` (with
  `HYBRID_SIGNING_ENABLED`) as the ML-DSA-65 key of a hybrid pair with the
  Ed25519 key, and `SESSION_COOKIE_SECRET`, when set, as the first cookie HMAC
  key. Each `_PATH` variable counts as its variable. The public keys are
  derived from the private keys with `node:crypto`. A key keeps
  `JWT_RS256_KID` or `JWT_MLDSA_KID` as its `kid` when set, and otherwise gets
  the RFC 7638 thumbprint, so the Ed25519 key has a `kid` for the first time.
  The step then creates every standard key the realm still lacks
  (`event_signing` and `data_at_rest`, and `token_signing` and `cookie_hmac`
  on a fresh deployment), and gives a fresh realm an RS256 signing key too.
  It is one transaction, so two nodes that boot together import once. A
  warning at every boot names each key variable that is still set ([#491] and
  [#493] change what it says, above). Until rotation through the store ships, a signing
  variable that holds a new key replaces the stored key of its algorithm, as
  changing the variable replaced the key before: the stored key is retired and
  leaves the JWKS at once, and the boot warns with both `kid`s.
- `/.well-known/jwks.json` publishes the Ed25519 key with its thumbprint `kid`,
  and the RS256 key with its thumbprint `kid` when `JWT_RS256_KID` is unset;
  ID tokens signed with RS256 carry that `kid` ([#485]). The keys themselves
  are unchanged, and tokens signed before the upgrade still verify.
- **`auth-server:keys:create`** ([#485]): an operator command that creates one
  key for a realm, purpose and algorithm on a host that holds the KEK, for
  example an RS256 signing key for an OpenID Foundation run:
  `pnpm nx run auth-server:keys:create --purpose=token_signing --algorithm=RS256`.
  In the auth-server image it runs as `tsx src/keys-create.ts` with the same
  arguments.

- **A guard on the stable surface** ([#451], ADR-018 §5). Every OpenAPI
  operation carries `x-qauth-stability` (`stable` or `experimental`; the wallet
  federation routes, which a switch registers, are experimental). The OpenAPI
  export now runs twice: under default flags to `stable-surface/openapi.json`,
  the stable surface, and with every route switch on to the docs site's
  `openapi.json`. A new CI job regenerates every surface registered in
  `stable-surface/surfaces.json` and fails on drift from the committed file, on
  a missing stability tag, and on a break since the latest release tag that
  `stable-surface/approved-breaks.json` does not approve. Release candidates
  are skipped: a break an rc shipped is measured against the last release until
  its own release is tagged. See `stable-surface/README.md`.

- **Shared test vectors** ([#478], ADR-018 §6 and §7). The new top-level
  `test-vectors/` directory holds language-neutral vector files that every SDK
  and the server's own tests run. A file is plain JSON in the `qauth-vectors/1-rc.0`
  format (`test-vectors/schema/vector-file.schema.json`): a header and cases of
  `input` and `expected`. The first files cover PKCE S256 (with RFC 7636
  Appendix B), Standard Webhooks signatures (generated with the reference
  library `standardwebhooks@1.1.1`), `act` chain flattening with the delegation
  depth cap of 4, and the access token checks of RFC 9068 §4.
  `pnpm exec nx run test-vectors:validate` checks every file and runs in CI's
  unit job; `@qauth-labs/shared-test-vectors` gives TypeScript tests
  `loadVectors(id)`. Vectors are append-only: changing a case's expected result
  takes a new case id. See `test-vectors/README.md`.

- **An upgrade test in CI** ([#475], ADR-018 §5). The new `upgrade-test` job
  runs once per release tag in `upgrade-baselines.json` (today `v0.1.3`;
  releases only, never release candidates).
  It builds that release's images from its tag, writes data through its HTTP
  API (verified users, clients, a code flow with PKCE and its tokens, a
  consent, an API key), runs this commit's migration runner and nothing else,
  and checks on the new server that the old access token still introspects,
  the refresh token rotates, the consent and the API key are still there and
  the passwords still sign in; the wire suite runs on the upgraded database
  too. Then the released server runs again on the migrated database: the
  rolling-upgrade leg, which reports a failure without failing the job until
  the 1.0 release candidate. It runs on pull requests that touch the
  migrations, the runner or the auth server, and on every push to `main`.
  `scripts/upgrade-test/upgrade-test.sh all` runs it locally. See
  `apps/upgrade-test/README.md`, and the new "Upgrading within 1.x" section of
  the upgrade guide.
- **A wire test for every stable operation** ([#535], ADR-018 §5). A wire test
  now names the operation it checks in its `describe` or `it` title, as the
  OpenAPI document lists it: `[POST /oauth/token]`. The new
  `scripts/wire-coverage.mjs` reads the document and the wire suite's report and
  fails when a stable operation has no passing test that tags it; `pnpm
  spec-matrix` runs it after the joiner, so CI's `conformance-matrix` job checks
  it, and `pnpm wire-coverage` runs it alone. Experimental operations are
  exempt. The 37 stable operations with no wire test today are listed in
  `apps/wire-suite/exempt-operations.json`, each with a reason and an issue, and
  the list may only shrink: `wire-suite:exempt-operations`, which `lint` depends
  on, fails when it names an operation the base branch's list does not. The
  conformance matrix blanks a tag out before it reads citations, so a path in a
  title takes no section from its spec. `CONTRIBUTING.md` has a new "How the
  wire suite grows" section, and the repository has a pull request template
  with three checks: a changed stable route and its wire test, an added event
  type and its registration, an added migration that is non-destructive.
- **Reference reverse-proxy configuration** ([#482], ADR-019 Decisions 1, 5 and
  8). `deploy/reference/proxy/` holds an nginx configuration that sends every
  realm host to the auth server and `/ui/*` on the same host to the ceremony
  app. It routes on the normalised path and sends both upstreams that path. It
  answers 404 for an encoded slash or a backslash and for any `/ui` look-alike
  that is not `/ui/` (`/UI/`, `/ui;x`, `/ui`), 421 for a host that is not a
  realm host (only `/health` and `/ready` pass), and 404 for `/metrics` and
  `/internal/*`. On `/ui/*` it strips the `Cookie` header, drops any
  `Set-Cookie` the app sends, and replaces the CSP,
  `Referrer-Policy` and `Cache-Control` the app sends; `Cache-Control` is
  `no-store` except on content-hashed assets. It overwrites `X-Forwarded-For`,
  `X-Forwarded-Host` and `X-Forwarded-Proto`, removes `Forwarded` and the other
  client-sent proxy headers, and ignores `X-Accel-*` answers, so no upstream can
  make nginx fetch another location. Certificates are mounted files. A container
  test runs the configuration, unchanged, in front of stub upstreams and checks
  each rule (`reference-proxy:test-integration`, in CI's `integration` job). The
  docs site's new **Reverse Proxy** page (`operate/reverse-proxy`) lists the
  rules proxy-neutrally, with the file layout. The ceremony app has not shipped
  yet, so the configuration is not yet a working front for browser sign-in.
- **A Shared Signals Framework transmitter** ([#410], ADR-018 §3, ADR-019
  Decisions 8 and 9). Experimental and off by default: with
  `SSF_TRANSMITTER_ENABLED=true`, a realm whose new `ssf_transmitter_enabled`
  column is on serves `/.well-known/ssf-configuration` (SSF 1.0 §7) and stream
  management under `/ssf/` (§8.1): one push stream per receiver, its status,
  subjects and verification. A realm whose own switch is off answers the `404`
  of a route that does not exist. A receiver is an OAuth client using its own
  `client_credentials` token with the `ssf:stream` scope and the realm's issuer
  as audience; a token whose audience also names another realm's issuer, or
  whose client no longer holds the scope, is refused. Security Event Tokens
  come out of the event store through the delivery role (RFC 8935 push, retried
  on its schedule; a `400` ends a delivery only with a known SET error); the
  signer signs them with the realm's `event_signing` key, and the `jti` is the
  event id on every retry. The SET keys are published apart, at
  `/ssf/jwks.json`, the metadata's `jwks_uri`; the realm JWKS at
  `/.well-known/jwks.json` holds only token keys, and so does the signer's
  `getJwks` (`REALM_JWKS_PURPOSES` is `token_signing` alone), so a verifier
  that skips the `typ` check cannot take a SET for an access token. A paused
  stream's events are held without spending attempts and sent within 30
  seconds of it being enabled: delivery routes gain a `hold` outcome for that.
  `endpoint_url` is checked through the egress client at registration and at
  every delivery; the receiver's `authorization_header` is stored encrypted
  with the realm's `data_at_rest` key, and the delivery role's signer grant
  gains `decrypt` for a `delivery:` context only, to send it. The delivery role
  reads only the event subject of each stream subject, not the subject the
  receiver sent.
  `GET /ssf/status` adds `delivery_status`, the pending deliveries and the latest
  failed attempt; a refused and an unreachable endpoint both read
  `destination_unreachable` there. With `SSF_TRANSMITTER_ENABLED` off, SSF
  deliveries left from when it was on hold back no event retention. The docs
  site's new **SSF transmitter** page (`operate/ssf-transmitter`) walks through
  a receiver and the verification event.
- **Security events on SSF streams** ([#540], ADR-018 §3, ADR-019 Decision 8).
  The event registry marks every type that records a security change, and each
  declares the SSF event it is sent as, or `ssf: 'none'`; the registry test
  fails a security type that declares neither. A sign-out is CAEP 1.0
  `session-revoked`, a withdrawn consent `token-claims-change`, a client
  secret, API key or wallet credential change `credential-change`; RFC 7009
  revocation and emergency key retirement get QAuth-defined events,
  `urn:qauth:secevent:<name>:v1-rc.0`, release candidates until 1.0.0. Step-up
  elevation and a client's suspension or deletion have none: no standard event
  says what they are. Each SET carries the event's members with
  `event_timestamp` and `initiating_entity`, and a `sub_id` naming a user as
  `iss_sub` under the realm's issuer and a client by #410's rules. A withdrawn
  consent, a revocation, a replay's family revocation and a client's own
  credential change reach only the stream of the client concerned. Two types are new: `token.family_revoked`, recorded
  beside `token.request_failed` when a code or refresh-token replay revokes
  refresh tokens, and `key.emergency_retired`, which emergency retirement will
  emit for a published key only. `token.revoked` now names the user whose token was revoked,
  and commits in the transaction that revokes a refresh token's family; a refresh token whose
  family was revoked already names no one, so a second revocation sends no second SET. A receiver
  may add a user as a subject only when the user holds an active consent for
  its client or a live refresh token it was issued, or a live refresh token
  whose audience names the receiver as a resource server (a value of its
  `audience`, never a `urn:qauth:aud:` value or the realm's issuer); any other
  user is refused with `403`, and a disabled user is related to no receiver.
  A user subject lasts as long as that relation: the new `ssf-subject-sweep`
  job (hourly, on `api`) deletes it once the relation has ended and every event
  about the user has reached the stream, so the SET of the withdrawal that
  ended it is still sent. The delivery role now
  reads `realms.issuer`, for the `iss_sub` subjects. Each delivery attempt reads
  the stream as it is then: a held or retried delivery of an event the receiver
  no longer requests, or about a subject it has removed, is not sent. The docs
  site's new **SSF events** page (`reference/ssf-events`) is generated from the
  registry, and a test fails when it differs.

  **Action for operators**: a deployment that runs the delivery role as its
  own database user grants that user `SELECT` on `realms.issuer` before it
  upgrades, by applying `eventDeliveryGrantStatements(<role>)` of
  `@qauth-labs/infra-db` again, or `GRANT SELECT ("issuer") ON TABLE "realms"
  TO <role>`. Nothing checks the grants at boot: without this one every SSF
  delivery attempt fails with `permission denied for table realms` (SQLSTATE
  `42501`) until its attempts run out. A delivery role that uses the server's
  own database user needs nothing. See the upgrade guide (`operate/upgrades`).

- **Schema**: migration 0039 adds `ssf_streams`, `ssf_stream_subjects`,
  `realms.ssf_transmitter_enabled` (default off) and an index on
  `event_deliveries` that finds a destination's latest failed delivery ([#410]).
  Expand-only; the index build holds back delivery writes while it runs.
- **The egress allowlist** ([#481], ADR-019 Decision 8). `EGRESS_ALLOWLIST_PATH`
  names a JSON file of hosts and CIDR ranges, each for the realms it lists, that
  the egress client may reach although they are not public. An entry applies
  only to a destination the operator or a realm admin set, for a realm it names;
  a destination that a client, an end user or a fetched document supplies never
  uses it, and no entry opens an unspecified or multicast address or a cloud
  metadata endpoint. A `cidr` entry may be no wider than `/8` (IPv4) or `/32`
  (IPv6) and may not overlap a translation range (IPv4-mapped, NAT64, 6to4,
  Teredo). The server reads the file once at boot: a file that cannot be read,
  does not validate or others can write stops the boot, and one its group can
  write, or that neither root nor the server's user owns, gives a warning. The
  list is not in the database and no API edits it. A KEK custody adapter's calls
  to its key service stay outside the egress client (ADR-019 amendment of
  2026-10-27): their destination is deployment-wide, with no realm for the list
  to name. Every egress call now names who set its destination (`source`), and
  tests reach a local fixture server through `createTestEgressClient`, which
  exists only under `NODE_ENV=test`. The configuration page lists removed keys.

- **Admin scopes, the admin permission catalog and the built-in admin roles**
  ([#507], ADR-019 Decision 7). The admin API's scopes are `qauth:admin:read`,
  `qauth:admin:write` and `qauth:admin:security`, one per permission class, and
  no scope implies another. A permission registry (`definePermission`) gives
  each permission id exactly one class; a security permission never shares an
  id with a write permission. The built-in roles `viewer`, `editor` and
  `security-admin` follow the catalog by class and cannot be edited, and a
  custom role may not take a name that reads as one of theirs (compared after
  folding case, white space, dashes and compatibility forms).
  `effectivePermissions` keeps a role's permission only when the token carries
  its class's scope, and `validateCustomRole` refuses an unknown or retired id.
  The catalog starts with `realms.read`, `realms.export`, `realms.import.plan`,
  `realms.policies.write`, `realms.policies.security`, `approvals.read` and
  `approvals.approve`. A removed permission is retired and keeps its id; like
  every QAuth-defined identifier, the ids are promised from 1.0.0 on (ADR-018
  §5). The docs site's new **Admin permissions** page
  (`reference/admin-permissions`) is generated from the registry, and so is a
  new stable surface, `apps/docs-site/public/schemas/admin-permissions.json`
  (`auth-server:admin-permissions-export`): the stable-surface check reports a
  removed permission or a changed class as a break. The API conventions check
  refuses an admin operation whose `x-qauth-permission` names a permission the
  catalog cannot grant, or whose `x-qauth-class` is not the strictest class
  among them. No admin API route reads the catalog yet.

- **One audience per API family, and a token guard for each** ([#509], ADR-019
  Decision 7). The admin, account and developer APIs have the audiences
  `urn:qauth:aud:admin:v1-rc.0`, `urn:qauth:aud:account:v1-rc.0` and
  `urn:qauth:aud:developer:v1-rc.0`, and `requireFamilyToken(family, options)`
  guards a family route: it requires `typ: at+jwt` whatever
  `requireAccessTokenTyp` says, an `iss` its `IssuerResolver` hook accepts (by
  default only `JWT_ISSUER`), `sub`, `exp` and a non-empty `jti`, an `aud`
  holding exactly the family's audience, and, on the developer family, no
  `act` claim. Its required `subjects` option names the subjects a route
  admits, and the guard resolves the subject in the realm of the request
  (ADR-019 Decision 1): a user of that realm who is enabled, or for a
  `client_credentials` token a client of that realm that is enabled and not
  suspended, so a user's token is refused in every other realm. It answers a
  problem document, as every family route does ([#513]): a request with no
  token gets 401 `unauthorized` with a challenge that names no error, a refused
  token 401 `invalid_access_token` (or `access_token_expired`) with the RFC 6750
  `invalid_token` challenge, and a token that lacks a route's scope 403
  `forbidden` with the `insufficient_scope` challenge, whose `scope` names the
  scopes. `ForbiddenError`'s `requiredScope` takes a list for that, joined with
  spaces in the challenge. The developer and account routes moved under their
  prefixes in [#524], behind these guards. The token endpoint issues
  an audience in the reserved `urn:qauth:aud:` namespace only to a client whose
  `audience` lists it, on every grant (`invalid_target` otherwise, at
  `/oauth/authorize` and `/ui/consent` too); a code refused this way is not
  spent. A client resolved from a Client ID Metadata Document or registered at
  `/oauth/register` lists none, whatever its row holds. On a user's grant
  (authorization code and refresh token) a family audience is issued only when a
  `resource` names it, so a client's default audience leaves it out there. The
  Bearer path of `/oauth/authorize`, retired since by [#524], refused
  `access_denied` when the request or the client's default audience held one,
  and a family audience never makes a
  client authoritative at introspection. Self-registration never obtains one,
  by the rule the reserved `qauth:` scopes follow: dynamic registration and a
  Client ID Metadata Document ignore it in `audience` or `resource` metadata,
  and the seed manifest refuses it in a `cimd_clients` entry's `audience`. The
  JWT plugin's new `verifyRequestAccessToken(request, policy)` runs
  `requireJwt`'s checks under a route's issuer rule and `typ` requirement.

- **Admin roles and grants, with the issuer-bound realm rule** ([#510], ADR-019
  Decision 7). Migration 0043 adds `admin_roles` (a realm's custom roles: a
  name and permission ids from the catalog, checked with `validateCustomRole`)
  and `admin_grants` (an account, a built-in or custom role, one target realm
  or every realm, who created it, and when it was created, revoked and last
  changed in what it gives). Only an account of the operator realm holds a
  grant on every realm or on another realm than its own, and a custom role is
  granted only within its realm: the repositories refuse anything else, and so
  does the trigger `admin_grants_realm_rule` for every writer. A grant is
  revoked, never changed (the trigger `admin_grants_revoke_only`), and written
  live at the database's time, never already revoked or dated back (the
  trigger `admin_grants_insert_live`); a role is disabled, never deleted while
  a grant names it. A grant is looked up by its id or its account's id only
  within a realm ([#489]): the realm it covers, or its account's realm, and
  revoked only from its account's realm. The
  operator flag a realm carries, on which the realm rule rests, is written only
  by the realms repository's `setOperator`, no longer by `update`. `resolveAdminAuthority({ iss, sub, scopes, targetRealmId })` decides what
  an admin token may do to a realm, reading the grants on every request, never
  from the token: an operator-realm admin needs a grant on the realm or on every
  realm, a realm-local admin acts only on its own realm and never on the
  operator realm, a realm outside the grants answers 404 exactly as a missing
  one, and the grants' permissions are intersected with the token's scopes. So
  a disabled account, a revoked grant or a disabled role counts from the next
  request, with the same token. `RealmIssuerDirectory` (issuer to realm) and
  `IssuerKeyResolver` are the seams per-realm issuers and keys replace
  ([#491]); the defaults know only `JWT_ISSUER`, its realm and today's signing
  key. No admin route uses them yet; the admin listener comes with [#511].
- **The Interaction API v1 contract** ([#590], ADR-019 Decision 6, ADR-017
  Decision 3, ADR-018 §5). The API sign-in pages will use to reach the engine is
  written down before its handlers: one OpenAPI 3.1 document for
  `/interaction/v1-rc.0` and one JSON Schema per step, published on the docs
  site under `/interaction/v1-rc.0/` and served by the auth server at
  `GET /interaction/v1-rc.0/openapi.json`. It has four operations: read the
  current step with the interaction id alone (no personal data), read the step's
  personal data with the flow cookie, answer the step as JSON or as a plain form
  post with the flow cookie and the step's CSRF value, and cancel. It reserves
  `/interaction/v1-rc.0/wallet/` for the wallet return leg. Its 17 steps are the
  nine of ADR-017 and eight only the Interaction API serves, each named
  `urn:qauth:ia:<name>:v1-rc.0`, with its params, answer fields, closed error
  set, `amr` and an example. Every step read carries the realm's brand block.
  Errors are problem documents with a `code` and a `trace_id` and no prose,
  whose `type` and `title` are their code's entry on the problem types page; the
  registry gains `invalid_answer` (400) and `interaction_expired` (410).
  The versioning rules are in the document and on the new **Interaction API**
  reference page. A typed client generated from the document lives in
  `libs/shared/interaction-client`. The operations themselves are not served
  yet.
  - Every params, personal-data and envelope object is closed
    (`additionalProperties: false`); only the two maps keyed by step name and
    the problem document stay open, and a test holds every schema a response
    reaches to that. The versioning rules say so: a later version may add
    members, so a client never validates a response strictly against an older
    schema.
  - Before a first factor succeeds, an identifier comes back exactly as the
    person gave it, after the one normalisation; the form the account holds
    appears only after authentication.
  - A reset of an unknown address gets a phantom `email_code` with the same
    `expires_in`, `resend_after` and error sequence as a real one.
  - `email_code`'s purpose `verify_address` is `verify_account`, here and in
    ADR-017.
  - A `consent` step always names its client, and an `unverified` client's
    `redirect`; `params` always holds the current step's own params;
    `alternatives` holds no step twice.
  - `ClientDisplay` refuses another kind's members: `federation` on a `cimd`
    or `admin_registered` client, `verifiedDomain` on a `federation` one.
  - Answer and cancel name the same-origin check: `Sec-Fetch-Site:
    same-origin`, or, without it, an `Origin` equal to the realm origin (`null`
    refused). The personal-data read gains a 403 for a `Sec-Fetch-Site` or an
    `Origin` that names another origin, and allows a request with neither.
  - The step read's `alternatives` after a first factor are documented as an
    accepted exposure (methods, not identity), and a device's network name is
    marked as declared.
  - The typed client rejects a redirect a browser hides from `fetch` with
    `UnexpectedRedirectError` rather than as status 0.

- **The step grammar library** ([#591], ADR-017 Decision 3, ADR-019 Decision
  6). `libs/server/step-grammar` (`@qauth-labs/server-step-grammar`) holds the
  17 steps of the Interaction API contract as Zod schemas, the single source of
  their params, personal-data and answer types, with each step's URN, closed
  error set and `amr`. The JSON Schema generated from the Zod schemas must
  equal the step files the contract publishes, and a unit test compares all 17.
  One mapper per transport turns the engine's next step into its envelope: the
  Interaction API's step-read members (`step`, `error`, `alternatives`,
  `params`), and the FiPA endpoint's `403 insufficient_authorization` with
  `interaction_type_required`, `qauth_interaction_types_offered`,
  `qauth_interaction_params` and `qauth_interaction_error`. The steps a
  transport serves are its configuration. The FiPA mapper cannot emit a step
  only the Interaction API serves: as the required step it answers
  `403 redirect_to_web`, as an alternative it is left out, and no
  configuration can list one. Neither mapper sends prose: an offer with an
  undeclared member, an out-of-schema value or an error outside the step's set
  is refused, and a bot challenge is offered alone. The Zod schemas check
  `uri` and `date-time` formats with ajv-formats, as the published schemas'
  validator does. A step added without a mapper on each transport fails the
  type check. Nothing serves the mappers yet; the engine and the two endpoints use
  them in later issues. The contract's step examples are published as shared
  test vectors, `test-vectors/interaction/steps.json`, with each transport's
  answer.

- **The interaction record and the flow cookie** ([#592], ADR-019 Decision 6,
  ADR-017 Decision 6). The server side of one browser ceremony of the
  Interaction API, for its routes to build on ([#616], [#628]); no route serves
  it yet. An interaction is a Redis record keyed by the realm and the SHA-256 of
  a 32-byte random id, so the id is stored nowhere, holding a bounded snapshot of
  the validated authorization request (at most 16 KiB, as the
  pending-authorization stash holds, and at most 32 KiB with the first step;
  refused with `invalid_request` above), the engine transaction, the current
  step and its personal data, the hash of the flow secret, the creation time and
  an absolute expiry: `INTERACTION_TTL`, a new advanced key, 30 minutes by
  default (60 to 7200 seconds). Starting an interaction takes no account, so one
  nobody answers lives only 10 minutes: its record, turn and expiry-index entry
  are written with that deadline, and the first answer the server processes
  (which needs the flow cookie) moves them to the absolute expiry, which never
  moves. The `__Host-qauth_flow` cookie (`HttpOnly`, `Secure`,
  `SameSite=Lax`, `Path=/`, no `Domain`) carries the flow secret; a browser
  holds up to four, one per ceremony. The id alone reads the step's display
  data. The personal data, an answer, a cancel and a user switch need the
  cookie. An answer takes the interaction's turn with `GETDEL`, now in the cache
  utilities (`takeValue`, `takeSession`, `takeCache`), reads the record again
  and writes the next state, so of two concurrent answers exactly one is
  processed while the step stays readable; a failure before the next state is
  written gives the turn back. Authentication creates a new browser session (a
  new `sid`) and rotates the flow secret; a browser that loses that response
  retries with the old secret and gets `interaction_expired`, so the ceremony
  transport ([#616]) must submit credential steps by `fetch` or guard a form
  against a double submit. A user switch ends the interaction and starts a new
  one for the same request at the identifier step, with nothing proved carried
  over and the request's absolute expiry kept. "Not you?", a switch at any step
  but the account chooser, also signs the browser out of the account the screen
  shows, and of no other, as a sign-out by that account; its label says that it
  signs out. The account shown is the one a sign-in during the interaction
  proved, the user a consent is for or, while nobody has signed in during it,
  the account the identifier the person gave names. Its sessions that end: the
  one a sign-in during the interaction started ([#896]); the session the
  browser was already signed in with when `/oauth/authorize` started the
  interaction, for a consent or a sign-in the client asked for again, which the
  interaction records as carried in, when it is that account's ([#964]); and
  the session the browser's cookie names when it is a later one of the same
  account (a sign-in again in another tab). It clears the cookie when it names
  one of them, and `interaction.cancelled` records it with `sessionEnded: true`,
  about that account. Another account's session stays, and when the cookie
  keys cannot be read only the sessions the interaction holds end. "Use another
  account", the switch at the account chooser, ends no session: the accounts it
  lists stay signed in. An unknown, expired or finished
  interaction and a wrong cookie get one
  `interaction_expired` answer (410), the same bytes whatever the cause, and so
  does a finish after the session its sign-in started has ended, by a sign-out
  in another tab, a revoke or its own end ([#963]): no request completes under
  a session that was signed out, and the interaction stays at its step. Every
  problem document on an `/interaction/<version>/` path, `404` included, carries
  no `instance`, `detail` or `errors`. Four new events, `interaction.created`,
  `.answered`, `.cancelled` and `.expired`, name an interaction by a random
  reference, never by its id or cookie; a sweep job on the `web` role audits
  each expiry once, the 10-minute one of an unanswered interaction included,
  claiming each in one Redis transaction so a dropped connection cannot lose
  one, and a finish or cancel the sweep beat is answered as expired. The
  request log now censors the interaction id in an `/interaction/<version>/`
  path, plain or percent-encoded (once or twice), whatever else in the URL is
  malformed, and a Redis error in the log names its command but no longer
  carries the command's arguments.
- **The sign-in engine core** ([#614], ADR-017 Decisions 4 and 7, ADR-019
  Decision 6). `libs/server/sign-in-engine`
  (`@qauth-labs/server-sign-in-engine`) is the one engine both sign-in
  transports will call, the Interaction API ([#616]) and the FiPA endpoint
  ([#646]); no route calls it yet. Its entry point,
  `advance(transaction, answer, context)`, answers the next step, a completed
  sign-in (subject, `amr`, `auth_time`; the transport mints the session or the
  code), a redirect or a refusal, and runs ADR-017's rules in order: the realm's
  and client's MFA policy, read on every round through an interface (a policy
  that cannot be read refuses the round; until it has storage, no second factor
  is required), hooks for the limiters, the transport's request checks, the bot
  challenge and the per-account ladder, the identifier, then the password.
  Until a factor succeeds it reads only what the password check needs of the
  account the identifier names, and answers an unknown, password-only,
  passkey-only, disabled or locked account alike, with one Argon2id
  computation per password (against a dummy hash when none is usable) and a
  500 ms floor on every round. An answer counts only when its step is the next
  one. A second identifier, another user's proof, or a passkey that proves
  another account than the identifier names ends the transaction as
  `subject_mismatch`. The transaction carries its realm, its client and when
  it began, and one of another realm or client, or older than two hours, ends;
  it is not sealed, so the transports keep it server-side. Every refusal is
  audited, a limiter's, the request checks' and a malformed answer's included,
  and a production server builds the engine only with a per-account ladder. A disabled user gets the ordinary invalid-credentials
  answer and no subject; an unverified account under `REQUIRE_VERIFIED_ACCOUNT`
  still does too. After a password, the downgrade rule (a disabled factor still
  counts as bound) and the MFA policy answer a redirect until the steps that
  meet them exist. Later steps (passkeys, TOTP, the email code) join through a
  step-handler interface. `libs/fastify/plugins/sign-in-engine` holds the auth
  server's adapters: the account directory over the repositories, Argon2id with
  the dummy verification, an identifier HMAC keyed from the realm's cookie
  secret, and the mapping of the engine's audit records onto events. A new
  event, `user.sign_in_step_passed`, records each accepted step; refusals stay
  `user.sign_in_failed`, with the person named by the identifier HMAC until a
  user is resolved. The sign-in graph `graphs/flows/core/sign-in` now describes
  the engine (proposed), and the captured graph of the `/ui/login` page moved
  to `graphs/flows/core/sign-in-page`.
- **Round limits per end-user IP, per network bucket and per client**
  ([#636], ADR-017 Decision 7, ADR-008 §5). Around the per-account ladder,
  every Interaction API round is counted in Redis per end-user IP (an IPv6
  client by its /64) and per bucket (its /24, or its /48). A credential round
  (a password, any `otp`, a recovery code, a WebAuthn response, an email
  code) is counted as failed before its credential is checked and before the
  ladder, and taken back when it was right, so parallel guesses meet the same
  limits as guesses sent one at a time. From 10 failed rounds of an IP in 15
  minutes, or failures for more than 20 distinct identifiers from its bucket,
  the IP gets one credential round per 30 seconds and `429`
  with `Retry-After` for the others, neither verified nor counted; at 30
  failures every round of the IP gets `429` for 15 minutes. Crossing a
  threshold logs `a sign-in round limit was crossed` at `error` with the
  key's HMAC. A client whose effective environment is `development` meets ten
  times the counts; `staging` keeps production's. A Redis error or a call
  slower than 2 s refuses the round with `503` before any credential is
  checked, and a production server refuses to build a sign-in engine without
  the limits. The client row (a failure ratio above 50 % over 200 rounds, a
  failure budget of a tenth of `FIRST_PARTY_CLIENT_MAX_ROUNDS`, 600 rounds a
  minute) and the registration-start caps (`REGISTRATION_RATE_LIMIT` per IP,
  1,000 an hour per client) are in the library, for the first-party login
  endpoint and the registration steps that will use them.
- **The per-account failure ladder** ([#615], ADR-017 Decisions 5 and 7,
  ADR-020 §3, NIST SP 800-63B-4 §3.2.2). Wrong passwords are counted per
  account in Redis, before the password is checked: one Redis script reads the
  account's wait, refuses an attempt that falls inside it, and otherwise counts
  the attempt and sets the next wait, so 200 guesses sent in parallel reach the
  password check no more often than the same guesses sent one at a time. From
  5 consecutive failures the next attempt waits 2^(n−5) seconds, capped at 15
  minutes; an attempt inside the wait gets `429` with `Retry-After`, is not
  verified and is not counted. A correct password clears the password's
  counter and no other. An end-user IP with a successful sign-in to the
  account in the last 30 days (up to 16 per account) skips the wait while
  fewer than 20 of the run's counted failures came from such known IPs, and
  from then on waits as any other address does ([#968]): many clients can
  share one address, which must not guess its way to the hard action within
  seconds, and failures from elsewhere never use the 20 up. Its attempts still
  count toward the hard action. A run of failures is kept 2 days after its
  last counted failure while it has fewer than 5, and 30 days after its last
  counted failure once it has reached a wait ([#969]). Both follow the count
  alone, the same whether or not an account holds the identifier. A spray
  that tries each made-up address a few times so ages out of Redis within 2
  days, while an account under attack keeps its run. The observability page
  sizes Redis for the sprays that last longer, and asks for
  `maxmemory-policy noeviction`. The counter is keyed on a keyed HMAC of the realm and
  the normalised identifier, whether or not an account holds it, and known IPs
  are kept as keyed HMACs too, so no Redis key or value holds an address; both
  keys are derived with HKDF from the realm's cookie HMAC secret under labels
  of their own (`urn:qauth:key-use:end-user-ip-hmac:v1-rc.0` for the IPs), and
  no new secret is added. A rotation of that secret starts every run afresh. A
  Redis error or a call slower than 2 s refuses the attempt with `503` and
  `Retry-After: 5` before any credential is checked. `POST /auth/login` and
  `POST /ui/login`, and the password check of the email verification
  (`POST /auth/verify`, `POST /ui/verify`), reserve and count on the ladder
  beside their own lock (the realm's `bruteForce` policy, unchanged), and the
  sign-in engine's `ladder` hook is the same ladder. At 100 consecutive counted
  failures the hard action disables the password
  (`user_credentials.disabled_at`, migration `0052`), alerts the
  operator (the error log `password disabled by the failure ladder`) and
  notifies the owner, but only while it is armed: while the realm's hosted
  password reset is on ([#642]) and the deployment can send the notice
  ([#637]), asked at run time. Neither ships yet, so the hard action stays
  unarmed: each failure from the 100th on logs a warning, the credential
  lookup ignores a disabled mark, and the next successful sign-in clears it.
  The notice is sent without being awaited, so a slow mail transport cannot
  tell, by the answer's timing, an account from a made-up address. The two
  sign-in flow graphs (`graphs/flows/core/sign-in-page`, `sign-in-token`)
  draw the reservation, the wait and the unavailable store.
- **Service roles and a role switch** ([#495], ADR-019 Decisions 8 and 9).
  `SERVICE_ROLES` (stable) starts the auth server as `all`, the default and
  unchanged single process, or as a comma-separated list of `web`, `api`,
  `admin`, `signer` and `delivery`. A route manifest
  (`apps/auth-server/src/app/route-manifest.ts`) replaces the folder autoload:
  it names every route module with its roles, and a process registers only
  the routes, plugins, repositories and jobs of its roles. `web` serves the
  browser-session endpoints; `api` token, introspection, revocation,
  userinfo, registration, discovery, JWKS, the account and developer APIs,
  SSF and the legacy `/auth` routes, and runs `purge-expired`; `delivery`
  runs the event delivery reader and event retention; every role answers
  `/health` and `/metrics`. A read of a repository its roles leave unbuilt
  throws, naming it, and the boot is refused for a route without a role.
  Only a process with the `signer` role holds the KEK and the private keys:
  any other refuses to boot when `KEK`, `KEK_PATH`, a KEK provider adapter, a
  `JWT_*_PRIVATE_KEY*` or an `OID4VP_VERIFIER_SIGNING_KEY*` variable is set,
  naming it, and needs `SIGNER_URL` and `INTERNAL_TLS_CERT_PATH`,
  `INTERNAL_TLS_KEY_PATH` and `INTERNAL_TLS_CA_PATH` (advanced). The key
  variables are refused before the configuration reads any key file. Until
  the signer service ships, such a process answers a request that needs a
  signature with `503` `temporarily_unavailable`, and its event deliveries wait
  without spending attempts (the delivery role now holds a delivery whose
  signer is unavailable). It verifies a realm's tokens, and serves its JWKS,
  from the realm's published public keys (`realm_public_keys`), which it reads
  without a KEK through the new `realmPublicKeys` repository, which every
  role builds ([#491]): no public key variable is needed, and the
  verification keys and JWKS are the signer's own. `HYBRID_SIGNING_ENABLED`
  describes what the deployment's signer issues, so every process of a
  hybrid deployment sets it: one without the signer verifies hybrid tokens
  with the realm's published ML-DSA-65 keys and answers `503` when asked to
  sign one. `@fastify/autoload` is no longer a
  dependency. The docs site's new **Service roles** page
  (`operate/service-roles`) describes the split that works today. The egress
  client (`fastify.egress`) is registered where a route makes an outbound call
  (`web` and `api`); `GET /auth/verify`, the email verification page, and
  `POST /ui/verify` are `web` routes, while `POST /auth/verify` stays on `api`.
  A route tagged only with roles the process does not hold refuses the boot.
  `SESSION_COOKIE_SECRET` is required in production only on a process holding
  `web` or `api`, and the Swagger UI under `/docs` is served only on one
  holding `api`. A delivery held because the signer is unavailable is logged at
  `warn` when first held and every 15 minutes while it lasts, and the new
  gauges `qauth_events_delivery_signer_held` and
  `qauth_events_delivery_signer_held_oldest_seconds` show such holds.

- **The Interaction API's operations** ([#616], ADR-019 Decision 6, ADR-017
  Decisions 6 and 7). The auth server now serves the four operations of
  `/interaction/v1-rc.0`: the step read, the personal read, the answer and the
  cancel. Every answer and cancel needs the realm origin (`Sec-Fetch-Site`,
  `Origin`), the flow cookie and the CSRF value of the step read, checked in
  that order, and the sign-in engine runs only once all three pass; another
  origin or a wrong value gets one generic `403`, audited as
  `request.csrf_rejected` with the new `form: interaction`. The CSRF value is
  derived from a per-interaction key, the revision and the step, so it answers
  its step view once and never another step; it travels in the body, never in
  a URL. An answer is JSON or a plain HTML form post: a form post gets `303` to
  the ceremony page, `/ui/interaction/{id}`, or to the final redirect, so the
  password step needs no JavaScript. Bodies are bounded (16 KiB, 64 KiB for
  `webauthn_create`, a repeated form field refused), every answer is
  `Cache-Control: no-store` with no CORS header, and a throttled sign-in is
  `429` with `Retry-After`. An answer that carries a credential spends the
  sign-in form's rate limit (`LOGIN_RATE_LIMIT`), as one form post to
  `/ui/login` does; any other answer and the cancel spend the authorization
  endpoint's. The step read counts per address at the authorization
  endpoint's budget too, except from the ceremony app server's egress
  addresses, which make it for every browser ([#982]): the operator lists them
  in the new `CEREMONY_APP_PEERS` (addresses and CIDR ranges, empty by
  default), and a listed address's reads count per interaction, under the new
  `CEREMONY_APP_PEER_RATE_LIMIT` reads a minute. The two are set together; a
  boot that sets one without the other is refused. A deployment whose ceremony
  app reads the step from its server must list it, or everyone signing in
  shares that server's one address bucket. The engine shares the legacy
  sign-in forms' per-account failure ladder. The redirect comes from the
  interaction record and the realm, never the request; a finished sign-in goes
  on with its authorization request ([#628]). The interaction record is now
  version 2 (an interaction of the previous release reads as expired).

- **`/oauth/authorize` can start an interaction** ([#628], ADR-019 Decision 6).
  With the new, temporary `INTERACTION_UI_ENABLED` switch on (default off),
  where the endpoint sent the person to `/ui/login` or `/ui/consent` it now
  creates an interaction holding the validated request, at most 16 KiB, and
  redirects to the ceremony page `/ui/interaction/{id}` with the id only, so no
  URL carries the request's parameters again (a 2048-character `state` no
  longer makes a long `Location`). An interaction is created only after every
  check that needs no user, `client_id`, `redirect_uri` and PKCE included,
  and the endpoint runs those checks and its decision unchanged in both modes:
  a request refused today is refused the same way. When the sign-in finishes,
  the request is checked and decided again for the session the interaction
  holds, and only then is the code minted (`mintAuthorizationCode`, under the
  consent and the session) and the browser sent to the client with `code`,
  `state` and `iss`; a consent it still needs starts a consent interaction, and
  an error is redirected to the client. A finish the expiry sweep beat, and a
  replayed answer, issue no code. `prompt=none` starts no interaction. The
  person can cancel the consent step, which redirects with
  `error=access_denied` once the request is checked again, as a finish is, and
  answer it ([#629]). The endpoint takes
  `login_hint` (OpenID Connect Core 1.0 §3.1.2.1, at most 254 bytes in UTF-8,
  longer is `invalid_request`), which the identifier step offers as its
  pre-fill, in the step's personal data; the request log censors it, and the
  interaction id of the ceremony page path. The flow graph `core.authorization`
  draws the endpoint in both modes.

- **The consent step of the Interaction API can be answered** ([#629],
  ADR-019 Decision 6). With `INTERACTION_UI_ENABLED` on, the decision
  `/ui/consent` makes is now the `consent` step, which the ceremony app only
  renders. Its read names the client through `client` ([#593]), lists the
  requested scopes the client may have (QAuth's own text for `openid`,
  `profile`, `email` and `offline_access`, and a mark on each dangerous one),
  the resources, or else the `aud` the token gets from the audience an operator
  configured for the client (the new `audience` param), and, for an AI agent,
  the new `agent` param, from
  which the screen says in QAuth's words that the app is an AI agent and how
  long it may keep working (the realm's `sso_max_lifespan`). "Remember this
  decision" starts checked, and the step's personal data is the identifier the
  person signed in with. The answer carries `decision` (`allow` or `deny`) and
  `remember` and nothing else, so it cannot add a scope or a resource. The
  interaction finishes first, then the request is checked again: `deny`
  redirects with `error=access_denied`, `state` and `iss` (`consent.denied`);
  `allow` checks the account, the agent scope cap, the QAuth API audiences,
  whether the client is still the kind the step showed, the shown scopes
  against the client's allowlist and the step-up gate (a dangerous scope on a
  stale sign-in, `prompt=login`, `max_age` or a native first-party profile
  starts a fresh sign-in interaction, `step_up.required`), and then one
  transaction mints the code for exactly the shown scopes and resources, saves
  the grant when "remember" is set, and records `step_up.elevated` and
  `consent.granted`. An AI agent never skips the step. The `/ui/consent` page
  is unchanged; its graph is now `core.consent-page`, and `core.consent` is
  the proposed graph of the step. ADR-015 Decision 11 now says which flows it
  covers.

- **Security operations, defined by effect, as an enforced classification**
  ([#508], ADR-019 Decision 7). The eleven effect tags (`credential-path`,
  `token-content`, `issue-for-other`, `administration`, `import`,
  `federation-operator`, `key-custody`, `realm-lifecycle`,
  `authority-tree-power`, `posture-loosening`, `bulk-revocation`) are a closed
  list in `@qauth-labs/shared-validation`. Every admin operation is defined once
  with `defineOperation` (id, class, effects, permissions); the registry refuses
  a `write` or `read` operation with an effect, a `security` operation without
  one, a class other than the strictest class of its permissions and an unknown
  member. An operation whose request decides what it needs declares the
  security case and a pure `classify`; a `classify` that throws, meets an
  unknown field or returns an unknown member, effect, class or permission, or
  more than the declaration, gives the request the declared security
  classification. The admin pipeline's classification stage
  (`plugins/admin-operations.ts`, for the admin listener) loads only before any
  route, refuses at boot a route that names no registered operation or whose
  OpenAPI members differ from the registry, and on every request hands the
  handler a frozen classification it cannot lower and freezes the parameters,
  query and body it classified. A reserved table names, for each effect, the
  operation ids later areas register; the registry refuses one registered with
  a weaker classification, a case variant of one, and a `classify` on one whose
  entry does not say the request decides. The API conventions check fails when
  an admin operation of the OpenAPI document disagrees with the registry, and
  the docs site's new **Security operations** page
  (`reference/security-operations`) is generated from it. No admin operation is
  registered yet.
  - Each request-dependent reserved entry (`realms.policies.update`,
    `clients.update`, `realms.imports.apply`) lists security cases; the registry
    runs the operation's `classify` on them at boot and refuses one that gives a
    case less than its effects or fails closed on it, so a `classify` that
    answers `write` for everything cannot take the entry. By effect, lengthening
    a token or session lifetime or the key rotation interval, and shortening or
    switching off audit-event retention, are `posture-loosening`.
    `mergePatchLeafPaths(body)` gives a merge patch's changed fields from the
    body's own keys.
  - An operation with `loadState` names the version of the state it read
    (`stateVersion`); the classification carries it, the stage answers 428
    (the new `PreconditionRequiredError`, `precondition_required`) when the
    request has no `If-Match` and 412 (the new `PreconditionFailedError`,
    `precondition_failed`) when it names another version, and the handler's
    write must be conditional on it. The `posture-loosening` tag now names
    lifetimes, the key rotation interval and audit-event retention.
    The classification also carries the SHA-256 digest of a binary body
    (`bodyDigest`), which cannot be frozen.
  - The stage requires an `authorize(request, classification)` option and calls
    it on every request right after classifying.
  - Every admin route runs under a request ceiling: a listener that registers
    the server's rate limit before the stage keeps it, and one that does not
    gets the stage's own (`@fastify/rate-limit`, 100 requests a minute by
    default, the `rateLimit` option).
  - The reserved table adds realm roles and groups and their role mappings,
    credentials an admin sets for an account (password, passkey, other
    credential), and rotating a client's secret or registration access token.

- **The admin API's own listener and request pipeline** ([#511], ADR-019
  Decisions 7 and 8). A process that holds the `admin` role runs a second HTTP
  server for the admin API, on `ADMIN_API_HOST` and `ADMIN_API_PORT`
  (`127.0.0.1`, port `3002`, by default) once `ADMIN_API_ENABLED=true` turns it
  on: it is off by default until the first admin operations ([#517]) ship. It
  binds before the public port and closes with the server. The public listener
  answers 404 for every admin path, but for a CORS preflight, which it answers
  as on any other path, and refuses to boot an admin route. The
  listener grants nothing for a caller's network position: every admin route
  runs behind the same stages, in order: the request id, the admin family's
  token guard (with the keys of the realm the token's issuer names, and one
  answer for every refusal), the DPoP proof check ([#520]), the realm from the path
  (`/admin/v1-rc.0/realms/{realmId}/...`, never the host), the authority from
  the caller's grants and scopes, the classification and permission check, an
  approval gate, the handler inside one database transaction, and the audit
  row. A request classified `security` that carries no approval bound to it
  ([#512]) answers the new `approval_required` problem code (403) and never
  runs. A call that reaches a realm within the caller's grants writes
  exactly one admin audit row, reads included: `succeeded` in the handler's
  transaction, or `denied` or `failed` in a new one with no diff (a `denied`
  or `failed` row that cannot be written is logged instead). A realm
  outside the grants answers 404, is logged, and adds no row to that realm's
  chain. The listener has request ceilings of its own, 100 calls a minute each,
  whatever `RATE_LIMIT_MAX` and `RATE_LIMIT_WINDOW` say (`RATE_LIMIT_ENABLED`
  only chooses Redis or memory for the counts): per client address (the TCP
  peer: the listener trusts no proxy), the calls the token guard refuses, past
  which a call without a token is refused before the guard and a refused token
  answers 429, while a valid token is never held back; per token subject, every
  call after the guard; and per address, every call to the OpenAPI document.
  Every request id is the server's own. A handler answers by returning its
  body, serialized inside its transaction, so a body its response schema
  refuses fails the call and rolls its change back; a route's own preHandler
  refuses by throwing, never by sending the reply; and an admin route may not
  have hooks that would run before authorization. The admin OpenAPI document is
  served on the listener only, at `/admin/v1-rc.0/openapi.json`, without a
  token. No admin operation ships yet ([#517] adds the first).
- **Admin tokens are DPoP-bound and short-lived** ([#520], ADR-019 Decision 7,
  ADR-014 §3). The admin listener takes an access token only under the `DPoP`
  scheme, bound to a key (`cnf.jkt`), with a proof (RFC 9449 §7.1) made with
  that key for the call's method and for the new `ADMIN_API_BASE_URL` followed
  by the call's path, never a URL built from the request; its `iat` within 60
  seconds of the server's clock, its `ath` the token's hash, and its `jti`
  used once (kept in Redis for 181 s, the proofs of the public listener's
  store). A token under the `Bearer` scheme, a token bound to no key, or a
  proof under another key is refused with 401 and a `DPoP`
  `error="invalid_token"` challenge, any other refused proof with
  `invalid_dpop_proof`; every challenge of the listener is a `DPoP` one. The
  proof is checked inside the token guard, before the per-subject ceiling, so
  a stolen token without its key counts against the caller's address, not the
  admin's. The token endpoint issues the admin audience, or an admin scope,
  only with a DPoP proof: without one an admin scope the account's grants
  would give is withheld (RFC 6749 §3.3), and a request for the admin
  audience, or for nothing but such scopes, is refused with
  `invalid_dpop_proof` (`invalid_target` or `invalid_scope` on a process with
  DPoP off, where no proof could help). The answers to an account without a
  grant are unchanged. The refresh token issued beside an admin token is
  bound to the proof's key whatever the client, so a confidential client
  refreshes it only with that key. A token for the admin API never lives
  longer than 900 s, whatever `tokens.adminAccessTokenLifespanSeconds` says. Where the admin listener runs (`ADMIN_API_ENABLED=true` on a process
  with the `admin` role), the boot now requires `ADMIN_API_BASE_URL` (the
  absolute http(s) URL clients address the admin API at) and
  `DPOP_ENABLED=true`, and the production rule that `ADMIN_API_HOST` be
  loopback is lifted: the listener may sit behind a load balancer that
  terminates TLS. In production `ADMIN_API_BASE_URL` must be `https`, unless
  both it and `ADMIN_API_HOST` name loopback. A refresh token issued bound to
  no DPoP key never refreshes into an admin token: the admin audience is
  refused with `invalid_grant` (sign in again) and the admin scopes are
  withheld and dropped from the rotated refresh token, so a later refresh
  of that family never issues them either, even once a public client's
  rotation binds it to a key. The token endpoint's processes need
  `DPOP_ENABLED=true` too, to
  issue admin tokens.
  The admin OpenAPI document names the `dpopAuth` security scheme.
- **An internal listener with mutual TLS** ([#496], ADR-019 Decision 8). A
  process that holds the `signer` role while the roles are split runs one more
  HTTP server, on `INTERNAL_HOST` and `INTERNAL_PORT` (`127.0.0.1`, port
  `3443`, by default; advanced keys), for the other roles' calls to the signer
  service ([#497] adds its routes). A single process runs none. It serves
  HTTP/1.1 over TLS 1.3 only and requires a client certificate that
  `INTERNAL_TLS_CA_PATH` issued: a client with none, or one from another CA,
  gets no HTTP answer. A CA file that holds a public root CA, as a system
  bundle does, is refused, and one with no `CA:TRUE` certificate, or a key file
  its group or others may read, is warned of. The new `INTERNAL_PEER_ROLES`
  maps a subject alternative name of the peer's certificate (a DNS name, or a
  URI such as a SPIFFE ID) to the role it calls as, `request.peerRole`, and
  refuses `signer`, which never calls as a peer; a peer whose SANs it does not
  map, or map to two roles, gets `403` `forbidden` on every path. Each internal
  route module names the peer roles that may call it, and a peer of another
  role gets `403` on its routes. A request on a connection whose peer
  certificate has expired since the handshake, or that was made before the TLS
  files were last reloaded, gets `403` too; every `403` closes its connection,
  so the peer connects again. The certificate, key and CA files are read again
  every five seconds and applied with no restart once a rotation is complete.
  The listener holds at most 1024 connections at once. Its routes register by
  role from an internal route manifest, all under `/internal/`, which the
  public listener refuses to register. Such a process refuses to start without
  the three TLS files and `INTERNAL_PEER_ROLES`, naming each, before it waits
  for the database. The listener is not routed by host, shares the app's
  database pool, cache and signer, and closes at the same time as the admin
  listener. The admin API keeps its own listener and its own rule: a peer
  certificate grants nothing there. `createInternalClient`
  (`apps/auth-server/src/app/internal/client.ts`) is how the other roles call
  it: `https` only, the server known by `expectedServerSan` rather than its
  host name, every request kept below the base URL's path, a keep-alive pool
  (a request whose pooled connection the server had just closed is sent once
  more on a new one), a deadline and a cap on each answer, and credentials
  that can be reloaded.
- **Client display data and the verified domain** ([#593], ADR-019 Decision 6).
  One function in the auth server says who a client is from the server's own
  records, as the Interaction API's `ClientDisplay`: the host of a CIMD client's
  client id URL in its `xn--` form, or the domain an admin set on a client the
  operator provisioned, each with its registrable domain and a flag for a host
  under a shared-hosting suffix (the Public Suffix List's private section);
  any other client is unverified. A loopback redirect is "this device". The
  name a client declares is capped at 64 characters and stripped of control,
  bidirectional, zero-width and markup characters and of stacked combining
  marks; a client-supplied logo or link is never returned. Migration 0047 adds
  the nullable `oauth_clients.verified_domain`, which only the
  `db:seed-oauth-clients` manifest (`verified_domain`) and, since [#914],
  `db:set-client-verified-domain` write until the admin API's `clients.update`
  does, as a security operation.
- **Operator commands for the clients #593 changed** ([#914]). A redirect URI
  the consent screen cannot show breaks a client stored before #593, and an
  operator-provisioned client shows as unverified until its verified domain is
  set. `db:list-unshowable-redirect-uris` lists, per realm (or for one
  `--realm`), the clients holding such a URI, why each URI fails and who can
  replace it; it only reads, runs against a 0.1 database before the upgrade,
  and exits `1` when it lists any. Every boot of a process with the `web` role
  names such clients as `warn` lines too, up to 20 with a count of the rest,
  within a 2-second scan that says when it stopped early; the boot waits for
  it at most 3 seconds and never fails for it. `db:set-client-verified-domain`
  sets or clears an operator-provisioned client's `verified_domain` without
  issuing it a new secret, refusing a value the manifest refuses, a public
  suffix included, and refusing a CIMD client or one that is not
  operator-provisioned. Each change is recorded as the new
  `client.verified_domain_changed` event (`admin`, `warning`), with the domain
  before and after. `redirectTargetRefusal` in
  `@qauth-labs/shared-validation` names why `redirectTarget` refuses a URI.

- **Approvals for security operations, bound to the exact request** ([#512],
  ADR-019 Decision 7). The admin pipeline's approval gate, which refused every
  security operation, now lets one run with the approval its `QAuth-Approval`
  header names. The client files the approval with
  `POST /admin/v1-rc.0/realms/{realmId}/approvals` (the operation's id, path
  parameters, query and body, and an optional reason), reads it with
  `GET …/approvals/{approvalId}` and may withdraw it with
  `POST …/approvals/{approvalId}/cancel` (`If-Match` on the version its `ETag`
  gave). Migration 0045 adds `admin_approvals`, and 0054 ([#901]) takes the
  request body out of it. An approval binds the canonical request (operation
  id, method, path parameters, query, body, realm and requester, RFC 8785)
  through `op_hash`, its SHA-256 with a nonce the server draws: the gate
  computes the retried call's `op_hash` with the stored nonce and compares the
  two, and an approver's factor signs a challenge derived from it. The
  approval keeps the method, path parameters and query, never the body, which
  may hold a secret, and no hash of the request without the nonce. The retry
  consumes the approval with one conditional update in its own transaction, so
  it runs once, and an operation that rolls back leaves the approval usable
  until it expires, five minutes after it was filed. Filing and withdrawing take the
  classification of the operation they name, reading needs `approvals.read`,
  and anyone but the requester and an eligible approver gets 404. A human
  requester's own fresh step-up is the one approval an operation needs today;
  the engine counts a required second approval only from a different account
  that holds `approvals.approve`, which the two-admin rule ([#521]) will
  require where a realm asks, with ADR-019's other eligibility rules. Approving
  happens through a factor (the `ApprovalFactor` interface), never through an
  admin route. Neither the passkey factor nor the approval page has shipped,
  so no code a deployment runs gives an approval; the one factor that exists is
  for tests and is built only in a test run, never under
  `NODE_ENV=production`. The answer
  carries `approvalUrl`, `/approvals/{realmId}/{approvalId}` on the requester
  realm's issuer, built from its row. Every security
  operation registers a renderer, and the admin listener refuses to boot one
  without it: the approver sees typed display data rendered from the request
  when the approval is filed and stored with it, every string length-capped
  with its control, bidirectional, format and other default-ignorable
  characters, private-use and unassigned code
  points and spaces other than U+0020 shown escaped and its backslashes
  doubled, and the requester's reason apart, as quoted text. A consumed,
  cancelled, denied or expired approval has its nonce overwritten with random
  bytes, so neither its `op_hash` nor the audit log's copy of it can be tested
  against a guessed body (a dump, replica or WAL archive taken while it was
  open still holds both, so a secret that can be guessed is safe in a body
  only as long as those copies are); the `approval-expiry` job, every minute on the
  `admin` role, stores `expired` on one that expired unused. No job removes
  approvals.
  Filing, approving, declining, withdrawing and consuming each write the admin
  audit log; the operation's own row lists the approvals it ran on.
- **Operator-set first-party client profiles** ([#631], ADR-017 Decision 2).
  Migration 0048 adds `oauth_clients.first_party_profile` (`web_redirect`,
  `native_backend`), `first_party_policy` and `first_party_reason`, nullable
  with no default, and six CHECKs: no profile on a dynamic, CIMD, agent or
  developer-owned client; a profile only with `private_key_jwt`; a policy
  exactly on `native_backend`; `native_backend` only with the
  `authorization_code` grant; a written reason (at most 1000 characters)
  exactly with a profile; a policy that is a JSON object. `resolveFirstPartyProfile` in shared-validation
  reads a row and fails closed on an unknown profile or a policy that does not
  parse; the strict policy is `flows` (default `login`),
  `email_code_after_password` (default `false`) and `pkce_required` (default
  `true`). The `db:seed-oauth-clients` manifest sets the three fields, the
  reason required; a native profile also needs the backend's keys, the
  `authorization_code` grant and an `https`, private-use or loopback browser-leg
  redirect URI. Dynamic registration, `/api/clients` and CIMD never write them.
  A change is recorded as the new `client.first_party_changed` event, and
  removing a profile revokes every refresh token of the client not yet revoked.
  The consent waiver reads the profile ([#633]); the authorization challenge
  endpoint comes later.
- **The system client is provisioned from operator configuration** ([#631],
  ADR-017 phase F0). The migration runner reads `SYSTEM_CLIENT_REDIRECT_URI`,
  `SYSTEM_CLIENT_JWKS_URI` or `SYSTEM_CLIENT_JWKS`, `SYSTEM_CLIENT_ID` and
  `DEFAULT_REALM_NAME`, and after the migrations makes the system client a
  `private_key_jwt` client with the `web_redirect` profile and the portal's
  callback, keeping its id, scopes, audience and suspension. A realm the auth
  server has not created yet is reported and skipped; a row that cannot be
  first party exits `4`. The seed manifest's new `system_client` section does
  the same.
- **Administrative consent for first-party clients, and a fresh login for
  native profiles** ([#633], ADR-017 Decision 9). `/oauth/authorize` issues a
  code without the consent screen to a client whose operator-set first-party
  profile resolves, when none of the requested scopes is dangerous and the
  request does not carry `prompt=consent`. No consent row is written: unless
  the user once remembered a consent for the client on the consent screen, it
  is not listed under `/consents` and `/oauth/token` returns no
  `refresh_token` for such a code. Every such code is recorded as the new
  `consent.administrative` event (the profile, the scopes, the resource
  indicators, the endpoint) in the transaction that mints it. A dangerous scope
  or `prompt=consent` shows the screen even under a stored consent. Every
  request of a `native_backend` client counts as `prompt=login`, on
  `/oauth/authorize` and on `POST /ui/consent`, whatever it says: a session
  signed in more than two minutes earlier meets the login page (the window
  `prompt=login` gives every client), and `prompt=none` answers
  `login_required`; the request's own `prompt=consent` still shows the screen.
  A client without a profile is unaffected; no client has one until an
  operator sets it. The system client is the first an upgrade reaches: once
  the operator provisions it from `SYSTEM_CLIENT_*` or the seed manifest's
  `system_client` section ([#631]), which give it the `web_redirect` profile,
  its `/oauth/authorize` requests skip the screen too.

- **The AuthMethod contract, experimental** ([#599], ADR-003 as amended,
  ADR-018 §4, ADR-019 Decision 12). The plugin API for sign-in methods, such as
  an upstream OpenID Connect provider, versioned `qauth-auth-method/1-rc.0`
  and outside the 1.0 stability promise (the experimental item `plugin-api`).
  An AuthMethod extends `CredentialProvider` with an id, display data, a config
  schema, the upstream step, the routes it mounts under `/upstream/<type>` and
  `start(request, context)`, which takes its arguments in the order a route's
  `handle(request, context)` does. The engine checks every answer of a method: the redirect, the
  transaction and its binding, which the host compares in constant time
  before it takes the pending transaction, the identity (its assurance level
  capped, `low` by default) and every attribute, whose source must be the
  method's type. A method is handed its config, the egress client, the signer
  role and a logger, never a database handle or a key, and `resolve(type)`
  answers a fail-closed stand-in for it. The contract test kit
  (`@qauth-labs/server-federation/testing`) checks a method against all of
  it, PKCE with S256 included. The plugin runtime ([#600], below) loads
  methods into a running server; the upstream sign-in flow is [#639].

- **The plugin runtime for AuthMethod plugins, experimental** ([#600],
  ADR-019 Decision 12, ADR-018 §4 and §5). A plugin is an npm package the
  operator installs with the deployment and lists in `AUTH_METHOD_PLUGINS`
  (package names only: a path or URL stops the boot). At boot a process that
  serves the sign-in pages or the admin API imports each one, checks the
  contract version its `authMethod` export declares, holds it to the whole
  contract and registers it; a package that is not installed, exports no
  method, is built for another contract version or repeats another plugin's
  id or type stops the boot. A plugin outside the first-party list, a fixed
  list in the server's code that is empty until the first-party plugins ship,
  loads only while `PLUGIN_API_ENABLED=true`, the switch of the experimental
  item `plugin-api`, which now warns at boot while on; with it off the
  package is never imported and the boot logs why. Each realm keeps its state
  of each plugin in `realm_auth_method_plugins` (migration 0050): off by
  default, its config's plain members, and each secret member (marked
  `writeOnly` in the plugin's schema) as a ciphertext under the realm's
  `data_at_rest` key. The admin API lists and reads the installed plugins
  (`plugins.list`, `plugins.get`, the permission `plugins.read`), seals a
  secret value for one member (`plugins.secrets.seal`, under the new write
  permission `plugins.write`; it changes nothing) and configures, enables and
  disables one per realm (`plugins.update`, `plugins.enable`,
  `plugins.disable`, each of which names in its body the version of the
  state it acts on, so an approval binds it): security operations with
  `credential-path`, under the new permission `plugins.security`, so they need
  `qauth:admin:security` and an approval. A configure carries only sealed
  values, so the request an approval stores never holds a secret in the
  clear. A config must pass the plugin's own schema; secrets are write-only
  and never shown in a response, an audit row or a log. A disabled plugin's routes
  under `/upstream/<type>` answer the `not_found` document of a path no route
  serves, and plugin routes are left out of the OpenAPI documents. A plugin's
  context holds its realm config, the egress client, the signer bound to the
  realm and the plugin, and a logger: no database handle and no key.

- **The generic upstream OpenID Connect client, experimental** ([#601],
  ADR-018 §3, ADR-019 Decisions 8 and 9). The new library
  `libs/server/upstream-oidc` is the first AuthMethod: one per configured
  provider type `oidc_<alias>`, with its own callback,
  `/upstream/oidc_<alias>/callback`, so a response for one provider cannot be
  replayed at another. It reads the provider's discovery document through the
  egress client (its `issuer` must match byte for byte, and every URL it names
  goes out as a `remote_document` destination, which the egress allowlist
  never opens) or takes the endpoints set by hand for a provider on a private
  address. It sends the code flow with `state`, `nonce` and PKCE S256, checks
  the RFC 9207 `iss` parameter, accepts the callback as `GET` and as
  `form_post` (bounced to the `GET` callback so the `SameSite=Lax` flow cookie
  comes along), redeems the code with `client_secret_basic`,
  `client_secret_post` or a `private_key_jwt` assertion the signer role signs,
  validates the ID token against the provider's cached key set and an
  allowlist of asymmetric algorithms (`iss`, `aud`, `azp`, `exp`, `iat`,
  `nonce`), and reads userinfo when configured. Every call follows no
  redirect and has its own deadline and size cap. A stored client secret is
  sealed with the realm's data-at-rest key and never shown, and a
  registration check runs discovery and the egress address checks for the
  provider administration ([#714]). It makes no account decision: the
  upstream sign-in flow is [#639]. The AuthMethod contract's egress request
  gains `redirect: 'error'`, the one cap a method may set (no redirect
  followed), which the client uses on every call. The signer lets the `api`
  role decrypt a provider's client secret (a context under
  `upstream-oidc:client-secret:`) as well as a realm's mail secret, so the
  host opens a stored config as `api`. The stored secret is bound to where it
  is sent: after the issuer or a token endpoint set by hand changes, it no
  longer opens and must be entered again.

- **The developer API and the account API's consents, under versioned
  prefixes** ([#524], ADR-019 Decision 7, ADR-018 §5). `/developer/v1-rc.0`
  serves a developer's clients (list, create, read, merge-patch update,
  delete, `regenerate-secret`), their static API keys and the developer's own
  consents; `/account/v1-rc.0` serves the user's consents (list and revoke).
  Each route is guarded by its family's token guard ([#509]) and follows the API
  conventions: RFC 7591 names for registered client metadata, RFC 3339 times,
  lists as `{ items, nextCursor }` with `limit` and `cursor` (`invalid_cursor`
  for a cursor another list issued), an `ETag` on each read of a client and a
  JSON Merge Patch update that needs `If-Match` (428 without it, 412 for a stale
  one, 415 for another media type, 422 for `client_name` set to `null`), and
  problem documents. A client of another developer is 404, as before. The
  domain logic is shared with the deprecated paths, which keep their shapes.

- **`graphs:check`, delurio's check of the flow graphs** ([#560], ADR-021).
  `graphs/` is now an Nx project, `graphs`, whose `check` target runs
  `delurio check graphs --strict` with `@delurio/cli`, a root development
  dependency pinned to 0.5.0: a graph that cannot be loaded, a graph file that
  does not follow its kind's JSON Schema (which holds every state but an exit to
  camelCase), a broken assertion or a main story that cannot be walked fails
  it. The five `graphs/domain/*.yaml` files are read as one domain and checked
  too. It needs no server and no database, and is cached on `graphs/**`; no app
  or lib depends on delurio, and no shipped image carries it. `graphs/README.md` now states QAuth's flow
  conventions: an effect ends in `DONE` or `FAIL.<class>`, a protocol flow has
  one exit per cause, named `<error>.<cause>`, every protocol exit declares its
  response, and every flow is complete (no unreachable state, no transition
  never taken, no dead end, no effect without a failure path). delurio does not
  enforce those structural rules yet, so they are review items until it does.
  `flows/admin/plugin-enable` now names its exits that way too, one exit per
  cause for a refused enable and a refused disable alike. CI does not run the
  target yet; [#568] will.
- **The upgrade guide from 0.1 to 0.2** ([#501]). `operate/upgrades` gains
  _Upgrading from 0.1 to 0.2_: back up first, no downgrade, a numbered upgrade
  procedure, a table of every new host, key, session and role setting with its
  default, and what to do about the permanent issuer, the endpoint hosts, the
  KEK, the key import and its boot warnings, the key variables left over,
  `/health`, `/ready` and the internal metrics, the removed private-address
  switches and the operator realm. `operate/keys` is rewritten for the key
  store: the KEK, the boot import, the rotation windows, adding a key with
  `auth-server:keys:create`, and how a relying party caches the JWKS. The new
  **Topology** page (`operate/topology`) gives the layout ADR-019 fixes: one
  host and issuer per realm, a dedicated host, DNS and TLS per realm, endpoint
  hosts, service roles and mutual TLS, database users and the proxy rules. The
  OIDF certification runbook adds the RS256 key in the key store. The key
  import's acceptance of a PKCS#1 RSA key, which the docs used to call refused,
  is now pinned by a test.

### Changed

- **docs.qauth.dev and the developer portal use the design system** ([#472]).
  The portal's pages name the tokens of `libs/ui` instead of Tailwind's
  palette. The docs site maps Starlight's theme onto the same tokens and
  fonts. Both follow the system's light or dark setting and draw one focus
  outline, in the teal accent, on every control.
- **The auth server's `/ui` pages use the design system** ([#472]). Sign-in,
  consent, the second-factor, passkey, recovery-code and wallet pages, e-mail
  verification and sign-out link one stylesheet: the tokens and fonts of
  `libs/ui`, served by the auth server itself under `/assets/ui/` with
  content-hashed names, a year's immutable cache and a rate-limit bucket of
  their own. Square corners, flat
  cards, DM Sans and Instrument Serif, light and dark after the system's
  setting, and the teal focus outline on every control.
- **A process whose only role is `delivery` skips the default realm's boot
  step** ([#498]). The step creates and updates the realm row, which the
  delivery role's database user may not write; any other role's process runs
  it as before.
- **`POST /auth/register` applies one password policy, with a minimum of 15
  characters** ([#634], ADR-017 Decision 8, NIST SP 800-63B-4 §3.1.1.2). This
  is the announced change of ADR-017's first phase: every deployment refuses,
  from this release, a new password the policy does not meet. In order: the
  length as typed (at most 256 UTF-16 code units, `too_long`, before anything
  else runs; on this route the request schema refuses a longer password
  first, with the `400` `validation_error` it answered before); Unicode NFC
  normalisation, after which a password lengthened past 256 is `too_long` too;
  a minimum length counted in code points, 15 by default (`too_short`); a
  whole-password blocklist of zxcvbn's dictionaries and the context words (the
  address, its local part and the part before a `+` tag, its domain and the
  domain's labels, the realm's mail sender name and the realm's name),
  compared ignoring case and the spaces around the password, and never as a
  substring (`blocklisted`); and the zxcvbn score floor `password.minScore`, 2
  by default (`too_weak`, also the answer for an unpaired UTF-16 surrogate,
  which is not text and would be hashed as U+FFFD). There are no composition
  rules and no periodic change. The `422` `weak_password` problem document
  gains a `reasons` member listing every reason found, and `errors` carries a
  message for each under `/password`, then zxcvbn's feedback. The new realm
  policy `password.minLength` (8 to 64) holds the minimum; the new
  `PASSWORD_MIN_LENGTH` (default 15) seeds it in a new realm and in a realm
  stored without it, at the first boot of this release. A value below 8 fails
  the boot, and one below 15 boots with a warning: NIST allows a shorter
  minimum only for a password used within multi-factor authentication, while a
  password can still be the only factor here. New passwords are hashed after
  NFC normalisation, and their credential records it as
  `credential_data.password_normalization: "nfc"`; the password sign-ins
  (`/auth/login`, `/ui/login`), the email verification and the sign-in engine
  verify such a credential on the presented password in NFC, so two spellings
  of the same text sign in. Existing passwords are kept: a credential without
  the marker is verified on the password as typed, as before, and no existing
  password is checked against the policy. The developer portal marks its
  address field as the username and shows a message for each reason.

  **Action for operators**: tell users who register through
  `POST /auth/register` that a password needs at least 15 characters (a
  passphrase of a few words meets it). To keep a shorter minimum, set
  `PASSWORD_MIN_LENGTH` (8 or more) before the first boot of this release, or
  change the realm's `password.minLength` afterwards; read the rolling upgrade
  note in the upgrade guide first.

- **`/health` is liveness, `/ready` is new, and the metrics move to the
  internal listener** ([#500], ADR-019 Decisions 1 and 8). `GET /health`
  answers `200` while the process serves, with the service roles it runs
  (`roles`), and checks no dependency: the `services` field and the `503
  unhealthy` answer are gone. `GET /ready` runs the readiness checks of the
  process's roles at once, each within 2 seconds: `database` on every role,
  `redis` on `web`, `api` and `admin`, `kek` on `signer` (the KEK unwraps one
  stored key per KEK reference in use) and `outbox` on `delivery`. It answers
  `200` when every one passes, and otherwise `503` with a
  `service_unavailable` problem document whose `checks` member holds each
  check's result, a failure naming its reason (`error` or `timeout`) and never
  the error, which is logged. A role's plugin adds its own check through `fastify.readiness`.
  Both answer on any host, carry no realm data and keep
  `HEALTH_RATE_LIMIT_MAX` per `HEALTH_RATE_LIMIT_WINDOW`, now counted per
  client address in the process's memory, so they answer while Redis does not.
  `GET /metrics` leaves the public port: every process serves its metrics as
  `GET /internal/metrics` on the internal listener while `METRICS_ENABLED` is
  on, to a peer whose certificate `INTERNAL_PEER_ROLES` maps to the new
  `metrics` role, and in a single process without the internal TLS files, in
  plain HTTP to loopback callers only. The Compose healthcheck calls `/ready`;
  the image's `HEALTHCHECK` stays on `/health`.

  **Action for operators**: point a probe that should take a process out of
  rotation at `/ready`, since `/health` no longer fails for a database or Redis
  outage. Move the Prometheus scrape to `INTERNAL_HOST:INTERNAL_PORT`
  (`/internal/metrics`): issue the scraper a client certificate from the
  internal CA and map its SAN to `metrics`, or scrape `127.0.0.1:3443` from
  beside a single process. A process whose roles are split now runs the
  internal listener for its metrics too, and refuses to boot without the
  internal TLS files and `INTERNAL_PEER_ROLES`: map a scraper there, or set
  `METRICS_ENABLED=false` on a process no scraper reads.

- **The OID4VP verifier key moves into the key store** ([#546], ADR-019
  Decision 9). `OID4VP_VERIFIER_SIGNING_KEY` (or its `_PATH` form) is imported
  once, like the JWT keys, as the default realm's ES256
  `oid4vp_request_signing` key; a later boot that still sets it warns, and a
  different key in it replaces the stored one. The signer signs every request
  object with the request realm's key (`signRequestObject`, `typ`
  `oauth-authz-req+jwt`, `x5c` from the configured chain), as the `web` role,
  and refuses a chain whose leaf names another key. The certificate chain and
  its anchors stay public configuration. At boot the chain is compared with the
  stored key's published half, so the boot stops when it names no stored key,
  on processes without the key too, and the capability descriptor claims
  `ES256` only for a stored key the chain names. Each per-request response
  encryption key is now sealed by the signer with the realm's `data_at_rest`
  key, bound to its row's `kid` (`web` seals, `api` opens), and the row records
  the sealing key's `kid` in the new `response_encryption_sealing_kid` column
  (migration 0053) in place of the scheme marker. A row the previous release
  wrote keeps opening, with its marker and `OID4VP_RESPONSE_KEY_SECRET`, until
  it expires (at most 15 minutes). During a rolling upgrade a node of the
  previous release cannot redeem a row a new node sealed: the wallet's
  response there answers 500 and leaves the row live, so the wallet can retry,
  and a retry that reaches a new node completes the sign-in. Keys are kept per
  realm and the import lands in the default realm only, so under a profile
  that signs its requests (`haip-1.0`) a realm whose own store holds no
  request key the chain names offers no wallet login on its sign-in and
  account-linking pages; the unsigned `oid4vp-1.0-base` profile is offered in
  every realm as before.
- **CIMD comes from the realm row** ([#534], ADR-019 Decisions 1 and 10,
  ADR-007). Whether a realm accepts an HTTPS URL as a `client_id`, its trust
  policy and its trusted domains are the realm's `registration.cimd` policy, so
  two realms of one deployment can accept Client ID Metadata Document clients
  differently. Client resolution at the authorization, consent and token
  endpoints (client assertions included) reads it off the realm row the request
  resolved to, with no query of its own, and the realm's discovery documents
  advertise `client_id_metadata_document_supported` from it. A realm with CIMD
  off treats a URL `client_id` as an unknown client; a realm with the
  `allowlist` trust policy and no trusted domains accepts no CIMD client. The
  realm's switch and trust policy are checked before the document cache is
  read, so a document one realm resolved never lets its client into a realm
  that refuses its host. `CIMD_ENABLED`, `CIMD_TRUST_POLICY` and
  `CIMD_TRUSTED_DOMAINS` now only seed a new realm, and a realm that had no
  policies at the first boot after the upgrade ([#516]): a later change of them
  leaves an existing realm as it is, and the boot warns that each one set is
  ignored. `CIMD_CACHE_DEFAULT_TTL`, `CIMD_CACHE_MAX_TTL`,
  `CIMD_MAX_DOCUMENT_BYTES` and `CIMD_FETCH_TIMEOUT_MS` stay deployment
  settings. A stored policy the schema refuses fails the realm's client
  resolution and discovery with a server error rather than guess. Until the
  admin API's realm policy update ([#517]) ships, `operate/docker` shows the
  SQL that changes a realm's CIMD policy. `POST /oauth/register` already holds a
  registration to the realm's own dynamic registration allowlist and drops a
  scope outside it ([#516]); a new integration suite proves both against real
  containers, and a test refuses any read of a migrated seed key outside the
  boot steps.
- **The verified-account gate, the password score and the failed-login lockout
  come from the realm row** ([#528], ADR-019 Decision 10). Each realm's
  `accounts.requireVerifiedAccount`, `password.minScore` and `bruteForce`
  policies apply to it, so two realms of one deployment can differ: one may
  let an unverified account sign in while another refuses it, accept a weaker
  new password, or lock an address out after another number of failures, or
  never. `POST /auth/login`, `POST /ui/login` and the email verification read
  the gate and the lockout off the realm row the realm resolver already loaded,
  with no query of their own, and `POST /auth/register` checks a new password
  against the realm's lowest score. The failed-login counters and lockouts were
  already kept per realm ([#487]), so the failures of one realm never lock the
  same address in another. `REQUIRE_VERIFIED_ACCOUNT` (and its old name
  `REQUIRE_EMAIL_VERIFIED`), `PASSWORD_MIN_SCORE` and the four
  `FAILED_LOGIN_*` keys now only seed a new realm, and a realm that had no
  policies at the first boot after the upgrade ([#516]): a later change of them
  leaves an existing realm as it is, and the boot warns that each one set is
  ignored. In particular `REQUIRE_VERIFIED_ACCOUNT=false` set on a deployment
  that already ran this release no longer lets the existing realms' unverified
  accounts sign in. A realm a node of the previous release created during a
  rolling upgrade runs on the keys until a node of this release boots again
  and fills it. A realm policy change reaches the realm's next request once the
  realm resolver reads the row again (its cache time, 30 s), without a restart.
  With the seeded defaults nothing changes. The password plugin
  (`@qauth-labs/fastify-plugin-password`) no longer takes a `validationConfig`:
  it decorates `fastify.passwordValidators`, whose `forMinScore(score)` builds a
  validator per score on first use and keeps it (`createPasswordValidators` of
  `@qauth-labs/shared-validation`), in place of `fastify.passwordValidator`.
- **Token lifetimes come from the realm row** ([#527], ADR-019 Decision 10,
  ADR-008 §5). The access, development access and refresh token lifetimes are
  each realm's `tokens` policies, so two realms of one deployment can issue
  tokens that live differently long. The token endpoint reads them off the
  realm row it already loads for the environment policy, with no query of its
  own; the ADR-008 tiers are unchanged (`short` is the realm's
  `tokens.accessTokenLifespanSeconds`, `long` its
  `tokens.developmentAccessTokenLifespanSeconds`), an ID token gets the
  realm's access lifetime, and a new or rotated refresh token its
  `tokens.refreshTokenLifespanSeconds`. The legacy `POST /auth/login` signs
  with the realm's access lifetime, which its `expires_in` names, and gives
  its refresh token the realm's refresh lifetime. `ACCESS_TOKEN_LIFESPAN`,
  `DEV_ACCESS_TOKEN_LIFESPAN` and `REFRESH_TOKEN_LIFESPAN` now only seed a new
  realm, and a realm that had no policies at the first boot after the upgrade
  ([#516]): a later change of them leaves an existing realm's tokens as they
  are, and the boot warns that each one set is ignored. A realm a node of the
  previous release created during a rolling upgrade runs on the keys until a
  node of this release boots again and fills it. A realm policy change reaches
  the realm's next token once the realm resolver reads the row again (its
  cache time, 30 s), without a restart; until the admin API's realm policy
  update ([#517]) ships, no route changes them. `signIdToken` of
  `@qauth-labs/fastify-plugin-jwt` takes an `expiresInOverride`, as
  `signAccessToken` does; the plugin's `accessTokenLifespan` and
  `refreshTokenLifespan` stay the fallback. Each lifetime is bounded, in the
  realm policies and in the keys that seed them: an access token (and so an ID
  token) and a development access token at a day, so a token always expires
  well inside the 14 days a retired signing key stays published, and a
  refresh token at 90 days. A key above its bound refuses to boot; a realm row
  written by hand above it is refused like any invalid policy, so the realm's
  token requests fail rather than issue it. A token whose audience is the
  admin API lives at most the realm's `tokens.adminAccessTokenLifespanSeconds`
  (ADR-019 Decision 7, at most 900 s), whatever its client's tier gives. A
  delegated token of token exchange is capped at its subject token's `exp`
  when it is signed (`signAccessToken`'s new `expiresNotAfter`), not only
  when its lifetime is computed.

- **BREAKING (operators): SMTP needs TLS and a public host, unless the operator
  allows otherwise** ([#529]). A realm's smtp transport whose `mail.smtp.secure`
  is off now requires STARTTLS (nodemailer `requireTLS`), with the certificate
  checked against the host name, and connects only to a public unicast address
  its host resolves to, never to `localhost`, a private, loopback, link-local,
  unique-local or cloud metadata address; each mail resolves the host, checks
  the address and dials that address with the host name as its TLS server name,
  so DNS cannot point the connection elsewhere. A policy update that names
  `localhost` or such an IP address as `mail.smtp.host` is refused. Two
  operator-only keys, which no realm policy can change, relax this:
  `SMTP_ALLOW_PLAINTEXT=true` lets a transport send without STARTTLS, and
  `SMTP_ALLOWED_HOSTS` lists the hosts a realm may name and reach although they
  are not public (a metadata address never). **Action for operators**: a local
  plaintext SMTP relay, such as Mailpit on `localhost:1025` or a relay
  container on a private network, needs `SMTP_ALLOW_PLAINTEXT=true` and its
  host in `SMTP_ALLOWED_HOSTS`, or its mail fails, logged with the refused
  host. Each boot logs an error, and still serves, for every realm whose
  stored SMTP host is `localhost`, a non-public IP address not in
  `SMTP_ALLOWED_HOSTS` or a cloud metadata address, or a listed relay that
  starts in the clear while `SMTP_ALLOW_PLAINTEXT` is off, naming the realm,
  the host and the key to set; a host name is checked when a mail connects,
  not at boot. See **Mail secrets move into the realm** in `operate/upgrades`.
- **BREAKING (operators): the token lifetime keys are bounded** ([#527]).
  `ACCESS_TOKEN_LIFESPAN` and `DEV_ACCESS_TOKEN_LIFESPAN` above 86400 s (a day),
  or `REFRESH_TOKEN_LIFESPAN` above 7776000 s (90 days), now refuse to boot.
  Lower them before upgrading; a realm row above the same bounds is refused
  like any invalid policy (see the entry above).
- **The developer portal's token carries the developer audience** ([#524]).
  The system client is created with `urn:qauth:aud:developer:v1-rc.0`, and a
  boot step gives it to the system client of every realm that has one, so
  `POST /auth/login` mints the developer audience and the token reaches the
  developer API. `/auth/logout` and the deprecated `/api/clients` and
  `/api/consents` accept exactly that audience on a system-client token, but
  for the sign-out grace of this release (under **Removed**).

  **Action for operators**: developers sign in to the portal again when the
  first node of this release boots: a portal token minted before carries the
  system client's id as its audience, which no node of this release accepts any
  more, except to sign out. This release carries both steps, accepting the new
  token ([#509]) and minting it, so during a rolling upgrade from v0.1.x a
  developer is signed out of the portal whenever a request reaches a node of
  the other version, until the roll ends (a portal session lasts
  `PORTAL_SESSION_TTL`, 15 minutes by default). A single-node deployment, or
  one upgraded stop-start, is unaffected. See **Upgrades**
  (`operate/upgrades`).

- **The developer portal calls the developer API** ([#524]). Its server
  functions reach `/developer/v1-rc.0` for clients, API keys and consents, read
  each list page by page, and name the client's `ETag` in `If-Match` when they
  save it, so an edit to a client changed in another tab is refused ("this
  client was changed since you opened it") rather than overwriting it. A
  secret regeneration changes the client too, and the page takes the `ETag`
  its answer carries, so the next save is not refused as stale.

- **The auth server no longer creates a secret-based system client** ([#631],
  ADR-017 phase F0). When a realm has no system client yet, the first sign-in
  creates a placeholder that holds no secret and no key (`private_key_jwt`
  with no key set, no redirect URI, no first-party profile), instead of a
  `client_secret_post` row with a random secret nobody held. An existing row is
  read as it is, so management tokens keep working.
- **An agent client always sees the consent screen** ([#845], ADR-015
  Decision 11, ADR-014 §11). A stored consent that covers the request no
  longer skips `/ui/consent` for a client with `is_agent`: every browser
  authorization of an agent shows the screen, which says the client is an AI
  agent and how long it may keep working. `prompt=none` from an agent answers
  `consent_required`, with no code, whenever no fresh login is needed; a
  fresh-login requirement still answers `login_required` first. The legacy
  Bearer path of `/oauth/authorize`, which cannot show the screen, answers an
  agent with `access_denied`. An agent integration that relied on a remembered
  consent to get a code without a page now gets the page, or the error, each
  time.
- **The consent screen leads with what the server verified about the client**
  ([#593]). Its heading and title name the verified domain, or say "An
  unverified app", never the client's own name, which now appears below,
  labelled as declared by the app. Every client an operator provisioned shows
  as unverified until its `verified_domain` is set. A loopback redirect warns
  for every client, not only CIMD ones.
- **BREAKING (clients): a redirect URI the consent screen cannot show is
  refused** ([#593]). Dynamic registration, `/api/clients`, CIMD documents and
  the seed manifest refuse one (a host that is not a DNS name of valid labels,
  such as one with an underscore; an IPv6 address that is not loopback; a
  scheme over 64 characters) with `invalid_redirect_uri`. A client stored
  before the upgrade that holds one breaks in three ways. A CIMD client whose
  document lists one no longer resolves once the server fetches the document
  again, at the consent screen and at the token endpoint alike, where its
  refresh answers `invalid_client`. A seed manifest that names one is refused
  whole, so running it again changes no client. A client registered
  dynamically, through `/api/clients` or by the manifest keeps working for a
  user whose stored consent covers the request, but the consent screen answers
  a new user `invalid_request` (400). `db:list-unshowable-redirect-uris`
  ([#914]) lists such clients, before the upgrade too; the upgrade guide
  (`operate/upgrades`) shows how.
- **A split process holding the signer needs the internal listener's TLS
  files** ([#496]). A process whose `SERVICE_ROLES` names `signer` but not every
  role, such as `api,admin,signer,delivery`, now refuses to start unless
  `INTERNAL_TLS_CERT_PATH`, `INTERNAL_TLS_KEY_PATH`, `INTERNAL_TLS_CA_PATH` and
  `INTERNAL_PEER_ROLES` are set, and listens on `INTERNAL_PORT` (`3443` by
  default) besides `PORT`. A single process (`SERVICE_ROLES=all`, the default)
  is unchanged and binds nothing new.
- **The request log censors `code`, `id_token` and `access_token` in logged
  URLs** ([#599]), as it censors `response_code` and `token`: an upstream
  provider's authorization code rides in an AuthMethod's callback URL, and a
  `form_post` bounce may carry a provider's tokens there.
- **A process binds a second port only once the admin listener is turned
  on** ([#511]). An existing deployment binds nothing new: the listener is off
  by default. A process with `ADMIN_API_ENABLED=true` and the `admin` role
  (`SERVICE_ROLES=all`, the default, holds it) also listens on
  `127.0.0.1:3002` (`ADMIN_API_HOST` and `ADMIN_API_PORT`), and refuses to start
  when that port is taken: two such processes in one network namespace, such as
  a blue/green pair on one host or containers on the host network, need a
  distinct `ADMIN_API_PORT` each.
- **BREAKING (relying parties and resource servers): tokens are signed and
  verified per realm, through the signer** ([#491], ADR-019 Decisions 1 and 9).
  The JWT plugin holds no key any more. Every access token, ID token, hybrid
  token and ID-JAG is signed by the signer with the keys of the realm it is
  issued in: its `iss` is the realm's issuer, as discovery publishes it, and its
  protected header names the signing key in `kid` (a hybrid token names its
  ML-DSA-65 key in `pqc_kid` too). Each realm's `/.well-known/jwks.json` lists
  its own keys, and the server verifies a token only with the keys of the
  request's realm and only under that realm's issuer, so a token one realm
  issued is refused by another outright: `requireJwt`, the API family guards,
  the SSF stream routes, introspection, revocation, logout, userinfo, the
  token-exchange subject and actor tokens and the Bearer path of
  `/oauth/authorize`. A token issued before the upgrade carries no `kid`: it
  still verifies, but only against the Ed25519 key that `JWT_PRIVATE_KEY` (or
  `JWT_PUBLIC_KEY` on a process without the signer role) holds, never against
  a key the store generated; keep the variable set until those tokens expire.
  This path goes away in the next release. The key boot step refuses to import
  a key variable that holds a key another realm already stores, naming it. A
  token's `typ` is checked before its expiry is reported, so logout's
  expired-token path accepts an expired access token only, never an expired ID
  token or ID-JAG; a hybrid token must be an access token (`typ: at+jwt`) too;
  and the Bearer path of `/oauth/authorize` answers `access_denied` only for a
  refused token, a key store or denylist failure failing the request closed
  instead. A deployment whose
  `JWT_ISSUER` ends with a slash: its access and ID tokens now name the issuer
  without it, as discovery already did, so a relying party that compares `iss`
  with the slashed form must drop the slash. During a rolling upgrade the nodes
  of the previous release refuse the new tokens and the new nodes refuse the
  access tokens the old ones issued, until they expire
  (`ACCESS_TOKEN_LIFESPAN`): upgrade such a deployment all at once.
- **BREAKING (browser sessions): the browser cookies are signed with the realm
  cookie key** ([#493], ADR-019 Decisions 3 and 9). The session, login-CSRF and
  wallet-flow cookies are no longer signed with `SESSION_COOKIE_SECRET` but with
  the realm's `cookie_hmac` key, which the signer hands the browser-facing role;
  each process keeps a realm's current and previous cookie keys in memory and
  reads them again every 60 seconds. Each value is `<kid>.<payload>.<mac>`: it
  names the key that signed it, so after a rotation a cookie of the previous key
  keeps verifying while it is the previous key, and its HMAC-SHA256 covers
  the cookie's name and the realm id, so a value never passes for another
  cookie or for a cookie of another realm. The session payload lists the
  session ids and the active one (`{ s: [sid], a: sid }`). The MAC is compared
  in constant time, and a cookie that does not verify is now cleared, as one
  whose session is gone already was. The session cookie's `Max-Age` is the time
  left until the session's absolute end (the realm's `sso_max_lifespan`, or
  `SESSION_COOKIE_TTL` without one) instead of `SESSION_COOKIE_TTL`. A cookie an
  earlier release signed does not verify, so every user signed in to the hosted
  pages signs in once more after the upgrade (sessions are not moved anyway).
  During a rolling upgrade a browser whose requests reach old and new nodes in
  turn is asked to sign in at each switch, not once: an old node refuses the
  new cookie and sets one of the old format, which a new node clears. Send the
  browser traffic to the new nodes only, or route each browser to one node,
  until the roll ends (see **Upgrades**).
  `SESSION_COOKIE_SECRET` is now optional: the key boot step imports it into
  the default realm's store, and a value that differs from the stored cookie key
  (compared in constant time, after opening the stored key with the KEK)
  replaces it. The replaced key stays the realm's previous cookie key, so
  nobody is signed out, until the next replacement: a time limit comes with
  rotation through the store ([#542]), so a leaked secret is cut off by
  replacing it twice. A value that matches a retired key changes nothing.
  `NODE_ENV=production` refuses the values QAuth's examples published (the
  `.env.example` development value and the old `.env.docker.example` one) on
  every process, and no longer refuses an unset one. A process without the
  signer role answers `503` on the browser routes that read or set a signed
  cookie until it can call the signer service ([#497]): a split deployment
  keeps `web` with the signer for now, and `/auth/logout` there still ends
  everything but leaves the cookie for the next page to clear.
- ID tokens are signed with RS256 when the realm's key store holds an RS256
  key, and discovery's `id_token_signing_alg_values_supported` lists what each
  realm holds: `["RS256","EdDSA"]` or `["EdDSA"]`. A fresh deployment generates
  an RS256 key ([#485]); one upgraded without `JWT_RS256_PRIVATE_KEY` keeps
  EdDSA ID tokens until it imports or creates one.
- **The key variables are optional** ([#491]). `JWT_PRIVATE_KEY` (or its
  `_PATH`) is no longer required, and `HYBRID_SIGNING_ENABLED=true` no longer
  requires `JWT_MLDSA_PRIVATE_KEY`: once the realm's key store holds the keys,
  the server boots with no key variable, and a fresh deployment generates them
  (the hybrid pair too, with hybrid signing on). The key boot step still
  imports a variable the store lacks, and a signing variable that holds a new
  key still replaces the stored key until rotation through the store ships. A
  deployment with hybrid signing on whose realm holds an Ed25519 signing key
  without its ML-DSA-65 key refuses to start. The boot warning for a token key
  variable now says the boot step reads it only to replace the stored key.
  Without `JWT_PUBLIC_KEY`, the boot no longer fails ([#359]): the key step
  derives the public key, and nothing else imports the private one.
- `@qauth-labs/fastify-plugin-jwt` takes `signer` and `requestRealm` instead of
  `privateKey`, `publicKey`, `issuer`, `keyId`, the `rs256*` and `mlDsa*`
  options and the retired keys; `signAccessToken`, `signIdToken`,
  `signHybridAccessToken`, `verifyAccessToken`, `verifyHybridAccessToken`,
  `getJwks` and `getIdTokenSigningAlgValuesSupported` take the realm, and
  `getIssuer` is gone. The wallet verifier's crypto capability gate reads the
  default realm's stored token keys, not the key variables.
- **BREAKING (clients that hold `qauth:admin:*` scopes or the admin audience)**:
  the token endpoint issues an admin scope only when the client lists the admin
  API's audience and the account holds a live admin grant whose role has a
  permission of that scope's class, and the admin audience only to an account
  that holds a live admin grant ([#510]), on the grants that sign an account
  in at QAuth: authorization code and refresh token. A scope that fails is left out of the token
  and the response's `scope` says so; when nothing is left of the scopes asked
  for, the request is refused with `invalid_scope`. The audience is refused with
  `invalid_target`. Grants are read at every issuance, so the refresh after a
  revocation no longer carries what the grant gave. Neither ever reaches a
  `client_credentials` token, which names no account (until service accounts
  exist, [#522]), an ID-JAG minted for another authorization server, a token
  of the jwt-bearer grant, whose authority comes from another identity
  provider, or a delegated token of token exchange: an admin acts as itself,
  never through an agent. `/auth/login` leaves the admin audience out of its token, whatever
  the system client lists. No other scope of the reserved `qauth:` namespace is
  ever issued. The admin family's
  token guard also refuses a delegated token (an RFC 8693 `act` claim), as the
  developer family's does; the account family accepts one, and its routes
  decide per operation. **Action for operators**: no route needs these tokens
  yet. Before the admin API ships, give each account that will use it an admin
  grant.

- **BREAKING (clients of the non-OAuth routes)**: every route that is not an
  OAuth protocol endpoint answers an error with an RFC 9457 problem document,
  `application/problem+json` ([#513], ADR-019 Decision 7): `type`, `title`,
  `status`, `detail`, `instance`, a stable lower-case `code` and `trace_id`
  (the request id), plus `errors[]` with a `pointer` and a `message` for a
  validation failure and for weak-password feedback under `/password`. The old
  `{ error, statusCode, code, feedback, details }` body is gone, from the
  `/auth`, `/api`, `/consents` and `/ui` routes, the well-known documents, the
  wallet-link API, the 404 for a path no route serves, the router's own refusals
  (a path that is not valid percent-encoding, 400; an over-long path parameter,
  414 `uri_too_long`) and a request that cannot be read (400, 408
  `request_timeout`, 431 `request_header_fields_too_large`). Each code has its own
  problem type, listed on the docs site's new **Problem types** page
  (`reference/problem-types`), and one registry maps every class of
  `@qauth-labs/shared-errors`, and every error class a route defines, to its
  code. A 401 or 403 on a bearer-protected route also carries a
  `WWW-Authenticate` challenge; a 403 says `insufficient_scope` only when a
  wider token would be let through. A request that presents no credentials
  answers `unauthorized`, and its challenge names no error (RFC 6750 §3.1); a
  token that was presented and refused answers `invalid_access_token` or
  `access_token_expired`, with `error="invalid_token"` in the challenge. A
  one-time email verification token that is refused answers
  `invalid_verification_token`, and a duplicate `already_exists`.
  `POST /api/clients` and `PATCH /api/clients/{id}` refuse client metadata
  with the codes dynamic registration answers: `invalid_client_metadata` for a
  scope outside the realm's allowlist, a grant and response type that do not
  fit together or a public `client_credentials` client, and
  `invalid_redirect_uri` for a missing `redirect_uris`. The root's own answers
  carry the request id in `X-Request-Id` (`REQUEST_ID_HEADER`) too, as its
  `trace_id`, and a missing Swagger UI file under `/docs` answers the
  `not_found` document. `GET /consents` and `DELETE
  /consents/{id}` answer a request without a browser session with the 401
  `unauthorized` problem document too, with no challenge (they answered
  `{ "consents": [] }` and an empty body). The SSF transmitter's routes
  ([#410]) answer problem documents as well, SSF 1.0 defining no error body:
  a realm that does not run the transmitter gets the `not_found` document of a
  path no route serves, and a token without `ssf:stream` a 403 whose challenge
  names that scope.
- **BREAKING (OAuth clients that read QAuth's own members)**: the OAuth protocol
  endpoints (token, authorize, introspect, revoke, register, userinfo and the
  wallet-facing OID4VP endpoints) answer only the members their specification
  defines, `error` and `error_description` ([#513]). `code`, `statusCode`,
  `feedback` and `retryAfter` are gone; the `Retry-After` and
  `WWW-Authenticate` headers stay. Two shapes are fixed on the way: an unknown
  `grant_type` answers `unsupported_grant_type` (RFC 6749 §5.2) instead of a
  validation error, and dynamic registration answers `invalid_client_metadata`
  or `invalid_redirect_uri` bare in `error`, with the text in
  `error_description` (RFC 7591 §3.2.2), also for a body its schema refuses. A
  validation failure answers `invalid_request`, the rate limiter's 429
  `temporarily_unavailable`, and a 5xx `server_error`. At `/oauth/authorize`, a
  `client_id` that names no client answers `invalid_request` (it was
  `invalid_client`). Redeeming a code whose user has been deleted answers 400
  `invalid_grant`, as for a disabled user (it was a 404 naming the user's id),
  and so does a code or refresh token another request spent or revoked first
  (it was a 404 `invalid_request`). The `authorization.failed` event of a
  `client_id` that names no client records `error: "invalid_request"`, the
  code the caller is answered (it recorded `invalid_client`). More shapes that
  change at these endpoints:
  - userinfo answers every 401 with `error: "invalid_token"` (it was prose in
    `error`); a request without a token gets a challenge with no error code;
  - `/oauth/register` answers a developer token that is not valid with 401
    `invalid_token`, and the developer's client limit with 403
    `access_denied` (both were prose in `error`); RFC 7591 defines no error
    for the limit;
  - a 421 (a host no realm answers for) answers `invalid_request`, as do a body
    too large (413), an unsupported media type (415) and any other refusal
    Fastify raises before the route runs;
  - a validation failure carries no `details[]` any more; `error_description`
    names the fields.
- A refusal that several routes raise now reads one way everywhere ([#513]): an
  access token whose subject is not an active user answers `invalid_access_token` on a
  problem route and `invalid_token` at userinfo, in one wording that does not
  say whether the account was deleted or disabled; a `subject_token` naming no
  active user answers `invalid_request` in one wording; the consent page refuses
  an unknown client, a refused redirect URI and a malformed `dpop_jkt` with the
  same code as `/oauth/authorize`, and a disabled or suspended client with
  `unauthorized_client` (it was `invalid_client`); a CSRF mismatch answers
  `invalid_csrf_token`.
- The OpenAPI documents list each operation's error responses, referencing the
  shared `Problem` schema, or `OAuthError` on an OAuth protocol endpoint
  ([#513]). Neither schema refuses members it does not name: RFC 9457 §3.2
  and RFC 6749 §5.2 let a type or an extension add some, and a client ignores
  those it does not know.

  **Action for clients**: branch on `code` and the status of a problem document,
  or on `error` and the status of an OAuth body, never on `title`, `detail` or
  `error_description`. The developer portal ships updated with this release.

- **The developer portal's token: the developer audience is accepted** ([#509]).
  `/api/clients`, `/api/consents`, `/auth/logout`, the Bearer path of
  `/oauth/authorize` and userinfo accept a system-client token whose `aud` is
  the developer API's audience, `urn:qauth:aud:developer:v1-rc.0`, beside
  the token of before, whose `aud` is the system client's id. [#524] mints it
  and retires the old token in the same release (above), so the two steps of
  ADR-018 §5 ship together: see that entry for what a rolling upgrade from
  v0.1.x does to portal sessions, and **Upgrades** (`operate/upgrades`).

- **`@qauth-labs/mcp-guard` is now `@qauth-labs/resource-guard`** ([#595],
  ADR-018 §6). It has never been published, so there is no alias. It moved to
  `libs/sdk/resource-guard`, and its names follow: `ResourceGuard`,
  `resourceGuardPlugin`, `ResourceGuardConfig`, `ResourceGuardError`,
  `ResourceGuardConfigError` and the `resourceGuard` Fastify decorator. The root
  entry is the framework-agnostic core and never imports Fastify. The plugin
  moved to `@qauth-labs/resource-guard/fastify`, and `fastify` became an
  optional peer dependency (`jose` stays a dependency). `api-report.md` lists the
  public API, and a test keeps it in step with both entry points. A new
  `scope:sdk` boundary rule lets an SDK library import no workspace library.
  Behaviour is unchanged.
- **BREAKING (operators with scopes in the `qauth:` namespace)**: every scope
  that starts with `qauth:`, in any case, is QAuth's own ([#507]); the admin
  API's scopes live there. Other servers' `admin:` scopes, such as `admin:org`,
  are ordinary scopes. A realm's dynamic registration allowlist cannot hold a
  `qauth:` scope: the boot refuses `DEFAULT_DYNAMIC_REGISTRATION_SCOPES` when it
  names one, and the realms repository refuses one with `400`. So dynamic
  registration drops one like any scope outside the allowlist and registers the
  client with the rest; a Client ID Metadata Document's `scope` is never stored,
  so one there is ignored; the developer API (`POST /api/clients`,
  `PATCH /api/clients/{id}`) refuses one as a scope the realm does not allow,
  with the 400 `invalid_client_metadata` problem document ([#513]); discovery
  never lists one in `scopes_supported`; and the seed manifest refuses one in a
  `cimd_clients` entry's `scopes`. Migration 0040 removes such entries from
  every realm's `dynamic_registration_allowed_scopes`, keeping the others in
  their order, then adds the CHECK
  `realms_dynamic_registration_scopes_not_qauth`. An empty allowlist is filled
  from `DEFAULT_DYNAMIC_REGISTRATION_SCOPES` at the next registration, so where
  the removal would leave a list empty, or the value is not a list, the
  migration stops before changing anything and names the realms. Clients that
  already hold such a scope keep it.

  **Action for operators**: none unless a scope of yours starts with `qauth:`.
  Rename it. Remove it from `DEFAULT_DYNAMIC_REGISTRATION_SCOPES` before the
  upgrade, or the new release does not boot. If migration 0040 stops, set each
  realm it names to the list of scopes dynamic registration should allow, as
  its hint shows, and run the migrations again.

- `PATCH /api/clients/{id}` checks only the scopes it adds against the realm's
  allowlist ([#507]). A client keeps a scope the realm no longer allows, or one
  an operator gave it, while its owner renames it or sends its scopes back
  unchanged; before, such a request was refused.

- **BREAKING (operators who read `audit_logs`)**: the auth server records what
  a person or a client did as events in the event store ([#458], ADR-019
  Decision 8) and writes no `audit_logs` row. One emitter, `emitUserEvent`,
  replaces the 89 writes in `apps/auth-server` and the client-suspension tool's:
  it fills the realm, the request id as trace id, the client address and
  `User-Agent`, the subject, the client and the actor, with the RFC 8693
  delegation chain of a delegated request. Where a change has a transaction,
  its event commits in it: a registration (now recorded too, as
  `user.registered`), an authorization code's issue and redemption, a refresh
  rotation, a consent revocation and a wallet link. A redemption and a
  rotation sign their tokens in that transaction too, after the code or the
  refresh token is spent and before the event, so a token that cannot be
  signed rolls them back: the code or the refresh token stays usable, and no
  `token.issued` records a token that was never made. Every other write is
  awaited and fails the request when it fails, as the audit write did; the
  developer API's client and API key events stay best-effort. A failure event
  carries the OAuth `error` and a `reason` code instead of an exception
  message, and an event no longer holds the address a failed sign-in typed, a
  session id or a token subject. What a refused client or identity assertion
  said about itself goes to the server log. The structured log lines of
  `logAuthEvent` are unchanged.

  Migration 0031 copies every `audit_logs` row into `events`, with the type the
  event contract's map gives its name, its time, and the realm of its user, its
  client or the default realm. `data` keeps only the members the type
  declares; a required member an old row cannot supply gets a fixed value
  (`unknown` for a code). The table stays, read-only, until a contract
  migration drops it after one release.

  **Action for operators**: move any query, export or alert that reads
  `audit_logs` to `events`; the Events page (`reference/events`) maps each old
  name to its type. Rows a previous release writes while the upgrade rolls out,
  after migration 0031 has run, stay in `audit_logs`; the copy is idempotent, so
  running its statement again picks them up.

- `REQUIRE_EMAIL_VERIFIED` is now an alias in the key registry, resolved by the
  same mechanism every future rename uses, instead of code of its own. It
  behaves as before: the old name alone works and logs a deprecation warning,
  and the two names set to different values fail the boot, naming both.
  `resolveRequireVerifiedAccount` is removed from `@qauth-labs/server-config`;
  `readConfiguredEnv` and `applyKeyAliases` replace it.

- The auth-server refuses to start when the default realm's passkeys are
  bound to another RP ID than `WEBAUTHN_RP_ID` gives ([#467]), and the
  `default realm ready` line names the passkey RP ID. A realm has a lock only
  after its first passkey enrolment, which no release can make yet, so no
  existing deployment is affected.
- The passkey RP ID is now a setting on each realm, with a lock of its own
  ([#553], ADR-019 Decision 2). `realms.webauthn_rp_id` holds the RP ID, NULL
  for the realm host; the boot step stores `WEBAUTHN_RP_ID` there while the
  realm has no passkey. Migration 0034 adds `realms.webauthn_rp_id_locked_at`,
  which the first passkey enrolment sets in the transaction that stores the
  passkey; from then on a trigger refuses any change of the RP ID or of the
  lock. A realm that migration 0028 had locked stays locked under the same
  RP ID. A parent-domain RP ID that is a public suffix (`co.uk`, or a
  private-section entry of the Public Suffix List) is now refused even with
  `WEBAUTHN_RP_ID_ALLOW_PARENT_DOMAIN=true`; before, only a single label was.
- **BREAKING**: the auth-server refuses to start when the default realm's
  stored issuer differs from `JWT_ISSUER` ([#484]). A realm's issuer and its
  host are permanent, and the error names both values. It also refuses a
  `JWT_ISSUER` that cannot be a realm issuer (plain `http` off `localhost`, an
  IP address as the host, a query or a fragment), and a `JWT_ISSUER` host or a
  `DEFAULT_REALM_ENDPOINT_HOSTS` name that another realm already has. The step
  needs the database, so a server that cannot reach it no longer starts.

  **Action for operators**: keep `JWT_ISSUER` as it is at the first boot after
  the upgrade, and make it an `https` URL on a host name (`http://localhost`
  serves development). A trailing slash or a path keeps working, with a boot
  warning: the realm stores the issuer without the slash, while tokens carry
  `JWT_ISSUER` as written.

- **BREAKING**: the auth-server needs a key-encryption key (KEK) ([#485]).
  `NODE_ENV=production` refuses to start without `KEK` or `KEK_PATH` (or a
  `KEK_PROVIDER` adapter), and in every environment the boot stops, naming the
  variables, when a key variable must be imported and the KEK is the published
  development KEK. The boot also stops when `JWT_PUBLIC_KEY` or
  `JWT_RS256_PUBLIC_KEY` is not the public half of its private key, when
  `JWT_RS256_PRIVATE_KEY` is shorter than 2048 bits, when a new key comes
  with a `JWT_RS256_KID` or `JWT_MLDSA_KID` that already names a stored key,
  and, with hybrid signing on, when only one key of the pair is new.

  **Action for operators**: before upgrading, set `KEK` or `KEK_PATH` to the
  base64 of 32 random bytes (`openssl rand -base64 32`) and keep a copy where
  you keep backups: every stored key is wrapped with it, and without it the
  keys cannot be read. Docker Compose passes `KEK`, `KEK_PATH` and their
  `_PREVIOUS` forms through. Leave the key variables as they are.

- **BREAKING**: the auth-server answers `421 Misdirected Request` for any host
  that is not a realm's host or endpoint host ([#486]). In simple mode those are
  the host of `JWT_ISSUER` and the names in `DEFAULT_REALM_ENDPOINT_HOSTS`. A
  disabled realm gets 421 too, and an endpoint host answers 421 for the
  browser-session routes. The 421 carries no cookie and no realm data, and
  there is no fallback to the default realm. Only `/health` answers on every
  host; a request for a route that does not exist still gets 404.

  **Action for operators**: list in `DEFAULT_REALM_ENDPOINT_HOSTS` every other
  name or address a server-side caller uses to reach the auth-server: the
  developer portal's `AUTH_SERVER_URL` host (the Compose file sets
  `auth-server`), resource servers that call introspection or the JWKS
  through an internal name, and the Prometheus scrape target of `/metrics`.
  A reverse proxy must keep the client's `Host`, or set `X-Forwarded-Host`
  itself from an address listed in `TRUST_PROXY`. For local development, set
  `JWT_ISSUER=http://localhost:3000`.

- **Every handler takes the realm of the request's host** ([#487], ADR-019
  Decision 1). `getOrCreateDefaultRealm` is gone: the token, introspection,
  revocation, registration, sign-in, consent and wallet routes and the
  management API use the realm the host named, and `DEFAULT_REALM_NAME` only
  names the default realm at boot (a lint rule refuses any other read). A
  deployment with one realm behaves as before. With a second realm:
  - clients and accounts are found in the host's realm only, so the same
    `client_id` in two realms names two clients;
  - `POST /auth/register` creates the account in the host's realm, and a body
    `realmId` that names another realm answers 400;
  - a developer-portal management token works only at the host of its user's
    realm, and is refused with 401 elsewhere;
  - failed-login counters and lockouts, and every rate-limit bucket, are kept
    per realm: the same address and source in two realms count apart.

  Realm settings read on the request path (the environment ceiling of ADR-008
  and the rate-limit tier it sets) come from the row the host lookup cached, so
  an operator's change applies within the host cache time (30 seconds) rather
  than on the next request; the dynamic registration scope list is still read
  from the database. The failed-login and rate-limit counters start from zero
  after the upgrade, as their Redis keys now carry the realm id.

- **BREAKING (deployments whose `EMAIL_BASE_URL` is not `JWT_ISSUER`)**: the
  link in a verification mail starts at the issuer of the account's realm
  ([#490], ADR-019 Decisions 1 and 6), `<issuer>/auth/verify?token=…`, never at
  `EMAIL_BASE_URL`. For the default realm that issuer is `JWT_ISSUER` without a
  trailing slash, so a deployment that set `EMAIL_BASE_URL` to another base sees
  its links move, and the boot logs a warning saying so. With the shipped
  defaults the two are equal and the link is unchanged.
  - The link now lands on the auth server's own `GET /auth/verify` page (see
    Fixed below). Only an operator's own page or proxy that answered
    `GET /auth/verify` on the `EMAIL_BASE_URL` host made the old link work, and
    such a deployment now gets QAuth's page instead.
  - `EMAIL_BASE_URL` is optional and no longer read. It is still accepted, and
    the boot warns when it is set to another base than `JWT_ISSUER`.
  - The verification token of such a link is censored in every log line, the
    request line and the unknown-route line included.
  - The mail library's `sendVerificationEmail` takes the link base with each
    mail instead of from its configuration.

- **Every URL comes from the realm row** ([#490], ADR-019 Decision 1). The
  issuer and endpoint URLs in discovery and in the SSF transmitter metadata,
  the RFC 9207 `iss` of an authorization response, the userinfo audience, the
  client-assertion audience, both sides of ID-JAG, the wallet `response_uri`,
  `request_uri` and same-device return URI, the link in a verification mail and
  the base a DPoP proof's `htu` is checked against are built on the issuer of
  the realm the request's host named. After boot nothing reads `JWT_ISSUER`,
  `EMAIL_BASE_URL` or the `Host` header to build a URL. A lint rule refuses
  reading the request's authority outside the realm resolver, through type
  assertions too: `request.host`, `.hostname`, `.port`, `.protocol` and
  `.rawHeaders`, the `Host`, `:authority` and `Forwarded` headers,
  `X-Forwarded-*` and a socket's `encrypted`. A deployment with one realm sees
  the same URLs as before, mail links aside (above).

  The issuer pins of introspection, revocation, logout, the token-exchange
  subject token, the Bearer path of `/oauth/authorize` and the API family
  guards (`requireFamilyToken`) name the request realm's issuer, which since
  [#491] is the `iss` of every token the realm issues (below).

- **Discovery and the JWKS are the same on every node** ([#494], ADR-019
  Decisions 1, 8 and 9). `/.well-known/oauth-authorization-server`,
  `/.well-known/openid-configuration` and `/.well-known/jwks.json`, served per
  realm since [#490] and [#491], are built from the realm's row, its published
  keys (`realm_public_keys`) and the deployment's settings, and from nothing
  else a node holds. So every node that serves them (the `api` role), with the
  signer or without ([#495]), answers the same bytes for the same realm under
  the same settings; after a key change a node may serve its previous key list
  for up to a minute. The JWKS lists the realm's active keys, a next key from
  its publication, before it signs, and a retired key while it stays published
  ([#492]); `id_token_signing_alg_values_supported` follows its active keys. A
  host that names no realm gets 421 for all three ([#486]). An endpoint host
  gets its realm's documents unchanged, with the realm's issuer inside: a
  server-side caller that fetches them there must configure that issuer
  explicitly, since RFC 8414 §3.3 expects the issuer of the URL it fetched.
  `CIMD_ENABLED`, `ID_JAG_ENABLED` and `DPOP_ENABLED` stay deployment
  settings, which every realm advertises alike. The caching is unchanged:
  `public, max-age=300` on the JWKS and `public, max-age=3600` on the
  discovery documents.

- **An id from another realm is an unknown id** ([#489], ADR-019 Decision 1).
  The lookups by an id that a request, a token or a code carries now take the
  realm of the request's host: users, clients, consents, API keys,
  credentials, refresh tokens, authorization codes, email verification tokens
  and a wallet's OID4VP state, encryption `kid` and Response Code. Browser
  sessions, whose id a cookie carries, are not scoped yet ([#493]). The
  repository methods take the realm id as a required first argument;
  refresh tokens, codes and verification tokens, which have no realm column,
  are found through their client's or credential's realm. A value of another
  realm gets the answer an unknown value gets, leaves the same events and
  changes nothing in its own realm:
  - an authorization code or a refresh token issued in another realm answers
    `invalid_grant`; presenting the refresh token there, or revoking it, revokes
    no family;
  - another realm's access token is `active: false` at introspection and 401
    at userinfo, and revocation and `/auth/logout` ignore or refuse it: these
    routes and token exchange check the token's `iss` against the request
    realm's token issuer, and since [#491] verify it only with the request
    realm's keys;
  - a consent, client or API key id of another realm answers 404 at the
    management API, and a verification token mailed for another realm's
    account is an invalid token;
  - a management token whose user belongs to another realm is now refused as a
    token for an unknown user is ("Access token subject is not an active
    user"), no longer with "Access token was not issued in this realm".

  The verification-mail counters of `POST /auth/resend-verification` and
  `POST /auth/register` (`rate-limit:resend:*`, `last-email-sent:*`) carry the
  realm id, so an address has an allowance in each realm; they start from zero
  after the upgrade, and during a rolling upgrade old and new nodes count
  apart for one window. A deployment with one realm behaves as before. Tokens
  are signed per realm ([#491], above), so each realm's host accepts its own
  realm's tokens only: a `client_credentials` token of a same-named client in
  another realm is `active: false` at the default realm's introspection, and
  its revocation there denylists nothing.

- **Browser sessions are stored in Postgres** ([#488], ADR-019 Decision 3).
  `POST /ui/login` and the wallet sign-in create the session through the
  session service ([#469]): one `sessions` row with the realm, the user,
  `auth_time`, the assurance level a wallet credential established, and the
  sign-in request's address and `User-Agent`. Every route that reads the
  session cookie (`/oauth/authorize`, the consent screen, `/consents`, wallet
  linking) finds the session through the service, in the realm of the
  request's host: a cookie of another realm names no session there, and a
  realm's `sso_max_lifespan` and `sso_idle_timeout` now end its sessions. The
  consent screen's CSRF token and the scopes and resources it showed, the
  consent API's CSRF token and the address shown as "Signed in as" are kept in
  a Redis record beside the session, which expires with it and never reaches
  Postgres. `/oauth/token` and `POST /auth/login` no longer write a session:
  nothing read those. `POST /auth/logout` revokes the user's sessions through
  the service, and a session of a disabled user is revoked when its cookie is
  next used.

  **Action for operators**: none, but the sessions the previous version kept
  in Redis are not moved. Everyone signed in to the hosted pages signs in once
  more after the upgrade; tokens and consents are unaffected (see the upgrade
  guide).

- **BREAKING (realms that set `sso_max_lifespan`)**: the realm's
  `sso_max_lifespan` now caps its refresh-token families too ([#552], ADR-019
  Decision 3). A family is every refresh token descended from one code
  exchange or `POST /auth/login`; the new `refresh_tokens.family_created_at`
  (migration 0038) records when it started, and every rotation keeps it. A
  family also ends no later than the browser session that backed its code: the
  code records the session's absolute end (`authorization_codes.session_expires_at`)
  and the family keeps it (`refresh_tokens.family_session_expires_at`), so a
  silent re-authorization just before the session's end starts a family that
  ends with the session. A family no browser session started (`POST /auth/login`)
  has only its start plus the limit. A token issued in the family expires no
  later than that end, and a refresh at or past it revokes the whole family and
  answers `invalid_grant` (the `token.request_failed` event's reason is
  `refresh_family_expired`). Replay detection runs first, as before. The limit
  is read from the realm at each refresh, within the host cache time, so
  lowering it ends older families at their next refresh. A realm with no
  `sso_max_lifespan` keeps the sliding `REFRESH_TOKEN_LIFESPAN`, and the
  session's end does not cap its families either. Families that exist at the
  upgrade have no recorded session end, so their start plus the limit caps them
  alone. During a rolling upgrade the previous release does not write the new
  columns: a trigger gives its insert the start and session end of the family
  the token joins, or the current time and no session end for a new family.
- **BREAKING (realms with `sso_max_lifespan` or `sso_idle_timeout` of zero or
  less)**: a realm's `sso_max_lifespan` and `sso_idle_timeout` must now each be
  null (no limit) or a positive number of seconds ([#552]). Migration 0038
  turns a value of zero or less into null, then adds the CHECKs
  `realms_sso_max_lifespan_positive` and `realms_sso_idle_timeout_positive`;
  the realms repository refuses such a value with `400` before it reaches the
  database. Before, a maximum of zero ended every session and every
  refresh-token family at its start, and an idle timeout of zero ended every
  session at its first request after sign-in.
- **Migration 0038 pauses refresh-token traffic** ([#552]). It fills
  `family_created_at` for every row of `refresh_tokens` in one statement,
  inside the runner's transaction, with the table locked until it commits.
  Measured on a 12-vCPU virtual machine against a default `postgres:18-alpine`
  container: 5.7 s for 100,000 rows, 100 s for 1,000,000. It first locks
  `authorization_codes` and then `refresh_tokens`, the order a code redemption
  takes them in, so a redemption in flight waits for it instead of deadlocking
  with it; minting and redeeming codes wait for the same pause. A database
  that ran 0038 from `main` before its locks moved to the start is unaffected:
  the change only reorders its locks. See the upgrade guide
  (`operate/upgrades`) before upgrading a large deployment.

  **Action for operators**: none for a realm without `sso_max_lifespan`. In a
  realm that sets it, a family already older than the limit ends at its next
  refresh after the upgrade, and its client sends the user through
  `/oauth/authorize` again. Nodes of the previous release do not enforce the
  limit, so it applies once the last of them is gone.

- **A replayed authorization code revokes the tokens it issued** ([#627],
  ADR-017 Decision 10). A second redemption of a code was refused with
  `invalid_grant` but revoked nothing, because the token endpoint could not
  tell a spent code from an unknown one. It now reads spent codes too, and a
  second redemption that is otherwise a valid request (the code's own client,
  its `redirect_uri`, the right `code_verifier`, the DPoP key the code is bound
  to, a `resource` inside its binding) answers `invalid_grant` and revokes
  every refresh token descended from the first redemption, rotations included,
  and every access token issued from the code or in that family (OAuth 2.1
  §4.1.3, RFC 6749 §4.1.2). Each access token's `jti` and `exp` are recorded
  in Redis when it is issued; the replay puts the unexpired ones on the
  revocation denylist, so userinfo, introspection, token exchange and the
  bearer-protected routes refuse them. An access token issued while Redis
  could not record it, or a replay while Redis cannot be written, leaves the
  token valid until it expires; both are logged, and issuance does not wait on
  a Redis failure to succeed. The `token.request_failed` event's reason is
  `code_replay`; its new optional members `refreshFamilyId` and
  `revokedRefreshCount` name the family and how many of its tokens the replay
  revoked, and the event commits in the transaction of that revocation. A
  replay that fails
  any of those checks answers `invalid_grant` as before, with that check as its
  reason, and revokes nothing, so whoever saw a code without the client's
  credentials or verifier cannot end the client's tokens (OAuth 2.1 §7.5.3). A
  redemption that loses the race to a concurrent one is the same replay, and
  revokes the family the winner started. A refusal that burns the code (user
  disabled, agent scope cap) and loses that race keeps its own answer,
  `invalid_grant` or `invalid_scope`. A replay is recognised until the hourly
  purge job deletes the code, at the
  earliest when it expires (`AUTHORIZATION_CODE_TTL_MS`, 5 minutes); after
  that the code is unknown and revokes nothing. `code_replay` is also the
  reason for a code that a logout, a consent revocation or a refused
  redemption (user disabled, agent scope cap) had spent: the server records no
  difference, and such a code started no family, so nothing is revoked for it.
  Migration 0041 adds the link that makes
  this possible, `refresh_tokens.authorization_code_id` (nullable, set on the
  first token of each family, `ON DELETE SET NULL` when the purge job deletes
  the code). Families started before the upgrade, or by a node of the previous
  release during a rolling upgrade, have no link, so a replay of their code is
  refused but revokes nothing. The conformance matrix's RFC 9700 waiver for
  this becomes a covered row, beside new OAuth 2.1 and RFC 6749 rows.
  Migration 0041 locks `authorization_codes` and then `refresh_tokens` before
  it changes them, the order a redemption takes them in, so a redemption in
  flight during the upgrade waits for it instead of deadlocking with it.
- **A replayed refresh token also revokes the access tokens of its family**
  ([#627]). Presenting a refresh token that is no longer live revoked the
  family's refresh tokens (RFC 9700 §4.14.2); every access token issued in the
  family that has not expired is now put on the denylist too, as for a
  replayed code. The `token.request_failed` event (reason `refresh_replay`)
  carries `refreshFamilyId` and `revokedRefreshCount`, and commits with the
  revocation.
- **`POST /oauth/token`: an authorization code presented without
  `redirect_uri` answers `invalid_grant`** ([#627], ADR-017 Decision 10). The
  request schema required the parameter, so a missing one was refused as a
  malformed request (`400 VALIDATION_ERROR` in v0.1, `invalid_request` with
  the RFC 6749 error bodies of [#513]). Every code QAuth issues came through a
  browser redirect and still needs the URI the authorization request named, so
  a missing or empty value is now a mismatch: `400 invalid_grant`, like a
  different value, with the `error_description` `redirect_uri is required for
  this code`, and the code is not spent. A client that follows OAuth 2.1 alone,
  which drops the parameter, is still refused, and the description tells it
  what to send.
- Every authorization code is minted by one helper, `mintAuthorizationCode`
  ([#627], ADR-017 Decision 10), which refuses to write a code without an S256
  PKCE challenge of 43 to 128 unreserved characters (RFC 7636 §4.2) in every
  environment. `/oauth/authorize` validated the challenge that way already. The
  consent screen's form checked only its length, so a hand-built
  `POST /ui/consent` with a challenge outside that character set was given a
  code that could never be redeemed; it now answers a `400` `validation_error`
  problem document ([#513]). A consent screen the server rendered always
  carries a valid challenge, so nothing a browser sends changes. The published
  OpenAPI document gains the same `pattern` on that form's `code_challenge`, an
  approved stable-surface break.

- **BREAKING**: the auth-server refuses to start when `DB_POOL_MAX` is below 2
  ([#452]). A running background job holds one pool connection for its lock,
  so a pool of one would leave requests waiting until the job ends. The error
  names the variable.

  **Action for operators**: set `DB_POOL_MAX` to 2 or more, or leave it unset
  (the default is 20).

- **BREAKING (security)**: the auth-server refuses to start when `NODE_ENV` is
  `production` and `CIMD_ALLOW_PRIVATE_ADDRESSES` or
  `ID_JAG_ALLOW_PRIVATE_ADDRESSES` is `true` ([#435]). Both switches turn the
  SSRF guard off on outbound fetches so tests can use a localhost server. The
  error names the variable. `development` and `test` accept both as before.

  **Action for operators**: unset both switches in production. Docker Compose
  defaults `NODE_ENV` to `production`, so a local stack that needs one sets
  `NODE_ENV=development` in `.env`.

- **BREAKING (security)**: `CIMD_ALLOW_PRIVATE_ADDRESSES` and
  `ID_JAG_ALLOW_PRIVATE_ADDRESSES` are removed ([#481]). Set to any value, in
  any `NODE_ENV`, either one stops the boot with a message that names
  `EGRESS_ALLOWLIST_PATH`. The CIMD document, client `jwks_uri` and ID-JAG
  issuer fetches go through the egress client (ADR-019 Decision 8) instead of
  the auth server's own fetcher. A metadata document or `jwks_uri` never reaches
  a private address. A trusted ID-JAG issuer's discovery URL may, through an
  allowlist entry naming the realm, but the `jwks_uri` its document names may
  not, so an issuer whose keys are on a private network cannot be used yet. The
  fetches now also refuse documentation and other reserved ranges
  (`203.0.113.0/24` and the rest of the egress address table), send
  `User-Agent: qauth-egress`, and run in the egress client's fetch processes: up
  to 8, about 70 MB each while busy, exiting after a minute idle.

  **Action for operators**: remove both variables. An operator-set private
  destination goes into the allowlist file.

- **BREAKING (ID-JAG; only with `ID_JAG_ENABLED`, which is off by default)**:
  a client's ID-JAG targets have a column of their own, `oauth_clients.id_jag_targets`
  (migration 0027, [#434], [ADR-011](./docs/adr/011-enterprise-managed-authorization.md)
  §3). Minting reads it for the `audience` and `resource` a client may name, and
  the `jwt-bearer` grant reads it for the `resource` an assertion may be redeemed
  for. Both used to read `oauth_clients.audience`, which also bounds
  `client_credentials`, so listing a foreign authorization server for ID-JAG let
  the client request QAuth access tokens naming it. `audience` now grants no
  ID-JAG target, and `id_jag_targets` grants no `client_credentials` audience.
  An empty list denies both sides. Only the seed manifest's `clients` entries
  set the column; dynamic registration, `POST /api/clients`, CIMD documents and
  `cimd_clients` entries cannot. The migration copies nothing from `audience`.

  **Action for operators**: for each client that mints or redeems ID-JAGs, add
  `id_jag_targets` to its manifest entry and re-run it with `--rotate`, which
  also issues a new secret, or set the column by hand. See the operator guide
  (`operate/docker`, "Provisioning a client for ID-JAG").

- **BREAKING (only where `ID_JAG_JWKS_CACHE_TTL` is set above 3600)**: the
  ID-JAG issuer key resolver bounds how often it dials an issuer ([#433],
  [ADR-011](./docs/adr/011-enterprise-managed-authorization.md) §4). An
  assertion whose `kid` is not in the cached key set forces a refresh of the
  issuer's discovery document and JWKS at most once per issuer per
  `ID_JAG_JWKS_REFRESH_COOLDOWN` (default 30 seconds); inside the cooldown it is
  refused without a fetch. Before, every such assertion cost the issuer two
  fetches, and the refresh runs before the signature is checked. A failed fetch
  is now remembered for `ID_JAG_JWKS_NEGATIVE_CACHE_TTL` (default 30 seconds),
  during which nothing is fetched from that issuer, and requests that arrive
  together in one process share the fetch already running, so an outage costs
  one attempt per window instead of two fetches, each up to
  `ID_JAG_FETCH_TIMEOUT_MS`, on every token request. Both new settings take 1 to
  300 seconds. The cooldown bounds forced refreshes only: with
  `ID_JAG_JWKS_CACHE_TTL=0` nothing is cached and every assertion still costs
  the issuer two fetches. `ID_JAG_JWKS_CACHE_TTL` now has a ceiling of 3600 seconds, as
  `CIMD_CACHE_MAX_TTL` does for CIMD, and the auth-server refuses to start with
  a larger value; the error names the variable.

  **Action for operators**: set `ID_JAG_JWKS_CACHE_TTL` to 3600 or less, or
  leave it unset (the default is 300). An identity provider that rotates its
  signing key should publish the new key in its JWKS at least one cooldown
  before it signs with it; otherwise an assertion under the new key can be
  refused for up to one cooldown.

- **BREAKING (operators who run commands through the migration-runner
  image)**: the image no longer holds the workspace, pnpm or nx ([#474]), so
  `docker compose run --entrypoint pnpm migration-runner nx run …` no longer
  works. Its entrypoint is `node /app/main.js`, and arguments after the image
  name go to the runner, such as `--check`.

  **Action for operators**: run operator commands such as
  `db:seed-oauth-clients` from a checkout with pnpm installed, against the
  deployment's `DATABASE_URL`; `apps/wire-suite/README.md` shows the seed
  against the compose database.

- The images and CI run on Node.js 26 and pnpm 12.14.0, up from Node.js 24 and
  pnpm 11. Node 26 no longer ships corepack, so each image installs pnpm from
  npm at that exact version while it builds. The migration-runner image no
  longer downloads pnpm each time it runs, which also made it fail whenever
  the npm registry was slow. `engines` now asks for Node.js ≥ 26.10.0 and
  pnpm ≥ 12.14.0.

  **Action for contributors**: install Node.js 26 (`nvm use` reads `.nvmrc`)
  and `npm install --global pnpm@12.14.0`.

- Lint and formatting run on Oxc. Oxlint checks the rules ESLint checked,
  through the same `lint` target, and Oxfmt formats what Prettier formatted,
  with the same options and Tailwind class order. ESLint keeps one rule,
  `@nx/dependency-checks` on package.json files, as the new `dependency-checks`
  target. CI now checks the formatting of every file, Markdown and YAML
  included, in a new `format` job; before, it checked only the files ESLint
  linted. `.prettierrc` and `.prettierignore` are gone: the settings are in
  `.oxlintrc.json` and `.oxfmtrc.json`, and `pnpm format` and the pre-commit
  hook run Oxfmt. The switch reformats 28 files once; `.git-blame-ignore-revs`
  lists that commit.

  **Action for contributors**: run `pnpm install`, then point your editor's
  linter and formatter at Oxlint and Oxfmt. A Prettier extension left on would
  format with Prettier's defaults, since the repository no longer has a
  Prettier config.

- Type-checking runs on TypeScript 7. Every `typecheck` target but the docs
  site's runs `tsgo`, TypeScript 7's native compiler from
  `@typescript/native-preview`, in place of `tsc`, and so do the ui and
  mcp-guard builds, which emit the same JavaScript as before. Nx's plugins,
  `astro check` and the auth server's esbuild build, which type-checks before
  it bundles, keep the `typescript` 6.0 package. `tsconfig.base.json` resolves
  modules with `"bundler"`, because TypeScript 7 removed `"node"`, and no
  longer sets `ignoreDeprecations`.

  **Action for contributors**: run `pnpm install`. Typecheck targets now run
  tsgo, while an editor checks with the TypeScript it is set to. Point it at
  the workspace's TypeScript 6.0 or at TypeScript 7: TypeScript 5 rejects
  `"bundler"` with the libraries' `module: commonjs` (TS5095).

- CI's `affected` legs use a self-hosted Nx remote cache ([#960]), a server
  speaking Nx's HTTP cache spec. A push to main reads and writes it with a
  write token only main can reach (the `protected` environment); every other
  run reads at most, with a token the server refuses to store with, so a pull
  request replays what main built and checked and never stores its own
  results. Nx talks to the server through a local proxy
  (`.github/actions/nx-remote-cache`) that turns an unreachable or failing
  server into cache misses, so losing the cache makes CI slower and never red.
  The docs site's `build` is now cacheable, with the docs records and the
  root-level Markdown files as declared inputs.

  **Action for contributors**: nothing. Local runs do not use the remote cache.

- A newer push to the same pull request or branch now cancels the CI run of
  the push it supersedes. Merging a stack pushes main once per pull request,
  and each push started a full run; together they filled the account's
  concurrent-job limit, so the last run, the one whose result counts, waited
  for runners.

[#359]: https://github.com/qauth-labs/qauth/issues/359
[#410]: https://github.com/qauth-labs/qauth/issues/410
[#433]: https://github.com/qauth-labs/qauth/issues/433
[#434]: https://github.com/qauth-labs/qauth/issues/434
[#435]: https://github.com/qauth-labs/qauth/issues/435
[#448]: https://github.com/qauth-labs/qauth/issues/448
[#449]: https://github.com/qauth-labs/qauth/issues/449
[#451]: https://github.com/qauth-labs/qauth/issues/451
[#452]: https://github.com/qauth-labs/qauth/issues/452
[#456]: https://github.com/qauth-labs/qauth/issues/456
[#457]: https://github.com/qauth-labs/qauth/issues/457
[#458]: https://github.com/qauth-labs/qauth/issues/458
[#459]: https://github.com/qauth-labs/qauth/issues/459
[#460]: https://github.com/qauth-labs/qauth/issues/460
[#461]: https://github.com/qauth-labs/qauth/issues/461
[#462]: https://github.com/qauth-labs/qauth/issues/462
[#464]: https://github.com/qauth-labs/qauth/issues/464
[#467]: https://github.com/qauth-labs/qauth/issues/467
[#468]: https://github.com/qauth-labs/qauth/issues/468
[#469]: https://github.com/qauth-labs/qauth/issues/469
[#470]: https://github.com/qauth-labs/qauth/issues/470
[#474]: https://github.com/qauth-labs/qauth/issues/474
[#475]: https://github.com/qauth-labs/qauth/issues/475
[#476]: https://github.com/qauth-labs/qauth/issues/476
[#477]: https://github.com/qauth-labs/qauth/issues/477
[#478]: https://github.com/qauth-labs/qauth/issues/478
[#479]: https://github.com/qauth-labs/qauth/issues/479
[#480]: https://github.com/qauth-labs/qauth/issues/480
[#481]: https://github.com/qauth-labs/qauth/issues/481
[#482]: https://github.com/qauth-labs/qauth/issues/482
[#484]: https://github.com/qauth-labs/qauth/issues/484
[#485]: https://github.com/qauth-labs/qauth/issues/485
[#486]: https://github.com/qauth-labs/qauth/issues/486
[#487]: https://github.com/qauth-labs/qauth/issues/487
[#488]: https://github.com/qauth-labs/qauth/issues/488
[#489]: https://github.com/qauth-labs/qauth/issues/489
[#490]: https://github.com/qauth-labs/qauth/issues/490
[#491]: https://github.com/qauth-labs/qauth/issues/491
[#493]: https://github.com/qauth-labs/qauth/issues/493
[#494]: https://github.com/qauth-labs/qauth/issues/494
[#495]: https://github.com/qauth-labs/qauth/issues/495
[#496]: https://github.com/qauth-labs/qauth/issues/496
[#497]: https://github.com/qauth-labs/qauth/issues/497
[#498]: https://github.com/qauth-labs/qauth/issues/498
[#500]: https://github.com/qauth-labs/qauth/issues/500
[#501]: https://github.com/qauth-labs/qauth/issues/501
[#507]: https://github.com/qauth-labs/qauth/issues/507
[#508]: https://github.com/qauth-labs/qauth/issues/508
[#509]: https://github.com/qauth-labs/qauth/issues/509
[#510]: https://github.com/qauth-labs/qauth/issues/510
[#511]: https://github.com/qauth-labs/qauth/issues/511
[#512]: https://github.com/qauth-labs/qauth/issues/512
[#513]: https://github.com/qauth-labs/qauth/issues/513
[#514]: https://github.com/qauth-labs/qauth/issues/514
[#516]: https://github.com/qauth-labs/qauth/issues/516
[#517]: https://github.com/qauth-labs/qauth/issues/517
[#520]: https://github.com/qauth-labs/qauth/issues/520
[#521]: https://github.com/qauth-labs/qauth/issues/521
[#522]: https://github.com/qauth-labs/qauth/issues/522
[#524]: https://github.com/qauth-labs/qauth/issues/524
[#527]: https://github.com/qauth-labs/qauth/issues/527
[#528]: https://github.com/qauth-labs/qauth/issues/528
[#529]: https://github.com/qauth-labs/qauth/issues/529
[#534]: https://github.com/qauth-labs/qauth/issues/534
[#535]: https://github.com/qauth-labs/qauth/issues/535
[#536]: https://github.com/qauth-labs/qauth/issues/536
[#540]: https://github.com/qauth-labs/qauth/issues/540
[#541]: https://github.com/qauth-labs/qauth/issues/541
[#542]: https://github.com/qauth-labs/qauth/issues/542
[#545]: https://github.com/qauth-labs/qauth/issues/545
[#546]: https://github.com/qauth-labs/qauth/issues/546
[#549]: https://github.com/qauth-labs/qauth/issues/549
[#550]: https://github.com/qauth-labs/qauth/issues/550
[#552]: https://github.com/qauth-labs/qauth/issues/552
[#553]: https://github.com/qauth-labs/qauth/issues/553
[#560]: https://github.com/qauth-labs/qauth/issues/560
[#568]: https://github.com/qauth-labs/qauth/issues/568
[#577]: https://github.com/qauth-labs/qauth/issues/577
[#578]: https://github.com/qauth-labs/qauth/issues/578
[#590]: https://github.com/qauth-labs/qauth/issues/590
[#591]: https://github.com/qauth-labs/qauth/issues/591
[#592]: https://github.com/qauth-labs/qauth/issues/592
[#593]: https://github.com/qauth-labs/qauth/issues/593
[#595]: https://github.com/qauth-labs/qauth/issues/595
[#596]: https://github.com/qauth-labs/qauth/issues/596
[#599]: https://github.com/qauth-labs/qauth/issues/599
[#600]: https://github.com/qauth-labs/qauth/issues/600
[#601]: https://github.com/qauth-labs/qauth/issues/601
[#614]: https://github.com/qauth-labs/qauth/issues/614
[#615]: https://github.com/qauth-labs/qauth/issues/615
[#616]: https://github.com/qauth-labs/qauth/issues/616
[#624]: https://github.com/qauth-labs/qauth/issues/624
[#627]: https://github.com/qauth-labs/qauth/issues/627
[#628]: https://github.com/qauth-labs/qauth/issues/628
[#629]: https://github.com/qauth-labs/qauth/issues/629
[#631]: https://github.com/qauth-labs/qauth/issues/631
[#633]: https://github.com/qauth-labs/qauth/issues/633
[#634]: https://github.com/qauth-labs/qauth/issues/634
[#635]: https://github.com/qauth-labs/qauth/issues/635
[#636]: https://github.com/qauth-labs/qauth/issues/636
[#637]: https://github.com/qauth-labs/qauth/issues/637
[#639]: https://github.com/qauth-labs/qauth/issues/639
[#640]: https://github.com/qauth-labs/qauth/issues/640
[#641]: https://github.com/qauth-labs/qauth/issues/641
[#642]: https://github.com/qauth-labs/qauth/issues/642
[#643]: https://github.com/qauth-labs/qauth/issues/643
[#646]: https://github.com/qauth-labs/qauth/issues/646
[#649]: https://github.com/qauth-labs/qauth/issues/649
[#651]: https://github.com/qauth-labs/qauth/issues/651
[#653]: https://github.com/qauth-labs/qauth/issues/653
[#655]: https://github.com/qauth-labs/qauth/issues/655
[#662]: https://github.com/qauth-labs/qauth/issues/662
[#663]: https://github.com/qauth-labs/qauth/issues/663
[#670]: https://github.com/qauth-labs/qauth/issues/670
[#672]: https://github.com/qauth-labs/qauth/issues/672
[#675]: https://github.com/qauth-labs/qauth/issues/675
[#689]: https://github.com/qauth-labs/qauth/issues/689
[#700]: https://github.com/qauth-labs/qauth/issues/700
[#709]: https://github.com/qauth-labs/qauth/issues/709
[#714]: https://github.com/qauth-labs/qauth/issues/714
[#827]: https://github.com/qauth-labs/qauth/issues/827
[#845]: https://github.com/qauth-labs/qauth/issues/845
[#857]: https://github.com/qauth-labs/qauth/issues/857
[#891]: https://github.com/qauth-labs/qauth/issues/891
[#896]: https://github.com/qauth-labs/qauth/issues/896
[#901]: https://github.com/qauth-labs/qauth/issues/901
[#908]: https://github.com/qauth-labs/qauth/issues/908
[#914]: https://github.com/qauth-labs/qauth/issues/914
[#472]: https://github.com/qauth-labs/qauth/issues/472
[#933]: https://github.com/qauth-labs/qauth/issues/933
[#951]: https://github.com/qauth-labs/qauth/issues/951
[#960]: https://github.com/qauth-labs/qauth/issues/960
[#963]: https://github.com/qauth-labs/qauth/issues/963
[#964]: https://github.com/qauth-labs/qauth/issues/964
[#968]: https://github.com/qauth-labs/qauth/issues/968
[#969]: https://github.com/qauth-labs/qauth/issues/969
[#982]: https://github.com/qauth-labs/qauth/issues/982
[#1009]: https://github.com/qauth-labs/qauth/issues/1009
[#1012]: https://github.com/qauth-labs/qauth/issues/1012

### Deprecated

- **`OID4VP_RESPONSE_KEY_SECRET`** ([#546]). It is read only to open the
  response keys a release before this one stored with it, and a set value warns
  at boot. Remove it once every node runs this release and 15 minutes have
  passed; a later release removes it.
- **`/api/clients`, `/api/consents` and the cookie-authenticated `/consents`**
  ([#524]). Each operation is `deprecated: true` in the OpenAPI document, and
  every answer, errors included, carries the RFC 9745 `Deprecation` header and
  a `Link` to the API conventions page, whose Deprecations table names each
  replacement under `/developer/v1-rc.0` or `/account/v1-rc.0`. They keep their
  shapes until the release-candidate cleanup removes them.

### Removed

- **The Bearer path of `/oauth/authorize`** ([#524]). The developer portal's
  access token no longer stands in for a sign-in there: an `Authorization`
  header signs no one in, a request without a browser session goes to the
  login page, and `prompt=none` answers `login_required`. Nothing QAuth ships
  used it. A web-only process no longer loads the JWT plugin.
- **The system client's id as a portal token's audience** ([#524]). Its
  acceptance had no end date at `/auth/logout`, where an expired token still
  passed. One grace stays for this release only: `/auth/logout` still takes a
  live portal token that carries it, so a developer who signs out while the
  upgrade rolls still has their refresh tokens, sessions and codes ended. An
  expired one is refused, and the next release removes the grace.

### Fixed

- **An ID-JAG bound to a DPoP key needs a proof under that key** ([#927],
  ADR-011 gate 16; only with `ID_JAG_ENABLED`, which is off by default). An
  identity provider may bind the ID-JAG it mints to the client's DPoP key with
  `cnf.jkt`, and `draft-ietf-oauth-identity-assertion-authz-grant-04`
  §9.8.1.2 then requires a DPoP proof under that key at the token endpoint.
  The `jwt-bearer` grant never read `cnf`, so a bound assertion was redeemed
  without one. It is now refused with `invalid_grant` without a proof (the
  description says a proof is required, and the assertion is not spent), with a
  proof under another key, or while `DPOP_ENABLED` is off; a `cnf` naming any
  confirmation method but `jkt` is refused too. With the matching proof the
  access token is bound to that key (`cnf.jkt`, `token_type: DPoP`). An
  assertion without `cnf` is handled as before. The grant type stays
  `jwt-bearer`; `-06`'s `jwt-dpop` waits for the EMA extension to name a later
  revision.

- **No CORS at the authorization endpoint** ([#930]). `@fastify/cors` answered
  for every route, so with `CORS_ORIGIN` set, or in any environment but
  production, `/oauth/authorize` answered CORS preflights and sent
  `Access-Control-Allow-Origin` like the token endpoint. OAuth 2.1
  (draft-ietf-oauth-v2-1-17 §3.1) says CORS MUST NOT be supported there: the
  client sends the user agent to it and never calls it. The authorization
  endpoint and the other `browser` routes (the `/ui/*` sign-in, consent and
  wallet pages, `/consents`, `/auth/link/wallet` and the verification page
  `GET /auth/verify`) now send no `Access-Control-*` header in any
  environment, and a preflight for one of them gets the `404` of a path no
  route serves. No cross-origin caller needs them: a page is navigated to, and
  a call the session cookie authorizes could not be made cross-origin before
  either, since the CORS answers never allowed credentials. Every other route
  keeps CORS as before, and a browser-based client's origin still goes in
  `CORS_ORIGIN`, for its calls to the token endpoint.

- **A client key set that carries an RSA private key is refused** ([#935]).
  The key sets a client publishes, in its Client ID Metadata Document's `jwks`
  or at its `jwks_uri`, were refused only for a `d` or `k` member. An RSA key
  carrying its primes or CRT values (`p`, `q`, `dp`, `dq`, `qi`, `oth`)
  without `d`, or an ML-DSA key's `priv`, had those members dropped and was
  trusted, although the client had published its private key. Such a set is
  now refused, and so is a key of a known type without the public members it
  needs (EC `crv`, `x` and `y`; OKP `crv` and `x`; RSA `n` and `e`). This is
  the seed manifest's rule, now `publicJwkProblem` in
  `@qauth-labs/shared-validation`, which both use. The token endpoint still
  answers a bare `invalid_client`; the operator's log names the key, its
  private members and that the client must rotate it. Keys fetched before the
  upgrade are trusted until their cache entry expires.

- **Signing out everywhere ends every session, whatever Redis has lost**
  ([#912], found in the review of [#550]). `/auth/logout` found the user's
  browser sessions through a per-user index in Redis, so a session the index
  no longer named (an eviction, a restart without persistence, a failover)
  survived the sign-out. It now ends them in Postgres, in one transaction,
  through the session service's `revokeAllForUser`, then drops their side
  records; the authorization codes and refresh tokens are swept after it as
  before. A Redis failure while the side records are dropped is logged and
  no longer stops the sweep. Nothing needs the index any more, so sign-in no
  longer writes it: an index an earlier version left in Redis is never read
  and expires on its own.

- **A refresh token needs a stored consent for its resources too** ([#633]).
  `/oauth/token` minted a refresh token for an authorization code whenever the
  active consent covered the code's scopes, whatever RFC 8707 resources the
  code was bound to. So a user who remembered `read:x` at one resource server,
  and later approved `read:x` at another without **Remember this decision** or
  under a first-party client's administrative consent, gave the client a
  refresh family at the second: standing access that no stored consent
  records. A refresh token is now minted only when the stored consent covers
  the code's scopes at every resource the family is bound to (the ones a
  narrowing `resource` on the token request names, if it has one), the rule
  the consent skip already applies; otherwise the client gets the access token,
  and the ID token when `openid` was granted, without one. A code bound to no
  resource is unaffected.

- **A client that signs users in can be kept from minting tokens with no user
  for its users' scopes** ([#891]). `client_credentials` granted any scope in
  a client's `scopes`, so a relying party given the grant to manage its SSF
  stream could also get a token whose `sub` is its own `client_id` for a scope
  its users grant it (`notes:read`, say), which a resource server that did not
  check `sub` acted on app-wide. Migration 0051 adds
  `oauth_clients.client_credentials_scopes`, the scopes that grant may issue,
  out of `scopes`; the seed manifest's `client_credentials_scopes` is the only
  way to set it, and no owner route can change it. With a list, the token
  endpoint refuses any other scope on `client_credentials` with `invalid_scope`
  (event reason `scope_not_allowed_for_grant`); without one the grant is as
  before. The manifest refuses a listed scope `scopes` does not hold, an empty
  list, and the list on a client without the grant, and `--rotate` refuses an
  entry without the list for a client whose row has one, so a rotation cannot
  lift it unnoticed. The admin API's reserved `clients.update` cases count
  lifting or widening the list as `token-content`. The **SSF transmitter**
  page's receiver example now lists `["ssf:stream"]` there, and its warning
  covers only a client without the list.

  **Action for operators**: give every client that signs users in and holds
  `client_credentials` a `client_credentials_scopes`, an SSF receiver's
  `["ssf:stream"]`, in its manifest entry, and keep an SSF receiver's
  `audience` to the realm's issuer alone: the list narrows the token's scopes,
  not its `aud`. The seeder writes an existing client only with `--rotate`;
  without rotating, also set the column with an `UPDATE` (see the SSF
  transmitter page and the upgrade guide). The list takes effect on a node
  once that node runs this release; until every node does, a node of the
  previous release, which ignores the column, still issues every scope of
  `scopes`. Setting it during the roll does no harm, since such a node's
  writes leave the column as it is. Rolling back to an earlier release without
  restoring the backup lifts every list, because older code ignores the
  column; the column and its values are kept, and the lists apply again after
  upgrading.

- **A fetch process can no longer exhaust the server's memory** ([#857]). The
  egress client's fetch processes answer over a plain socket of size-capped
  frames instead of Node's IPC channel, which deserialized a message whole
  before any check ran. Each frame's cap depends on the process's state, a
  frame over its cap is refused before its payload is read, and every header,
  `location` and failure message is bounded before it is decoded. A process
  that sends what it may not is killed and its call fails.
- **A token signed by a retired key keeps verifying until the key's retention
  ends** ([#492], ADR-019 Decision 9, ADR-001). The server picks a token's key
  by its `kid` and `alg` together (`selectJwksKey`) among the realm's
  verification set: its active keys and its retired keys still inside their
  retention. A `kid` that names a key of another algorithm, a `next` key or a
  `compromised` key finds none, and the token is refused. A hybrid token's
  ML-DSA-65 key is found the same way, by its signed `pqc_kid`, among the active
  and retired keys. A token without a `kid`, from before the upgrade, keeps
  verifying against the imported key after that key retires. Every check of the
  server uses the set: `requireJwt`, userinfo, introspection, revocation,
  `/auth/logout` and the token-exchange subject and actor tokens. So a rotation
  through the key store (scheduled #542, manual #544) will not make anyone sign
  in again; replacing a key through its variable still unpublishes the old key
  at once. ADR-001's and ADR-019's notes on the three retired-key gaps now say
  they are closed. The OAuth 2.1 flow page states the JWKS cache rule for
  relying parties: cache it for at most 5 minutes, fetch it again for an unknown
  `kid` at most once a minute, and drop the keys it no longer lists.

- **Enabling an account again no longer brings back what it held before it
  was disabled** ([#748], the case [GHSA-vw34-9q55-2vg3](https://github.com/qauth-labs/qauth/security/advisories/GHSA-vw34-9q55-2vg3)
  left open). Since 0.1.0 a disabled account's sessions and tokens are refused
  where they are used, but a browser session or a refresh token nobody used
  while the account was disabled worked again once it was enabled, so whoever
  held it came back without signing in. Migration 0044 adds
  `users.not_valid_before`: triggers set it from the database's clock whenever
  `enabled` turns false, by any `UPDATE`, to the commit of that transaction,
  and nothing can clear it or move it back. An account already disabled when
  the migration runs gets the time of the migration. Every browser session,
  refresh token, authorization code, access token and ID-JAG assertion of the
  user issued before it is refused, a refresh token by the start of its family,
  a code by the sign-in behind it, and an ID-JAG assertion as issued
  `ID_JAG_CLOCK_SKEW_LEEWAY` before its `iat`, the clock skew its validation
  allows the identity provider. A sign-in and a code exchange take the issue
  time of the session or the refresh family they start before they read the
  account, so one that read it before the disabling commit counts as issued
  before it. Where such a credential is used, the hosted pages send the
  browser to sign-in, the token endpoint answers `invalid_grant`,
  introspection reports the token inactive, and userinfo, token exchange, the
  developer API, the API families, the admin API and the `/oauth/authorize`
  Bearer path refuse it as they refuse a disabled account's. Such a token cannot sign the owner out
  either. The refusal `reason` in events is `issued_before_disablement`. The
  new operator tool `db:disable-user` disables an account or, with `--enable`,
  enables it again, and writes the new admin events `user.disabled` and
  `user.enabled` in the same transaction; SSF streams receive them as RISC 1.0
  `account-disabled` and `account-enabled` ([#540]). A refresh token issued
  before the disablement no longer relates the user to an SSF receiver
  either. The operator guide's new **Accounts** page (`operate/accounts`)
  describes both, what to undo after a takeover before enabling the account,
  and the bounds of the margin; the upgrade guide says why to enable an
  account disabled for a takeover only once every node runs this release.

  **Action for operators**: an account disabled and enabled again before the
  upgrade gets no time, so what the previous release brought back when it was
  enabled keeps working. For each account enabled again after a takeover,
  once every node runs this release, run `db:disable-user`, take the steps
  the Accounts page lists after a takeover, and run `db:disable-user --enable`:
  disabling records the time now and ends every session and token the account
  holds.

- **A blank `PASSWORD_MIN_SCORE` no longer means score 0.** The schema read
  `''` as the number `0`, the weakest zxcvbn score, so a deployment that set
  the variable blank (`PASSWORD_MIN_SCORE=`, or an orchestrator that passes an
  absent variable as `''`) accepted a password of any strength. Blank is now
  unset and takes the default, `2`. `docker-compose.yml` forwards
  `${PASSWORD_MIN_SCORE:-2}` and was not affected. `EMAIL_FROM_NAME`,
  `SMTP_HOST` and `SMTP_USER` read blank as unset too, as the other keys that
  seed a realm's policies do (#514); `EMAIL_FROM_NAME` then takes its default,
  `QAuth`.
- **The OpenAPI document no longer claims version 1.0.0.** `info.version` was
  a fixed `1.0.0` from the first Swagger UI (2026-02-28), which read as the 1.0
  stability promise QAuth has not made. A release image now carries its own
  version (`release-images.yml` passes the tag's `X.Y.Z` or `X.Y.Z-rc.N` as
  `QAUTH_VERSION`); every other build, the committed
  `stable-surface/openapi.json` and the docs site's copy among them, says
  `0.0.0-dev`. The stable-surface check is unchanged: it compares release
  tags, not this field.
- **The verification email's link works again.** Since 42c4d1e4 (2026-09-25)
  the auth server verified an account only on `POST /auth/verify`, with the
  token and the account's password in a JSON body, but the mail still links to
  `/auth/verify?token=…`, which a mail client opens with GET.
  That GET was a `404`, and with `REQUIRE_VERIFIED_ACCOUNT` on by default a new
  password account could not verify from the mail and so could not sign in.
  `GET /auth/verify` is now a server-rendered page: it holds the token in a
  hidden field and asks for the password, and its form posts to the new
  `POST /ui/verify`, which verifies through the same code as
  `POST /auth/verify` and answers each outcome with the same status. Opening
  the link changes nothing and reads nothing from the database, so a link
  scanner or a prefetch still cannot verify an account. The page sends
  `Cache-Control: no-store` and `Referrer-Policy: no-referrer`, and the form has
  the login pages' CSRF check and the JSON route's rate limit. The link
  verifies only at a host of its account's realm, whose issuer it names
  ([#490]): at another realm's host its token is unknown ([#489]).
  `POST /auth/verify` is unchanged. This page is interim: the email-code step
  ([#638]) and the hosted account verification UI ([#644]) replace link
  verification.

[#492]: https://github.com/qauth-labs/qauth/issues/492
[#638]: https://github.com/qauth-labs/qauth/issues/638
[#644]: https://github.com/qauth-labs/qauth/issues/644
[#748]: https://github.com/qauth-labs/qauth/issues/748
[#912]: https://github.com/qauth-labs/qauth/issues/912
[#927]: https://github.com/qauth-labs/qauth/issues/927
[#930]: https://github.com/qauth-labs/qauth/issues/930
[#935]: https://github.com/qauth-labs/qauth/issues/935

## [0.1.3] - 2026-10-21

One addition backported from `main` to the 0.1 line, so that native apps that
call back on a scheme without a period, such as the Cursor desktop app, can
sign in to a deployment that lists that scheme.

### Added

- **Redirect URI schemes without a period, when the operator lists them**
  ([#774]). Since 0.1.0 a redirect URI has had to be `https`, loopback `http`
  or a reverse-domain private-use scheme (`com.example.app:`), which shut out
  native apps that call back on a bare scheme: the Cursor desktop app's
  `cursor://anysphere.cursor-mcp/oauth/callback` could neither register nor
  authorize. `REDIRECT_URI_CUSTOM_SCHEMES` (empty by default) names the
  bare schemes a deployment accepts, such as `cursor`. A listed scheme is
  accepted by dynamic client registration, `POST /api/clients`, CIMD documents
  and the authorization-time gate in `/oauth/authorize` and the consent screen;
  matching stays exact. PKCE, required for every client, protects the code at
  either kind of custom scheme (RFC 8252 §8.1). The server refuses to start
  when an entry is not a scheme name or names one a browser or the operating
  system acts on itself (`http`, `https`, `javascript`, `data`, `file`,
  `intent`, `mailto` and the like), and refuses such schemes at authorization
  whatever the list holds. With the variable unset, behaviour is unchanged.

[#774]: https://github.com/qauth-labs/qauth/issues/774

## [0.1.2] - 2026-10-21

One addition backported from `main` to the 0.1 line, so that a deployment on
0.1 can grant scopes to its CIMD clients from the seed manifest instead of
writing the rows by hand.

### Added

- **Scopes for CIMD clients from the seed manifest** ([#770]). A CIMD client
  starts with no scopes, and until now only a hand-written database row could
  give it any. The seed manifest's new `cimd_clients` section sets a CIMD
  client's `scopes` and `audience` and nothing else: the client's metadata
  document still supplies every other field, and re-resolving it never changes
  the grant. An entry has no secret, so the seed prints none for it and every
  run sets the row to the entry's values. The seed refuses an entry whose
  `client_id` belongs to a client that is not a CIMD client. `clients` is now
  optional, so a manifest may hold only CIMD entries; existing manifests work
  as before. The Docker guide's CIMD section describes it.

[#770]: https://github.com/qauth-labs/qauth/issues/770

## [0.1.1] - 2026-10-21

Fixes backported from `main` to the 0.1 line. One of them changes what the ID
token carries; see Changed.

### Changed

- **BREAKING**: ID tokens now carry `name` only when the granted scope
  includes `profile`, the rule userinfo already follows (OIDC Core §5.4)
  ([#755]). Before, the `authorization_code` grant put the user's name in the
  ID token whatever was granted, so a client that asked only for `openid` got
  it. The ID token and userinfo now resolve the claim through one helper and
  release the same profile claims for the same grant. No other grant signs an
  ID token, and access tokens never carried `name`.

  **Who is affected**: a client that reads `name` from the ID token without
  requesting `profile`. **Action**: request the `profile` scope, which shows
  on the consent screen. Userinfo behaves as before.

### Fixed

- The auth server no longer exits when PostgreSQL closes an idle pooled
  connection, as a restart, a failover or `pg_terminate_backend` does
  ([#746]). pg-pool emits that error on the pool after it has dropped the
  client, and with no listener Node threw it and ended the process. The pool
  now logs the error and opens a fresh connection on the next query.

- `/oauth/userinfo` answers a token whose subject is not a user with 401
  `invalid_token` and a `WWW-Authenticate: Bearer` challenge, on GET and POST
  ([#754], OIDC Core §5.3.3, RFC 6750 §3.1). A `client_credentials` token
  carries its `client_id` as `sub`, and with no `resource` and no client
  `audience` its `aud` is the `client_id` too, so it passed the audience check
  and failed with 500: the user lookup, then the failure audit, sent the
  `client_id` to PostgreSQL as a user id. A token whose user no longer exists
  gets the same 401 instead of 404. Token exchange refuses such a token as
  `subject_token` with `invalid_request` before any lookup, and the users
  repository answers "no such user" for an id that is not a UUID without
  querying. `/auth/logout` had the same failure audit: a sign-out with the
  token of a deleted user answered 500. It now answers 401 `invalid_token`
  instead of the intended 404.

[#746]: https://github.com/qauth-labs/qauth/pull/746
[#754]: https://github.com/qauth-labs/qauth/issues/754
[#755]: https://github.com/qauth-labs/qauth/issues/755

## [0.1.0] - 2026-10-19

### Added

- **Wallet federation (T4, [ADR-004](./docs/adr/004-wallet-agnostic-federation.md)) —
  browser wallet sign-in.** QAuth can now generate an OID4VP 1.0 authorization
  request, take back a `direct_post` response, validate an SD-JWT VC presentation,
  resolve the account, and mint a session — a complete browser sign-in. Wallet
  sign-in never creates an account; a wallet is linked from a signed-in account
  (see **Changed**). Covered end-to-end against a mock wallet: the refusal of an
  identifier with no account, sign-in with a linked wallet, the ADR-009 §1
  takeover attempt, untrusted-issuer refusal, account linking, and `acr`
  presence/absence.

  **Off by default.** Nothing below changes how an existing email/password or
  OAuth client behaves — the routes are not even registered unless
  `WALLET_FEDERATION_ENABLED=true`. Validated so far only on the
  `oid4vp-1.0-base` profile against a mock wallet; the HAIP profile (#377) and a
  real-wallet interoperability pass (#376) remain open.

  Note: `WalletProvider.verify()` still throws unconditionally and is required to
  keep doing so (#232) — the wallet login path does not go through the generic
  `CredentialProvider` registry.
  - OID4VP 1.0 request generation + `direct_post` intake ([#233])
  - `VerifierProfile` abstraction for configurable deployment profiles ([#299])
  - SD-JWT VC presentation validation ([#234])
  - Static per-realm issuer trust registry ([#236])
  - ES256 + JWE (ECDH-ES / A\*GCM) crypto prerequisites for HAIP ([#298])
  - Credential revocation via Token Status List, HAIP §6.1 ([#297])
  - Interoperable Key Attestations validation, HAIP §9.2 ([#308])
  - VC claims normalization into `user_attributes` ([#235])
  - Configurable `SubjectResolutionStrategy` ([#300], [ADR-009](./docs/adr/009-wallet-account-resolution.md))
  - Account linking — attach a wallet credential to an existing user ([#238])
  - `acr` claim propagation from assurance level ([#237], [ADR-010](./docs/adr/010-acr-assurance-mapping.md))
  - Wallet sign-in flow in the login screens ([#239])
  - E2E integration suite against a reference mock wallet ([#240])

  **New operator configuration** (all optional; the feature is off by default):
  `WALLET_FEDERATION_ENABLED`, `OID4VP_VERIFIER_PROFILE`, `OID4VP_REQUESTED_VCT`,
  `OID4VP_SUBJECT_RESOLUTION`, `OID4VP_SUBJECT_CLAIM`,
  `OID4VP_SUBJECT_CLAIM_ISSUERS`, `OID4VP_SUBJECT_BINDING_CLAIMS`,
  `OID4VP_STATUS_LIST_TRUST_ANCHORS` (or `_PATH`),
  `OID4VP_STATUS_LIST_URI_ALLOWLIST`, `OID4VP_WALLET_INVOCATION_ENDPOINT`,
  `OID4VP_ISSUER_JWKS`, `OID4VP_TRUSTED_ISSUERS`, `OID4VP_ISSUER_ASSURANCE`,
  `ACR_VALUE_STYLE`.

- **Post-quantum hybrid signing (T4, [ADR-005](./docs/adr/005-pqc-hybrid-signing.md))
  — implemented and off by default.** Detached-parallel ML-DSA-65 + Ed25519
  signing, a mixed `AKP` + `OKP` JWKS, a napi-rs native backend over `aws-lc-rs`
  and a `@noble/post-quantum` fallback. **No behavior changes unless enabled**:
  `SIGNING_ALGORITHM_MODE` defaults to `ed25519` and `HYBRID_SIGNING_ENABLED` to
  `false`, so tokens remain Ed25519-only and classical verifiers need no action.
  Enabling hybrid by default is gated on the pre-default-on checklist in the
  [security gate review](./docs/security/005-pqc-hybrid-signing-review.md)
  (CONDITIONAL PASS). See the
  [verifier guide](./docs/hybrid-signing-verifier-guide.md).
  ([#242], [#243], [#244], [#245], [#246], [#247], [#248], [#249])

  **New operator configuration:** `SIGNING_ALGORITHM_MODE`,
  `HYBRID_SIGNING_ENABLED`, `JWT_MLDSA_PRIVATE_KEY` (or `_PATH`),
  `JWT_MLDSA_KID`, `PQC_TOKEN_DELIVERY`, `PQC_SELF_CONTAINED_ACK`.

[#232]: https://github.com/qauth-labs/qauth/issues/232
[#233]: https://github.com/qauth-labs/qauth/issues/233
[#234]: https://github.com/qauth-labs/qauth/issues/234
[#235]: https://github.com/qauth-labs/qauth/issues/235
[#236]: https://github.com/qauth-labs/qauth/issues/236
[#237]: https://github.com/qauth-labs/qauth/issues/237
[#238]: https://github.com/qauth-labs/qauth/issues/238
[#239]: https://github.com/qauth-labs/qauth/issues/239
[#240]: https://github.com/qauth-labs/qauth/issues/240
[#242]: https://github.com/qauth-labs/qauth/issues/242
[#243]: https://github.com/qauth-labs/qauth/issues/243
[#244]: https://github.com/qauth-labs/qauth/issues/244
[#245]: https://github.com/qauth-labs/qauth/issues/245
[#246]: https://github.com/qauth-labs/qauth/issues/246
[#247]: https://github.com/qauth-labs/qauth/issues/247
[#248]: https://github.com/qauth-labs/qauth/issues/248
[#249]: https://github.com/qauth-labs/qauth/issues/249
[#297]: https://github.com/qauth-labs/qauth/issues/297
[#298]: https://github.com/qauth-labs/qauth/issues/298
[#299]: https://github.com/qauth-labs/qauth/issues/299
[#300]: https://github.com/qauth-labs/qauth/issues/300
[#308]: https://github.com/qauth-labs/qauth/issues/308

### Changed

- **BREAKING**: access tokens now carry `email`/`email_verified` only when the
  granted scope includes `email`, the rule ID tokens (#259) and userinfo
  (#229) already follow. This holds on every grant that mints a user access
  token: `authorization_code`, `refresh_token`, RFC 8693 token exchange and
  the RFC 7523 `jwt-bearer` grant. A refresh or an exchange that narrows
  `email` out of the scope drops the claims. The first-party `/auth/login`
  token is granted no scope and no longer carries them. `client_credentials`
  never did. Before, every user access token carried the user's verified
  address whatever was granted. The client could read it from the JWT in the
  same response whose ID token withheld it, so the `email` scope and the
  consent screen line for it controlled nothing (ANT-2026-2O0T72HY).

  **Who is affected**: a resource server that reads `email` from access tokens
  issued without the `email` scope. **Action**: have the client request the
  `email` scope, which shows on the consent screen. ID tokens and userinfo
  behave as before.

- **BREAKING**: `/oauth/userinfo` (GET and POST) now checks the access token's
  audience, as [`docs/security/threat-model.md`](./docs/security/threat-model.md)
  promises for every token. A token is accepted only when its `aud` contains
  the token's own `client_id` or the `userinfo_endpoint` URL that discovery
  publishes. Every other token gets `401` with
  `WWW-Authenticate: Bearer error="invalid_token"`. Before, any live token this
  server issued was accepted, so a resource server could read the claims of
  the user whose token it had been handed.

  **Who is affected**: an OIDC client that runs the code flow without
  `resource` gets `aud` = its `client_id` and keeps working, and so does the
  developer portal's `/auth/login` token. A client that binds its grant to a
  resource server with RFC 8707 `resource`, or whose operator configured an
  `audience` for it, and then calls UserInfo with that token is refused.
  **Action**: read identity from the ID token, or add the UserInfo URL as
  another `resource` at `/oauth/authorize` (an operator can add it to the
  client's `audience` instead).

- **BREAKING (ID-JAG mint; only with `ID_JAG_ENABLED`, which is off by
  default)**: an ID-JAG minted through RFC 8693 token exchange now carries only
  scopes that are in the agent client's registered `scopes`. This is the ceiling
  `client_credentials` and the `jwt-bearer` consume side already apply
  ([ADR-011](./docs/adr/011-enterprise-managed-authorization.md) §3, amended
  2026-10-19). Before, the mint copied the subject token's scope unchecked, so
  an agent could carry a scope it is not registered for to a partner's server
  (ANT-2026-L66R3GFR). A scope outside the list is refused with
  `invalid_scope`, not dropped; the agent sends `scope` to ask for less.

  **Action for operators**: an agent provisioned with an empty `scopes` list
  can no longer mint a scoped assertion. List in its `scopes` every scope it
  should be able to carry to a partner. The delegation branch of token exchange
  (`requested_token_type` access token) is unchanged.

- **BREAKING (security)**: `POST /auth/register` no longer reveals whether an
  address already has an account (ANT-2026-SPEMY9GU). It answered `409` for a
  registered address and `201` with the new user for a free one, so any caller
  could test any address.
  - Every address now gets `202 Accepted` with the same body,
    `{ "message": "Registration received. Check your inbox for an email with the next step." }`,
    the same headers (`Cache-Control: no-store`) and the same work on the
    request path (the password is hashed and the insert attempted either way,
    under a 500 ms floor). The body has **no `id`, `email`, `emailVerified`,
    `realmId`, `createdAt` or `updatedAt`** any more, and the route never
    answers `409`.
  - What happened goes to the mailbox. A free address gets its account and a
    verification link. The owner of a verified account gets a new "someone
    tried to register with your address" notice, with no link. An account that
    is still unverified gets its verification link again, which verifies only
    with the password chosen at the first registration. Mail to an existing
    account counts toward the `RESEND_VERIFICATION_*` per-address caps, and
    every registration claims the minimum interval there, so a resend straight
    after a registration answers `429`. No mail is awaited by the request.
  - `POST /auth/login` and `POST /ui/login` refuse an account whose address is
    not verified exactly as they refuse a wrong password: `401 INVALID_CREDENTIALS`
    (it was `403 EMAIL_NOT_VERIFIED`) and the same login page. The
    `qauth_login_attempts_total` metric counts it as `invalid_credentials`; the
    log line and audit row keep `email_not_verified`.
  - The developer portal shows the same "check your inbox" screen for both
    cases and no longer has an "Email already registered" error.

  **Action for clients**: treat any `2xx` from `/auth/register` as "check your
  inbox" and stop reading a user id from it. Do not branch on `409` or on
  `EMAIL_NOT_VERIFIED`.

- **BREAKING (security)**: `REQUIRE_VERIFIED_ACCOUNT` now defaults to **`true`**
  (maintainer decision, 2026-10-19). Without it, registering an address with a
  password of one's choice and then logging in with it told a free address
  (`200`) from a registered one (`401`). An unset or blank value of the
  variable, or of its deprecated alias `REQUIRE_EMAIL_VERIFIED`, now means
  `true`.

  **Action for operators**: existing accounts whose address was never verified
  can no longer sign in with a password until they verify (they can request a
  new link through `POST /auth/resend-verification` or the portal). A stack on
  `EMAIL_PROVIDER=mock` delivers no mail, so its sign-ups cannot be verified:
  configure `smtp` or `resend`. Set `REQUIRE_VERIFIED_ACCOUNT=false` only
  knowingly; it gives the register-then-login answer back.

- **BREAKING (wallet federation, `WALLET_FEDERATION_ENABLED=true` only)**: a
  first wallet presentation no longer creates an account. From `v0.1.0-rc.1` to
  `v0.1.0-rc.3`, presenting a valid credential on `/ui/wallet-login` with an
  identifier that had no account enrolled a new account on that identifier,
  bound to the presenter's credential, while an identifier with an account was
  refused. Anyone holding a credential from a trusted issuer could therefore
  learn which identifiers have accounts (including wallet-only accounts) and
  claim identifiers that belong to other people. Wallet sign-in now signs in
  only an account the credential is already bound to; an identifier with no
  account gets the same refusal as a taken one (same status, body, headers and
  cookies) and nothing is written.
  ([ADR-009](./docs/adr/009-wallet-account-resolution.md) §1, amended
  2026-10-19; ANT-2026-NCX3VXDP)

  **Action for operators**: accounts that wallet sign-in created before this
  release keep signing in. A new person gets wallet sign-in by creating an
  account, signing in to it, and linking the wallet at `/ui/wallet-link` (or
  `POST /auth/link/wallet`). Wallet-first sign-up arrives with the hosted
  sign-up pages ([ADR-017](./docs/adr/017-first-party-login.md)). No
  configuration or migration is involved.

- **BREAKING**: ID tokens now release `email`/`email_verified` only when the
  granted scope includes `email`, matching the userinfo endpoint's gating
  (OIDC Core §5.4 data minimization). Clients requesting only `openid` no
  longer receive the user's email in the ID token — request the `email`
  scope. Access-token convenience claims and userinfo behavior are
  unchanged. ([#259]) _Superseded in part on 2026-10-19: access tokens now
  follow the same `email` scope rule (see the access-token entry above)._

[#259]: https://github.com/qauth-labs/qauth/issues/259

- **BREAKING (schema)**: migration 0011 completes ADR-002 — it **drops**
  `users.email`, `users.email_normalized`, and `users.password_hash` (and
  their indexes), drops `email_verification_tokens.user_id`, and promotes
  `email_verification_tokens.credential_id` to NOT NULL. `users` is now a
  pure identity anchor; all credential data lives in `user_credentials`, and
  the `(realm_id, provider_type, external_sub)` unique index is the sole
  duplicate-registration guard. ([#230], Epic #224)

  **Deploy ordering (enforced)**: the previous release (#228/#229 dual-write)
  must be fully deployed — with no pre-#228 app instances still running —
  before applying this migration. Migration 0011 opens with an in-SQL guard
  that **aborts atomically** (zero DDL applied) if any user's identity data
  exists only in the legacy columns, printing remediation instructions.
  Conversely, apply migration 0011 (`pnpm nx run infra-db:db:migrate`)
  before starting any instance of this release — the new binary writes only
  the ADR-002 tables; this direction has no in-SQL guard.
  Upgrading from a pre-#229 deployment is a two-hop path: first deploy the
  previous release — the last one containing the `db:backfill-identity`
  target, which is commit **`00c23f04`** ("Merge pull request #260 …",
  2026-07-18), the immediate parent of `29abe4a` and therefore the newest
  state of `main` that still has the tool and does _not_ yet have migration
  0011 — run its backfill runbook (`--refresh`, then `--verify-only`; both
  exit 0), then upgrade to this release. **No tag names that commit yet**;
  giving the hop a pinnable tag is tracked in [#362]. `v0.1.0-rc.0`
  (2026-07-25) is **not** it — that tag postdates 0011 and already contains
  the destructive migration, so starting the two-hop path from it is exactly
  the mistake this note exists to prevent. Note: that script's help says `--refresh` is
  "PRE-CUTOVER ONLY" — the warning does not apply on that release, because
  its binary dual-writes the legacy columns in the same transactions,
  keeping them equal to the authoritative tables; `--refresh` is safe there.

  **Rollback**: there is **no rollback after 0011**. Dropped columns cannot
  be reconstructed (password hashes are unrecoverable by design). Take a
  database backup immediately before applying; restoring it is the only undo
  and discards all post-migration writes.

  **Minor operational notes**: in-flight verification tokens minted without a
  `credential_id` are re-pointed where resolvable and otherwise deleted (the
  affected user clicks resend once). For accounts created before #228, a few
  user-visible strings (verification response, consent-screen address, logs)
  now show the normalized lowercase email — the original-case string ceased
  to exist with the column. `users.email_verified`/`email_verified_at`
  survive as vestigial columns (no writers; one sanctioned reader — the
  register 201 response's default surface); their drop is tracked in
  [#261].

[#230]: https://github.com/qauth-labs/qauth/issues/230
[#362]: https://github.com/qauth-labs/qauth/issues/362
[#261]: https://github.com/qauth-labs/qauth/issues/261

- **BREAKING**: `email` and `email_verified` claims — in ID tokens, userinfo
  responses, **and** the non-standard access-token convenience claims — now
  resolve exclusively from **verified** `user_attributes` rows using the
  ADR-002 trust order (`wallet > oidc_* > self_reported`, expiry-aware). When
  a user has **no verified email attribute, both claims are omitted entirely**
  — never `null`, never present-with-`false`. When `email` is present,
  `email_verified` is always `true`: presence is the verification signal
  (OIDC Core 1.0 §5.1). There is **no compatibility flag** — this is the
  OIDC-correct behavior; the previous always-emit behavior was a documented
  MVP shortcut. ([#229], ADR-002)

  **Migration for operators**: claim emission now depends entirely on
  `user_attributes` rows. Before deploying this release against a database
  that predates the ADR-002 identity backfill (#226) — or whose backfill may
  be partial — run:

  ```bash
  pnpm nx run infra-db:db:backfill-identity -- --refresh
  pnpm nx run infra-db:db:backfill-identity -- --verify-only
  ```

  Both must exit 0. `--verify-only` confirms every user has a
  `(self_reported, email)` attribute row; without it, existing users —
  **including those with a verified email** — silently lose the
  `email`/`email_verified` claims on token, refresh, and userinfo responses.

  **Migration for integrators**: treat `email` as optional everywhere.

  ```js
  // Before — unsafe after this release:
  const { sub, email } = await userinfo(accessToken); // email may be absent!

  // After:
  const { sub, email } = await userinfo(accessToken);
  if (email === undefined) {
    // No verified email on record — collect one, or proceed without.
  }
  ```

  Clients that require an email for account linking should request the
  `email` scope AND handle its absence; an absent claim means QAuth has no
  _verified_ address for that user, not that the user has no address.

[#229]: https://github.com/qauth-labs/qauth/issues/229

- **Schema**: migration 0012 drops the vestigial
  `users.email_verified`/`email_verified_at` columns kept out of 0011's
  issue-literal scope. No behavior change: they had no writers since #230,
  and the register 201 response's `emailVerified: false` is now a literal
  (byte-identical wire value). No guard or special deploy ordering needed.
  ([#261])

- **Schema**: migrations 0013–0016 support the OIDC and T4 work above. All four
  are additive and require no special deploy ordering or backfill.
  - `0013` — adds `authorization_codes.auth_time`, carrying the authentication
    instant through to the ID token's `auth_time` claim.
  - `0014` — widens `authorization_codes.nonce` and `.state` from `varchar` to
    `text`. Clients that previously had long values rejected now succeed; no
    existing row changes.
  - `0015` — adds the `oid4vp_request_states` table (realm-scoped, with a unique
    `state_hash`, the DCQL query, expiry and single-use `redeemed_at`), backing
    OID4VP request/response correlation. Unused unless wallet federation is on.
  - `0016` — adds `authorization_codes.assurance_level`, constrained to
    `substantial` / `high` or NULL, feeding the `acr` mapping in ADR-010.

### Deprecated

- **`REQUIRE_EMAIL_VERIFIED` is renamed `REQUIRE_VERIFIED_ACCOUNT`.** Email is a
  user attribute, not the trust gate. The gate is a verified account.
  **The rename alone changes no behaviour**: for a password account, the proof
  is still the confirmed address. (The default changed separately, to `true`;
  see Changed above.)
  - The old name keeps working as an alias through the 1.x deprecation window
    of at least 12 months.
  - A deployment that sets only the old name logs a deprecation warning at
    boot.
  - Setting both names to different values fails the boot with a message that
    names both.
  - `docker-compose.yml` forwards both names, so a deployment that still sets
    only the old one keeps its gate.
  - A blank value of either name now reads as unset, instead of failing the
    boot. This lets compose forward both names when they are unset.

  **Action for operators**: rename the variable to `REQUIRE_VERIFIED_ACCOUNT`.

### Security

- **66 security advisories are fixed in this release.** 65 come from a private
  report by Anthropic's OSS Scanner (scan `qauth-20261015-005`, 2026-10-15);
  one was found while fixing them. Every release candidate, `v0.1.0-rc.0` to
  `v0.1.0-rc.3`, is affected: upgrade to `v0.1.0`. Each advisory names its fix
  commits and anything the fix does not cover.
  - Critical: [GHSA-cvh4-23vc-5f3v](https://github.com/qauth-labs/qauth/security/advisories/GHSA-cvh4-23vc-5f3v) — Resource validation bypass in OAuth authorize lets clients set aud to system
  - High: [GHSA-442q-jwq9-p5g4](https://github.com/qauth-labs/qauth/security/advisories/GHSA-442q-jwq9-p5g4) — Oversized request arrays get one Zod error per element: unauthenticated DoS
  - High: [GHSA-5gvj-7cjh-2rmx](https://github.com/qauth-labs/qauth/security/advisories/GHSA-5gvj-7cjh-2rmx) — ssrfSafeGet(): idle timeout lets a client_id host hold fetches open (DoS)
  - High: [GHSA-6fcc-mxv4-c4mq](https://github.com/qauth-labs/qauth/security/advisories/GHSA-6fcc-mxv4-c4mq) — max_age coercion: nested JSON arrays let anyone block the event loop
  - High: [GHSA-87qh-m945-hhvv](https://github.com/qauth-labs/qauth/security/advisories/GHSA-87qh-m945-hhvv) — Unbounded client size and count let any account crash auth-server (heap OOM)
  - High: [GHSA-98f5-2857-ggjf](https://github.com/qauth-labs/qauth/security/advisories/GHSA-98f5-2857-ggjf) — Unauthenticated ReDoS in normalizeInternalAuthorizeUrl via # in request URL
  - High: [GHSA-9f5r-frxp-952q](https://github.com/qauth-labs/qauth/security/advisories/GHSA-9f5r-frxp-952q) — Deeply nested typ array in unsigned SD-JWT VC blocks the event loop
  - High: [GHSA-9hr7-g6qj-pchf](https://github.com/qauth-labs/qauth/security/advisories/GHSA-9hr7-g6qj-pchf) — Quadratic check on unbounded refresh_token scope blocks the event loop
  - High: [GHSA-c4qp-jrqq-g428](https://github.com/qauth-labs/qauth/security/advisories/GHSA-c4qp-jrqq-g428) — Crafted CIMD JWK member names block the event loop via localeCompare
  - High: [GHSA-p5hg-342x-frxj](https://github.com/qauth-labs/qauth/security/advisories/GHSA-p5hg-342x-frxj) — Event loop blocked by non-ASCII resource URLs parsed before length cap
  - High: [GHSA-r7r3-r5xx-ghmq](https://github.com/qauth-labs/qauth/security/advisories/GHSA-r7r3-r5xx-ghmq) — ssrfSafeGet(): TLS handshake lets a client_id host block the event loop
  - High: [GHSA-rpfh-v75p-mp6p](https://github.com/qauth-labs/qauth/security/advisories/GHSA-rpfh-v75p-mp6p) — Deeply nested key_ops in a client JWK blocks the event loop pre-auth
  - High: [GHSA-wwwm-6wr3-qmg5](https://github.com/qauth-labs/qauth/security/advisories/GHSA-wwwm-6wr3-qmg5) — auth-server OOM crash: stalled POSTs to unknown routes skip rate limiting
  - High: [GHSA-x3h3-q45q-qwc7](https://github.com/qauth-labs/qauth/security/advisories/GHSA-x3h3-q45q-qwc7) — Stale consent page can grant newly allowlisted scopes it never showed
  - Medium: [GHSA-2659-cfr9-8m7c](https://github.com/qauth-labs/qauth/security/advisories/GHSA-2659-cfr9-8m7c) — Slow client_id DNS starves all other DNS lookups, blocking CIMD clients
  - Medium: [GHSA-2vrf-hhqc-26w9](https://github.com/qauth-labs/qauth/security/advisories/GHSA-2vrf-hhqc-26w9) — Per-IP failed-login lockout bypass: own-account login resets the counter
  - Medium: [GHSA-3x89-8vq5-mjp9](https://github.com/qauth-labs/qauth/security/advisories/GHSA-3x89-8vq5-mjp9) — refresh_token grant keeps minting scopes removed from the client
  - Medium: [GHSA-45rm-3wwq-cwj3](https://github.com/qauth-labs/qauth/security/advisories/GHSA-45rm-3wwq-cwj3) — CIMD allows non-loopback http redirect URIs, auth codes sent in cleartext
  - Medium: [GHSA-4j52-qf49-36jx](https://github.com/qauth-labs/qauth/security/advisories/GHSA-4j52-qf49-36jx) — Refresh token revocation racing a rotation leaves the new token valid
  - Medium: [GHSA-5vr7-c5hq-ghp6](https://github.com/qauth-labs/qauth/security/advisories/GHSA-5vr7-c5hq-ghp6) — Anyone registering a wallet-only user's email permanently locks them out
  - Medium: [GHSA-67hx-hp5c-gg7j](https://github.com/qauth-labs/qauth/security/advisories/GHSA-67hx-hp5c-gg7j) — SSRF guard treats NAT64 and site-local IPv6 addresses as public
  - Medium: [GHSA-6fqv-hjx9-jgj2](https://github.com/qauth-labs/qauth/security/advisories/GHSA-6fqv-hjx9-jgj2) — zxcvbn l33t matcher blocks event loop for 7 s despite the length cap
  - Medium: [GHSA-6qmv-hg2c-5gwc](https://github.com/qauth-labs/qauth/security/advisories/GHSA-6qmv-hg2c-5gwc) — mcp-guard: junk tokens exhaust shared introspection rate limit (DoS)
  - Medium: [GHSA-6x6v-r7rf-xqgq](https://github.com/qauth-labs/qauth/security/advisories/GHSA-6x6v-r7rf-xqgq) — Wallet sign-in as another holder: binding claims above 2^53 collide
  - Medium: [GHSA-7773-2gx7-gpch](https://github.com/qauth-labs/qauth/security/advisories/GHSA-7773-2gx7-gpch) — private_key_jwt uses stale CIMD row: removed keys accepted, CIMD off ignored
  - Medium: [GHSA-7fxx-3c59-jx98](https://github.com/qauth-labs/qauth/security/advisories/GHSA-7fxx-3c59-jx98) — Argon2 client-secret checks exhaust the thread pool, stalling JWT verification
  - Medium: [GHSA-7hqm-pq5g-m4j4](https://github.com/qauth-labs/qauth/security/advisories/GHSA-7hqm-pq5g-m4j4) — readCookie() trims NBSP, bypassing the __Host- prefix (login CSRF)
  - Medium: [GHSA-7rw4-gmrr-w8w3](https://github.com/qauth-labs/qauth/security/advisories/GHSA-7rw4-gmrr-w8w3) — Consent screen resets session TTL, so stolen sessions never expire
  - Medium: [GHSA-86p7-gc4h-mr29](https://github.com/qauth-labs/qauth/security/advisories/GHSA-86p7-gc4h-mr29) — Status-list fetch crashes auth-server by leaving an error body unread
  - Medium: [GHSA-8hhv-hgc6-x8gp](https://github.com/qauth-labs/qauth/security/advisories/GHSA-8hhv-hgc6-x8gp) — One-time consent yields a refresh token the user cannot list or revoke
  - Medium: [GHSA-8qcr-q895-p5p3](https://github.com/qauth-labs/qauth/security/advisories/GHSA-8qcr-q895-p5p3) — Failed-login lockout race lets concurrent guesses exceed the limit
  - Medium: [GHSA-9xvv-wmw4-rxxw](https://github.com/qauth-labs/qauth/security/advisories/GHSA-9xvv-wmw4-rxxw) — Auth codes still mint refresh tokens after consent revocation or logout
  - Medium: [GHSA-c9jp-4m3g-mfxx](https://github.com/qauth-labs/qauth/security/advisories/GHSA-c9jp-4m3g-mfxx) — Operator-disabled client can be re-enabled by its owner via PATCH
  - Medium: [GHSA-ccg3-88g5-42w3](https://github.com/qauth-labs/qauth/security/advisories/GHSA-ccg3-88g5-42w3) — Explicit-curve keys in Status List Token x5c block the event loop
  - Medium: [GHSA-cmf7-wjxq-4pch](https://github.com/qauth-labs/qauth/security/advisories/GHSA-cmf7-wjxq-4pch) — Unbounded client_id and email let anyone grow audit_logs and Redis
  - Medium: [GHSA-f656-4x94-rwcx](https://github.com/qauth-labs/qauth/security/advisories/GHSA-f656-4x94-rwcx) — Logout accepts any client's token, revoking all the user's refresh tokens
  - Medium: [GHSA-h45w-5rh3-4jfc](https://github.com/qauth-labs/qauth/security/advisories/GHSA-h45w-5rh3-4jfc) — Wallet email marked verified if holder withholds email_verified false
  - Medium: [GHSA-hhf6-7jxh-56mg](https://github.com/qauth-labs/qauth/security/advisories/GHSA-hhf6-7jxh-56mg) — ID-JAG mint via token exchange ignores the agent's scope allowlist
  - Medium: [GHSA-hqvc-gxfj-5jfc](https://github.com/qauth-labs/qauth/security/advisories/GHSA-hqvc-gxfj-5jfc) — Bearer path on OAuth authorize skips consent, even for DCR clients
  - Medium: [GHSA-hr63-jxw4-gwp8](https://github.com/qauth-labs/qauth/security/advisories/GHSA-hr63-jxw4-gwp8) — mcp-guard: child-scope guard accepts tokens for the parent's resource
  - Medium: [GHSA-j6vv-jh87-x5p9](https://github.com/qauth-labs/qauth/security/advisories/GHSA-j6vv-jh87-x5p9) — Race in OAuth authorize: code issued after consent is revoked
  - Medium: [GHSA-m48p-6v3q-gr97](https://github.com/qauth-labs/qauth/security/advisories/GHSA-m48p-6v3q-gr97) — Open redirect via authorize errors for anonymously registered clients
  - Medium: [GHSA-m96q-3554-9vmg](https://github.com/qauth-labs/qauth/security/advisories/GHSA-m96q-3554-9vmg) — Revoked wallet credential's email still emitted as a verified claim
  - Medium: [GHSA-mv5p-wm66-jj74](https://github.com/qauth-labs/qauth/security/advisories/GHSA-mv5p-wm66-jj74) — Token endpoint leaks internal IPs via private_key_jwt failure reasons
  - Medium: [GHSA-qr96-hx7r-rqw5](https://github.com/qauth-labs/qauth/security/advisories/GHSA-qr96-hx7r-rqw5) — OAuth revoke silently ignores refresh tokens hinted as access_token
  - Medium: [GHSA-rwcf-7xw4-vw87](https://github.com/qauth-labs/qauth/security/advisories/GHSA-rwcf-7xw4-vw87) — private_key_jwt and ID-JAG replay: jti TTL short by one clock-skew leeway
  - Medium: [GHSA-vpf6-9vgr-6rj4](https://github.com/qauth-labs/qauth/security/advisories/GHSA-vpf6-9vgr-6rj4) — Consent ignores RFC 8707 resource: client gets tokens for any audience
  - Medium: [GHSA-vv57-g568-5vx9](https://github.com/qauth-labs/qauth/security/advisories/GHSA-vv57-g568-5vx9) — Access tokens and unredeemed auth codes survive grant revocation
  - Medium: [GHSA-vw34-9q55-2vg3](https://github.com/qauth-labs/qauth/security/advisories/GHSA-vw34-9q55-2vg3) — Disabled users keep using existing browser sessions and management tokens
  - Medium: [GHSA-w4jp-r6vp-v3qj](https://github.com/qauth-labs/qauth/security/advisories/GHSA-w4jp-r6vp-v3qj) — Any anchored certificate can sign any status list (revocation bypass)
  - Medium: [GHSA-w5x8-p2qg-mg6f](https://github.com/qauth-labs/qauth/security/advisories/GHSA-w5x8-p2qg-mg6f) — CIMD re-resolution race lets a client undo an operator's disable
  - Low: [GHSA-2rcm-rp7j-h3xf](https://github.com/qauth-labs/qauth/security/advisories/GHSA-2rcm-rp7j-h3xf) — Account enumeration via 409 on registration, contrary to threat model
  - Low: [GHSA-4g89-vhr5-8r96](https://github.com/qauth-labs/qauth/security/advisories/GHSA-4g89-vhr5-8r96) — Logout does not end browser session; old cookie still gets new tokens
  - Low: [GHSA-8gmh-6wp5-xxv6](https://github.com/qauth-labs/qauth/security/advisories/GHSA-8gmh-6wp5-xxv6) — Hosted login page: content spoofing via the error query parameter
  - Low: [GHSA-935x-3jwv-755g](https://github.com/qauth-labs/qauth/security/advisories/GHSA-935x-3jwv-755g) — Unknown key_storage entry lets a basic grade pass the haip-1.0 floor
  - Low: [GHSA-c46j-f88j-9hcf](https://github.com/qauth-labs/qauth/security/advisories/GHSA-c46j-f88j-9hcf) — Email verification password check skips failed-login lockout
  - Low: [GHSA-chc6-vw6m-mr8h](https://github.com/qauth-labs/qauth/security/advisories/GHSA-chc6-vw6m-mr8h) — Account enumeration via wallet login: unknown identifiers are enrolled
  - Low: [GHSA-g6cw-g5qq-2pqp](https://github.com/qauth-labs/qauth/security/advisories/GHSA-g6cw-g5qq-2pqp) — Race in resend-verification interval check allows email enumeration
  - Low: [GHSA-p97w-p94p-4f8v](https://github.com/qauth-labs/qauth/security/advisories/GHSA-p97w-p94p-4f8v) — authorization_code grant ignores max_agent_mode lowered after consent
  - Low: [GHSA-prxf-g4px-38hw](https://github.com/qauth-labs/qauth/security/advisories/GHSA-prxf-g4px-38hw) — Account enumeration via login timing once Argon2id jobs queue up
  - Low: [GHSA-rg3w-mqm8-m8x8](https://github.com/qauth-labs/qauth/security/advisories/GHSA-rg3w-mqm8-m8x8) — Access tokens leak user email to clients without the email scope
  - Low: [GHSA-rjh9-w9rr-vxw4](https://github.com/qauth-labs/qauth/security/advisories/GHSA-rjh9-w9rr-vxw4) — Client registration accepts javascript: and data: redirect URIs
  - Low: [GHSA-rrw7-9pwv-vxm6](https://github.com/qauth-labs/qauth/security/advisories/GHSA-rrw7-9pwv-vxm6) — Duplicate registration logs password hash via Drizzle SQL params
  - Low: [GHSA-w26w-8h69-7h5w](https://github.com/qauth-labs/qauth/security/advisories/GHSA-w26w-8h69-7h5w) — Wallet login DoS: pinned but untrusted issuer trips status-list breaker
  - Low: [GHSA-wx9c-x6qf-24jr](https://github.com/qauth-labs/qauth/security/advisories/GHSA-wx9c-x6qf-24jr) — Timing-based email enumeration in resend-verification via slow mail send
  - Low: [GHSA-xh4j-6p3v-qqw4](https://github.com/qauth-labs/qauth/security/advisories/GHSA-xh4j-6p3v-qqw4) — Skipped key attestation stating basic storage still clears haip-1.0 floor
- **BREAKING, from the other advisory fixes** (each advisory has the detail):
  - Consent now covers RFC 8707 resources: an existing consent asks once more
    for a request that names a `resource`. Migration 0021 adds
    `oauth_consents.resource_scopes`.
  - The `/oauth/authorize` Bearer path needs a consent that covers the
    request, and `unauthorized_client` is answered with HTTP 400.
  - A one-time approval no longer gets a refresh token, and a refresh into a
    scope the client no longer has is refused.
  - `SESSION_COOKIE_TTL` is an absolute lifetime, and logout ends the
    user's hosted browser sessions.
  - `http://` redirect URIs to a host that is not a loopback address are
    refused in every environment.
  - `private_key_jwt` failures carry no `error_description`.
  - Requests are refused that carry URIs with raw Unicode or spaces, URIs or
    `client_id`s over 2048 characters, email addresses over 254 characters,
    or a `max_age` that is not all digits.
  - A wallet email counts as verified only with a disclosed
    `email_verified: true`, or when its issuer is in
    `OID4VP_EMAIL_VERIFYING_ISSUERS`. Migration 0022 adds
    `user_attributes.provenance`.
  - A status list served from another host needs a matching SAN or an entry
    in `OID4VP_STATUS_LIST_SIGNERS`.
  - `haip-1.0` grades key storage more strictly, and DSA and DH keys in
    `x5c` are refused.
  - Two `mcp-guard` instances registered on one plugin scope no longer boot.
- **New configuration from the advisory fixes**: `MAX_CLIENTS_PER_DEVELOPER`
  (default 100), `REQUEST_TIMEOUT_MS` (default 60000),
  `OID4VP_EMAIL_VERIFYING_ISSUERS` and `OID4VP_STATUS_LIST_SIGNERS` (both
  unset), and `mcp-guard`'s `introspectionLocalCheck` option (default `true`).
- **BREAKING**: `/oauth/authorize` and `GET /ui/consent` redirect an
  authorization error automatically only to a client an operator provisioned
  (RFC 9700 §4.11.2, ANT-2026-O8U3P920). Every other client, including one a
  developer account creates through `POST /api/clients`, gets the error on an
  issuer page (HTTP 400) with a link to its redirect URI. Migration 0023 adds
  `oauth_clients.provisioned_by_operator` (default `false`) and sets it for the
  system client and the clients the seed scripts created; the
  `db:seed-oauth-clients` manifest sets it on create and on `--rotate`. An
  owner who changes the redirect URIs of a marked client loses the marker.
  OIDF conformance `prompt=none` modules need an operator-provisioned client
  (see `docs/oidf-op-certification-runbook.md`).
- **Operator suspension separate from `enabled`** (ANT-2026-DR5XI3LV).
  `oauth_clients.enabled` is the client owner's switch again:
  `PATCH /api/clients/{id}` may set it either way (it no longer answers `403`
  to `"enabled": true`). An operator keeps a client off with the new
  `oauth_clients.suspended` / `suspended_at` (migration 0023), which no route
  writes and a CIMD re-resolution never touches; a suspended client is refused
  wherever a disabled one is, with the same error. New operator tooling:
  `pnpm nx run infra-db:db:suspend-oauth-client -- --realm=<name>
  --client-id=<client_id> [--lift]`. The management API returns a read-only
  `suspended` field. **Upgrade note**: migration 0023 suspends every client that
  is disabled when it runs; one its owner had disabled stays off until an
  operator lifts the suspension, after which the owner re-enables it.
- **BREAKING**: a Client ID Metadata Document is refused whole when any of its
  `redirect_uris` fails the check Dynamic Client Registration applies
  (ANT-2026-D0XJAT8S follow-up). Such URIs were dropped and the rest accepted;
  now the client does not resolve (`invalid_client` at `/oauth/authorize` and
  `/oauth/token`), including a client already in use whose document lists one.
- **BREAKING**: redirect URIs are limited to `https`, `http` to a loopback host,
  and RFC 8252 §7.1 private-use schemes (a reverse domain name such as
  `com.example.app:/callback`). Dynamic Client Registration,
  `POST /api/clients` (create and update) and CIMD documents refuse any other
  scheme, including `javascript:`, `data:`, `file:` and schemes without a period
  such as `myapp:`, with `invalid_redirect_uri`. `/oauth/authorize` and the
  consent screen refuse such a URI on a client stored earlier
  (`redirect_uri not permitted for this environment`). Re-register a native
  app that used a scheme without a period under a reverse-domain scheme.

[Unreleased]: https://github.com/qauth-labs/qauth/compare/v0.1.3...HEAD
[0.1.3]: https://github.com/qauth-labs/qauth/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/qauth-labs/qauth/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/qauth-labs/qauth/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/qauth-labs/qauth/releases/tag/v0.1.0

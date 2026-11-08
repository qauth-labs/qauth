/**
 * The single source for QAuth's delivery status: what shipped, what is
 * flag-gated, and what is still open work. Two consumers read this file —
 * the Reference lane's status page (`content/docs/reference/status.mdx`,
 * which renders it) and, as prose vocabulary only, the drift guard in
 * `src/invariants/status-claims.ts` (which does NOT import this module —
 * see that file's `FEATURE_EVIDENCE` table for why: it detects "shipped" by
 * checking whether evidence paths exist on disk, not by trusting a declared
 * status.
 *
 * UNIFICATION: settled 2026-08-31, and the answer is NO (#399). The two are
 * kept separate on purpose, because they answer different questions and a
 * merged one would answer neither well. This file is a CURATED narrative — what
 * a reader should be told about delivery status, in what order, with the
 * caveats that matter. The guard is a FALSIFIER — a small set of claims that
 * can be mechanically disproved against the tree and against GitHub. Feeding
 * this file into the guard would make the guard trust exactly the thing it
 * exists to check; deriving this file from the guard would reduce a status page
 * to a list of paths that happen to exist. What #399 added instead is a second
 * falsifier — issue-state claims resolved against the GitHub API — so more of
 * this file's claims are checkable without either side absorbing the other.
 * `#379` is why: it went stale in this file within 24 hours of closing, and no
 * amount of unification would have caught that. An API lookup does.)
 *
 * Plain data with types only: no rendering, no filesystem access. Every
 * claim below must stay true of the tree at HEAD — update this file, not a
 * hand-typed copy on a content page, when status changes.
 */

/** A named window of related work, as tracked in README.md's roadmap (T0–T5). */
export type TrackState = 'shipped' | 'partial';

export interface DeliveryTrack {
  /** The track identifier used throughout README.md and docs/README.md, e.g. `T3`. */
  id: string;
  name: string;
  state: TrackState;
  summary: string;
}

/**
 * `shipped` — the described capability's code is complete and present in
 * the tree, in full. `partial` — only some of the described capability
 * shipped; the rest is open work, named in `summary`.
 *
 * This says nothing about whether the feature is reachable by default: that
 * is a separate axis, carried by the optional `flag` field below. A feature
 * can be `shipped` and still be off by default behind a flag (PQC hybrid
 * signing) — that is not a lesser degree of "shipped", it is an operator
 * decision layered on top of complete code. Do not read `shipped` as
 * "enabled" or `partial` as "flag-gated"; check `flag` for gating and
 * `state` for completeness, independently.
 */
export type FeatureState = 'shipped' | 'partial';

export interface FeatureFlag {
  /** The environment variable name, as declared in `apps/auth-server/src/config/env.ts`. */
  name: string;
  default: 'on' | 'off';
}

export interface FeatureStatus {
  /** Matches a `feature` name in `status-claims.ts`'s `FEATURE_EVIDENCE` table where one exists. */
  feature: string;
  state: FeatureState;
  summary: string;
  /** Set when a boolean environment flag gates whether the feature is reachable at runtime. */
  flag?: FeatureFlag;
}

export interface ReleaseInfo {
  version: string;
  stage: 'pre-release' | 'pre-1.0' | 'ga';
  /** ISO date (`YYYY-MM-DD`) this version was cut. */
  date: string;
}

export const CURRENT_RELEASE: ReleaseInfo = {
  version: 'v0.2.1',
  stage: 'pre-1.0',
  date: '2026-11-08',
};

/**
 * The near-term roadmap (T0–T3, T5) is complete; T4 — the long-term
 * federation + post-quantum platform — is partially shipped. See
 * `FEATURE_STATUS` below for the feature-level detail behind the T4 row.
 */
export const DELIVERY_TRACKS: DeliveryTrack[] = [
  {
    id: 'T0',
    name: 'Trust floor',
    state: 'shipped',
    summary:
      'Real-DB (testcontainers) repository tests, logout endpoint test, CI typecheck + coverage gate.',
  },
  {
    id: 'T1',
    name: 'MCP productization',
    state: 'shipped',
    summary:
      '`@qauth-labs/resource-guard` (RFC 9728 metadata + token validation + step-up scope challenges), Client ID Metadata Documents (CIMD) support, MCP quickstart + example, RFC 7009 revocation.',
  },
  {
    id: 'T2',
    name: 'Agent-native authorization',
    state: 'shipped',
    summary:
      'Agent client type, RFC 8693 on-behalf-of token exchange, scope modes (ReadOnly / Admin / Exec), step-up, per-agent audit.',
  },
  {
    id: 'T3',
    name: 'OIDC conformance + hardening',
    state: 'shipped',
    summary:
      'Security headers, CSRF, secure cookies, OIDC ID token/nonce/claims, structured logging + Prometheus metrics, failed-login lockout.',
  },
  {
    id: 'T5',
    name: 'Environment-aware authorization',
    state: 'shipped',
    summary:
      '`environment` (development / staging / production) as a fail-safe policy dimension; `resolveEnvironmentPolicy` drives token TTLs, PKCE, localhost redirects, rate-limit tier, agent step-up; environment-gated developer API keys.',
  },
  {
    id: 'T4',
    name: 'Federation + PQC (long-term platform)',
    state: 'partial',
    summary:
      'Identifier abstraction, the gate this track waited on, shipped and closed. Wallet federation completes a browser sign-in end to end behind a default-off flag — HAIP profile wiring (#377) and the same-device return leg (#405) both landed 2026-09-11 — with the real-wallet interoperability pass still open; PQC hybrid signing shipped behind a default-off flag. See the feature rows below.',
  },
];

/**
 * Feature-level status. Names mirror `status-claims.ts`'s `FEATURE_EVIDENCE`
 * table where that guard also tracks the feature, so a reader can cross
 * reference the two — the two lists are not code-linked (see the module
 * doc comment above).
 */
export const FEATURE_STATUS: FeatureStatus[] = [
  {
    feature: 'Identifier abstraction (ADR-002)',
    state: 'shipped',
    summary:
      'Epic #224 closed. Migrations 0010–0012 shipped, including the destructive 0011 that dropped `users.email`, `users.email_normalized`, and `users.password_hash`. `users` is now a pure identity anchor; credentials live in `user_credentials`. Not a gate for anything else — done.',
  },
  {
    feature: 'PQC / hybrid signing',
    state: 'shipped',
    summary:
      'Epic #241 closed. Hybrid ML-DSA-65 + Ed25519 signing, mixed AKP+OKP JWKS, a native aws-lc-rs backend via napi-rs, and an attested reproducible build channel (byte-for-byte determinism verified on Linux only) all shipped.',
    flag: { name: 'HYBRID_SIGNING_ENABLED', default: 'off' },
  },
  {
    feature: 'Wallet federation / OID4VP',
    state: 'partial',
    summary:
      'Merged: `VerifierProfile` (#299), OID4VP 1.0 request generation and `direct_post` intake (#233), the per-realm issuer trust allowlist (#236), ES256 + JWE crypto (#298), SD-JWT VC presentation validation (#234), Token Status List revocation (#297), the wallet sign-in UI (#239) and the end-to-end mock-wallet suite (#240, `apps/auth-server/src/app/wallet-federation.integration.test.ts`). A browser completes a wallet sign-in — account linking, sign-in with a linked wallet, and `acr` — once the flag is on and a `VerifierProfile` is named; since 2026-10-19 wallet sign-in creates no accounts (ADR-009 §1, amended), so a wallet is linked from a signed-in account first; with the flag on and no profile named the deployment refuses to start rather than falling back to a default posture. Validated so far only against a mock wallet, on both profiles. HAIP profile wiring (#377) closed 2026-09-11 with Phase C (encrypted `direct_post.jwt`), so `haip-1.0` boots when provisioned; the same-device return leg (#405, ADR-013) landed the same day — the user picks the device on the sign-in form, a same-device flow is answered with an OID4VP 1.0 §8.2 `redirect_uri` carrying a single-use Response Code and completes only in the browser that started it, and the cross-device QR flow is unchanged. Open: the real-wallet interoperability pass (#376). Key-storage assurance into the assurance policy (#379) closed 2026-08-26.',
    flag: { name: 'WALLET_FEDERATION_ENABLED', default: 'off' },
  },
  {
    feature: 'Agent-native authorization',
    state: 'shipped',
    summary:
      'Agent client type, RFC 8693 on-behalf-of token exchange (`act` claim), scope modes (ReadOnly / Admin / Exec), step-up before dangerous operations, per-agent audit.',
  },
  {
    feature: 'Environment-aware authorization',
    state: 'shipped',
    summary:
      '`environment` selects a fail-safe policy profile across token TTLs, PKCE, localhost redirects, rate-limit tier, and agent step-up.',
  },
  {
    feature: 'RP-initiated logout',
    state: 'shipped',
    summary:
      'OpenID Connect RP-Initiated Logout 1.0 at `/oauth/end-session` (GET and POST), listed in discovery as `end_session_endpoint`. A valid `id_token_hint` for the signed-in account ends that browser session at once; any other signed-in browser confirms first. The browser goes back only to a `post_logout_redirect_uris` entry the client registered, matched exactly. There is no front-channel logout (ADR-018).',
  },
  {
    feature: 'Back-channel logout',
    state: 'shipped',
    summary:
      'OpenID Connect Back-Channel Logout 1.0: a client registers `backchannel_logout_uri` (an `https` URI on public addresses), and whenever a session ends, by any path, each client it served gets a signed `logout+jwt` logout token at that URI. The token is queued in the transaction that ends the session and sent by the delivery role through the SSRF-safe egress client, with retries; a failed delivery never holds a sign-out back. Discovery lists `backchannel_logout_supported` and `backchannel_logout_session_supported` (#624).',
  },
  {
    feature: 'Upstream OpenID Connect sign-in',
    state: 'partial',
    summary:
      "A person signs in, or signs up when the realm allows it (`ALLOW_SIGN_UP`, off by default), through one of the realm's upstream OpenID Connect providers (#639): a button per listed provider on the sign-in page and the `upstream` step of the Interaction API, or `qauth_upstream=<type>` on the authorization request, hidden providers included. The account is found by `(realm, provider type, sub)` and tied to the ID token's issuer, never matched by email; a new one gets the provider's claims as attributes, verified unless the provider's verified switch is off. On the ceremony page an unknown identity first asks whether it starts a new account or joins an existing one, which links it only after a fresh sign-in to that account; a signed-in person links one with `qauth_link=<type>`, and the account API lists and unlinks them (#670). Open: the admin API that manages the providers (#714), which are rows of `realm_upstream_providers` until then; provider icons; and the review-your-details page. An account that holds a passkey is asked for it while passkeys are on (`WEBAUTHN_ENABLED`) and refused otherwise, and while `INTERACTION_UI_ENABLED` is off an unverified account is refused rather than verified inline.",
  },
  {
    feature: 'Passkey sign-in',
    state: 'partial',
    summary:
      'Built (#651): the sign-in engine\'s `webauthn_get` and `webauthn_create` steps, passkey-first order with no `login_hint`, the downgrade rule (a login completes only after the account\'s strongest bound factor, a disabled passkey included), an assertion refused without the user-verification flag, `amr` `["pop","mfa"]` or `["pwd","pop","mfa"]`, the optional enrolment after a password sign-in with a recovery set at the first one, and the two `/ui` pages that run the ceremonies. Sign-up with a passkey alone (#655): an account with no email address and no password, verified by the ceremony, whose recovery set is shown before the code is issued; no mail is ever sent to it, its notices are in the security log, and a recovery code offered beside the first sign-in step finds it, then binds a new passkey in place of the lost one. `/auth/login` and `/ui/login` already refuse a right password of an account that holds a passkey. Open: the FiPA endpoint (#646); the design-system screens (#652).',
    flag: { name: 'WEBAUTHN_ENABLED', default: 'off' },
  },
  {
    feature: 'Authenticator app (TOTP) second factor',
    state: 'partial',
    summary:
      'Built (#653): the sign-in engine\'s `totp` step after the first factor of an account that holds one (SHA-1, six digits, 30 seconds, one step of tolerance, a time step never accepted twice), `amr` `["pwd","otp","mfa"]` for a password then a code, and the `totp_setup` step that binds a new secret after a first valid code, a fresh factor and, for a password-only account, a mailed code, with a recovery set at the first binding. The secret is sealed under the realm\'s `data_at_rest` key. Wrong codes count per account on their own failure ladder, a password never clears them, and at 100 in a row the app is turned off only while the hosted pages are on and the account keeps another way in; three notices no realm can switch off. The two `/ui` pages serve the steps. `/auth/login` and `/ui/login` refuse a right password of an account that holds one. Open: the stored MFA policy that asks for the set-up (the admin console), the account API\'s own enrolment, the FiPA endpoint (#646) and the design-system screens (#654).',
  },
  {
    feature: 'Hosted account pages',
    state: 'partial',
    summary:
      "Built (#844): `/ui/account`, the signed-in person's own account on the hosted pages, in their current server-rendered style: the sign-in methods, a password change under the realm's password policy, passkeys (add through the sign-in's enrolment step, rename, remove), the authenticator app (set up, turn off), a new recovery code set shown once, linked upstream accounts (link by signing in, unlink) and the sessions (sign one out, sign out everywhere, which tells each relying party with a back-channel logout URI). Every form works without JavaScript and carries a CSRF value, every change asks for the fresh authentication the account API asks of it, a removal never leaves the account without a way in, and each change is a user event. On while the hosted pages are (`INTERACTION_UI_ENABLED`); the routes are experimental. The design-system account console replaces them: the overview and the password (#685), the passkeys (#686), the authenticator app and recovery codes (#687), the sessions (#688).",
    flag: { name: 'INTERACTION_UI_ENABLED', default: 'off' },
  },
  {
    feature: 'API keys',
    state: 'shipped',
    summary:
      'Environment-gated developer API keys (backend + portal UI), governed by the same environment-aware authorization policy rather than a standalone flag.',
  },
];

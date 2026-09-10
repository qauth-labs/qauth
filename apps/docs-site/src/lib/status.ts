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
  stage: 'pre-release' | 'ga';
  /** ISO date (`YYYY-MM-DD`) this version was cut. */
  date: string;
}

export const CURRENT_RELEASE: ReleaseInfo = {
  version: 'v0.1.0-rc.0',
  stage: 'pre-release',
  date: '2026-07-25',
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
      '`@qauth-labs/mcp-guard` (RFC 9728 metadata + token validation + step-up scope challenges), Client ID Metadata Documents (CIMD) support, MCP quickstart + example, RFC 7009 revocation.',
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
      'Security headers, CSRF, secure cookies, OIDC ID token/nonce/claims, structured logging + `/metrics`, failed-login lockout.',
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
      'Identifier abstraction, the gate this track waited on, shipped and closed. Wallet federation completes a browser sign-in end to end behind a default-off flag, with HAIP profile wiring and the real-wallet interoperability pass still open; PQC hybrid signing shipped behind a default-off flag. See the feature rows below.',
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
      'Merged: `VerifierProfile` (#299), OID4VP 1.0 request generation and `direct_post` intake (#233), the per-realm issuer trust allowlist (#236), ES256 + JWE crypto (#298), SD-JWT VC presentation validation (#234), Token Status List revocation (#297), the wallet sign-in UI (#239) and the end-to-end mock-wallet suite (#240, `apps/auth-server/src/app/wallet-federation.integration.test.ts`). A browser completes a wallet sign-in — first-time enrolment, returning login, account linking and `acr` — once the flag is on and a `VerifierProfile` is named; with the flag on and no profile named the deployment refuses to start rather than falling back to a default posture. Validated so far only on the `oid4vp-1.0-base` profile against a mock wallet. Open: HAIP profile wiring (#377) and the real-wallet interoperability pass (#376). Key-storage assurance into the assurance policy (#379) closed 2026-08-26.',
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
    feature: 'API keys',
    state: 'shipped',
    summary:
      'Environment-gated developer API keys (backend + portal UI), governed by the same environment-aware authorization policy rather than a standalone flag.',
  },
];

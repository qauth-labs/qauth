# Changelog

All notable changes to QAuth are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
  section. Every pull request runs the same stamp, pack, check and install as a
  dry run. `@qauth-labs/resource-guard` is the first package: ESM with type
  declarations, an `exports` map, `engines` and its licence. `RELEASING.md` is
  the maintainer guide for both the images and the packages: release, rollback
  (deprecate, never unpublish) and the version rule.
- **A registry of configuration keys** ([#449], ADR-018 §5). Every environment
  key the auth server and the developer portal read has one entry in
  `libs/server/config/src/lib/registry/`: a tier (stable, advanced or
  experimental), a role (deployment or realm seed), a default and one sentence.
  The docs site's new **Configuration** page (`operate/configuration`) is
  generated from it, and tests fail when the registry, the env schemas, the page
  and `.env.example` disagree. Stable keys follow the deprecation policy, an
  advanced key may change in a minor release, and an experimental key may change
  at any time.
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
  and ID tokens, `event_signing` only `secevent+jwt` and `logout+jwt`. Every
  call names its caller's role (`local`, `web`, `api`, `delivery`, `admin`),
  and a policy table decides what each may call. No operation returns a
  private key. The in-process signer unwraps a key on first use, keeps it in a
  bounded cache and re-reads the active key once a minute, so a signature with
  a warm cache runs no database query; a missing key is an error, never a new
  key. The KEK provider, envelope encryption and key factory move to the
  `@qauth-labs/server-keys/custody` entry point, and a lint rule lets only the
  signer's wiring, the new `@qauth-labs/fastify-plugin-signer`, import it.
  The auth-server registers the plugin for the key import at first boot
  ([#485]); tokens are still signed with the environment keys until token
  signing moves onto the signer.

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
  on a fresh deployment), and gives a fresh realm an RS256 signing key too;
  while `JWT_PRIVATE_KEY` stays required, every deployment imports its
  signing key instead. It is one transaction, so two nodes that boot together import once. A
  warning at every boot names each key variable that is still set and says to
  keep it: tokens and the session cookie keep using the variables until they
  move onto the signer. Until rotation through the store ships, a signing
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
  deliveries left from when it was on hold back no event retention. Until the
  event mapping of #540, verification events are the only SETs sent. The docs
  site's new **SSF transmitter** page (`operate/ssf-transmitter`) walks through
  a receiver and the verification event.
- **Schema**: migration 0039 adds `ssf_streams`, `ssf_stream_subjects`,
  `realms.ssf_transmitter_enabled` (default off) and an index on
  `event_deliveries` that finds a destination's latest failed delivery ([#410]).
  Expand-only; the index build holds back delivery writes while it runs.

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
  spaces in the challenge. No route uses the guards yet; the developer and
  account routes move under their prefixes in [#524]. The token endpoint issues
  an audience in the reserved `urn:qauth:aud:` namespace only to a client whose
  `audience` lists it, on every grant (`invalid_target` otherwise, at
  `/oauth/authorize` and `/ui/consent` too); a code refused this way is not
  spent. A client resolved from a Client ID Metadata Document or registered at
  `/oauth/register` lists none, whatever its row holds. On a user's grant
  (authorization code and refresh token) a family audience is issued only when a
  `resource` names it, so a client's default audience leaves it out there. The
  Bearer path of `/oauth/authorize` refuses `access_denied` when the request or
  the client's default audience holds one, and a family audience never makes a
  client authoritative at introspection. Self-registration never obtains one,
  by the rule the reserved `qauth:` scopes follow: dynamic registration and a
  Client ID Metadata Document ignore it in `audience` or `resource` metadata,
  and the seed manifest refuses it in a `cimd_clients` entry's `audience`. The
  JWT plugin's new `verifyRequestAccessToken(request, policy)` runs
  `requireJwt`'s checks under a route's issuer rule and `typ` requirement.

### Changed

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
  today's token, whose `aud` is the system client's id. Nothing mints it in
  this release: `/auth/login` still mints today's token and the system client's
  row is left as it is. [#524] mints it. Expand, then contract (ADR-018 §5): a
  node of the previous release accepts every portal token this release mints,
  so the upgrade is safe to roll. See **Upgrades** (`operate/upgrades`).

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

- **Every URL comes from the realm row** ([#490], ADR-019 Decision 1). The
  issuer and endpoint URLs in discovery, the RFC 9207 `iss` of an authorization
  response, the userinfo audience, the client-assertion audience, both sides of
  ID-JAG, the wallet `response_uri`, `request_uri` and same-device return URI,
  the link in a verification mail and the base a DPoP proof's `htu` is checked
  against are built on the issuer of the realm the request's host named. After
  boot nothing reads `JWT_ISSUER`, `EMAIL_BASE_URL` or the `Host` header to
  build a URL, and a lint rule refuses `request.host`, `request.hostname`,
  `request.port`, `request.protocol`, the `Host` header and `X-Forwarded-*`
  outside the realm resolver. A deployment with one realm sees the same URLs as
  before, except mail links where `EMAIL_BASE_URL` was set to another base than
  `JWT_ISSUER`: they now start at `JWT_ISSUER`, and the boot logs a warning
  saying so. With a second realm:
  - its discovery, `iss`, mail links and wallet URLs name its own issuer;
  - a DPoP proof sent to it must name its own endpoint URL, so proofs to a
    realm other than the boot one are no longer refused;
  - introspection, revocation, logout, the token-exchange subject token and the
    Bearer path of `/oauth/authorize` accept only a token whose `iss` is the
    realm's issuer. Tokens still carry `JWT_ISSUER` until they are signed per
    realm ([#491]), so until then only the default realm's tokens pass there.

  `EMAIL_BASE_URL` stays required but is no longer read for links. The mail library's
  `sendVerificationEmail` takes the link base with each mail instead of from
  its configuration.

  The discovery documents, `/.well-known/jwks.json` and
  `/.well-known/ssf-configuration` state the global ceiling, `RATE_LIMIT_MAX`
  requests per `RATE_LIMIT_WINDOW` seconds for each realm and client address,
  as a limit of their own. Each of them now counts in a bucket of its own
  instead of the one that the routes without a limit share.

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

- Nx tasks use a remote cache (Nx Cloud, `nxCloudId` in `nx.json`). CI's
  `affected` legs write to it only on a push to main, with a read-write token
  that only main can reach; every other run reads at most, so a pull request
  replays what main already built and checked and never stores its own
  results. A run with no token, such as a fork's pull request or a local run,
  is anonymous and never stores. Jobs whose Nx targets are not cacheable, the
  image builds and the dev containers set `NX_NO_CLOUD=true`.

  **Action for contributors**: nothing is required. Nx contacts the cache
  service on every task run; offline, or to keep a run local, set
  `NX_NO_CLOUD=true`. Without it, a network that drops packets delays each
  `nx` command by up to about 50 seconds before Nx falls back to the local
  cache.

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
[#482]: https://github.com/qauth-labs/qauth/issues/482
[#484]: https://github.com/qauth-labs/qauth/issues/484
[#485]: https://github.com/qauth-labs/qauth/issues/485
[#486]: https://github.com/qauth-labs/qauth/issues/486
[#487]: https://github.com/qauth-labs/qauth/issues/487
[#488]: https://github.com/qauth-labs/qauth/issues/488
[#490]: https://github.com/qauth-labs/qauth/issues/490
[#491]: https://github.com/qauth-labs/qauth/issues/491
[#507]: https://github.com/qauth-labs/qauth/issues/507
[#509]: https://github.com/qauth-labs/qauth/issues/509
[#513]: https://github.com/qauth-labs/qauth/issues/513
[#524]: https://github.com/qauth-labs/qauth/issues/524
[#536]: https://github.com/qauth-labs/qauth/issues/536
[#541]: https://github.com/qauth-labs/qauth/issues/541
[#552]: https://github.com/qauth-labs/qauth/issues/552
[#553]: https://github.com/qauth-labs/qauth/issues/553
[#577]: https://github.com/qauth-labs/qauth/issues/577
[#595]: https://github.com/qauth-labs/qauth/issues/595
[#596]: https://github.com/qauth-labs/qauth/issues/596
[#627]: https://github.com/qauth-labs/qauth/issues/627
[#827]: https://github.com/qauth-labs/qauth/issues/827

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

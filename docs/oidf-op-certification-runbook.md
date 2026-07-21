# OIDF OP Certification Runbook — QAuth (Basic OP + Config OP)

**Date:** 2026-07-20
**Applies to:** QAuth OAuth 2.1 / OIDC server (TypeScript · Fastify · Nx), repo `qauth-labs/qauth`
**Target certifications:** OpenID Foundation **Basic OP** (bundling **Config OP**)
**Related work:** gap analysis #286 · RS256 ID-token signing #309 · POST authorize/userinfo + `auth_time` #310 (PR #312)

## Purpose

This runbook takes an operator top-to-bottom from a clean deployment to a submitted OIDF certification request. It covers generating the signing keys QAuth needs, configuring the environment, deploying and smoke-verifying the OIDC surface, registering the conformance client, driving the OpenID Foundation conformance suite through the **Basic OP** and **Config OP** plans, working the residual-uncertainty checklist from the #286 gap analysis, and exporting results for submission (including fees, membership, and the open-source fee-waiver path). Every QAuth-specific claim is anchored to `file:line` in the repo; every step that only a live suite settles is flagged **[RE-CHECK AT RUN TIME]**. Because the conformance suite evolves, re-verify the drift-flagged items against the certified snapshot before the publishable run (see the closing section).

---

## Prerequisites

Confirm all of these **before** touching the suite — a wrong pre-flight wastes an entire run.

1. **#309 merged (RS256 signing).** The RS256 ID-token path is merged (`libs/fastify/plugins/jwt/src/lib/fastify-plugin-jwt.ts:107-116, 276-289`). It is inert until you set the RS256 key (Step 2). Without RS256, QAuth signs ID tokens EdDSA-only, and the Basic OP `id_token` signature test **hard-fails**.
2. **#310 / PR #312 merged (POST `/authorize`, POST `/userinfo`, `auth_time`).** These are required by the suite's POST-endpoint modules and the `max_age` / `auth_time` modules. **Deploy from a commit that contains both #309 and #312** — a build predating #312 lacks POST `/authorize` and POST `/userinfo` and emits no `auth_time`, each a hard-fail. (As of this runbook's date, #312 is open; confirm it is merged into your deploy commit.)
3. **A publicly reachable HTTPS deployment with a publicly-trusted certificate.** When testing an OP, the suite acts as the RP: it fetches your discovery doc, JWKS, token, and userinfo endpoints server-to-server, and the browser is redirected between QAuth and the suite. A self-signed cert or a private host will fail. Point a real hostname at the deployment and set `JWT_ISSUER` to exactly that HTTPS origin (the `iss` in tokens must equal discovery `issuer`, byte-for-byte).

The rest of the deployment env (DB, Redis, email, rate limits, environment-policy per ADR-008) is documented in `.env.example`, `docs/docker.md`, and `docs/environment-authorization.md` — follow those; this runbook only adds the JWT/conformance-specific configuration.

---

## Step 1 — Generate the signing keys

### What QAuth actually imports (verified)

Private keys are imported with jose `importPKCS8`; public keys with `importSPKI` (`libs/core/crypto/src/lib/key-management.ts:7, 41-42, 51-52`). RS256 wiring: EdDSA private → `importPrivateSigningKey(pem,'EdDSA')`, RS256 private → `importPrivateSigningKey(pem,'RS256')`, RS256 public → `importSPKI(...,'RS256')`, and public-key derivation via `node:crypto` `createPublicKey(...).export({type:'spki',format:'pem'})` (`libs/server/jwt/src/lib/key-management.ts:44-46, 74-76, 84-86, 104-106`).

Therefore:

- **Private keys MUST be PKCS#8 PEM** — first line `-----BEGIN PRIVATE KEY-----`.
- **Public keys (optional) MUST be SPKI PEM** — first line `-----BEGIN PUBLIC KEY-----`. QAuth derives the public key from the private key if you omit it.
- **RSA MUST be ≥2048-bit.** The conformance test fixture uses exactly `rsa` `modulusLength: 2048` exported pkcs8/pem, ed25519 as pkcs8/spki, example kid `'rsa-2026'` (`apps/auth-server/src/app/routes/oauth/oidc-conformance.test.ts:53-56, 61-63, 68`).

> **Pitfall:** `openssl genrsa` emits **PKCS#1** (`-----BEGIN RSA PRIVATE KEY-----`), which `importPKCS8` rejects. Use `openssl genpkey` (PKCS#8) below, or convert: `openssl pkcs8 -topk8 -nocrypt -in old.pem -out jwt-rs256-private.pem`.

### (a) EdDSA (Ed25519) — required; signs access tokens (and ID tokens when RS256 absent)

```bash
openssl genpkey -algorithm ed25519 -out jwt-ed25519-private.pem
# optional matching public key (derived if omitted):
openssl pkey -in jwt-ed25519-private.pem -pubout -out jwt-ed25519-public.pem
```

### (b) RS256 (RSA-2048) — REQUIRED for the conformance deployment

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out jwt-rs256-private.pem
# optional matching public key (derived if omitted):
openssl pkey -in jwt-rs256-private.pem -pubout -out jwt-rs256-public.pem
```

### Verify format before deploying

```bash
head -1 jwt-ed25519-private.pem   # MUST be: -----BEGIN PRIVATE KEY-----
head -1 jwt-rs256-private.pem      # MUST be: -----BEGIN PRIVATE KEY-----  (NOT "RSA PRIVATE KEY")
openssl pkey -in jwt-rs256-private.pem -noout -text | head -1   # "Private-Key: (2048 bit ...)"
```

---

## Step 2 — Configure the environment

Names verified in `libs/server/config/src/lib/schemas/jwt.ts`; plugin wiring in `apps/auth-server/src/app/app.ts:122-140`.

| Env var                                                     | Required?               | Meaning / notes                                                                                                                                                                                                                                                                                                                                                                                                                   | Source                  |
| ----------------------------------------------------------- | ----------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------- |
| `JWT_ISSUER`                                                | **Yes**                 | Public issuer URL; must be a valid URL. Sets the `iss` claim, the base for every well-known URL, and the RFC 9207 `iss` redirect param. Use the exact public HTTPS origin the suite reaches. A single trailing slash is stripped (`resolveIssuerIdentifier`, `apps/auth-server/src/app/helpers/discovery.ts:183-185`); prefer **no** trailing slash so the compared value is byte-identical.                                      | `jwt.ts:124`            |
| `JWT_PRIVATE_KEY` **or** `JWT_PRIVATE_KEY_PATH`             | **Yes (one of)**        | EdDSA private key (PKCS#8 PEM), inline or path. Enforced at boot.                                                                                                                                                                                                                                                                                                                                                                 | `jwt.ts:65-71, 156-168` |
| `JWT_PUBLIC_KEY` / `JWT_PUBLIC_KEY_PATH`                    | No                      | EdDSA public key (SPKI PEM). Derived if omitted.                                                                                                                                                                                                                                                                                                                                                                                  | `jwt.ts:77-83`          |
| `JWT_RS256_PRIVATE_KEY` **or** `JWT_RS256_PRIVATE_KEY_PATH` | **Yes for conformance** | RS256 private key (PKCS#8 PEM). Presence flips ID-token signing to RS256 and publishes the RSA JWK. Absent ⇒ EdDSA-only ⇒ OIDF suite **hard-fails**.                                                                                                                                                                                                                                                                              | `jwt.ts:93-99`          |
| `JWT_RS256_PUBLIC_KEY` / `JWT_RS256_PUBLIC_KEY_PATH`        | No                      | RS256 public key (SPKI PEM). Derived if omitted.                                                                                                                                                                                                                                                                                                                                                                                  | `jwt.ts:106-111`        |
| `JWT_RS256_KID`                                             | Recommended             | Stable `kid` for the RSA JWK (e.g. `rsa-2026`). Distinctness across published keys is enforced **when the JWKS is served** (`assertDistinctJwksKeyIds`, `fastify-plugin-jwt.ts:344`): a duplicate kid makes `/.well-known/jwks.json` return 500, which Step 3b's smoke curl surfaces before you start the suite. In practice a collision is near-impossible — `app.ts` configures no EdDSA `kid`, so the RSA kid is the only one. | `jwt.ts:113-118`        |

**Path-vs-inline precedence:** if both a `_PATH` and an inline value are set, the **file wins** (`resolveKey`, `jwt.ts:32-49`). For containers, mount the PEMs and use the `_PATH` variants:

```bash
JWT_ISSUER=https://auth.example.com
JWT_PRIVATE_KEY_PATH=/run/secrets/jwt-ed25519-private.pem
JWT_RS256_PRIVATE_KEY_PATH=/run/secrets/jwt-rs256-private.pem
JWT_RS256_KID=rsa-2026
```

> **Doc caveat:** the RS256 vars are **not yet listed in `.env.example`** (its JWT block `.env.example:183-241` is EdDSA + ML-DSA only). They are fully supported by the schema — just undocumented there.

---

## Step 3 — Deploy and smoke-verify

Deploy the build (both #309 and #312) with the Step 2 env, then run these against the **live** issuer. `export ISSUER=https://auth.example.com` first.

### (a) Discovery advertises RS256

```bash
curl -sS "$ISSUER/.well-known/openid-configuration" \
  | jq '{issuer, id_token_signing_alg_values_supported, jwks_uri, token_endpoint_auth_methods_supported}'
```

Expect `id_token_signing_alg_values_supported` = `["RS256","EdDSA"]` and `issuer` byte-identical to `JWT_ISSUER` (minus any trailing slash). This is sourced live from the plugin (`well-known.ts:34` → `getIdTokenSigningAlgValuesSupported`, `fastify-plugin-jwt.ts:321-327`), so `["EdDSA"]` here means the RS256 key was **not** picked up — fix the env before proceeding.

### (b) JWKS has a distinct RSA key

```bash
curl -sS "$ISSUER/.well-known/jwks.json" | jq '.keys[] | {kty, kid, alg, use}'
```

Expect ≥2 entries: one `kty:"OKP"` (Ed25519) and one `kty:"RSA"` (`alg:"RS256"`). The RSA entry carries `kid` = `JWT_RS256_KID`; the OKP entry has **no** `kid` by default (`app.ts` configures no EdDSA `keyId`, so expect `kid: null` there) — harmless for Basic OP, since the RS256 ID token resolves by the RSA kid. The RSA entry appears only when RS256 is configured (`getJwks`, `fastify-plugin-jwt.ts:328-346`).

### (c) Manual code + PKCE round trip (optional sanity)

`/oauth/authorize` requires an authenticated end-user — a `__Host-qauth_session` cookie or a legacy Bearer (`authorize.ts:243-253`) — so a full round trip needs a test user logged in at `$ISSUER/ui/login` first.

```bash
# 1. PKCE pair (S256 is hard-required — oauth.ts:35)
VERIFIER=$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')
CHALLENGE=$(printf '%s' "$VERIFIER" | openssl dgst -binary -sha256 | openssl base64 | tr '+/' '-_' | tr -d '=')

# 2. In a browser: log in at $ISSUER/ui/login, then visit:
#    $ISSUER/oauth/authorize?response_type=code&client_id=<CID>&redirect_uri=<CB>
#    &scope=openid%20profile%20email&state=xyz&nonce=n1
#    &code_challenge=$CHALLENGE&code_challenge_method=S256
#    Consent, then read ?code=... from the redirect.

# 3. Exchange (confidential, client_secret_basic):
curl -sS -X POST "$ISSUER/oauth/token" \
  -u "<CID>:<SECRET>" \
  -d grant_type=authorization_code -d code=<CODE> \
  -d redirect_uri=<CB> -d code_verifier=$VERIFIER | jq .
```

Confirm the returned `id_token` header decodes to `{"alg":"RS256","kid":"<JWT_RS256_KID>"}` and the payload carries `iss/aud/sub/exp/iat/nonce` (and `auth_time`).

---

## Step 4 — Register the conformance client

Route `apps/auth-server/src/app/routes/oauth/register.ts`; body schema `apps/auth-server/src/app/schemas/oauth.ts:300-336`.

**Facts that shape the client:**

- **Open registration** — no `initial_access_token` gate (`register.ts:20-30`); IP rate-limited (`register.ts:44-53`).
- Accepted fields (unknown keys stripped, `schema:298`): `redirect_uris` (`:302`), `grant_types` ⊆ `authorization_code|refresh_token|client_credentials` (`:303-306`), `response_types` = only `code` (`:307-310`), `token_endpoint_auth_method` ∈ `none|client_secret_basic|client_secret_post` (`:311-313`), `scope` (`:314`).
- **Confidential vs public:** `token_endpoint_auth_method: none` ⇒ public, no secret (`register.ts:95-107, 182-189`). Any other value ⇒ confidential, `client_secret` returned **once** in the 201 body (`register.ts:104-107, 208-210`, `Cache-Control: no-store`).
- **One confidential client covers both Basic OP auth methods.** The token endpoint infers the method from how credentials are presented and does **not** enforce it against the registered method — `extractClientCredentials` labels by presentation (`client-auth.ts:109-137`), `authenticateClient` only verifies the secret hash (`client-auth.ts:144-161`). So the same `client_id`/`client_secret` works for both `client_secret_basic` and `client_secret_post`.
- **Scope cap:** requested scopes must fall within the realm allowlist, seeded on first use from `DEFAULT_DYNAMIC_REGISTRATION_SCOPES` = exactly `openid profile email offline_access` (`libs/server/config/src/lib/schemas/auth.ts:282-290`; seeding `register.ts:63-78`). Requesting those four always succeeds out of the box.
- **Redirect-URI exact match** at authorize time — no wildcards (`authorize.ts:131`, `client.redirectUris.includes(redirectUri)`). Register the callback **verbatim**.
- **Environment gate:** DCR clients are created `environment: 'production'` (`register.ts:142`), which permits **HTTPS redirect URIs only**; plain-HTTP `localhost` is rejected outside a `development` client (`authorize.ts:154-172`). The hosted suite callback is HTTPS, so this is fine.

**Suite callback URL:** hosted = `https://www.certification.openid.net/test/a/<ALIAS>/callback`; self-hosted = `https://localhost.emobix.co.uk:8443/test/a/<ALIAS>/callback` (or your `BASE_URL`). Pick your `<ALIAS>` (globally unique on the hosted suite) first.

### Register a confidential client (recommended for Basic OP)

```bash
ISSUER=https://auth.example.com
ALIAS=qauth-basic          # your unique OIDF alias

curl -sS -X POST "$ISSUER/oauth/register" \
  -H 'Content-Type: application/json' \
  -d '{
    "client_name": "OIDF Basic OP conformance",
    "redirect_uris": ["https://www.certification.openid.net/test/a/'"$ALIAS"'/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "token_endpoint_auth_method": "client_secret_basic",
    "scope": "openid profile email offline_access"
  }' | jq .
```

Capture `client_id` and `client_secret` — the secret is shown **only once**.

**Public-client variant** (to also demonstrate the `none` path): set `"token_endpoint_auth_method": "none"`, drop the secret; PKCE is then mandatory (`register.ts:124-127`).

**Static vs dynamic in the suite:**

- **`dynamic_client`** (recommended) — the suite calls `POST /oauth/register` itself per test; **no manual step**. QAuth's DCR can mint confidential clients (above), so the dynamic path is viable for Basic OP.
- **`static_client`** (fallback) — register once as above, paste `client_id`/`client_secret` into the suite's static config. There is **no static client seed file/script** in the repo; DCR (or the developer-authenticated `POST /api/clients`, which needs a Bearer JWT) is the only way to create a client.

---

## Step 5 — Configure the OIDF suite (plan · variants · config JSON)

### Where to run

- **Hosted (use for the publishable run):** `https://www.certification.openid.net/` runs the current release; staging tracking `master` is at `https://staging.certification.openid.net/`. Log in with **Google or GitLab**.
- **Self-hosted (use for pre-flight iteration only):** open source, no cost.
  ```bash
  curl -O https://gitlab.com/openid/conformance-suite/-/raw/master/docker-compose-prebuilt.yml
  docker compose -f docker-compose-prebuilt.yml up
  # then visit https://localhost.emobix.co.uk:8443/   (add localhost.emobix.co.uk → 127.0.0.1 to /etc/hosts)
  ```
  Pin a release with `IMAGE_TAG=<tag>`; expose publicly with `BASE_URL=https://conformance.example.com:8443`.

**Recommendation:** iterate on self-hosted, then **reproduce and publish on the hosted instance on the current release** — the OIDF reviewer checklist verifies the plan version is "close enough" to the current suite version, that the plan is immutable, and that the zip came from the Certification Package button. The hosted run satisfies all three without argument.

### Plan + variants

Create plans from the **"Test an OpenID Provider"** section of the dropdown.

- **Basic OP** — UI: _"OpenID Connect Core: Basic Certification Profile Authorization server test"_, plan id `oidcc-basic-certification-test-plan`, certificationProfileName **"Basic OP"**.
- **Config OP** — plan id `oidcc-config-certification-test-plan`; tests only the discovery document, so it is essentially free once discovery is correct. **[RE-CHECK AT RUN TIME]** confirm the exact Config OP dropdown label in the live UI.

Variants:

- `response_type` = **code** (QAuth advertises only `code`).
- `response_mode` = **default** / query.
- `server_metadata` = **discovery** (QAuth publishes discovery — use it, don't hand-configure endpoints).
- `client_registration` = **dynamic_client** (recommended) or **static_client** (fallback).
- `client_auth_type` = **client_secret_basic** and **client_secret_post** — Basic OP requires both to be demonstrated. **[RE-CHECK AT RUN TIME]** whether one plan run covers both methods or whether you must run the plan **once per method** and publish both packages; plan for **two runs** if needed.

> Do **not** use the static_client loophole to dodge the RS256 signature test — RS256 is implemented (#309), so run the real signature test.

### Config JSON

The config form has **alias**, **description**, **publish**, and a **JSON** tab (edits sync both ways). The suite fetches `server.discoveryUrl` and either registers dynamically or uses the supplied `client`.

**3A — Dynamic (recommended):**

```json
{
  "alias": "qauth-basic",
  "description": "QAuth OP - Basic OP certification (dynamic registration)",
  "server": { "discoveryUrl": "https://auth.example.com/.well-known/openid-configuration" },
  "client": { "dynamicRegistration": true }
}
```

(You may add `"scope": "openid profile email offline_access"` under `client` if needed.)

**3B — Static (fallback):** pre-register the confidential client from Step 4 with the callback above, then:

```json
{
  "alias": "qauth-basic",
  "description": "QAuth OP - Basic OP certification (static client)",
  "server": { "discoveryUrl": "https://auth.example.com/.well-known/openid-configuration" },
  "client": { "client_id": "<client_id>", "client_secret": "<client_secret>" }
}
```

Set **publish** to allow results to be published for certification. Use the **JSON** tab for anything without a form field.

---

## Step 6 — Run Basic OP, then Config OP

1. Open the suite → **log in** (Google/GitLab).
2. **Create test plan** → pick Basic OP → set variants (Step 5) → paste config → **Start Test Plan**. The plan freezes its module list at creation.
3. For each module press **Run Test**. Interactive modules show **Browser Interaction → Visit** — complete QAuth's login + consent, then return to results. Some modules run the flow twice (re-consent / `prompt` / `max_age`) — repeat the login when asked.
4. **Read results:** each test ends `PASSED`, `WARNING`, `REVIEW`, `SKIPPED`, `FAILED`, or `INTERRUPTED`. Use **view logs** for the HTTP exchanges. `REVIEW` needs a human to confirm the captured page/response matches the expectation and that error messages are correct for both end users and RP developers.
5. **Iterate:** re-run individual failed modules after fixing QAuth.
6. **Gate to pass:** every test must be `PASSED`, `REVIEW`, `WARNING`, or `SKIPPED`. **You cannot certify with any `FAILED` or `INTERRUPTED` result.**
7. Repeat for the **Config OP** plan — it should pass off the same discovery doc.

---

## Step 7 — Residual-item checklist (mapped to QAuth)

Watch these during the run; each is anchored to QAuth code so you know the expected outcome and the one-line fix if it fails. (From the #286 gap analysis.)

- [ ] **`id_token` signature = RS256.** Discovery shows `["RS256","EdDSA"]` and tokens sign RS256. If EdDSA-only, the RS256 env was not picked up (Step 2 / Step 3a). _Hard-fail if wrong._
- [ ] **`auth_time` present** when `max_age` is requested (requires #312 deployed).
- [ ] **Both client-auth methods demonstrated** (`client_secret_basic` + `client_secret_post`) — one confidential client covers both (`client-auth.ts:109-137, 144-161`).
- [ ] **Optional `address` / `phone` scopes → expect SKIP/WARN.** `scopes_supported` = `['openid','profile','email','offline_access']` (`discovery.ts:19-24`); unsupported scopes are silently dropped (`filterRequestedScopes`, `authorize.ts:331`). No `address`/`phone` claims are ever returned. Nothing to fix.
- [ ] **`request` / `request_uri` modules → must land PASS or SKIP, not FAIL. WATCH THIS.** `authorizeQuerySchema` is a plain `z.object` with default-strip and has no `request`/`request_uri` field (`schemas/oauth.ts:26-47`), so those params are silently stripped and QAuth does **not** return `request_not_supported` / `request_uri_not_supported`. `buildOpenIdConfiguration` advertises neither `request_parameter_supported` (OIDC default `false`, matches reality) nor `request_uri_parameter_supported` (OIDC default `true`, does **not** match — QAuth ignores `request_uri`) (`discovery.ts:136-164`). Basic OP does not mandate request objects, so these should skip/pass. **Fix if a module fails:** explicitly advertise `request_parameter_supported:false` and `request_uri_parameter_supported:false`, or reject the params — one-line change at `discovery.ts:136-164`.
- [ ] **`claims` request parameter (OIDCCClaimsEssential) → expect SKIP.** No `claims` field in `authorizeQuerySchema` (`oauth.ts:26-47`); discovery does not advertise `claims_parameter_supported` (defaults `false`). Basic OP does not require it.
- [ ] **Authorization-code reuse → expect PASS (`invalid_grant`).** Codes are single-use: `findByCode` returns only unused, unexpired codes (`libs/infra/db/src/lib/repositories/authorization-codes.repository.ts:43, 53`), and a successful exchange atomically flips `used` (`markUsed`, `:72-82`, called `token.ts:443`); reuse → `undefined` → `invalid_grant` (`token.ts:307-318`). **Gap to note:** QAuth does **not** additionally revoke tokens previously issued from the reused code (RFC 9700 §4.5 SHOULD) — generally not a Basic OP hard-fail, but flag it if a module checks token revocation on replay.
- [ ] **Config OP discovery fields present and `jwks_uri` resolves** (see Appendix). All required fields present.

---

## Step 8 — Export results and submit certification

**1. Produce the package.** With every test `PASSED/WARNING/REVIEW/SKIPPED`, make the plan **immutable** and use the **Certification Package** ("Publish for certification") button to download the results zip (it embeds logs and is auto-named vendor/software/profile/date — a missing name signals the button wasn't used or the plan wasn't immutable). **One zip per profile** — one for Basic OP, one for Config OP. **[RE-CHECK]** exact button label.

**2. Payment code (or fee waiver).**

- Pay at `https://openid.net/foundation/members/certifications/new` — enter **Entity Name, Deployment Name & Version, Implementer's Email**, pay via **PayPal or invoice**; save the **payment code** (required at submission).
- **Fees:** OpenID Connect = **$700 member / $3,500 non-member per new deployment**, and one payment covers "as many profiles as you choose within a calendar year" — so **Basic OP + Config OP are covered by a single OIDC fee**.
- **Member-rate eligibility:** the reviewer checklist verifies the **owner of the implementation** is a current member. An **Individual Contributor is NOT a membership** (no discount) — you need an **Individual (~$50)** or an **entity** membership (**Non-Profit ~$250 / Corporate 1–25 ~$1,000**). Certify as **QAuth Labs** (the implementation owner). **[RE-CHECK]** exact 2026 dues.
- **Open-source waiver (optional):** QAuth may qualify under the OIDF Open-Source Project Certification Policy. Apply by emailing **certification@oidf.org**: the request must meet all normal requirements, the requester must be responsible for the deployment, and you must assert that **none of the primary maintainers are compensated by an employer for their work on the project**. Case-by-case; membership/application still applies; not guaranteed.

**3. Submit.** At `https://submissions.openid.net/` provide: contact email, entity name, deployment name + **version** (mandatory), regulatory regime (N/A), the **payment code**, signer + authorized-contact info, and the **result zip(s)**.

**4. Sign.** The signer receives a **DocuSign** "Declaration of Conformance" email; complete the e-signature. The signed `OpenID-Certification-of-Conformance.pdf` must reference the Terms & Conditions, carry a sensible suite version + profile name, include a software version number, and be **signed by the owner of the implementation** (QAuth Labs — not a third party).

**5. Review + publication.** The request enters the OIDF queue; on approval the entry is published to `https://openid.net/developers/certified/`, after which you may display the **"OpenID Certified"** mark.

---

## Appendix — Basic-plan modules mapped to QAuth behaviour

| Suite module (Basic OP)                                  | QAuth behaviour                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | Where                                                               | Expected                       |
| -------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------ |
| Discovery / `.well-known/openid-configuration`           | Emits `issuer`, `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`, `registration_endpoint`, `jwks_uri`, `response_types_supported:['code']`, `grant_types_supported`, `code_challenge_methods_supported:['S256']`, `token_endpoint_auth_methods_supported:['client_secret_basic','client_secret_post','none']`, `scopes_supported`, `subject_types_supported:['public']`, `id_token_signing_alg_values_supported`, `claims_supported`, `resource_indicators_supported`, `authorization_response_iss_parameter_supported` | `discovery.ts:68-164`                                               | PASS                           |
| JWKS fetch                                               | Ed25519 (OKP) + RSA (RS256) keys, distinct kids                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | `fastify-plugin-jwt.ts:328-346`                                     | PASS                           |
| Authorization code flow (`response_type=code`)           | Redirect exact-match, PKCE S256 mandatory                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | `authorize.ts:131`; `oauth.ts:35`                                   | PASS                           |
| Client auth `client_secret_basic` / `client_secret_post` | Method inferred from presentation, not enforced vs registration                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | `client-auth.ts:109-137, 144-161`                                   | PASS (both)                    |
| `id_token` RS256 signature + `iss/aud/sub/exp/iat/nonce` | RS256 default when key set                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | `fastify-plugin-jwt.ts:107-116, 276-289`                            | PASS                           |
| `nonce` echoed in ID token                               | Passed through to `signIdToken`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | `token.ts:490-500`                                                  | PASS                           |
| `max_age` / `auth_time`                                  | Requires #312 (`auth_time` emission)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | PR #312                                                             | PASS once #312 deployed        |
| UserInfo (`GET`/`POST`)                                  | Plain JSON; `email`/`email_verified` only when a verified email exists (#229)                                                                                                                                                                                                                                                                                                                                                                                                                                                          | `discovery.ts:160-162`                                              | PASS                           |
| Authorization-code reuse rejected                        | Single-use, atomic `markUsed`, reuse → `invalid_grant`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | `authorization-codes.repository.ts:43,53,72-82`; `token.ts:307-318` | PASS                           |
| `scope=address` / `scope=phone`                          | Unsupported; silently dropped                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | `discovery.ts:19-24`; `authorize.ts:331`                            | SKIP/WARN                      |
| `request` / `request_uri` object modules                 | Silently stripped; not rejected                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | `oauth.ts:26-47`; `discovery.ts:136-164`                            | SKIP/PASS — **watch** (Step 7) |
| `claims` request parameter                               | Silently stripped; `claims_parameter_supported` defaults false                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | `oauth.ts:26-47`; `discovery.ts:136-164`                            | SKIP                           |
| Config OP (discovery-only)                               | Same discovery doc; `jwks_uri` resolves                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | `discovery.ts:68-164`                                               | PASS                           |

---

## Re-verify at run time (suite version drift)

The conformance suite evolves and the plan freezes its module list at creation; OIDF reviewers require the plan version be "close enough" to the current release. **Create and run the publishable plan on the current hosted release shortly before submitting** (`https://gitlab.com/openid/conformance-suite/-/releases`). Re-confirm each item below in the live UI, because only a live run settles them:

- **Config OP plan label** — confirm the exact dropdown name (`oidcc-config-certification-test-plan`).
- **`client_auth_type` handling** — one plan covering both `client_secret_basic` + `client_secret_post`, or two runs (and two packages)?
- **DCR ↔ confidential clients** — re-verify `/oauth/register` returns a `client_secret` for `client_secret_basic`/`client_secret_post` on the deployed build; fall back to static clients if not.
- **Export button label** — "Publish for certification" vs "Certification Package".
- **Submission / DocuSign flow + fee and membership amounts** — form fields and 2026 dues change periodically.
- **Residual pass/warn items** — `address`/`phone` (skip/warn), `claims` parameter (`claims_parameter_supported=false`), request-object modules (must land pass or `request_not_supported`, not fail), and auth-code-reuse revocation (RFC 9700 SHOULD).

Primary sources: OIDF OP testing instructions (`openid.net/certification/connect_op_testing/`), certification instructions (`.../instructions/`), how-to-certify / how-to-submit, fee schedule (`.../certification/fees/`), open-source project certification policy, about-the-suite, the conformance-suite repo + wiki (`gitlab.com/openid/conformance-suite/` — `Certification-Check-List.md`, `Developers/Build-&-Run.md`, `Design/Configuration.md`, `Authlete-Example-Configuration.md`), and the certified-OP list (`openid.net/developers/certified/`).

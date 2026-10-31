# wire-suite

Black-box tests that talk to a **running** QAuth over HTTP and nothing else. They guard the
wire-level stability promise of [ADR-018 §5](../../docs/adr/018-1-0-scope-and-stability.md): what
a client sees on the wire, whatever the server is written in.

CI builds the auth-server image from the pull request, starts it with Postgres and Redis, and
runs this suite against it (the `wire-suite` CI job). Its JSON report
joins the unit suite's in the [conformance matrix](../../docs/conformance/README.md), so a wire
test that cites a registered spec section counts as evidence for that row.

## Rules

- **No server code.** The suite may use `fetch`, `jose` and its own helpers, and no workspace
  project. `nx lint` enforces it in both directions: `scope:wire-suite` may depend on no project,
  and no project may depend on it (`.oxlintrc.json`). A helper shared with the server could
  carry the same encoding bug on both sides and hide it.
- **Configured only through the environment** (below). The suite refuses to start without
  `QAUTH_WIRE_ALLOW_WRITES=1`, because it registers users and uses clients on the server it
  targets.
- **Users come from `src/fixtures/users.ts` only.** Today that file calls `POST /auth/register`;
  ADR-017 replaces registration with hosted sign-up, and then this one file changes. An account a
  test signs in with comes from `createSignInAccount()`, which verifies the address through the
  mail sink when `QAUTH_WIRE_MAIL_URL` is set (below).
- **Clients come from `seed/clients.json` only.** The run provisions them with the operator seed
  command before the suite starts. The one exception is `suites/registration/`, which tests
  dynamic registration itself: it registers clients, and uses one only to show that the secret it
  was issued authenticates. No other suite uses a client the server's routes created.
- **Every OAuth and discovery operation has a wire test.** A wire test sends a request to an
  operation with `call('METHOD /path', …)` (or builds its URL with `operationUrl`), naming it
  exactly as `apps/docs-site/public/openapi.json` lists it. `src/operation-coverage.test.ts`, a
  unit test, fails when an `/oauth/*` or `/.well-known/*` operation of that document has no such
  call in any `*.wire.test.ts`, unless it is experimental and `suites/experimental/` checks it.
- **A browser is a cookie jar and the redirects it follows.** `helpers/browser.ts` signs in on
  `/ui/login` and answers `/ui/consent` from the HTML forms the server renders, and stops at the
  client's redirect URI, which it never requests. `fixtures/authorization.ts` builds the seeded
  client's authorization requests (PKCE, `state`, `nonce`) and token requests.
- **What a default deployment hides comes from `src/fixtures/experimental.ts` only.** The auth
  server's tests generate it from the maximal OpenAPI export and the experimental-feature registry
  (`pnpm nx test auth-server -- -u`): every experimental operation, and every discovery member an
  experimental item adds. `suites/experimental/` checks the server answers each operation as a route
  that does not exist and lists none of the members, which holds while every switch is at its
  default, as CI starts the server.
- **Layout:** `src/suites/<area>/<topic>.wire.test.ts`.
- **Titles cite the spec and section** in the form the matrix reads, e.g.
  `describe('RFC 8414 §3 — …')` with `it('… (§3.1, §3.2)')`, or `OIDC Core 1.0 §3.1.2.1`. A bare
  `§` belongs to the nearest spec name to its left, and the joiner treats words such as `OAuth`,
  `OpenID` and `OIDC` as spec names too — so keep them, and paths like
  `/.well-known/openid-configuration`, out of a title between the spec name and its sections.
- **`src/suites/rate-limit/**` runs last**, in its own Vitest project (`wire-budget`,
  `sequence.groupOrder` in `vitest.wire.config.ts`). It spends the registration budget of the
  address the suite connects from, which would refuse every registration after it.

## Configuration

| Variable                     | Required | Meaning                                                                                                                                                                                                                                                                                                                                                             |
| ---------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `QAUTH_WIRE_ALLOW_WRITES`    | yes      | Must be exactly `1`. Confirms the server may be written to.                                                                                                                                                                                                                                                                                                         |
| `QAUTH_BASE_URL`             | yes      | The server's issuer identifier, e.g. `http://localhost:3000`. Discovery must report it as is.                                                                                                                                                                                                                                                                       |
| `QAUTH_ADMIN_URL`            | no       | Where admin operations go. Defaults to `QAUTH_BASE_URL`.                                                                                                                                                                                                                                                                                                            |
| `QAUTH_WIRE_CLIENT_ID`       | yes      | The confidential client from `seed/clients.json`: `wire-confidential`.                                                                                                                                                                                                                                                                                              |
| `QAUTH_WIRE_CLIENT_SECRET`   | yes      | Its secret, as the seed command printed it.                                                                                                                                                                                                                                                                                                                         |
| `QAUTH_WIRE_SSF_TRANSMITTER` | no       | `1` when the target's realm runs the SSF transmitter; the metadata suite then checks the document, and that its `jwks_uri` holds the SET keys apart from the realm JWKS, instead of the `404` problem, and the error suite checks that `/ssf/stream` refuses a request without a receiver token with a `401` problem and a Bearer challenge.                        |
| `QAUTH_WIRE_MAIL_URL`        | no       | The HTTP API of the Mailpit instance the target sends its mail to, e.g. `http://localhost:8025`. Every account the suite signs in is then verified first, as a person verifies it. Leave it unset only for a target that signs in unverified accounts (`REQUIRE_VERIFIED_ACCOUNT=false`): on a target with the default, every test that signs in fails and says so. |

## Run it locally

You need Docker and a workspace install (`pnpm install`).

1. **Configure the stack.** Copy `.env.docker.example` to `.env` and fill in `JWT_PRIVATE_KEY`,
   `JWT_PUBLIC_KEY`, `SESSION_COOKIE_SECRET` and `KEK`, as the
   [Docker guide](https://docs.qauth.dev/operate/docker/) describes. Then raise the rate limits
   for the run, as CI does — every request of the suite comes from one address, and the defaults
   allow three registrations and five logins per window:

   ```bash
   RATE_LIMIT_MAX=10000
   REGISTRATION_RATE_LIMIT=100
   LOGIN_RATE_LIMIT=100
   INTROSPECT_RATE_LIMIT=1000
   VERIFICATION_RATE_LIMIT=100
   # Optional: lets you run the suite again a minute later (see below).
   REGISTRATION_RATE_WINDOW=60
   ```

   The suite signs accounts in through `/ui/login`, and the server signs in only verified
   accounts by default. Through Compose, let unverified accounts sign in and leave
   `QAUTH_WIRE_MAIL_URL` unset:

   ```bash
   REQUIRE_VERIFIED_ACCOUNT=false
   ```

   Compose forwards only the settings it lists, and `TOKEN_RATE_LIMIT`, `AUTHORIZE_RATE_LIMIT`,
   `USERINFO_RATE_LIMIT`, `REGISTER_CLIENT_RATE_LIMIT` and `SMTP_*` are not among them. A full
   run sends the token endpoint more than its default 30 requests a minute from one address, so
   some tests may answer `429`; run one area at a time
   (`pnpm nx run wire-suite:run -- src/suites/oauth/userinfo.wire.test.ts`), or start the image
   with `docker run` and the rate limits of the `wire-suite` CI job. To keep the verified-account
   default, send the server's mail over SMTP to Mailpit (`axllent/mailpit`) and give the suite its
   HTTP API as `QAUTH_WIRE_MAIL_URL`.

2. **Start it.** The migration runner runs before the server does.

   ```bash
   docker compose up -d --build auth-server
   ```

3. **Seed the realm and the client.** The seed command provisions clients into an existing realm
   and prints each generated secret once. It runs from this checkout, against the port the compose
   Postgres publishes: the migration-runner image holds only the runner.

   ```bash
   docker compose exec postgres psql -U qauth -d qauth \
     -c "INSERT INTO realms (name) VALUES ('master') ON CONFLICT (name) DO NOTHING"

   DATABASE_URL=postgresql://qauth:qauth_dev_password@localhost:5432/qauth \
     pnpm nx run infra-db:db:seed-oauth-clients -- \
     --manifest="$PWD/apps/wire-suite/seed/clients.json"
   ```

   A second seed run skips the existing client and prints no secret; add `--rotate` after the
   manifest argument to issue a new one.

4. **Run the suite.**

   ```bash
   export QAUTH_BASE_URL=http://localhost:3000
   export QAUTH_WIRE_CLIENT_ID=wire-confidential
   export QAUTH_WIRE_CLIENT_SECRET=<the secret the seed printed>
   export QAUTH_WIRE_ALLOW_WRITES=1
   # Only for a target that sends its mail to Mailpit, as the CI job's does:
   # export QAUTH_WIRE_MAIL_URL=http://localhost:8025

   pnpm nx run wire-suite:run
   ```

   For the report the conformance matrix reads, add the JSON reporter:

   ```bash
   pnpm nx run wire-suite:run -- --reporter=default \
     --reporter=json --outputFile.json="$PWD/dist/wire-report.json"
   ```

**Running it again.** The rate-limit suite spends the registration budget, so a second run inside
the same `REGISTRATION_RATE_WINDOW` fails at its first registration with a `429`. Wait out the
window, or empty the local Redis: `docker compose exec redis redis-cli FLUSHALL`.

## The suite's own tests

`src/**/*.test.ts` (no `.wire.`) tests the configuration guard, the helpers and the operation
coverage. They need no server and run with the rest of the unit suite: `pnpm nx test wire-suite`.

## Not ported on purpose

The suite holds the core protocol checks. Wallet sign-in (OID4VP), ID-JAG, step-up, DPoP, token
exchange and private-key client authentication are off by default or need clients and keys the
seed does not provision; each area adds its own wire tests when it does.

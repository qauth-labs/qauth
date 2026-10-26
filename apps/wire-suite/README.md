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
  ADR-017 replaces registration with hosted sign-up, and then this one file changes.
- **Clients come from `seed/clients.json` only.** The run provisions them with the operator seed
  command before the suite starts. The suite never creates a client through the server's routes.
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

| Variable                     | Required | Meaning                                                                                                                                                                                                                                                                                                                                      |
| ---------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `QAUTH_WIRE_ALLOW_WRITES`    | yes      | Must be exactly `1`. Confirms the server may be written to.                                                                                                                                                                                                                                                                                  |
| `QAUTH_BASE_URL`             | yes      | The server's issuer identifier, e.g. `http://localhost:3000`. Discovery must report it as is.                                                                                                                                                                                                                                                |
| `QAUTH_ADMIN_URL`            | no       | Where admin operations go. Defaults to `QAUTH_BASE_URL`.                                                                                                                                                                                                                                                                                     |
| `QAUTH_WIRE_CLIENT_ID`       | yes      | The confidential client from `seed/clients.json`: `wire-confidential`.                                                                                                                                                                                                                                                                       |
| `QAUTH_WIRE_CLIENT_SECRET`   | yes      | Its secret, as the seed command printed it.                                                                                                                                                                                                                                                                                                  |
| `QAUTH_WIRE_SSF_TRANSMITTER` | no       | `1` when the target's realm runs the SSF transmitter; the metadata suite then checks the document, and that its `jwks_uri` holds the SET keys apart from the realm JWKS, instead of the `404` problem, and the error suite checks that `/ssf/stream` refuses a request without a receiver token with a `401` problem and a Bearer challenge. |

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
   # Optional: lets you run the suite again a minute later (see below).
   REGISTRATION_RATE_WINDOW=60
   ```

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

`src/**/*.test.ts` (no `.wire.`) tests the configuration guard and the helpers. They need no
server and run with the rest of the unit suite: `pnpm nx test wire-suite`.

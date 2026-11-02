# Contributing to QAuth

Thanks for your interest in contributing! QAuth is an open-source OAuth 2.1 /
OIDC identity server for the agent era, built as a federation hub and crypto-agile
for the post-quantum transition. This guide covers how to get set up and the
conventions the repo enforces.

By participating in this project, you are expected to uphold our
[Code of Conduct](./CODE_OF_CONDUCT.md).

## Prerequisites

- **Node.js** ≥ 26.10.0 (see `.nvmrc` — `nvm use`)
- **pnpm** ≥ 12.14.0 (`npm install --global pnpm@12.14.0`; Node 26 no longer ships corepack)
- **Docker** 23.0+ (BuildKit) and Docker Compose 2.0+ (for Postgres 18 + Redis 7)

## Getting started

```bash
pnpm install
cp .env.docker.example .env   # fill in the values listed in the README's Quick start
docker compose up -d          # Postgres + Redis + auth-server
curl http://localhost:3000/health
```

Interactive API docs (OpenAPI / Swagger UI) are at `/docs` on the running instance.

## Development workflow

This is an [Nx](https://nx.dev) monorepo — always run tasks through Nx rather than
the underlying tooling:

```bash
pnpm nx serve auth-server        # run an app
pnpm nx test <project>           # test one project
pnpm nx affected -t lint dependency-checks test typecheck   # validate only what you changed
pnpm format                      # oxfmt: format the repository in place
pnpm format:check                # oxfmt --check, as CI's format job runs it
```

Before opening a PR, make sure the affected projects pass and the files are formatted:

```bash
pnpm nx affected -t lint dependency-checks test typecheck build
pnpm format:check
```

`lint` runs Oxlint (`.oxlintrc.json`); `dependency-checks` runs the one rule still on ESLint,
`@nx/dependency-checks`, on package.json files (`eslint.config.mjs`); Oxfmt formats with
`.oxfmtrc.json`. `typecheck` runs TypeScript 7's `tsgo` (`"compiler": "tsgo"` in `nx.json`),
except on the docs site, where it runs `astro check`.

Your local runs use Nx's local cache only. CI's `affected` legs also read a self-hosted
remote cache that only runs on main write to (`.github/actions/nx-remote-cache`), so a pull
request replays the tasks main already ran; a fork's pull request gets no cache token and
computes everything. A cached task is only as good as its declared `inputs`: when you add a
file a target reads, add it to that target's inputs too, or CI will replay a stale result.

## Architecture principles

Keep changes aligned with the principles in [`AGENTS.md`](./AGENTS.md):

- **Security first** — OAuth 2.1, mandatory PKCE (S256), Argon2id, timing-safe
  comparisons. Never weaken these.
- **Federation first** — upstream sources plug in via `CredentialProvider`;
  downstream apps see only standard OAuth 2.1 / OIDC tokens.
- **API first** — design routes and schemas before implementation.
- **Modular first** — respect the Nx `apps/` + `libs/` boundaries.

## Commits

We use [Conventional Commits](https://www.conventionalcommits.org/), enforced by
commitlint via a husky `commit-msg` hook:

```
<type>(<scope>): <subject>
```

- **Types**: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `chore`, `ci`
- **Common scopes**: `auth`, `oauth`, `db`, `config`, `ci`, `api`, `portal`
- Example: `feat(oauth): add RFC 8693 token exchange for agent delegation`

A husky `pre-commit` hook runs lint-staged (`oxlint --fix`, then Oxfmt) on staged files.

## Pull requests

- Keep PRs small and focused; write a clear English description.
- Link issues with `Fixes #N` / `Closes #N`.
- Ensure `pnpm nx affected -t lint dependency-checks test typecheck build` and
  `pnpm format:check` pass before requesting review.
- A PR that adds, renames or removes an environment key registers it in the
  configuration key registry in the same PR, with its tier, role, default and
  one sentence (see [`libs/server/config`](./libs/server/config/README.md#configuration-key-registry)).
- All code, comments, docs, commits, and PRs are in **English**; only user-facing
  content may be localized.
- The pull request template lists three checks. Tick each one that applies: a stable route
  added or changed, with its wire test (below); an event type added, and registered
  ([`libs/shared/events`](./libs/shared/events/README.md#adding-an-event-type)); a migration
  added, and non-destructive (it drops or renames no table or column, narrows no column type
  and deletes no rows, [ADR-018 §5](./docs/adr/018-1-0-scope-and-stability.md)).

## How the wire suite grows

QAuth's 1.0 promise is what a client sees over HTTP
([ADR-018 §5](./docs/adr/018-1-0-scope-and-stability.md)). The wire suite,
[`apps/wire-suite`](./apps/wire-suite/README.md), guards it: black-box tests that talk to a running
server and nothing else. CI builds the server image from each pull request and runs the suite
against it.

**For issue writers:** "conformance suite" means this suite. A conformance test is a test in
`apps/wire-suite`. Name the OpenID Foundation's certification suite in full when you mean that one.

The rules:

- **A new or changed stable route needs a wire test in the same pull request.** A stable route is
  an operation of the OpenAPI document (`apps/docs-site/public/openapi.json`) whose
  `x-qauth-stability` is `stable`. Mark the test with the operation in a `describe` or `it` title,
  written exactly as the document lists it: `[POST /oauth/token]`,
  `[GET /developer/v1-rc.0/clients/{clientId}]`. A tag on a `describe` covers every test inside
  it, and a title may carry several tags. Tag a test only for the operation it checks, not for one
  it passes through on the way.
- **Wire tests cite the spec.** A title names the spec and the section it checks, in the form the
  [conformance matrix](./docs/conformance/README.md) reads: `RFC 7009 §2.2`, `OIDC Core 1.0 §5.3`.
- **The suite imports no server code.** It uses `fetch`, `jose` and its own helpers. `nx lint`
  refuses an import of any workspace project into the suite.

CI holds the first rule. `scripts/wire-coverage.mjs` reads the OpenAPI document and the wire
suite's report, and fails when a stable operation has no passing test that tags it. An
experimental operation is exempt: a default deployment does not serve it. The stable operations
that have no wire test yet are listed in `apps/wire-suite/exempt-operations.json`, each with a
reason and an issue. **That list may only shrink.** CI fails a pull request that adds an entry,
and the pull request that gives an operation its wire test removes the operation's entry. After a
local run of the suite, `pnpm wire-coverage` runs the same check.

## Releases

Releases are cut by maintainers. One tag, `vX.Y.Z` or `vX.Y.Z-rc.N`, releases
the server images and every SDK package at QAuth's version.
[RELEASING.md](./RELEASING.md) has the steps, the version rule and how to roll
back. Every pull request also packs
each SDK as npm would receive it and installs it into an empty project, so a
change that would break a published package fails there first.

## Reporting security issues

Do **not** open a public issue for security vulnerabilities. Use GitHub's private
[security advisory](https://github.com/qauth-labs/qauth/security/advisories/new)
flow instead.

## License

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](./LICENSE).

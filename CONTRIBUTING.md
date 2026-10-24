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
- **Docker** 20.10+ and Docker Compose 2.0+ (for Postgres 18 + Redis 7)

## Getting started

```bash
pnpm install
cp .env.docker.example .env   # add JWT keys — see the Quick Start in README.md
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

## Reporting security issues

Do **not** open a public issue for security vulnerabilities. Use GitHub's private
[security advisory](https://github.com/qauth-labs/qauth/security/advisories/new)
flow instead.

## License

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](./LICENSE).

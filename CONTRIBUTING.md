# Contributing to QAuth

Thanks for your interest in contributing! QAuth is an open-source OAuth 2.1 /
OIDC identity server for the agent era, built as a federation hub and crypto-agile
for the post-quantum transition. This guide covers how to get set up and the
conventions the repo enforces.

## Prerequisites

- **Node.js** ≥ 24.7.0 (see `.nvmrc` — `nvm use`)
- **pnpm** ≥ 11 (`corepack enable`)
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
pnpm nx affected -t lint test typecheck   # validate only what you changed
pnpm format                      # prettier --write .
```

Before opening a PR, make sure the affected projects pass:

```bash
pnpm nx affected -t lint test typecheck build
```

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

A husky `pre-commit` hook runs lint-staged (ESLint + Prettier) on staged files.

## Pull requests

- Keep PRs small and focused; write a clear English description.
- Link issues with `Fixes #N` / `Closes #N`.
- Ensure `pnpm nx affected -t lint test typecheck build` passes before requesting review.
- All code, comments, docs, commits, and PRs are in **English**; only user-facing
  content may be localized.

## Reporting security issues

Do **not** open a public issue for security vulnerabilities. Use GitHub's private
[security advisory](https://github.com/qauth-labs/qauth/security/advisories/new)
flow instead.

## License

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](./LICENSE).

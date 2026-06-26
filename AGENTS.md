<!-- nx configuration start-->
<!-- Leave the start & end comments to automatically receive updates. -->

# General Guidelines for working with Nx

- For navigating/exploring the workspace, invoke the `nx-workspace` skill first - it has patterns for querying projects, targets, and dependencies
- When running tasks (for example build, lint, test, e2e, etc.), always prefer running the task through `nx` (i.e. `nx run`, `nx run-many`, `nx affected`) instead of using the underlying tooling directly
- Prefix nx commands with the workspace's package manager (e.g., `pnpm nx build`, `npm exec nx test`) - avoids using globally installed CLI
- You have access to the Nx MCP server and its tools, use them to help the user
- For Nx plugin best practices, check `node_modules/@nx/<plugin>/PLUGIN.md`. Not all plugins have this file - proceed without it if unavailable.
- NEVER guess CLI flags - always check nx_docs or `--help` first when unsure

## Scaffolding & Generators

- For scaffolding tasks (creating apps, libs, project structure, setup), ALWAYS invoke the `nx-generate` skill FIRST before exploring or calling MCP tools

## When to use nx_docs

- USE for: advanced config options, unfamiliar flags, migration guides, plugin configuration, edge cases
- DON'T USE for: basic generator syntax (`nx g @nx/react:app`), standard commands, things you already know
- The `nx-generate` skill handles generator discovery internally - don't call nx_docs just to look up generator syntax

<!-- nx configuration end-->

# QAuth Project Guide

QAuth is an open-source **federated identity platform**: a TypeScript/Fastify
OAuth 2.1 authorization server. Upstream identity sources (email/password, OIDC
providers, and — later — Verifiable Credential wallets) plug in through the
`CredentialProvider` interface; downstream apps receive standard OAuth 2.1 access
tokens and OIDC ID tokens.

## Architecture Principles

- **Federation First**: Upstream sources plug in via `CredentialProvider`;
  downstream apps see only standard OAuth 2.1 / OIDC tokens.
- **Modular First**: Phase 1 is a modular monolith; libs are designed for
  microservice extraction later. Respect the Nx `apps/` + `libs/` boundaries.
- **API First**: Design the API (routes, schemas) before implementation.
- **Security First**: OAuth 2.1, PKCE mandatory (S256), Argon2id, timing-safe
  comparisons. Never weaken these.
- **Performance**: Consider it, but don't over-optimize prematurely.

## Code Standards

- **Language**: English for all code, comments, docs, commits, issues, and PRs.
  Only user-facing content may be localized (i18n).
- **TypeScript**: strict mode; prefer type safety over `any`.
- **Naming**: `camelCase` (variables/functions), `PascalCase`
  (classes/interfaces/types), `UPPER_SNAKE_CASE` (constants), `kebab-case`
  (file names).
- **Docs**: JSDoc/TSDoc for public APIs; concise comments for complex logic.

## Commits & Pull Requests

- **Conventional Commits**: `feat:`, `fix:`, `docs:`, `style:`, `refactor:`,
  `perf:`, `test:`, `chore:`. Scope where useful, e.g.
  `feat(auth): implement OAuth 2.1 authorization code flow`. Common scopes:
  `auth`, `oauth`, `db`, `config`, `ci`, `api`.
- **PRs**: small and focused; clear English description; link issues
  (`Fixes #N` / `Closes #N`); ensure CI passes before requesting review.

## Dependencies & Testing

- Prefer well-maintained libraries; check security advisories before adding;
  document why a dependency is needed; keep them current.
- Write tests for business logic and public APIs; aim for meaningful coverage.

## Agents & Skills

This repo ships Claude Code agents (`.claude/agents/`) and skills
(`.claude/skills/`). Invoke them as the work demands:

- **Agents**: `auth-specialist` (OAuth/auth implementation & review),
  `code-reviewer` (quality/security review), `debugger` (failures & root cause),
  `pr-opener` (open PRs), `product-manager` (scope/phase/task breakdown).
- **Domain skills**: `auth-oauth`, `oauth-oidc`, `auth-engine`, `schema`,
  `security`, `api-design`, `fastify`, `errors`, `validation`.
- **Workflow skills**: `nx-commands`, `nx-testing`, `nx-ci`, `nx-database`,
  `nx-docker`, `nx-project`.
- **GitHub skills**: shared conventions in `github-conventions`, plus focused
  operations (`create-issue`, `create-pr`, `add-sub-issue`, `add-to-project`,
  `investigate-issue`, `set-milestone`).

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

QAuth is an open-source **OAuth 2.1 / OIDC identity server** (TypeScript/Fastify).
Its **near-term identity is an authorization server for MCP servers and AI agents**
(see [ADR-007](./docs/adr/007-mcp-first-positioning.md)) — the MCP/agent-native
authorization layer (agent client type, RFC 8693 on-behalf-of delegation, scope
modes, step-up), the T3 production-hardening bundle, and the T5 environment-aware
posture ([ADR-008](./docs/adr/008-environment-aware-authorization.md)) all ship
today. By design it is also a **federation hub**: upstream identity sources
(email/password and — behind a default-off flag — Verifiable Credential wallets;
external OIDC providers still to come) plug in through the `CredentialProvider`
interface, and downstream apps receive standard OAuth 2.1 access tokens and OIDC
ID tokens.

**Track T4 status — 37 issues closed / 3 open** (`gh issue list --repo qauth-labs/qauth --milestone "T4 - Federation & PQC" --state all`; issues only — the milestone's own counter includes merged PRs; checked 2026-08-31) — do not describe it as "deferred":

- The ADR-002 identifier-abstraction migration is **complete** (epic #224;
  migrations 0010–0012). `users` is a pure identity anchor; credential data lives
  in `user_credentials`.
- Post-quantum hybrid signing is **implemented and default-off** (epic #241).
  `SIGNING_ALGORITHM_MODE=ed25519` and `HYBRID_SIGNING_ENABLED=false` are the
  defaults; the crypto layer stays crypto-agile via `@qauth-labs/core-crypto`.
- Wallet federation **works end-to-end behind `WALLET_FEDERATION_ENABLED`**
  (default off): the OID4VP verifier, SD-JWT VC validation, key attestations,
  status-list revocation, the claims pipeline and the browser sign-in flow are
  merged, with an E2E suite covering first-time enrolment, returning login,
  account linking and `acr`. Validated only on the `oid4vp-1.0-base` profile
  against a mock wallet so far.
- **`WalletProvider.verify()` throws unconditionally and must keep throwing** —
  a deliberate fail-closed property, not a stub. Never "fix" it. Wallet login
  does **not** use it; it runs on the dedicated `/ui/wallet-login` +
  `/oid4vp/response` seam in `apps/auth-server`. The provider is the generic
  `CredentialProvider`-registry entry point, which no wallet path calls.

Guides, the OAuth 2.1 / OIDC reference, and the rendered design records live at
[docs.qauth.dev](https://docs.qauth.dev); the ADRs and security review that
site renders stay in `docs/adr/` and `docs/security/` in this repository.

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

# GEMINI.md

This file provides a comprehensive overview of the QAuth project for Gemini, outlining its purpose, architecture, and development conventions.

## Project Overview

QAuth is a post-quantum ready, headless-first identity platform designed as a developer-friendly alternative to Keycloak. It offers flexible deployment modes, including a headless backend service and a self-hosted option for complete control.

The project is a TypeScript monorepo using pnpm workspaces and Nx for project management. It features a hybrid architecture that leverages Rust compiled to WebAssembly (WASM) for performance-critical cryptographic operations.

### Key Technologies

- **Backend:** Node.js, TypeScript, Fastify, Drizzle ORM, PostgreSQL, Redis
- **Frontend:** React, TanStack Start, Tailwind CSS
- **Monorepo:** Nx, pnpm
- **Crypto:** Rust (WASM) for post-quantum cryptography (ML-DSA, ML-KEM)

### Architecture

The architecture is designed to evolve from a modular monolith to a microservices-based system.

- **Phase 1 (Modular Monolith):** A single TypeScript/Bun auth server with a GraphQL and REST API layer, business logic modules, and a performance layer in Rust (WASM).
- **Phase 2 (Microservices):** The monolith will be broken down into smaller, independent services for the API Gateway, Auth, Token, Session, and Developer Portal.

The monorepo is structured into `apps` and `libs` directories, with applications like the `auth-server` and `developer-portal` in `apps`, and shared code, core logic, and SDKs in `libs`.

## Building and Running

The following commands are available in the `package.json` to build, run, and test the project:

- **Development:** `pnpm dev` (runs `nx serve`)
- **Build:** `pnpm build` (runs `nx build`)
- **Test:** `pnpm test` (runs `nx test`)
- **Lint:** `pnpm lint` (runs `nx lint`)
- **Format:** `pnpm format` (runs `prettier --write .`)
- **Format Check:** `pnpm format:check` (runs `prettier --check .`)

## Development Conventions

The project has a strict set of development conventions outlined in the `.cursor/rules/` and `CLAUDE.md` files.

### Language and Code Style

- **Language:** All code, documentation, and commit messages must be in English.
- **Naming Conventions:**
  - `camelCase` for variables and functions.
  - `PascalCase` for classes, interfaces, and types.
  - `UPPER_SNAKE_CASE` for constants.
  - `kebab-case` for file names.
- **Formatting:** Prettier is used for code formatting.
- **Linting:** ESLint is used for code linting.
- **Comments:** JSDoc/TSDoc is required for all public APIs.

### Git and Commit Messages

- **Commit Messages:** Conventional Commits specification must be followed. (`feat:`, `fix:`, `docs:`, etc.)
- **Pull Requests:** PRs should be small, focused, and have clear descriptions.

### Architecture

- **Modular First:** Design modules with the intention of extracting them into microservices later.
- **API First:** Design APIs before implementation.
- **Security First:** Always consider security implications.

### Nx Workspace

- The project is an Nx workspace. Use the Nx CLI for generating code, running tasks, and visualizing the project graph.
- Refer to the `.cursor/rules/nx-rules.mdc` file for detailed instructions on using Nx in this project.

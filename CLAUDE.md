# Claude Code - QAuth Development Guide

This file provides guidance for Claude Code when working on the QAuth project.

## Project Overview

**QAuth** is a modern, post-quantum ready, headless-first identity platform. It's designed as a developer-friendly alternative to Keycloak with two deployment modes:

1. **Auth as a Service**: Headless backend with custom branded UI
2. **Self-hosted**: Full control deployment on your infrastructure

## Tech Stack

### Backend

- **Runtime**: Node.js 24 LTS
- **Language**: TypeScript + Rust (WASM for performance-critical operations)
- **Framework**: Fastify
- **API**: REST (OAuth 2.1/OIDC) + GraphQL (Developer Portal)
- **ORM**: Drizzle ORM
- **Database**: PostgreSQL
- **Cache/Session**: Redis

### Frontend

- **Meta-framework**: TanStack Start
- **Framework**: React 19
- **Router**: TanStack Router (file-based, type-safe)
- **Data Fetching**: TanStack Query + Server Functions
- **Build Tool**: Vite
- **UI Primitives**: Radix UI
- **Styling**: Tailwind CSS
- **Tables**: TanStack Table
- **Forms**: TanStack Form

### Infrastructure

- **Monorepo**: Nx 21.x
- **Package Manager**: pnpm
- **Containerization**: Docker
- **Orchestration**: Kubernetes ready
- **Observability**: OpenTelemetry

### Performance Critical (Rust WASM)

- JWT signing/verification
- Password hashing (Argon2id, ML-DSA)
- Token validation
- Post-quantum cryptography (ML-DSA, ML-KEM, SLH-DSA)

## Project Structure

```
qauth/
├── apps/
│   ├── auth-server/          # Core auth server (Fastify)
│   ├── developer-portal/     # Developer console (TanStack Start)
│   ├── auth-ui/              # Login/Register UI (TanStack Start, SPA mode)
│   └── admin-panel/          # Admin dashboard (TanStack Start)
│
├── libs/
│   ├── core/
│   │   ├── auth/             # Auth business logic (TypeScript)
│   │   ├── oauth/            # OAuth 2.1 implementation (TypeScript)
│   │   ├── oidc/             # OIDC implementation (TypeScript)
│   │   └── crypto-wasm/      # Crypto operations (Rust → WASM)
│   │
│   ├── sdk/
│   │   ├── js/               # Vanilla JS SDK
│   │   ├── react/            # React SDK + hooks
│   │   └── node/             # Server-side SDK
│   │
│   ├── data-access/
│   │   ├── db/               # Drizzle ORM schema & queries
│   │   └── redis/            # Redis client
│   │
│   ├── ui/
│   │   └── components/       # Shared React components
│   │
│   ├── proto/                # gRPC/Protobuf definitions
│   │   ├── token.proto
│   │   └── session.proto
│   │
│   └── shared/
│       ├── types/            # Shared TypeScript types
│       ├── utils/            # Utilities
│       └── constants/        # Constants
│
└── services/                 # Future microservices (Rust)
    ├── token-service/        # Token generation (gRPC)
    └── session-service/      # Session management (gRPC)
```

## Language & Code Standards

### Language Policy

- **All code MUST be in English**:
  - Variables, functions, classes, comments
  - Documentation (README, inline comments, JSDoc/TSDoc)
  - Commit messages
  - Issues, PRs, and discussions
- **Exception**: User-facing content can be localized (i18n)

### Naming Conventions

- **camelCase**: Variables and functions (e.g., `getUserProfile`)
- **PascalCase**: Classes, interfaces, and types (e.g., `UserProfile`)
- **UPPER_SNAKE_CASE**: Constants (e.g., `MAX_LOGIN_ATTEMPTS`)
- **kebab-case**: File names (e.g., `user-profile.ts`)

### TypeScript Standards

- **Strict Mode**: Always enabled, full type coverage required
- **No `any`**: Prefer proper typing over `any`
- **Error Handling**: Use proper error types, never throw strings
- **Async/Await**: Prefer async/await over promise chains
- **Immutability**: Use `const` by default, prefer immutable patterns

### Code Documentation

- **Comments**: Clear, concise comments in English for complex logic
- **JSDoc/TSDoc**: Required for all public APIs
- **Examples**: Include usage examples for complex functions

## Architecture Principles

### Design Philosophy

- **Modular First**: Design modules to be extracted as microservices later
- **API First**: Design APIs before implementation
- **Security First**: Always consider security implications
- **Performance**: Consider performance, but don't over-optimize prematurely

### Phase 1: Modular Monolith (Current)

- TypeScript-based monolith with clear module boundaries
- Rust WASM for performance-critical crypto operations
- PostgreSQL + Redis for data persistence

### Phase 2: Microservices (Future)

- Extract performance-critical services to standalone Rust microservices
- gRPC communication between services
- Gradual migration based on actual needs

## Development Guidelines

### Code Quality

- **Formatting**: Prettier (configured in `.prettierrc`)
- **Linting**: ESLint with TypeScript rules (see `eslint.config.mjs`)
- **Commit Convention**: Conventional Commits (enforced by commitlint)
- **Git Hooks**: Husky for pre-commit and commit-msg hooks

### Conventional Commits

Follow these commit message conventions:

- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `style:` - Formatting, missing semicolons, etc.
- `refactor:` - Code restructuring
- `perf:` - Performance improvements
- `test:` - Adding tests
- `chore:` - Maintenance tasks

**Example**: `feat(auth): implement OAuth 2.1 authorization code flow`

### Dependencies

- Prefer well-maintained, popular libraries
- Check security advisories before adding dependencies
- Keep dependencies up to date
- Document why a dependency is needed

### Testing

- Write tests for business logic
- Write tests for public APIs
- Aim for meaningful coverage, not just high percentage
- Test critical auth flows end-to-end

### Pull Requests

- Keep PRs small and focused
- Write clear PR descriptions in English
- Link related issues
- Ensure CI passes before requesting review

## Nx Workspace

This is an Nx workspace using **Nx 21.6.4** with **pnpm** as the package manager.

### Nx MCP Server Tools

You have access to the Nx MCP server and its tools. Use them when working with the workspace:

#### General Guidelines

- Use `nx_workspace` tool first to understand workspace architecture
- Use `nx_docs` tool for Nx configuration and best practices
- Use `nx_visualize_graph` tool to demonstrate task dependencies
- Use `nx_workspace` tool to get any configuration or project graph errors

#### Generation Flow

When generating new code (apps, libs, components):

1. Learn about the workspace using `nx_workspace` and `nx_project_details` tools
2. Get available generators using `nx_generators` tool
3. Check `nx_available_plugins` tool if no relevant generators exist
4. Get generator details using `nx_generator_schema` tool
5. Use `nx_docs` tool to learn more if unsure
6. Open generator UI using `nx_open_generate_ui` tool
7. Wait for user to finish, then read log with `nx_read_generator_log` tool

#### Running Tasks Flow

When working with tasks (test, build, lint, etc.):

1. Use `nx_current_running_tasks_details` to get list of tasks
2. Use `nx_current_running_task_output` to get terminal output for specific tasks
3. Analyze output and help fix problems
4. Rerun tasks using `nx run <taskId>` in terminal
5. For continuous tasks, use `nx_current_running_task_output` to verify output

#### CI Error Flow

When fixing CI pipeline errors:

1. Use `nx_cloud_cipe_details` to retrieve CI Pipeline Executions
2. Use `nx_cloud_fix_cipe_failure` to retrieve task logs
3. Analyze logs and help fix problems
4. Verify fix by running the same task

### Project Commands

```bash
# Development
pnpm dev              # Start development server
pnpm build            # Build all projects
pnpm test             # Run tests
pnpm lint             # Lint code
pnpm format           # Format code with Prettier
pnpm format:check     # Check formatting

# Nx-specific commands
nx serve <app>        # Serve specific app
nx build <app>        # Build specific app
nx test <lib>         # Test specific library
nx graph              # View dependency graph
nx run <taskId>       # Rerun a specific task
```

### Adding New Code

```bash
# Generate a new library
nx generate @nx/js:library --name=my-lib --directory=libs/core/my-lib

# Generate a new application
nx generate @nx/node:application --name=my-app --directory=apps/my-app

# Run specific tests
nx test my-lib
nx test my-app

# Build for production
nx build my-app --configuration=production
```

## Security Considerations

### Post-Quantum Cryptography

- **Primary**: ML-DSA (Dilithium3) for signatures
- **Key Exchange**: ML-KEM (Kyber)
- **Backup**: SLH-DSA (SPHINCS+)
- **Hybrid Approach**: PQC + Classical cryptography for defense in depth

### Authentication & Authorization

- **Password Hashing**: Argon2id (OWASP recommended)
- **Tokens**: JWT with hybrid ML-DSA + Ed25519 signatures
- **Session Management**: Redis-backed sessions with secure cookies
- **MFA**: TOTP, WebAuthn/Passkeys support
- **Rate Limiting**: Protect all auth endpoints
- **CSRF Protection**: All state-changing operations

### Compliance

- OAuth 2.1 compliance
- OIDC 1.0 compliance
- PKCE mandatory for authorization code flow
- Secure token storage guidelines
- Audit logging for all auth events

### Security-First Mindset

- Always consider security implications
- Follow OWASP guidelines for auth code
- Crypto code only in Rust WASM modules, never in TypeScript
- Security-critical code requires extra scrutiny
- Validate all inputs, sanitize all outputs

## Important Files & Configurations

- [package.json](package.json) - Root package configuration
- [nx.json](nx.json) - Nx workspace configuration
- [tsconfig.base.json](tsconfig.base.json) - Base TypeScript configuration
- [eslint.config.mjs](eslint.config.mjs) - ESLint configuration
- [.prettierrc](.prettierrc) - Prettier configuration
- [commitlint.config.js](commitlint.config.js) - Commit message linting
- [README.md](README.md) - Project documentation
- [LICENSE](LICENSE) - Apache 2.0 License
- [NOTICE](NOTICE) - Copyright notice
- [.cursor/rules/language.mdc](.cursor/rules/language.mdc) - Language and code standards
- [.cursor/rules/nx-rules.mdc](.cursor/rules/nx-rules.mdc) - Nx workspace guidelines

## API Architecture

### REST Endpoints (OAuth 2.1/OIDC)

- `/oauth/*` - OAuth 2.1 endpoints
- `/oidc/*` - OIDC endpoints
- `/auth/*` - Core authentication endpoints
- `/.well-known/*` - Discovery endpoints

### GraphQL API (Developer Portal)

- Client management
- Analytics queries
- User management
- Webhook configuration

### Future gRPC Services

- Token service communication
- Session service communication

## Performance Optimization

### Why Rust WASM?

- **JWT Operations**: 10-100x faster than pure JavaScript
- **Password Hashing**: Argon2id with configurable work factors
- **PQC Operations**: ML-DSA signatures are computationally intensive
- **Token Validation**: High-frequency operation, needs maximum performance

### Performance Targets

- JWT signing: <1ms
- JWT verification: <0.5ms
- Password hashing: ~100ms (configurable for security/UX balance)
- Token validation: <0.1ms

## Testing Strategy

### Unit Tests

- All business logic in `libs/core/*`
- All crypto operations in `libs/core/crypto-wasm`
- All SDK functionality

### Integration Tests

- OAuth 2.1 flows
- OIDC flows
- Session management
- API endpoints

### E2E Tests

- Full authentication flows
- Developer portal workflows
- Admin panel operations

## Database & Cache

### Database (PostgreSQL)

- ACID compliance for auth data integrity
- Drizzle ORM for type-safe database access
- Migration strategy: TBD (Phase 1)

### Cache (Redis)

- Session storage
- Rate limiting
- Token blacklisting

## Deployment Modes

### Auth as a Service Mode

- Multi-tenancy support required
- Custom domain support
- Horizontal scalability
- CDN integration for static assets

### Self-hosted Mode

- Docker images
- Kubernetes manifests
- Environment-based configuration
- Migration tools from other platforms

## Development Workflow

### When Creating New Features

1. Check the [roadmap in README.md](README.md#-roadmap) for alignment
2. Create feature branch from `main`
3. Follow the modular monolith structure
4. Write tests for critical paths
5. Update documentation if needed
6. Use conventional commits
7. Run `pnpm format && pnpm lint` before committing

### When Writing Code

1. **Auth Code**: Security is paramount - follow OWASP guidelines
2. **Crypto Code**: Only in Rust WASM modules, never in TypeScript
3. **API Code**: Follow REST/GraphQL best practices
4. **UI Code**: Accessibility first (use Radix UI primitives)
5. **Database Code**: Use Drizzle ORM, never raw SQL
6. **All Code**: Must be in English (variables, comments, documentation)

### When Reviewing Code

1. Check type safety and error handling
2. Verify security implications for auth-related code
3. Ensure tests cover critical paths
4. Check for performance implications
5. Validate accessibility for UI components
6. Verify all code and comments are in English

## Common Patterns

### Frontend (TanStack Start)

```typescript
// Auth UI routes - SPA mode (fast load critical)
export const Route = createFileRoute('/login')({
  component: Login,
  // No SSR - fastest possible load
});

// Developer Portal - SSR for SEO
export const Route = createFileRoute('/dashboard')({
  loader: async () => getClients(), // Server-side
  component: Dashboard,
});

// Type-safe server functions
const createClient = createServerFn('POST', async (data) => {
  return await db.client.create({ data });
});
```

### Backend (Fastify)

```typescript
// Type-safe route handlers
fastify.post<{
  Body: LoginRequest;
  Reply: LoginResponse;
}>('/auth/login', async (request, reply) => {
  // Implementation
});
```

## Notes for Claude Code

### When Adding New Code

1. Always check existing patterns in the codebase first
2. Maintain consistency with the chosen tech stack
3. Security-critical code requires extra scrutiny
4. Follow the modular monolith architecture
5. Keep future microservices migration in mind
6. **All code must be in English** (variables, functions, comments)
7. Use Nx MCP tools for generation and workspace operations

### When Modifying Existing Code

1. Understand the security implications
2. Check for breaking changes in public APIs
3. Update tests if behavior changes
4. Maintain backward compatibility when possible
5. Ensure all changes maintain English-only code standard

### When Asked About Architecture

1. Refer to the modular monolith → microservices strategy
2. TypeScript for business logic, Rust WASM for performance
3. Explain the hybrid PQC approach
4. Emphasize security-first mindset
5. Use `nx_workspace` and `nx_visualize_graph` tools to explain structure

### When Using Nx Tools

1. Always use Nx MCP server tools when available
2. Use `nx_docs` tool instead of assuming Nx configuration
3. Use generator UI for creating new apps/libs
4. Use `nx run <taskId>` for rerunning tasks in correct context
5. Check workspace errors with `nx_workspace` tool first

### When Uncertain

1. Check OAuth 2.1 and OIDC 1.0 specifications
2. Refer to OWASP guidelines for security
3. Check NIST standards for PQC implementation
4. Use `nx_docs` tool for Nx-related questions
5. Ask for clarification rather than making assumptions

## Current Project Status

**Phase**: Early Development (Pre-MVP)
**Version**: 0.0.0
**Status**: Not production ready

The project is in the foundation phase. See the [roadmap in README.md](README.md#-roadmap) for planned features and timeline.

## Resources

- **Main Docs**: [README.md](README.md)
- **License**: [Apache 2.0](LICENSE)
- **Language Rules**: [.cursor/rules/language.mdc](.cursor/rules/language.mdc)
- **Nx Guidelines**: [.cursor/rules/nx-rules.mdc](.cursor/rules/nx-rules.mdc)
- **Contributing**: (TBD - see README for now)
- **Security Policy**: (TBD)

## Contact & Community

- **Repository**: https://github.com/qauth-labs/qauth
- **License**: Apache 2.0
- **Copyright**: © 2025 QAuth Labs

---

**Last updated**: 2025-10-14
**Nx Version**: 21.6.4
**Node Version**: >=24.0.0
**Package Manager**: pnpm >=10.0.0

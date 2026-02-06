---
name: security
description: Implements and reviews security controls for auth-server and OAuth flows following OWASP API Security Top 10, dependency hygiene (CVE/audit), and timing-safe practices. Use when hardening authentication, rate limiting, secrets handling, or when the user asks about security, CVEs, or OWASP.
---

# Security (QAuth)

Standards-aligned security for QAuth: authentication, authorization, rate limiting, timing-safe operations, secrets, and dependency hygiene. Use this skill when implementing or reviewing security-sensitive code, handling CVEs, or aligning with OWASP and related standards.

## When to Use This Skill

- Implementing or changing auth flows (login, token, PKCE, JWT)
- Adding rate limits, error handling, or audit logging
- Handling secrets, keys, or environment configuration
- Reviewing code for OWASP API Security risks
- Addressing dependency vulnerabilities (npm/pnpm audit, CVE)

## Quick Reference

| Concern           | QAuth pattern                                                                                              |
| ----------------- | ---------------------------------------------------------------------------------------------------------- |
| **Passwords**     | Argon2id via `@node-rs/argon2`; never store plaintext; validate strength (zxcvbn)                          |
| **Timing**        | Constant-time comparison for PKCE (`crypto.timingSafeEqual`); minimum response time on login/token/refresh |
| **Rate limiting** | Per-route and global via `@fastify/rate-limit`; Redis store; env-driven limits                             |
| **Errors**        | Generic messages for auth failures (no user enumeration); domain errors from `@qauth/shared-errors`        |
| **Secrets**       | Keys in env/secrets manager; never in images or logs; see ADR-001 for JWT keys                             |
| **Audit**         | Log auth/token events to `audit_logs` (success/failure, IP, userAgent, metadata)                           |
| **Dependencies**  | Run `pnpm audit` (or npm audit); fix or document exceptions; track CVEs                                    |

## OWASP API Security Top 10:2023 — Checklist

- **API1 Broken Object Level Authorization**: Check object IDs against current user/realm; validate every access by ID.
- **API2 Broken Authentication**: Strong auth (OAuth 2.1 + PKCE, JWT with Ed25519); no default/weak creds; rate limit auth endpoints.
- **API3 Broken Object Property Level Authorization**: Don't over-expose or mass-assign; validate input and response shape.
- **API4 Unrestricted Resource Consumption**: Rate limit (global + per-route); limit payload size; timeouts.
- **API5 Broken Function Level Authorization**: Enforce admin vs user; validate scope and client type.
- **API6 Unrestricted Access to Sensitive Business Flows**: Rate limit login, token, register, resend-verification; consider CAPTCHA/MFA for sensitive flows.
- **API7 SSRF**: Validate and allowlist URLs when fetching remote resources; no user-controlled URLs to internal services.
- **API8 Security Misconfiguration**: Secure defaults; no debug in production; HTTPS; lock headers (CORS, etc.).
- **API9 Improper Inventory Management**: Document endpoints; version APIs; remove or protect deprecated/debug routes.
- **API10 Unsafe Consumption of APIs**: Validate and sanitize data from third-party APIs; don't trust upstream blindly.

## OWASP Top 10:2025 — Checklist

- **A01 Broken Access Control**: Validate authorization on every request; check user/realm/scope before accessing resources; prevent IDOR.
- **A02 Security Misconfiguration**: Secure defaults; no debug in production; HTTPS; proper CORS/headers; remove unnecessary features.
- **A03 Software Supply Chain Failures**: Audit dependencies (`pnpm audit`); fix or document CVEs; review transitive deps; prefer trusted sources.
- **A04 Cryptographic Failures**: Use strong algorithms (Argon2id, Ed25519); no weak/outdated crypto; protect keys/secrets; proper TLS.
- **A05 Injection**: Validate and sanitize all inputs; parameterized queries; no eval/exec of user input; content-type validation.
- **A06 Insecure Design**: Threat modeling; secure-by-default architecture; fail securely; defense in depth.
- **A07 Authentication Failures**: Strong auth (OAuth 2.1 + PKCE); rate limit auth endpoints; generic error messages; no user enumeration; MFA where appropriate.
- **A08 Software or Data Integrity Failures**: Verify dependencies (lockfiles, checksums); secure CI/CD; protect against tampering; signed releases.
- **A09 Security Logging and Alerting Failures**: Log auth/token events; include IP/userAgent; no secrets in logs; monitor for abuse; alert on anomalies.
- **A10 Mishandling of Exceptional Conditions**: Generic error messages; don't leak stack traces; fail securely; proper exception handling; rate limit error responses.

## Authentication and Timing

1. **Login / token / refresh**  
   Use minimum response time (`ensureMinimumResponseTime`, `MIN_RESPONSE_TIME_MS`) so success and failure take similar time. Prevents user enumeration and reduces timing side channels.

2. **PKCE**  
   Verify code challenge with `crypto.timingSafeEqual` (see `libs/server/pkce`). Never use plain string comparison.

3. **Password verification**  
   Always run verification (even when user not found) so response time doesn't leak existence. Use Argon2id verify; avoid early returns that shorten failure path.

4. **Error messages**  
   Use the same generic message for "invalid credentials" and "user not found" (e.g. InvalidCredentialsError). Don't expose "email not found" vs "wrong password."

## Passwords and Hashing

- **Algorithm**: Argon2id (e.g. via `@node-rs/argon2`). Configurable memory/time/parallelism; meet or exceed project defaults.
- **Storage**: Store only the hash. Never log or echo passwords.
- **Strength**: Validate with zxcvbn (or equivalent); return feedback for weak passwords. Consider breach lists (e.g. Have I Been Pwned) for registration.
- **Policy**: Prefer length and entropy over complex rotation rules; align with NIST 800-63B where applicable.

## Rate Limiting and Abuse

- **Global**: `@fastify/rate-limit` with Redis; env to enable/disable and set default max/timeWindow.
- **Per-route**: Override via `config.rateLimit` (e.g. stricter for `/login`, `/oauth/token`, `/register`, `/resend-verification`).
- **429**: Return `Retry-After` when appropriate. Use `TooManyRequestsError` from shared errors.
- **Sensitive flows**: Login, token exchange, registration, and email resend should have stricter limits than general API.

## Secrets and Configuration

- **Keys and secrets**: Injected at runtime (env or secrets manager). Never in source, images, or logs. See `docs/adr/001-jwt-key-management.md` for JWT keys.
- **Environment**: Use validated config (e.g. env schema); fail fast on missing required secrets in production.
- **Logging**: No passwords, tokens, authorization codes, or client secrets in log messages or audit metadata (redact or omit).

## Dependency and CVE Hygiene

- **Audit**: Run `pnpm audit` (or `npm audit`) regularly; fix high/critical or document accepted risk.
- **CVEs**: Check advisories for direct and transitive dependencies; upgrade or patch when fixes exist. Prefer official advisories (npm, GitHub, Snyk, etc.).
- **Supply chain**: Prefer pinned or lockfile-based installs; review lifecycle scripts and new dependencies. Post-2025 supply-chain attacks (e.g. npm) underscore the need for continuous checks.
- **CI**: Consider failing CI on high/critical vulnerabilities or on known-bad CVEs; allow override with justification.

## Audit Logging

- **Events**: Log auth and token events (e.g. `user.login.failure`, `user.login.success`, token exchange, refresh, logout). Include success/failure, IP, userAgent, and minimal metadata (no secrets).
- **Storage**: Use `audit_logs` (or equivalent); realm-scoped where applicable. Retain per compliance requirements.
- **Integrity**: Prefer append-only; restrict write access to the app; use for forensics and abuse detection.

## Checklist for Security-Sensitive Changes

- [ ] No user enumeration via error messages or timing
- [ ] Timing-safe comparison for secrets/PKCE; minimum response time on auth endpoints
- [ ] Rate limiting on login, token, register, resend-verification (and other sensitive flows)
- [ ] Passwords hashed with Argon2id; strength validated; never logged
- [ ] No secrets or tokens in logs or error payloads
- [ ] Object/function level checks: validate user/realm/scope before acting on IDs
- [ ] Dependencies: audit run; known CVEs addressed or documented
- [ ] Audit log entries for success/failure where required

## Additional Resources

- OWASP API Top 10, CVE/dependency practices, and standards: [reference.md](reference.md)
- OAuth/PKCE security: `.claude/skills/auth-oauth/`
- JWT key management: `docs/adr/001-jwt-key-management.md`
- Security constants: `apps/auth-server/src/app/constants/security.ts`
- Timing helper: `apps/auth-server/src/app/helpers/timing.ts`

# Security — Standards & Reference

Summary of OWASP API Security Top 10 (2023), OWASP Top 10:2025 (auth), CVE/dependency practices, and how QAuth applies them. Sources: OWASP API Security, OWASP Top 10, npm/Snyk guidance, NIST 800-63B.

---

## 1. OWASP API Security Top 10 (2023)

| ID        | Risk                                            | Mitigation (QAuth-relevant)                                                                        |
| --------- | ----------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| **API1**  | Broken Object Level Authorization               | Validate every access by object ID against current user/realm; no “assume same realm.”             |
| **API2**  | Broken Authentication                           | OAuth 2.1 + PKCE; JWT with Ed25519; rate limit auth; no default creds; generic error messages.     |
| **API3**  | Broken Object Property Level Authorization      | Validate request/response; avoid mass assignment; don’t expose internal fields.                    |
| **API4**  | Unrestricted Resource Consumption               | Rate limit (global + per-route); Redis store; limit body size; timeouts.                           |
| **API5**  | Broken Function Level Authorization             | Enforce admin vs user; check scope and client type before sensitive actions.                       |
| **API6**  | Unrestricted Access to Sensitive Business Flows | Rate limit login, token, register, resend-verification; consider MFA/CAPTCHA.                      |
| **API7**  | Server Side Request Forgery (SSRF)              | Validate/allowlist URLs when fetching remote resources; no user-controlled URLs to internal hosts. |
| **API8**  | Security Misconfiguration                       | Secure defaults; no debug in prod; HTTPS; CORS and headers locked.                                 |
| **API9**  | Improper Inventory Management                   | Document endpoints; version APIs; remove or protect deprecated/debug.                              |
| **API10** | Unsafe Consumption of APIs                      | Validate/sanitize data from third-party APIs; don’t trust blindly.                                 |

---

## 2. OWASP Top 10:2025 — Authentication (A07)

- **Credential stuffing / password spray**: Rate limit; consider MFA and breach-list checks.
- **Brute force**: Rate limit failed logins; lockout or backoff when appropriate.
- **Weak passwords**: Enforce strength (e.g. zxcvbn); block top breached passwords where possible.
- **Session/token handling**: Secure storage; short-lived access tokens; refresh rotation; secure cookie flags when applicable.
- **Account enumeration**: Same error message and similar response time for “user not found” and “wrong password.”
- **Password recovery**: Rate limit; time-limited tokens; no sensitive data in URLs.

QAuth applies: rate limits on login/token/register/resend; minimum response time; generic InvalidCredentialsError; Argon2id + strength validation; audit logging.

---

## 3. CVE and Dependency Security

### npm / pnpm audit

- **pnpm audit** (or **npm audit**): Scans dependency tree against advisory DB; reports known vulnerabilities.
- **pnpm audit --fix**: Applies compatible fixes; review before committing.
- Run regularly in CI; fail or warn on high/critical; document exceptions.

### Supply chain (2025+)

- Lifecycle hooks (e.g. install scripts) can be abused; prefer minimal scripts and trusted packages.
- Pin versions or use lockfile; review new dependencies and transitive adds.
- Snyk, GitHub Dependabot, or similar for continuous CVE alerts and PRs.

### When a CVE is reported

1. Identify affected package and version (direct or transitive).
2. Check advisory for fixed version or mitigation.
3. Upgrade or patch; if no fix, document risk and compensating controls.
4. Re-run audit and tests; deploy with normal change process.

---

## 4. Standards Quick Reference

| Standard                             | Scope                                                                               |
| ------------------------------------ | ----------------------------------------------------------------------------------- |
| **NIST 800-63B**                     | Passwords: length/entropy, breach lists, avoid overly complex rotation.             |
| **RFC 7636**                         | PKCE: S256 only; high-entropy verifier; constant-time challenge verification.       |
| **RFC 6749 / 9700**                  | OAuth 2.0/2.1: PKCE mandatory; no implicit/password grant; redirect_uri validation. |
| **RFC 6750**                         | Bearer token usage; no tokens in URLs for front-channel.                            |
| **OWASP API Security Top 10 (2023)** | API-specific risks; see table above.                                                |
| **OWASP Top 10:2025**                | Web app risks; A07 Authentication Failures.                                         |

---

## 5. QAuth Security Conventions (Summary)

| Area         | Convention                                                      |
| ------------ | --------------------------------------------------------------- |
| Passwords    | Argon2id; zxcvbn strength; never log or store plaintext         |
| PKCE         | `crypto.timingSafeEqual` for challenge verification             |
| Auth timing  | `ensureMinimumResponseTime` on login, token, refresh            |
| Errors       | Generic message for auth failure; `@qauth-labs/shared-errors`   |
| Rate limit   | Global + per-route; Redis; env-driven; stricter on auth flows   |
| Secrets      | Env/secrets manager; never in code/images/logs; ADR-001 for JWT |
| Audit        | `audit_logs` for auth/token events; IP, userAgent, no secrets   |
| Dependencies | `pnpm audit`; fix or document; track CVEs                       |

These align with OWASP API Security Top 10 (2023), OWASP Top 10:2025 auth guidance, and current dependency/CVE best practice.

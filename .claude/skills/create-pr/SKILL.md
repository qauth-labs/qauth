---
name: create-pr
description: Create a pull request following QAuth conventions with gh pr create
disable-model-invocation: true
---

# Create Pull Request

Create a pull request following QAuth project conventions.

## Your Task

Create a PR that properly links to issues and follows the project's PR format.

## PR Title Format

Use conventional commits with scope:

- `feat(scope): description` - New feature
- `fix(scope): description` - Bug fix
- `refactor(scope): description` - Code restructuring
- `docs(scope): description` - Documentation
- `test(scope): description` - Testing
- `chore(scope): description` - Maintenance

Common scopes: `auth`, `oauth`, `db`, `config`, `docker`, `api`

## PR Body Format

```markdown
Closes #{issue_number}

{Bullet points of changes}
```

Or for bug fixes:

```markdown
Fixes #{issue_number}

{Bullet points of changes}
```

## Examples from Project

### Feature PR

```markdown
Closes #62

- Add TOKEN_RATE_LIMIT and TOKEN_RATE_WINDOW to auth config (30/min, 60s)
- Add MIN_RESPONSE_TIME_MS.TOKEN (300ms) for timing-attack mitigation
- Add tokenExchangeBodySchema and tokenExchangeResponseSchema in oauth schemas
- Implement POST /oauth/token: client_secret_post, PKCE, code validation
- Rate limit by IP; audit oauth.token.exchange.success/failure
```

### Fix PR

```markdown
Fixes #67

- Rewrites database seed script to use drizzle-seed
- Fixes secret leak and PKCE issues
```

## Command

```bash
gh pr create \
  --title "feat(scope): description" \
  --body "$(cat <<'EOF'
- Change 1
- Change 2
- Change 3

Closes #XX
EOF
)"
```

## Pre-PR Checklist

Before creating the PR, verify:

```bash
# Check for uncommitted changes
git status

# Run linting
pnpm nx affected -t lint

# Run tests
pnpm nx affected -t test

# Run typecheck
pnpm nx affected -t typecheck
```

## Instructions

1. Review the changes with `git diff` and `git log`
2. Identify which issue(s) this PR closes
3. Write concise bullet points describing each change
4. Use the appropriate conventional commit format for title
5. Include `Closes #X` or `Fixes #X` to auto-link issues
6. Create the PR and report the URL to the user

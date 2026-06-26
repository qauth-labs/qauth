---
name: create-pr
description: Create a pull request following QAuth conventions with gh pr create
disable-model-invocation: true
---

# Create Pull Request

Create a PR with `gh pr create`. For the title format (Conventional Commits +
scope) and PR body format (`Closes #N` / `Fixes #N` + bullets), follow the
`github-conventions` skill.

## Pre-PR Checklist

```bash
git status                      # no unintended uncommitted changes
pnpm nx affected -t lint        # lint passes
pnpm nx affected -t test        # tests pass
pnpm nx affected -t typecheck   # types pass
```

## Command

```bash
gh pr create \
  --title "feat(scope): description" \
  --body "$(cat <<'EOF'
Closes #XX

- Change 1
- Change 2
EOF
)"
```

### Example (feature)

```markdown
Closes #62

- Add TOKEN_RATE_LIMIT and TOKEN_RATE_WINDOW to auth config (30/min, 60s)
- Add MIN_RESPONSE_TIME_MS.TOKEN (300ms) for timing-attack mitigation
- Implement POST /oauth/token: client_secret_post, PKCE, code validation
- Rate limit by IP; audit oauth.token.exchange.success/failure
```

## Instructions

1. Review the changes with `git diff` and `git log`.
2. Identify which issue(s) this PR closes.
3. Write concise bullet points describing each change; pick the right
   Conventional Commit title (see `github-conventions`).
4. Include `Closes #X` / `Fixes #X` to auto-link issues.
5. Create the PR and report the URL to the user.

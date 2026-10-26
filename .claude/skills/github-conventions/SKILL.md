---
name: github-conventions
description: Shared GitHub conventions for QAuth — repo, gh CLI usage, branch naming, Conventional Commits, issue/PR body templates, labels, and milestones. Use when creating or editing issues, PRs, branches, or commits. The focused github skills (create-issue, create-pr, add-sub-issue, add-to-project, investigate-issue, set-milestone) reference this for conventions.
---

# GitHub Conventions (QAuth)

Shared conventions for GitHub work on QAuth. The focused operation skills load
only their own commands and reference this skill for the conventions below, so no
single task pulls in unrelated context.

## Tooling

QAuth uses the **`gh` CLI** for GitHub operations — deliberately preferred over
the GitHub MCP server as of this refactor. (Revisit this choice on the next
agentic-docs refactor.) All examples in the GitHub skills use `gh`.

- **Repo**: `qauth-labs/qauth`
- **Project scope**: some project commands need `gh auth refresh -s project` once.

## Branch Naming

`<type>/<issue>-slug`, e.g. `feature/62-oauth-token-endpoint`,
`fix/67-rewrite-dbseed`, `docs/…`, `refactor/…`, `chore/…`.

## Conventional Commits & Titles

Commit messages and PR/issue titles follow Conventional Commits:

`feat:`, `fix:`, `refactor:`, `docs:`, `style:`, `perf:`, `test:`, `chore:`.

Add a scope where useful: `feat(auth): …`. Common scopes: `auth`, `oauth`, `db`,
`config`, `ci`, `api`, `docker`.

## Issue Body Template

```markdown
## Summary

{1-2 sentence description}

## Tasks

- [ ] Task 1
- [ ] Task 2

## Technical Details

{code examples, config, architecture notes}

## Acceptance Criteria

- [ ] Criterion 1
- [ ] Criterion 2

## References

- docs/adr/{ADR file} - {relevant section}
```

## PR Body Template

Lead with the issue link so it auto-closes on merge, then concise bullets:

```markdown
Closes #62

- Bullet point of change 1
- Bullet point of change 2
```

Use `Fixes #N` for bug fixes, `Closes #N` for features.

## Labels & Milestones

- **Labels**: `enhancement` (features), `bug` (fixes); add others as needed
  (e.g. `priority:high`, `auth`).
- **Milestone**: new work goes on a release milestone of the 0.x → 1.0 path
  (ADR-018 §2), whose titles carry a descriptive suffix — e.g. `v0.3 - Core and UIs
  beta`. The older `MVP` and `T0`–`T6` milestones are finished history; never file new
  work against them. There has never been a `Phase N` milestone. Read the live list
  before setting one, because this file cannot stay ahead of it:

  ```bash
  gh api repos/qauth-labs/qauth/milestones --jq '.[] | "\(.title) (\(.state))"'
  ```

## Focused Skills

- `create-issue` — create an issue
- `create-pr` — open a pull request
- `add-sub-issue` — parent/child issue links (GraphQL)
- `add-to-project` — add an issue to a project board
- `investigate-issue` — gather context/requirements for an issue
- `set-milestone` — manage milestones on issues

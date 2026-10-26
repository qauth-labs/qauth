---
name: create-issue
description: Create a new GitHub issue following QAuth project conventions using gh issue create
disable-model-invocation: true
---

# Create GitHub Issue

Create a GitHub issue with `gh issue create`. For title format, the issue body
template, labels, and milestones, follow the `github-conventions` skill.

## Command Template

```bash
gh issue create \
  --title "feat: {title}" \
  --body "$(cat <<'BODY'
## Summary

{summary}

## Tasks

- [ ] {task1}
- [ ] {task2}

## Technical Details

{details}

## Acceptance Criteria

- [ ] {criterion1}
- [ ] {criterion2}

## References

- docs/adr/018-1-0-scope-and-stability.md - {relevant section}
BODY
)" \
  --label "enhancement" \
  --milestone "$MILESTONE"
```

Set `MILESTONE` from the live list, never from memory. New work goes on a release
milestone (`v0.2` … `v1.0`); filing it against a finished one (`MVP`, `T0`–`T6`)
buries the issue:

```bash
gh api repos/qauth-labs/qauth/milestones --jq '.[] | select(.state=="open") | .title'
```

Omit `--milestone` entirely if no open milestone fits; an unmilestoned issue is better
than a misfiled one.

## Instructions

1. Ask the user what they want to create if it isn't clear.
2. Determine the appropriate phase (see `github-conventions` for phases).
3. Write detailed tasks with checkboxes and clear acceptance criteria; include
   technical details/code examples where relevant.
4. Create the issue with `gh issue create`.
5. Report the issue URL back to the user.

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

- MVP-PRD.md
BODY
)" \
  --label "enhancement" \
  --milestone "MVP"
```

## Instructions

1. Ask the user what they want to create if it isn't clear.
2. Determine the appropriate phase (see `github-conventions` for phases).
3. Write detailed tasks with checkboxes and clear acceptance criteria; include
   technical details/code examples where relevant.
4. Create the issue with `gh issue create`.
5. Report the issue URL back to the user.

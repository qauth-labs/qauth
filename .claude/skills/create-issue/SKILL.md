---
name: create-issue
description: Create a new GitHub issue following QAuth project conventions using gh issue create
disable-model-invocation: true
---

# Create GitHub Issue

Create a new GitHub issue following the QAuth project conventions.

## Your Task

When the user describes a task or feature, create an issue using `gh issue create`.

## Issue Title Format

Use conventional commits style:

- `feat: {description}` - New feature
- `fix: {description}` - Bug fix
- `refactor: {description}` - Code restructuring
- `docs: {description}` - Documentation
- `test: {description}` - Testing
- `chore: {description}` - Maintenance

## Issue Body Template

```markdown
## Summary

{Brief description of the task - 1-2 sentences}

## Tasks

- [ ] Task 1
- [ ] Task 2
- [ ] Task 3

## Technical Details

{Code examples, configuration details, architecture notes}

## Acceptance Criteria

- [ ] Criterion 1
- [ ] Criterion 2
- [ ] Criterion 3

## Additional Notes

{Any limitations, warnings, or MVP considerations}

## References

- MVP-PRD.md - {relevant section}
- {Links to relevant documentation}
```

## Labels

- `enhancement` - For new features
- `bug` - For bug fixes

## Milestone

All MVP issues should use milestone: `MVP`

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

1. Ask the user what they want to create if not clear
2. Determine the appropriate phase (Phase 0-3)
3. Write detailed tasks with checkboxes
4. Include technical details with code examples where relevant
5. Define clear acceptance criteria
6. Create the issue using `gh issue create`
7. Report the issue URL back to the user

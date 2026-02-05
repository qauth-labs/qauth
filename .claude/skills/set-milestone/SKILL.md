---
name: set-milestone
description: Add, update, or remove milestones on GitHub issues using gh issue edit
disable-model-invocation: true
---

# Set Issue Milestone

Add or update the milestone on a GitHub issue.

## Your Task

Manage milestones on issues.

## List Available Milestones

```bash
gh api repos/{owner}/{repo}/milestones --jq '.[] | "\(.number): \(.title) (\(.state))"'
```

## Set Milestone on Issue

```bash
# Using gh issue edit (recommended)
gh issue edit {issue_number} --milestone "MVP"
```

## Remove Milestone

```bash
gh issue edit {issue_number} --remove-milestone
```

## Create New Milestone

```bash
gh api repos/{owner}/{repo}/milestones \
  -f title="v1.0" \
  -f description="First release milestone" \
  -f due_on="2026-06-01T00:00:00Z" \
  -f state="open"
```

## Update Milestone

```bash
# Get milestone number first
gh api repos/{owner}/{repo}/milestones --jq '.[] | select(.title=="MVP") | .number'

# Update milestone
gh api repos/{owner}/{repo}/milestones/{milestone_number} \
  -X PATCH \
  -f description="Updated description" \
  -f state="open"
```

## Close Milestone

```bash
gh api repos/{owner}/{repo}/milestones/{milestone_number} \
  -X PATCH \
  -f state="closed"
```

## Bulk Set Milestone

```bash
# Set milestone on multiple issues
gh issue edit 1 2 3 4 5 --milestone "MVP"
```

## Project Milestones

Current milestone: **MVP**

Phases:

- Phase 0: Foundation Setup
- Phase 1: Core Authentication
- Phase 2: Developer Portal
- Phase 3: Production Readiness

## Instructions

1. List available milestones if user is unsure
2. Use `gh issue edit` to set the milestone
3. Confirm the change was applied
4. For new milestones, use the API to create them first

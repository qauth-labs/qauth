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
gh issue edit {issue_number} --milestone "v0.3 - Core and UIs beta"
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
gh api repos/{owner}/{repo}/milestones --jq '.[] | select(.title=="{milestone_title}") | .number'

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
gh issue edit 1 2 3 4 5 --milestone "v0.3 - Core and UIs beta"
```

## Project Milestones

New work goes on a release milestone of the 0.x → 1.0 path (`v0.2 - Foundations`
through `v1.0 - Stable release`); see
`github-conventions`. **Never assume which one is current** — the live list is the only
authority, and this file cannot stay ahead of it:

```bash
gh api repos/qauth-labs/qauth/milestones --jq '.[] | "\(.title) (\(.state))"'
```

The older `MVP` and `T0`-`T6` milestones are finished history and must not be used for
new work. Note that a closed milestone can still have open issues attached (`MVP` has
two), so "closed" and "empty" are not the same thing. Re-derive all of it with the
command above rather than trusting this paragraph.

## Instructions

1. List available milestones if user is unsure
2. Use `gh issue edit` to set the milestone
3. Confirm the change was applied
4. For new milestones, use the API to create them first

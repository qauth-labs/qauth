---
name: gh-issues
description: Create and manage GitHub issues with gh CLI. Use for creating issues, investigating bugs, adding milestones, projects, and sub-issue hierarchies.
---

# GitHub Issues Management (gh CLI)

## Creating Issues

### Basic Issue

```bash
gh issue create --title "Issue title" --body "Description"
```

### With Labels, Assignee, Milestone

```bash
gh issue create \
  --title "feat: Add user authentication" \
  --body "Implement OAuth 2.1 authentication flow" \
  --label "feature,auth" \
  --assignee "@me" \
  --milestone "v1.0"
```

### Add to Project

```bash
# Requires: gh auth refresh -s project
gh issue create \
  --title "Bug: Login fails" \
  --label "bug" \
  --project "Roadmap"
```

### From Template

```bash
gh issue create --template "Bug Report"
gh issue create --template "Feature Request"
```

### Open in Browser

```bash
gh issue create --web
```

## Investigating Issues

### View Issue Details

```bash
gh issue view 123
gh issue view 123 --comments
gh issue view https://github.com/owner/repo/issues/123
```

### JSON Output for Scripting

```bash
gh issue view 123 --json title,body,labels,milestone,state
gh issue view 123 --json assignees --jq '.assignees[].login'
```

### List Issues

```bash
gh issue list
gh issue list --state open
gh issue list --label bug
gh issue list --assignee "@me"
gh issue list --milestone "v1.0"
gh issue list --search "auth in:title"
```

### View in Browser

```bash
gh issue view 123 --web
```

## Editing Issues

### Update Title/Body

```bash
gh issue edit 123 --title "New title"
gh issue edit 123 --body "Updated description"
gh issue edit 123 --body-file description.md
```

### Labels

```bash
gh issue edit 123 --add-label "bug,critical"
gh issue edit 123 --remove-label "wontfix"
```

### Assignees

```bash
gh issue edit 123 --add-assignee "@me"
gh issue edit 123 --add-assignee "username"
gh issue edit 123 --remove-assignee "username"
```

### Milestone

```bash
gh issue edit 123 --milestone "v1.0"
gh issue edit 123 --remove-milestone
```

### Project

```bash
# Requires: gh auth refresh -s project
gh issue edit 123 --add-project "Roadmap"
gh issue edit 123 --remove-project "Backlog"
```

### Bulk Edit

```bash
gh issue edit 123 124 125 --add-label "sprint-1"
```

## Milestones

### List Milestones

```bash
gh api repos/{owner}/{repo}/milestones
gh api repos/{owner}/{repo}/milestones --jq '.[].title'
```

### Create Milestone

```bash
gh api repos/{owner}/{repo}/milestones \
  -f title="v1.0" \
  -f description="First release" \
  -f due_on="2026-03-01T00:00:00Z"
```

### Update Milestone

```bash
gh api repos/{owner}/{repo}/milestones/1 \
  -X PATCH \
  -f title="v1.0-beta" \
  -f state="open"
```

### Close Milestone

```bash
gh api repos/{owner}/{repo}/milestones/1 -X PATCH -f state="closed"
```

## Projects (v2)

### Prerequisites

```bash
gh auth refresh -s project
```

### List Projects

```bash
gh project list
gh project list --owner "@me"
gh project list --owner "org-name"
```

### View Project

```bash
gh project view 1 --owner "@me"
gh project view 1 --owner "@me" --web
```

### Add Issue to Project

```bash
gh project item-add 1 --owner "@me" --url https://github.com/owner/repo/issues/123
```

### List Project Items

```bash
gh project item-list 1 --owner "@me"
```

## Sub-Issues (Parent/Child)

> **Note**: Native `gh` CLI doesn't support sub-issues yet. Use GraphQL API.

### Get Issue ID (Required for GraphQL)

```bash
gh issue view 123 --json id --jq ".id"
```

### Add Sub-Issue via GraphQL

```bash
# Get parent and child IDs first
PARENT_ID=$(gh issue view 100 --json id --jq ".id")
CHILD_ID=$(gh issue view 101 --json id --jq ".id")

# Link child to parent
gh api graphql \
  -H "GraphQL-Features: sub_issues" \
  -f query='
    mutation($parentId: ID!, $childId: ID!) {
      addSubIssue(input: { issueId: $parentId, subIssueId: $childId }) {
        issue { title }
        subIssue { title }
      }
    }
  ' \
  -f parentId="$PARENT_ID" \
  -f childId="$CHILD_ID"
```

### Remove Sub-Issue

```bash
gh api graphql \
  -H "GraphQL-Features: sub_issues" \
  -f query='
    mutation($parentId: ID!, $childId: ID!) {
      removeSubIssue(input: { issueId: $parentId, subIssueId: $childId }) {
        issue { title }
        subIssue { title }
      }
    }
  ' \
  -f parentId="$PARENT_ID" \
  -f childId="$CHILD_ID"
```

### CLI Extensions (Alternative)

Install community extensions for easier sub-issue management:

```bash
gh extension install yahsan2/gh-sub-issue
gh issue add-sub 100 101  # Add issue 101 as sub-issue of 100
```

## Issue Lifecycle

### Close Issue

```bash
gh issue close 123
gh issue close 123 --reason "completed"
gh issue close 123 --reason "not_planned"
gh issue close 123 --comment "Fixed in PR #456"
```

### Reopen Issue

```bash
gh issue reopen 123
```

### Pin/Unpin Issue

```bash
gh issue pin 123
gh issue unpin 123
```

### Lock/Unlock Conversation

```bash
gh issue lock 123
gh issue lock 123 --reason "spam"
gh issue unlock 123
```

### Transfer Issue

```bash
gh issue transfer 123 owner/other-repo
```

## Commenting

```bash
gh issue comment 123 --body "This is a comment"
gh issue comment 123 --body-file comment.md
gh issue comment 123 --web  # Open in browser
```

## Develop (Branch Linking)

```bash
# Create linked branch
gh issue develop 123 --name "feature/auth"
gh issue develop 123 --base main

# List linked branches
gh issue develop 123 --list
```

## Useful Patterns

### Create Bug Report

```bash
gh issue create \
  --title "fix: Login button unresponsive" \
  --body "## Steps to reproduce
1. Go to login page
2. Click login button
3. Nothing happens

## Expected behavior
Should show loading state and redirect

## Environment
- Browser: Chrome 120
- OS: macOS 14" \
  --label "bug,priority:high" \
  --assignee "@me"
```

### Create Feature with Subtasks

```bash
# Create parent feature
gh issue create \
  --title "feat: User authentication system" \
  --body "Implement complete auth flow" \
  --label "feature,epic"

# Create sub-tasks and link them
gh issue create --title "feat: Add login endpoint" --label "feature"
gh issue create --title "feat: Add JWT validation" --label "feature"
gh issue create --title "feat: Add logout endpoint" --label "feature"
# Then link via GraphQL (see Sub-Issues section)
```

### Search and Filter

```bash
# Open bugs assigned to me
gh issue list --state open --label bug --assignee "@me"

# Issues in milestone
gh issue list --milestone "v1.0" --state all

# Search with keywords
gh issue list --search "authentication in:title,body"
```

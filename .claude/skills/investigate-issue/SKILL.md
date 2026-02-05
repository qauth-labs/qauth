---
name: investigate-issue
description: Gather context and requirements for a GitHub issue using gh issue view and related commands
disable-model-invocation: true
---

# Investigate GitHub Issue

Investigate a GitHub issue to understand requirements and context.

## Your Task

When given an issue number or URL, gather all relevant information.

## Investigation Steps

### 1. View Issue Details

```bash
gh issue view {number} --json title,body,labels,milestone,state,comments,assignees
```

### 2. View Issue Comments

```bash
gh issue view {number} --comments
```

### 3. Check Related Issues

```bash
# Search for related issues
gh issue list --search "{keywords} in:title,body" --state all --limit 10
```

### 4. Check Linked PRs

```bash
# View PRs that reference this issue
gh pr list --search "#{number}" --state all
```

### 5. View Closed Related Issues

```bash
gh issue list --state closed --search "{keywords}" --limit 5 --json number,title,body
```

## Output Format

Provide a summary including:

1. **Issue Overview**: Title, state, labels, milestone
2. **Summary**: What the issue is about
3. **Tasks**: Outstanding tasks from the checkbox list
4. **Technical Context**: Key technical details
5. **Acceptance Criteria**: What defines "done"
6. **Related Issues/PRs**: Any linked work
7. **Blockers**: Any dependencies or blockers identified

## Sub-Issues Investigation

If the issue has sub-issues:

```bash
# Get issue ID for GraphQL
gh issue view {number} --json id --jq ".id"

# Query sub-issues (if any)
gh api graphql \
  -H "GraphQL-Features: sub_issues" \
  -f query='
    query($id: ID!) {
      node(id: $id) {
        ... on Issue {
          subIssues(first: 20) {
            nodes {
              number
              title
              state
            }
          }
        }
      }
    }
  ' \
  -f id="{issue_id}"
```

## Instructions

1. Fetch the full issue details
2. Parse the body to identify tasks, technical details, and acceptance criteria
3. Check for related issues and PRs
4. Summarize findings for the user
5. Identify any blockers or dependencies
6. Suggest next steps if appropriate

---
name: add-sub-issue
description: Link GitHub issues in parent-child (sub-issue) relationships using GraphQL
disable-model-invocation: true
---

# Add Sub-Issue (Parent/Child Relationship)

Create parent-child relationships between GitHub issues.

## Your Task

Link issues in a hierarchical structure using GitHub's sub-issues feature.

## Prerequisites

Sub-issues require the GraphQL API with a feature flag.

## Get Issue IDs

First, get the internal IDs for both issues:

```bash
# Get parent issue ID
PARENT_ID=$(gh issue view {parent_number} --json id --jq ".id")
echo "Parent ID: $PARENT_ID"

# Get child issue ID
CHILD_ID=$(gh issue view {child_number} --json id --jq ".id")
echo "Child ID: $CHILD_ID"
```

## Add Sub-Issue

```bash
gh api graphql \
  -H "GraphQL-Features: sub_issues" \
  -f query='
    mutation($parentId: ID!, $childId: ID!) {
      addSubIssue(input: { issueId: $parentId, subIssueId: $childId }) {
        issue { title number }
        subIssue { title number }
      }
    }
  ' \
  -f parentId="$PARENT_ID" \
  -f childId="$CHILD_ID"
```

## Remove Sub-Issue

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

## List Sub-Issues of a Parent

```bash
PARENT_ID=$(gh issue view {parent_number} --json id --jq ".id")

gh api graphql \
  -H "GraphQL-Features: sub_issues" \
  -f query='
    query($id: ID!) {
      node(id: $id) {
        ... on Issue {
          title
          number
          subIssues(first: 50) {
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
  -f id="$PARENT_ID"
```

## Workflow: Create Epic with Sub-Issues

1. Create the parent (epic) issue
2. Create child issues for each subtask
3. Link children to parent using the GraphQL mutation

```bash
# Example: Create epic
gh issue create \
  --title "feat: User authentication system" \
  --body "Epic for authentication implementation" \
  --label "enhancement" \
  --milestone "MVP"

# Note the issue number, then create sub-issues
gh issue create --title "feat: Add login endpoint" --label "enhancement" --milestone "MVP"
gh issue create --title "feat: Add JWT validation" --label "enhancement" --milestone "MVP"
gh issue create --title "feat: Add logout endpoint" --label "enhancement" --milestone "MVP"

# Link them (get IDs first, then run addSubIssue for each)
```

## Limits

- Maximum 100 sub-issues per parent
- Up to 8 levels of nesting

## Instructions

1. Get the parent and child issue numbers from the user
2. Fetch the internal IDs for both issues
3. Execute the GraphQL mutation to link them
4. Confirm the relationship was created
5. Optionally list all sub-issues to verify

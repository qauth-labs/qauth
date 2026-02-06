---
name: add-to-project
description: Add a GitHub issue to a project board using gh project item-add
disable-model-invocation: true
---

# Add Issue to Project

Add an issue to a GitHub Project board.

## Prerequisites

```bash
# Ensure project scope is authorized
gh auth refresh -s project
```

## Your Task

Add issues to the appropriate GitHub Project.

## List Available Projects

```bash
gh project list --owner qauth-labs
```

## Add Issue to Project

```bash
gh project item-add {project_number} \
  --owner qauth-labs \
  --url https://github.com/qauth-labs/qauth/issues/{issue_number}
```

## View Project Items

```bash
gh project item-list {project_number} --owner qauth-labs
```

## Instructions

1. List available projects to find the correct one
2. Add the issue using `gh project item-add`
3. Confirm the issue was added by listing project items
4. Report success to the user

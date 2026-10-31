---
name: nx-ci
description: CI/CD workflows with Nx affected commands. Use when setting up pipelines, debugging CI failures, or optimizing builds.
---

# Nx CI/CD Workflows

## Affected Commands

```bash
pnpm nx affected -t test
pnpm nx affected -t lint test build
pnpm nx affected -t test --base=origin/main --head=HEAD
```

## GitHub Actions

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0 # Required for affected

- uses: pnpm/action-setup@v2
- uses: actions/setup-node@v4

- run: pnpm install --frozen-lockfile
- run: pnpm nx affected -t lint test build --base=origin/main
```

## Nx Cloud

Not used. The workspace has no remote cache (`neverConnectToCloud` in `nx.json`); each CI
leg computes its tasks with the local cache only.

## Local CI Simulation

```bash
pnpm nx affected -t lint test build --base=origin/main
pnpm nx run-many -t lint test build --all
```

## Debugging CI Failures

```bash
pnpm nx affected:graph --base=origin/main
pnpm nx affected --target=test --base=origin/main --dry-run
pnpm nx test {failing-project} --skip-nx-cache
```

## Cache Management

```bash
pnpm nx reset                          # Clear cache
pnpm nx test {project} --skip-nx-cache # Bypass cache
pnpm nx report                         # Cache status
```

## Best Practices

1. Use affected commands in CI
2. Keep main branch green
3. Set proper base/head refs
4. Use `--parallel` for independent tasks

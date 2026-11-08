# docs-checks

The checks that compare the docs with the code of the libraries (#1044):

- `reference/realm-policies.md`, `reference/experimental-features.md` and
  `operate/configuration.md` are generated from the registries of `server-realm-policy`,
  `shared-stability` and `server-config`, and must match what they render, formatted with Oxfmt;
- every realm policy field's docs link names a page of the docs site and a heading on it;
- the docs pages flagged `experimental: true` and the experimental-feature registry match one to
  one (#477), and the decision records and evidence paths the registry names exist (#476);
- no project but the docs site and this one names a docs file in its Nx inputs, beyond the seven
  generated or checked reference pages a project writes or checks itself, which
  `docs-inputs.test.ts` lists with the reason for each.

```bash
pnpm nx test docs-checks        # run the checks
pnpm nx test docs-checks -- -u  # regenerate the three pages after a registry change
```

## Why a project of its own

Nx counts a project as touched by a changed file that one of its targets' inputs names, and with
`affected.legacy` (nx.json) a touched project marks every project that depends on it affected, for
every target. These checks used to be the libraries' own tests, with the docs among their inputs,
so a docs-only pull request marked the auth server affected and ran its tests. Here a docs edit
affects this project alone: nothing may depend on it, which a module-boundary constraint in
`.oxlintrc.json` enforces. (CI's integration job selects its tasks by their inputs instead, so a
docs edit runs no integration suite at all.)

The libraries' own tests still check what each registry renders; this project checks the committed
files. CI runs these tests in the `coverage` job's repository-wide Vitest run, like every other unit
test.

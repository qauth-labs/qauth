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

These checks used to be the libraries' own tests, with the docs among their inputs. Under the
whole-project selection Nx 24's migration had kept (`affected.legacy`), a docs edit touched those
libraries and marked every project depending on them affected, the auth server and its integration
suite among them. Here the checks read the docs from a project nothing may depend on, which a
module-boundary constraint in `.oxlintrc.json` enforces, and the libraries' test inputs are their
own files. `nx affected` now selects tasks by their inputs, so a docs edit reruns these checks and
nothing else.

The libraries' own tests still check what each registry renders; this project checks the committed
files. CI runs these tests in the `coverage` job's repository-wide Vitest run, like every other unit
test.

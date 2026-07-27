See the [repo manifest](/package.json) — a real repository file, but not one
under `apps/docs-site/public/` or a site route, so the deployed site never
serves it at that literal path. Proves the rule is general, not a `docs/`- or
`libs/`-specific special case: `package.json` has neither prefix.

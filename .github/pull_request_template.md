<!-- Lead with the issue: "Closes #N" for a feature, "Fixes #N" for a bug. -->

Closes #

## What and why

<!-- Why the change is needed and what it changes, by area. -->

## Checks

<!-- Tick each check that applies to this pull request, and strike out the ones that do not. CONTRIBUTING.md explains each one. -->

- [ ] **A stable route was added or changed, and its wire test is in this pull request.** A test in
      `apps/wire-suite` whose `describe` or `it` title carries the operation as the OpenAPI document
      lists it, for example `[POST /oauth/token]`, cites the spec it checks and imports no server
      code. `apps/wire-suite/exempt-operations.json` may only shrink.
- [ ] **An event type was added, and it is registered.** A `defineEventType` entry under
      `libs/shared/events/src/lib/types/`, the schema export run, and its schema file listed in
      `stable-surface/surfaces.json` (`libs/shared/events/README.md`).
- [ ] **A migration was added, and it is non-destructive.** It drops or renames no table or column,
      narrows no column type and deletes no rows; a change of shape adds the new form beside the
      old one, and the old form goes only in a major release (ADR-018 §5).

## Verification

<!-- The commands you ran and what they showed. -->

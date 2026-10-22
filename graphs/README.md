# graphs/

QAuth's flows and screens, written as semantic graphs
([ADR-021](../docs/adr/021-flows-and-ui-as-semantic-graphs.md)). Each graph is the specification of
a flow; the code implements it, and once CI checks the graphs it fails when the two disagree.
Nothing here is compiled into code.

The graphs are written in `delurio-graph/0`, the format of delurio, a separate project that owns
the format and every tool that reads it: the checker, the test-path generator, the replay on a
running QAuth, the state pages and the domain extraction. QAuth defines no schema of its own and
builds no graph tooling (ADR-021, amendment of 2026-10-22).

**The graphs are outside the 1.0 stability promise** (ADR-021 Decision 6).

## Layout

```text
graphs/
  domain/                the domain graph (kind: domain): entities, fields and edges generated
                         from the Drizzle tables and the Zod schemas, plus hand-written overlays
                         for sensitivity, policies and invariants
  flows/<area>/<flow>/   one delurio graph directory per flow
    flow.yaml            the statechart (kind: flow)
    ui.yaml              the screens, for a flow that has them (kind: ui)
    catalog/en.json      the UI strings that ui.yaml names
    binding.yaml         where a running QAuth is found when delurio replays the flow
  nav/<app>/nav.yaml     an app's navigation graph (kind: nav)
  bindings/              shared bindings that per-flow binding.yaml files extend: where the server
                         and the apps run, and how a replay signs in
  fixtures/              the seed data a replay starts from
  kits/                  delurio kits that draw the state pages with QAuth's own components
  claims.yaml            which API operations and UI routes each graph covers, or why one is exempt
```

`graphs/` will also become a small Nx project whose targets only run delurio's tool (#560). It
holds no code.

The areas under `flows/` follow the beta order of ADR-018 and the apps of ADR-020: `core`,
`authority-tree` and `federation` for protocol flows, `ceremony`, `account`, `admin` and
`developer` for the flows of each app. A flow is named after what it does, such as
`flows/core/authorize/` or `flows/account/revoke-consent/`.

Every document names the format version and its kind:

```yaml
schema: delurio-graph/0
kind: flow # or domain, ui, nav, binding, tutorial
```

## Checking the graphs

delurio's open command-line tool checks the graphs. QAuth will install it as a development
dependency pinned to an exact version, and CI will run it on every pull request, with no account
and no key. Until delurio publishes that tool, the graphs are written and reviewed, and CI does not
gate on them. Moving to a new delurio version, or a new format version, is one pull request that
moves the pin and the graphs together.

## Writing a graph

A flow's pull request does not merge without its graph (ADR-021 Decision 4). The rules each graph
must satisfy are in ADR-021 Decision 2. The authoring guide and the definition of done come with
#570.

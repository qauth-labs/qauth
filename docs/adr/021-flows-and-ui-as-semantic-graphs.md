# ADR-021: Flows and UI as Semantic Graphs

**Status:** Accepted 2026-10-11 — records the maintainer's decisions of 2026-10-10, together with the other 1.0 records.  
**Date:** 2026-10-10  
**Authors:** QAuth Team

> Nothing below is built. This record says how QAuth describes its flows and screens: as graphs in
> the repository, checked in CI and implemented by hand. A compiler that turns the graphs into code
> would replace the hand-written part. Writing that compiler is another project's job, and 1.0
> does not wait for it.
>
> **Amended 2026-10-22** (before any graph was written): the graph tooling moves to delurio, a
> separate project meant to become its own service, and QAuth uses it as any other project would.
> QAuth writes its graphs in delurio's format, `delurio-graph/0`, instead of a schema of its own;
> `qauth-graph/0` is retired unused. delurio builds the checker, the test-path generator, the
> replay adapters, the state pages and the domain extraction. QAuth pins delurio's open
> command-line tool to an exact version and runs it in CI on every pull request. Until delurio
> publishes that tool, the graphs are written and reviewed, and CI does not gate on them. The
> layers, the rules and the timing stand, as what QAuth requires of its graphs. Decisions 2, 3, 5
> and 6 are restated for the change.

## Context

### What exists today (checked 2026-10-10)

- Protocol flows live in Fastify route handlers and their tests. The
  [spec-conformance matrix](../conformance/README.md) maps normative requirements to those tests.
- Screens live in two places: five HTML pages rendered by the auth server, and the developer
  portal's React routes. [ADR-020](./020-ui-surfaces-and-acceptance-criteria.md) adds four apps.
- Nowhere is a flow written down as data. Its states, transitions, error exits and rules are spread
  over handlers, components, tests and comments.

### The problem

Code carries structure, not meaning. Take a control that removes an app's access to an account.
In JSX it is a button, a piece of `useState`, a dialog with `aria-labelledby="…"` and a focus call.
The rules that matter are conventions, not data:

- a destructive action asks for confirmation first;
- the dialog has a title, and the title's id is unique on the page;
- focus goes back to the button when the dialog closes;
- the request can be pending and can fail, and both states have a screen;
- the caller may remove only their own consents.

Nothing checks these rules except a reader. ADR-020's acceptance criteria (sign-in without
JavaScript, WCAG 2.2 AA, one design system) are checked screen by screen, after the screen exists.
Agents write much of QAuth's code, and they meet the same problem as a reviewer: they have to
infer the rules from text.

A graph with typed nodes and edges can state these rules. It can be validated before any code
exists, and agents can change it with operations that keep it valid.

### What already exists elsewhere

No tool does this at the level of flows and components. Parts of it exist, for example:

- projectional editing, where the source is a syntax tree and text is one view of it (JetBrains
  MPS, Hazel);
- content-addressed code, stored as hashed syntax trees rather than text files (Unison);
- statecharts as data ([SCXML](https://www.w3.org/TR/scxml/), XState and Stately);
- a component intermediate representation that compiles to several frameworks (Mitosis);
- generative UI over a catalog of approved components (A2UI,
  [json-render](https://github.com/vercel-labs/json-render)).

The last group works at screen level: a program picks components from a catalog and fills them at
run time. That is server-driven UI, the same idea as a controller that names a view and passes it
data. This record means something else. The graph describes the inside of a flow and of a
component: its states, its actions and their intent, and the relations between its parts.

The maintainer's position (2026-10-10): if such a tool existed, QAuth would use it. It does not,
so QAuth writes the graphs now and leaves the compiler to another project.

## Decision

### 1. Every flow is a graph

Every QAuth flow has a graph in the repository, UI included:

- protocol flows: authorization, token, token exchange, the device grant, CIBA, DCR and CIMD
  registration, and logout;
- ceremonies: sign-in, MFA, passkeys, consent and recovery;
- the flows of the account console, the admin console and the developer portal;
- the Authority Tree's approval flows (ADR-014).

The graph is the specification. The code implements it. When the two disagree, CI fails and one
of them is wrong.

### 2. Format

Graphs are YAML documents in `delurio-graph/0`, the format of delurio (Decision 6). QAuth defines
no schema of its own. Each document names the format version and its kind. QAuth's graphs use three
kinds, `domain`, `flow` and `ui`. delurio also defines `nav` for an app's navigation, `binding` for
where a running QAuth is found during a replay, and `tutorial`. The layers below are what QAuth
requires the format to express.

#### Domain layer

- **Entities and fields.** Each field is a JSON Schema 2020-12 schema (its type, format, enum and
  the like) plus delurio's keywords: `references` names another entity's key, `unique` marks a
  value that is unique, exactly or ignoring case, and `sensitivity` marks how far the value may
  travel. An entity names its `key` and its `lifecycle`. A `secret` field is never projected: no
  screen, response or tool output may contain it.
- **Edges.** Typed relations between entities, such as a client's realm or a consent's user. A
  field that holds another entity's key says so with `references`.
- **Policies.** An actor, a subject and an optional condition, followed by what the actor may read,
  write and do. The actors are the three API families of
  [ADR-019](./019-deployment-topology-and-trust-boundaries.md) Decision 7: admin, account and
  developer. An admin policy also names the scope it needs. A write that ADR-019 Decision 7 counts
  as a security operation names `qauth:admin:security`.
- **Invariants.** Named rules over fields and edges.

The part that code already declares is generated, never copied by hand:

- entities, fields and edges from the Drizzle tables;
- constraints from the Zod request schemas.

Generated files are rebuilt by delurio's domain extraction, and CI fails when the rebuilt output
differs from what is committed. Hand-written overlays add sensitivity, intent, policies and invariants. An overlay
that names a field the generator did not produce fails validation.

Two illustrative overlays, one for clients and one for consents. They are written in the shape
this record first proposed, `qauth-graph/0`; delurio's syntax differs, and the real overlays use it.
The real policies are written in the core beta:

```yaml
schema: qauth-graph/0
kind: domain
entity: Client # generated from the oauth_clients table
fields:
  clientSecretHash: { sensitivity: secret } # never projected
policies:
  - actor: admin
    scope: qauth:admin:write
    read: [clientId, name, environment, redirectUris, enabled]
    write: [name, enabled]
    do: [tightenEnvironment] # tightening is free, ADR-019 Decision 10
  - actor: admin
    scope: qauth:admin:security # security operations, ADR-019 Decision 7
    write: [environment, redirectUris]
  - actor: developer
    where: Client.developer = caller
    read: [clientId, name, environment, redirectUris, enabled]
    write: [name, redirectUris]
---
schema: qauth-graph/0
kind: domain
entity: Consent # generated from the oauth_consents table
policies:
  - actor: account
    where: Consent.user = caller
    read: [client.name, scopes, grantedAt]
    do: [revoke]
invariants:
  - id: one-active-consent # the table's partial unique index
    rule: at most one Consent per (user, client) with revokedAt = null
```

#### Flow layer

Flows are statecharts with SCXML semantics, written in the shape XState uses: states, events,
transitions, guards, effects and final states.

- An effect calls a domain action, such as `Consent.revoke`. The domain layer's policy for that
  action applies.
- An asynchronous effect has a pending state with both a success and a failure transition.
- A protocol flow's final states are its responses. Each OAuth error a flow can return is a final
  state of its own, so tests can reach every error.
- The ceremony flows agree with the step grammar of ADR-017 Decision 3, which the Interaction API
  carries (ADR-019 Decision 6).

#### UI layer

- **Nodes.** Semantic nodes such as action, dialog, field, text and status. An action has an intent:
  primary, confirm, destructive or dismiss.
- **Edges.** Typed relations: `labelledBy`, `describedBy`, `controls`, `triggers`, `confirms`,
  `returnsFocus`, and `bindsTo`, which ties a node to a domain field.
- **Binding to the flow.** Each node names the flow states in which it is shown and the events it
  emits.
- **Design tokens.** Nodes refer to tokens by name, in the
  [Design Tokens Community Group](https://www.designtokens.org/) format. An intent maps to its
  default tokens in one place.
- **No id strings and no class strings.** Relations are edges. The implementation derives the ids.
- **Text.** Strings are English, as ADR-020 decides for 1.0.

#### Rules

delurio's checker validates each graph's structure: required fields, allowed kinds, and edges that
point at nodes that exist. It then analyses the graph. QAuth requires it to reject a graph in which:

- a destructive action reaches its effect without passing through a confirm state;
- an interactive node has no accessible name;
- a dialog has no `labelledBy` edge;
- a transition that closes a dialog has no focus target;
- a `secret` field appears in any read list, binding or output;
- a state is unreachable, or a state that is not final has no exit.

These rules come from ADR-020's criteria and from QAuth's security rules. New rules are added the
same way: written once, checked everywhere. A rule delurio's checker does not enforce yet is
tracked with delurio, and until it lands it is a review item.

### 3. How the graphs are used before a compiler exists

Implementation stays conventional: the stack of ADR-020 §6 for the apps, Fastify for the server.
CI uses the graphs in four ways.

1. **Validation.** Every graph passes the schema and the checker.
2. **Model-based tests.** delurio's generator reads each statechart and produces event sequences
   that cover every state and every transition. delurio's replay runs them against a running QAuth,
   which a `binding` file locates:
   - Playwright for UI flows. The replay finds elements by role and accessible name, both of which
     come from the UI graph, so the tests need no test ids.
   - HTTP for protocol flows. The replay sends requests and checks each final state's response.
     It also checks every response body against the caller's policy: a field outside the read list,
     or any `secret` field, fails.

   A state or transition that no test reaches fails the build.

3. **Drift.** delurio's domain extraction runs over the Drizzle tables and the Zod schemas, and its
   output must equal the committed files.
4. **State gallery.** Every state of every UI graph is rendered by delurio and captured. The gallery feeds ADR-020's visual-regression criterion (criterion 8) and its
   accessibility checks (criterion 6). Reviewers look at the states, not only at the code.

delurio builds this tooling: the checker, the test-path generator, the replay adapters, the state
pages and the domain extraction. QAuth supplies its graphs and their bindings, and installs
delurio's open command-line tool at an exact version as a development dependency. CI runs it on
every pull request, a contributor's included, with no account and no key. Until delurio publishes
that tool, the graphs are written and reviewed, and CI does not gate on them. QAuth builds no graph
tooling and no compiler from graphs to code or UI.

### 4. Timing

The graphs come area by area, graph first, in the beta order of
[ADR-018](./018-1-0-scope-and-stability.md) §2:

1. **The core.** The `graphs/` layout and delurio's tool in CI come first. Then the existing core flows are graphed
   after the fact: authorization, token, token exchange, registration, consent, sign-in and
   logout. Then the new core flows, each graph before its code.
2. **The Authority Tree.**
3. **Federation.**

Wallet and PQC flows are graphed in the beta that carries them. A flow's pull request does not
merge without its graph.

### 5. Location

A top-level `graphs/` directory:

```text
graphs/
  domain/                the domain graph: generated from Drizzle and Zod, plus hand-written overlays
  flows/<area>/<flow>/   one delurio graph directory per flow: flow.yaml; ui.yaml and catalog/ for a
                         flow with screens; binding.yaml for a replay against QAuth
                         areas: core, authority-tree, federation, ceremony, account, admin, developer
  nav/<app>/             nav.yaml, an app's navigation graph
  bindings/              shared bindings that per-flow binding files extend
  fixtures/              the seed data a replay starts from
  kits/                  delurio kits that draw the state pages with QAuth's own components
  claims.yaml            which API operations and UI routes each graph covers
```

The graphs are neither prose nor TypeScript. `docs/` holds text for readers, and `libs/` holds Nx
code projects with their own boundaries. A top-level directory gives delurio, and any other
consumer, a stable path that does not depend on QAuth's build layout. QAuth has no graph tooling;
`graphs/` is an Nx project only so that its targets can run delurio's tool.

### 6. The boundary with delurio

- delurio is a separate project, the other project this record first left unnamed. It owns
  `delurio-graph/0`, its versions and every tool that reads it, and may one day compile graphs to
  code.
- QAuth publishes its graphs, not a schema. 1.0 depends on no compiler.
- QAuth uses delurio's open command-line tool as a development dependency, pinned to an exact
  version. Nothing QAuth ships runs delurio, and QAuth needs no hosted delurio service and no
  account. A new delurio version, or a new format version, is one pull request that moves the pin
  and the graphs together.
- The graphs stay outside the 1.0 stability promise.
- Hand-written code stays the implementation. Adopting generated code for a surface would take a
  new record.

## Consequences

### Positive

- Each flow's states, rules and error exits are written down once, and reviewers and agents read
  the same thing.
- Flow coverage becomes measurable: every state and every transition.
- ADR-020's criteria are stated per flow, before the screen exists, instead of found missing after.
- Responses are checked against policy, so a field that should not leave the server fails a test.
- delurio, or any other tool, can read QAuth's graphs; QAuth depends on delurio only while it is
  developed, never at run time.

### Negative

- Every flow has two artifacts, a graph and its code, until a compiler exists. A change touches
  both.
- QAuth depends on delurio for its graph tooling. A check delurio lacks is missing in QAuth too
  until delurio adds it, and CI does not gate on the graphs until delurio publishes its open tool.
- Graphing the existing core flows costs time in the core beta.
- `delurio-graph/0` is young and will change. Early graphs will need migrating.
- Contributors must learn the format.

### Neutral

- A compiler, if one comes, is delurio's. QAuth neither waits for it nor promises to adopt it.
- Generated domain files are committed, so their diffs show schema changes in review.

## Alternatives considered

- **A TypeScript DSL.** Rejected. The graph would exist only by running code, and a compiler would
  be tied to TypeScript.
- **RDF or Turtle with SHACL.** Rejected for now. It has the strongest semantics, but heavy tooling,
  and few contributors or agents are fluent in it.
- **Diagrams in documents only.** Rejected. A graph that nothing checks drifts from the code.
- **Waiting for an outside compiler.** Rejected. None exists, and 1.0 cannot wait for one.
- **QAuth's own schema and tooling.** This record first chose them (`qauth-graph/0`, 2026-10-10).
  Replaced on 2026-10-22: the tooling serves any product, so it lives in delurio, and QAuth uses it
  as one of its users.
- **Screen-level server-driven UI.** Rejected as the meaning of this record. It chooses components
  and fills them with data, but leaves the components' own states and rules in code.

## Worked example: removing an app's access

The account console lists the apps a person has consented to (ADR-020 §1). Each app has a control
that removes its access.

The example is written in the shape this record first proposed, `qauth-graph/0`. The real graph is
written in `delurio-graph/0`, under `graphs/flows/account/`, when the account console is graphed.

The flow:

```yaml
schema: qauth-graph/0
kind: flow
id: account.revoke-consent
context: { consent: Consent }
initial: idle
states:
  idle:
    on: { REVOKE: asking }
  asking:
    initial: fresh
    states:
      fresh: {}
      error: {} # entered after a failed attempt
    on: { CONFIRM: pending, CANCEL: idle }
  pending:
    invoke: Consent.revoke(consent) # the account policy applies
    on: { DONE: revoked, FAIL: asking.error }
  revoked:
    type: final
```

The UI:

```yaml
schema: qauth-graph/0
kind: ui
id: account.revoke-consent
flow: account.revoke-consent
nodes:
  revoke: { type: action, intent: destructive, label: 'Remove access', in: [idle], emits: REVOKE }
  ask: { type: alertdialog, in: [asking, pending] }
  title:
    type: text
    role: heading
    in: [asking, pending]
    text: "Remove {consent.client.name}'s access?"
  failure:
    type: text
    token: color.feedback.error
    in: [asking.error]
    text: 'Access was not removed. Try again.'
  confirm: { type: action, intent: confirm, label: 'Remove', in: [asking], emits: CONFIRM }
  cancel: { type: action, intent: dismiss, label: 'Cancel', in: [asking], emits: CANCEL }
  busy: { type: status, in: [pending], text: 'Removing access' }
  done: { type: status, in: [revoked], text: 'Access removed' }
edges:
  - { labelledBy: [ask, title] }
  - { triggers: [revoke, ask] }
  - { confirms: [confirm, pending] }
  - { returnsFocus: { on: CANCEL, to: revoke } }
  - { returnsFocus: { on: DONE, to: done } }
```

delurio's checker must reject each of these edits:

- `revoke` emits `CONFIRM` directly, skipping `asking`. A destructive action would reach its effect
  without a confirm state.
- The `labelledBy` edge is removed. The dialog would have no label.
- The `returnsFocus` edge for `CANCEL` is removed. Closing the dialog would leave focus nowhere.
- `pending` loses its `FAIL` transition. An asynchronous effect would have no failure path.

delurio's generated paths walk `idle → asking → idle`, `idle → asking → pending → revoked` and
`idle → asking → pending → asking.error → pending → revoked`. The state gallery shows five screens:
idle, asking, asking with an error, pending and revoked.

## Related

- [ADR-014](./014-agent-authority-tree.md) — the Authority Tree and its approval flows
- [ADR-018](./018-1-0-scope-and-stability.md) — the 1.0 scope and the beta order
- [ADR-019](./019-deployment-topology-and-trust-boundaries.md) — the API families and the
  Interaction API
- [ADR-020](./020-ui-surfaces-and-acceptance-criteria.md) — the UI surfaces, the stack and the
  acceptance criteria
- ADR-017 — first-party login and the step grammar the ceremony flows follow
- [WAI-ARIA 1.2](https://www.w3.org/TR/wai-aria-1.2/) — the roles and relations the UI layer's
  nodes and edges map to
- delurio — the separate project that owns `delurio-graph/0` and the tools that read it

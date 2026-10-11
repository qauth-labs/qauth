# ADR-021: Flows and UI as Semantic Graphs

**Status:** Accepted 2026-10-11 — records the maintainer's decisions of 2026-10-10, together with the other 1.0 records.  
**Date:** 2026-10-10  
**Authors:** QAuth Team

> Nothing below is built. This record says how QAuth describes its flows and screens: as graphs in
> the repository, checked in CI and implemented by hand. A compiler that turns the graphs into code
> would replace the hand-written part. Writing that compiler is another project's job, and 1.0
> does not wait for it.

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

Graphs are YAML documents. A versioned JSON Schema validates them; the first version is
`qauth-graph/0`. Each document names its schema version and one of three kinds: `domain`, `flow`
or `ui`.

#### Domain layer

- **Entities and fields.** Each field has a kind (text, identifier, enum, URI list, boolean, time
  and so on) and a sensitivity. A `secret` field is never projected: no screen, response or tool
  output may contain it.
- **Edges.** Typed relations between entities, such as a client's realm or a consent's user.
- **Policies.** An actor, a subject and an optional condition, followed by what the actor may read,
  write and do. The actors are the three API families of
  [ADR-019](./019-deployment-topology-and-trust-boundaries.md) Decision 7: admin, account and
  developer. An admin policy also names the scope it needs. A write that ADR-019 Decision 7 counts
  as a security operation names `admin:security`.
- **Invariants.** Named rules over fields and edges.

The part that code already declares is generated, never copied by hand:

- entities, fields and edges from the Drizzle tables;
- constraints from the Zod request schemas.

Generated files are rebuilt by a generator, and CI fails when the rebuilt output differs from what
is committed. Hand-written overlays add sensitivity, intent, policies and invariants. An overlay
that names a field the generator did not produce fails validation.

Two illustrative overlays, one for clients and one for consents. The real policies are written in
the core beta:

```yaml
schema: qauth-graph/0
kind: domain
entity: Client # generated from the oauth_clients table
fields:
  clientSecretHash: { sensitivity: secret } # never projected
policies:
  - actor: admin
    scope: admin:write
    read: [clientId, name, environment, redirectUris, enabled]
    write: [name, enabled]
    do: [tightenEnvironment] # tightening is free, ADR-019 Decision 10
  - actor: admin
    scope: admin:security # security operations, ADR-019 Decision 7
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

The schema checks structure: required fields, allowed kinds, and edges that point at nodes that
exist. A checker then analyses each graph. It rejects a graph in which:

- a destructive action reaches its effect without passing through a confirm state;
- an interactive node has no accessible name;
- a dialog has no `labelledBy` edge;
- a transition that closes a dialog has no focus target;
- a `secret` field appears in any read list, binding or output;
- a state is unreachable, or a state that is not final has no exit.

These rules come from ADR-020's criteria and from QAuth's security rules. New rules are added the
same way: written once, checked everywhere.

### 3. How the graphs are used before a compiler exists

Implementation stays conventional: the stack of ADR-020 §6 for the apps, Fastify for the server.
CI uses the graphs in four ways.

1. **Validation.** Every graph passes the schema and the checker.
2. **Model-based tests.** A generator reads each statechart and produces event sequences that cover
   every state and every transition. The implementation supplies adapters that run them:
   - Playwright for UI flows. The adapter finds elements by role and accessible name, both of which
     come from the UI graph, so the tests need no test ids.
   - HTTP for protocol flows. The adapter sends requests and checks each final state's response.
     It also checks every response body against the caller's policy: a field outside the read list,
     or any `secret` field, fails.

   A state or transition that no test reaches fails the build.

3. **Drift.** The domain generator runs, and its output must equal the committed files.
4. **State gallery.** Every state of every UI graph is rendered through the Playwright adapter and
   captured. The gallery feeds ADR-020's visual-regression criterion (criterion 8) and its
   accessibility checks (criterion 6). Reviewers look at the states, not only at the code.

QAuth builds this tooling: the schema, the checker, the test-path generator, the two adapters and
the domain generator. QAuth does not build a compiler from graphs to code or UI.

### 4. Timing

The graphs come area by area, graph first, in the beta order of
[ADR-018](./018-1-0-scope-and-stability.md) §2:

1. **The core.** The schema and the tooling come first. Then the existing core flows are graphed
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
  schema/   the JSON Schema, one file per version
  domain/   generated/ (from Drizzle and Zod) and overlays/ (hand-written)
  flows/    one statechart per flow, in core/, authority-tree/ and federation/
  ui/       one graph per screen or component, in ceremony/, account/, admin/ and developer/
```

The graphs are neither prose nor TypeScript. `docs/` holds text for readers, and `libs/` holds Nx
code projects with their own boundaries. A top-level directory gives an outside compiler a stable
path that does not depend on QAuth's build layout. The tooling is an Nx project; its name is chosen
when it is built.

### 6. The boundary with a compiler project

- QAuth publishes the schema and the graphs. 1.0 depends on no compiler.
- The schema stays outside the 1.0 stability promise until a compiler consumes it. Its version
  changes when it changes.
- Hand-written code stays the implementation. Adopting a compiler for a surface would take a new
  record.

## Consequences

### Positive

- Each flow's states, rules and error exits are written down once, and reviewers and agents read
  the same thing.
- Flow coverage becomes measurable: every state and every transition.
- ADR-020's criteria are stated per flow, before the screen exists, instead of found missing after.
- Responses are checked against policy, so a field that should not leave the server fails a test.
- An outside compiler can consume QAuth's graphs without QAuth depending on it.

### Negative

- Every flow has two artifacts, a graph and its code, until a compiler exists. A change touches
  both.
- New tooling must be built and kept up: the schema, the checker, a test generator, two adapters
  and a domain generator.
- Graphing the existing core flows costs time in the core beta.
- The schema is young and will change. Early graphs will need migrating.
- Contributors must learn the schema.

### Neutral

- The compiler is another project. QAuth neither waits for it nor promises to adopt it.
- Generated domain files are committed, so their diffs show schema changes in review.

## Alternatives considered

- **A TypeScript DSL.** Rejected. The graph would exist only by running code, and a compiler would
  be tied to TypeScript.
- **RDF or Turtle with SHACL.** Rejected for now. It has the strongest semantics, but heavy tooling,
  and few contributors or agents are fluent in it.
- **Diagrams in documents only.** Rejected. A graph that nothing checks drifts from the code.
- **Waiting for an outside compiler.** Rejected. None exists, and 1.0 cannot wait for one.
- **Screen-level server-driven UI.** Rejected as the meaning of this record. It chooses components
  and fills them with data, but leaves the components' own states and rules in code.

## Worked example: removing an app's access

The account console lists the apps a person has consented to (ADR-020 §1). Each app has a control
that removes its access.

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

The checker rejects each of these edits:

- `revoke` emits `CONFIRM` directly, skipping `asking`. A destructive action would reach its effect
  without a confirm state.
- The `labelledBy` edge is removed. The dialog would have no label.
- The `returnsFocus` edge for `CANCEL` is removed. Closing the dialog would leave focus nowhere.
- `pending` loses its `FAIL` transition. An asynchronous effect would have no failure path.

The generated tests walk `idle → asking → idle`, `idle → asking → pending → revoked` and
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
- [JSON Schema](https://json-schema.org/) — the schema language for `qauth-graph`

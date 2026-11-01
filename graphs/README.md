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

This is the target layout. `bindings/` and `kits/` do not exist yet; each arrives with the first
graph that needs it.

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

`graphs/` is also a small Nx project, `graphs` (`project.json`), whose targets only run delurio's
tool. It holds no code, so nothing can import it and it has no lint boundary.

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

delurio's open command-line tool, `@delurio/cli`, checks the graphs. It is a root development
dependency pinned to an exact version in the catalog of `pnpm-workspace.yaml`. No app or lib
depends on it, and no shipped image carries it: the auth-server image deploys with `--prod`, and the
portal and migration-runner images copy only build output. The development and security-review
images install every development dependency, this one included.

```sh
pnpm nx run graphs:check
```

runs `delurio check graphs --strict` from the repository root: every directory under `graphs/` that
holds a `flow.yaml` or a `nav.yaml` is loaded and checked. It reads graph files only, so it needs
no server, no database and no network, and Nx caches it on `graphs/**` and the pinned version. A
finding is a line `<file>:<line>:<column>: error: <message> [<rule id>]`, followed by `note:` lines
where it has a path to show, such as the events that break an assertion. The exit code is `0` when
every graph is clean, `1` when a graph cannot be loaded (such as a YAML error, an unknown state, an
unknown name in an expression, an `always` list that does not cover every context, a nested state,
or a graph written for a newer format), and `2` for a finding under `--strict` (such as a broken
assertion or a main story that cannot be walked).

To read a flow as a page, with its diagram, every way it ends and its guarantees:

```sh
pnpm exec delurio page graphs/flows/core/logout
```

writes `graphs/flows/core/logout/viz/`, which is git-ignored. CI does not run the check yet: #568
will run it on every pull request, with no account and no key.
Moving to a new delurio version, or a new format version, is one pull request that moves the pin
and the graphs together.

## Flow conventions

delurio defines the format; these are the rules QAuth adds for its own flows (ADR-021 Decision 2,
"Flow layer"). Every flow graph under `flows/` follows them.

### Flat states

`delurio-graph/0` has no nested, parallel or history states: a flow that uses them does not load.
A sub-state is a state of its own, named in camelCase like every state that is not an exit:
`askingError`, not `asking.error`. A process that runs beside another is its own flow, which this
one starts (`starts:`) or waits for (`invoke: { flow }`).

### Effects

An effect is a state with `invoke`: a domain action (`{ action: Consent.revoke }`), another flow
(`{ flow: <id> }`), or a store or service the domain graph holds no entity for
(`{ external: eventStore }`). It ends with one of two events:

- `DONE`, its success;
- `FAIL.<class>`, its failure. The class is a key under `failures.<state>`, which names the action
  (`from:`) and lists the refusal codes the class stands for. A state with one way to fail has one
  class, such as `server` for a store error that the error handler answers with 500.

Every effect has both: a `DONE` transition and at least one `FAIL.<class>` transition. A failure
the code answers like one of the successes still has its own transition, to that exit: the resume
handler of `flows/core/sign-in-page` answers a store error with the spent handle's page, so
`consumingHandle` has `FAIL.store` to `bad_request.handle_spent`.

From `flows/core/sign-in-token`, without its `title`, `description`, `say` and `source` lines:

```yaml
recordingSignIn:
  invoke: { external: eventStore }
  on:
    DONE:
      target: updatingLastLogin
    FAIL.server:
      target: server_error.store
      effect: [waitFloor]

failures:
  recordingSignIn: { from: eventStore, server: [server_error] }
```

### Protocol exits

A protocol flow, one that an HTTP endpoint answers, ends in the response a caller gets. Each
response is a final state of its own, so a test can reach every error:

- An error exit is named `<error>` or `<error>.<cause>`, where `<cause>` says why, such as
  `unauthorized_client.disabled` or `invalid_token.dpop_bound`. `<error>` is the error the caller
  reads where the response carries one: the OAuth `error`, the problem document's `code`, or the
  `error` of a `WWW-Authenticate` challenge. Some exits are named after the error they stand for
  instead: a 500 is `server_error.<cause>` though its problem code is `internal_error`; a 401 with
  a bare `Bearer` challenge is `invalid_token.<cause>`; a page or a redirect that carries no code is
  named for what it tells the caller, such as `bad_request.handle_spent` or
  `sign_in_required.no_session`. Each distinct cause has its own exit, even when two causes give
  the same error: a client cannot tell them apart, a test must.
- A success exit is named after what happened, such as `signed_out` or `code_issued`, with a cause
  when two successes answer differently (`signed_out.cookie_cleared`).
- Two exits may give the caller the same response, and sometimes must: the password sign-ins
  answer an unknown address, a wrong password, an unconfirmed account and a disabled one alike, so
  that nobody can tell which addresses have accounts. They are still four exits, because they are
  four causes, and a test that sees one answer differently names the cause that changed. What
  makes two exits one is the same response for the same cause: the same status, error and cause.

delurio's SPEC.md (§1, "Text") asks for camelCase identifiers, and delurio 0.2.0 and later enforce
it with a schema check that refuses these names. QAuth pins 0.1.1, which has no schema check, until
the names and delurio agree (#560).

A flow that a library answers rather than an endpoint, such as the sign-in engine
(`flows/core/sign-in`) or the upstream step (`flows/federation/upstream-step`), returns data to its
caller, not an HTTP response. Its exits are named in camelCase after the answer (`lockedOut`,
`failedProviderError`), and the response rules below do not apply to them.

### Responses

Every final state of a protocol flow declares the response the caller sees, as `response`, the form
delurio defines for a step with no screen (delurio's SPEC.md §2, "States"):

- `status`: the HTTP status;
- `headers`: every header the caller relies on, such as `Location`, `WWW-Authenticate`,
  `Set-Cookie`, `Retry-After` and `Cache-Control`, each as one string;
- `body`: the body's fields, or the page in words for an HTML answer.

A flow that can send the browser back to a client's `redirect_uri`, such as consent, also says on
each exit where the response sends it: `redirect: success`, `redirect: error` (to the client's
`redirect_uri` with `error`, `error_description`, `state` and `iss`) or `redirect: never` (a page
or an answer of QAuth's own), with the OAuth `code` on an error redirect and what a success
`carries`, all three on the state itself. A value that changes per request is written in
words (`the request id`); a value a client branches on is written exactly.

From `flows/core/logout`, with three of its body fields left out:

```yaml
invalid_token.missing_token:
  type: final
  title: Refuse a header that holds no single token
  source: apps/auth-server/src/app/routes/auth/logout.ts:79
  response:
    status: 401
    headers:
      WWW-Authenticate: 'Bearer realm="OAuth"'
    body:
      type: https://docs.qauth.dev/reference/problem-types/#unauthorized
      status: 401
      code: unauthorized
      trace_id: the request id
```

### Structure

Every flow graph is complete:

- every state is reachable from a starting situation;
- every transition is taken in some reachable situation;
- every state that is not final has a way out;
- every effect has a failure path (above);
- no two exits give the same response for the same cause (above).

delurio's checker does not fail on any of these yet: delurio-labs/delurio#2 adds the five rules.
Until a pinned delurio version enforces a rule, it is a review item (ADR-021 Decision 2), and every
flow graph under `flows/` meets all five.

## Writing a graph

A flow's pull request does not merge without its graph (ADR-021 Decision 4). The rules each graph
must satisfy are in ADR-021 Decision 2. The authoring guide and the definition of done come with
#570.

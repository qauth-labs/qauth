# @qauth-labs/shared-stability

The experimental-feature registry (#476, ADR-018 §4 and §5): every item that ships in QAuth but
stays outside the stability promise, its switch, the spec it implements, and the four conditions it
must meet to become stable. Pure types and data, with no I/O.

The published reference is the docs page `reference/experimental-features` (generated from this
library).

## What it holds

| Module             | What                                                                                                   |
| ------------------ | ------------------------------------------------------------------------------------------------------ |
| `lib/item.ts`      | What an item is: `ExperimentalItem`, the spec statuses and the four `PROMOTION_CONDITIONS`             |
| `lib/items.ts`     | `EXPERIMENTAL_ITEMS`, the registry: the six items of ADR-018 §4                                        |
| `lib/validate.ts`  | `validateExperimentalRegistry` and `missingEvidence`                                                   |
| `lib/evidence.ts`  | The forms of evidence: an RFC number, an issue, an `https` link or a repository path                   |
| `lib/enabled.ts`   | `enabledExperimentalItems`, the boot warning of an item that is on, and its docs link                  |
| `lib/status.ts`    | The promotion status that `scripts/experimental-status.mjs` prints, and what `--check-stable` fails on |
| `lib/docs-page.ts` | The docs page, rendered from the registry                                                              |
| `lib/fixtures.ts`  | Entries for this library's tests; not exported                                                         |

```ts
import { enabledExperimentalItems, experimentalBootWarning } from '@qauth-labs/shared-stability';

// The auth server says, per built item, how its parsed configuration turns it on.
const items = enabledExperimentalItems(env, {
  'oid4vp-1.0-base': (config) =>
    config.WALLET_FEDERATION_ENABLED && config.OID4VP_VERIFIER_PROFILE === 'oid4vp-1.0-base',
});
for (const item of items) {
  const warning = experimentalBootWarning(item);
  log.warn({ experimentalFeature: warning.id, docs: warning.docs }, warning.message);
}
```

In the auth server, `listEnabledExperimental()` (`apps/auth-server/src/config/experimental-features.ts`)
returns the items that are on, for the server-info screen of the admin console.

## Adding an item

An item is added to the registry **in the same pull request that adds its switch**. An item a
decision record names before it is built is listed with `built: false`; building it sets
`built: true` in the pull request that adds the switch.

1. Add the entry to `EXPERIMENTAL_ITEMS` in `src/lib/items.ts`: an `id`, the `adr` that decided it,
   the `switchKey` and `switchValue` (and any `requires`), the `spec` with its status, and the four
   conditions, each with no evidence until it holds.
2. For a `server` item, register its switch in the configuration key registry
   (`libs/server/config/src/lib/registry/keys/`) as `tier: 'experimental'`, or list its value in
   `experimentalValues`. The auth server's tests check both registries agree.
3. For a built `server` item, tell the auth server how its switch reads, in
   `apps/auth-server/src/config/experimental-features.ts`. The `ExperimentalSwitches` type names
   every built server item, so a missing entry fails to compile.
4. Run `pnpm nx test shared-stability -- -u` to regenerate the docs page, and commit it.

## Becoming stable

An item becomes stable in a minor release once the four conditions of ADR-018 §5 hold:

1. the spec it implements is an RFC or a Final specification;
2. it has seen external use in a beta;
3. the external audit covered it;
4. conformance tests exist for it.

Each condition lists its evidence: an RFC number (`RFC 9449`), an issue (`#476`), an `https` link,
or a path from the repository root that must exist, with an optional section
(`docs/security/audit.md#wallet-sign-in`).

```bash
node scripts/experimental-status.mjs                 # the four conditions of every item
node scripts/experimental-status.mjs --check-stable  # fails when a stable item lacks evidence
```

`validateExperimentalRegistry` refuses a stable item with a condition that has no evidence, so this
library's tests fail on it too. Setting `stable: true` is the maintainer's decision, in a minor
release.

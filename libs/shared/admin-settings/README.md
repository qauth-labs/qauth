# @qauth-labs/shared-admin-settings

The settings metadata the admin console renders (#589, ADR-020 §5 criteria 1 and 2): for each realm
policy setting, its one-sentence explanation, its docs.qauth.dev link, its default, which way is
stricter, and what a change of it needs (`write`, or `security` with an approval). Pure data and its
types, with no I/O and no workspace dependency, so an app may import it; the console cannot import
the server library the schema lives in (`scope:server`).

## What it holds

| Module                           | What                                                       |
| -------------------------------- | ---------------------------------------------------------- |
| `lib/settings.ts`                | The types: `RealmPolicySetting`, `RealmPolicySettingsFile` |
| `lib/realm-policy-settings.json` | The metadata, generated from the realm policy schema       |
| `index.ts`                       | `REALM_POLICY_SETTINGS`, the file, typed                   |

```ts
import { REALM_POLICY_SETTINGS } from '@qauth-labs/shared-admin-settings';

const minScore = REALM_POLICY_SETTINGS.settings.find(
  (setting) => setting.path === 'password.minScore'
);
```

## Generated, never edited by hand

`realm-policy-settings.json` is generated from the registry of `@qauth-labs/server-realm-policy`
(`libs/server/realm-policy/src/lib/settings.ts`), which refuses a field without a one-sentence
explanation, a docs link or a default. `pnpm nx test server-realm-policy -- -u` rewrites it, and the
library's test fails while the committed file differs. It stays plain `JSON.stringify` output, which
`.oxfmtrc.json` leaves alone.

What a change of a setting needs is decided by the server: a screen shows the preview the admin API
answers (`realms.policies.preview`) and never decides from this file whether a change is a security
change.

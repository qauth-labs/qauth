import { SECURITY_EFFECTS } from '@qauth-labs/shared-validation';

import { REALM_POLICIES_PAGE_URL } from './docs';
import { directionKind, type PolicyField } from './field';
import type { PolicyRegistry, RegisteredPolicyField } from './registry';

/**
 * The docs page `reference/realm-policies.md`, rendered from the registry
 * (#514). Generated, never edited by hand: `pnpm nx test server-realm-policy
 * -- -u` rewrites it, and `page.test.ts` fails while the committed page
 * differs.
 */

/** The page, from the repository root. */
export const REALM_POLICIES_PAGE_PATH =
  'apps/docs-site/src/content/docs/reference/realm-policies.md';

/** The date the page's hand-written prose was last checked; change it with the prose. */
export const REALM_POLICIES_PAGE_LAST_VERIFIED = '2026-10-31';

/** Where the schema lives, as the page names it. */
const SOURCE_PATH = 'libs/server/realm-policy';

/**
 * An inline code span. Its fence is longer than any run of backticks in the
 * value, so none can close it early, and a value that starts or ends with a
 * backtick or a space is padded, which the span strips again.
 */
function code(value: string): string {
  const longest = Math.max(0, ...(value.match(/`+/g) ?? []).map((run) => run.length));
  const fence = '`'.repeat(longest + 1);
  const padded = /^[\s`]|[\s`]$/.test(value) ? ` ${value} ` : value;
  return `${fence}${padded}${fence}`;
}

/**
 * A value as code in a table cell. A GFM table splits a cell on a pipe even
 * inside a code span, and no escape keeps both a backslash and a pipe as they
 * are there: `\|` hides the backslash, `\\|` ends the cell. So a value that
 * holds either is an HTML `code` element with every markup character as a
 * character reference, and any other value is a code span.
 */
const valueCode = (value: string) => (/[\\|]/.test(value) ? htmlCode(value) : code(value));

/** An HTML `code` element showing `value` as it is, with no markup character left raw. */
function htmlCode(value: string): string {
  return `<code>${value.replace(/[&<>"'\\|`*_[\]]/g, (c) => `&#${c.charCodeAt(0)};`)}</code>`;
}

/**
 * A table cell: backslashes and pipes escaped, newlines flattened. The
 * backslash goes first, or a `\|` in the text would end the cell.
 */
const tableCell = (value: string) =>
  value
    .replace(/\\/g, '\\\\')
    .replace(/\|/g, '\\|')
    .replace(/\s+/g, (run) => (run.includes('\n') ? ' ' : run));

/** A default as the table shows it. */
export function describePolicyDefault(field: PolicyField): string {
  const value: unknown = field.default;
  if (value === null) return 'none';
  if (Array.isArray(value)) {
    return value.length === 0 ? 'empty' : value.map((entry) => valueCode(String(entry))).join(', ');
  }
  return valueCode(String(value));
}

/** "Stricter when", in words. */
export function describeStricterWhen(field: PolicyField): string {
  const { direction } = field;
  switch (directionKind(direction)) {
    case 'lower-is-stricter':
      return 'lower';
    case 'higher-is-stricter':
      return 'higher';
    case 'true-is-stricter':
      return code('true');
    case 'false-is-stricter':
      return code('false');
    case 'subset-is-stricter':
      return 'fewer entries';
    case 'superset-is-stricter':
      return 'more entries';
    case 'opaque':
      return 'not ordered';
    default: {
      const order = typeof direction === 'string' ? [] : direction.order;
      return `closer to ${valueCode(order[order.length - 1])} (${order.map(valueCode).join(' < ')})`;
    }
  }
}

/** The class column: when a change needs `qauth:admin:security`, and its effects. */
export function describeClass(field: PolicyField): string {
  const effects = field.effects.map(code).join(', ');
  switch (field.securityWhen) {
    case 'never':
      return code('write');
    case 'loosening':
      return `${code('security')} when loosened (${effects}), else ${code('write')}`;
    default:
      return `${code('security')} on any change (${effects})`;
  }
}

function fieldRow(entry: RegisteredPolicyField): string {
  const { field } = entry;
  const notes: string[] = [field.doc.summary];
  if (field.secret) {
    const name = entry.segments[entry.segments.length - 1];
    notes.push(
      `Secret: write-only, never stored in the policy document, shown as ${code(`${name}Set`)}.`
    );
  }
  if (field.environmentBound) notes.push('Environment-bound.');
  if (!field.doc.link.startsWith(REALM_POLICIES_PAGE_URL)) {
    notes.push(`[More](${field.doc.link.replace('https://docs.qauth.dev', '')}).`);
  }
  return `| ${code(entry.path)} | ${describePolicyDefault(field)} | ${field.seedEnv === null ? 'none' : code(field.seedEnv)} | ${describeStricterWhen(field)} | ${describeClass(field)} | ${tableCell(notes.join(' '))} |`;
}

function groupSection(group: string, entries: readonly RegisteredPolicyField[]): string {
  return [
    `### ${code(group)}`,
    '',
    '| Field | Default | Seeded from | Stricter when | Class | Description |',
    '| --- | --- | --- | --- | --- | --- |',
    ...entries.filter((entry) => entry.segments[0] === group).map(fieldRow),
  ].join('\n');
}

/**
 * The whole page, before formatting, rendered from `registry`. The test that
 * generates the page formats it with Oxfmt and compares it with the committed
 * file.
 */
export function renderRealmPoliciesPage(registry: PolicyRegistry): string {
  const entries = registry.fields();
  const groups = registry.groups().map((group) => groupSection(group, entries));
  return `---
title: Realm policies
description: Every realm policy field with its default, the environment key that seeds it, which way is stricter and when a change is a security operation, generated from the schema in libs/server/realm-policy.
sidebar:
  order: 8
lastVerified: '${REALM_POLICIES_PAGE_LAST_VERIFIED}'
---

<!-- Generated from ${SOURCE_PATH} by its tests. Do not edit by hand: change the schema and run \`pnpm nx test server-realm-policy -- -u\`. -->

A realm's policies are its own settings: token lifetimes, the sign-in and password rules, client
registration, mail and the environment posture
([ADR-019](/reference/records/adr/019-deployment-topology-and-trust-boundaries/), Decision 10).
They are defined once, as a typed schema with a version, in \`${SOURCE_PATH}\`. The admin API's
realm representation, the realm file, the diff of two configurations and the rule that decides
which changes are security operations all come from it, and so does this page.

Today most of them are still read from the environment, for every realm. Some already live on the
realm row: the access, development access and refresh token lifetimes, the environment ceiling, the
scopes a dynamically registered client may hold, and the mail transport and sender. Nothing reads
the \`admin\` group yet. Once the policies live on the realm row, the environment only seeds a new
realm's values, and the realm row owns them from then on.

A secret field, such as the SMTP password, is never in the policies: the realm keeps its value in
its secret store, encrypted with the realm's data-at-rest key, and the representation shows only
whether it is set (\`passwordSet\`). The environment seeds the first realm's secrets once, at the
first boot that can encrypt them. A policy update that selects the \`smtp\` transport without its
host, port, user, sender address and password, or \`resend\` without its sender address and API key,
is refused, and so is one that selects \`smtp\` or changes its host, port or TLS mode without giving
the password again, or that names \`localhost\`, a non-public IP address or a cloud metadata address as
its SMTP host when the operator's \`SMTP_ALLOWED_HOSTS\` does not list it (a metadata address never).

Schema version: \`${registry.version}\`.

## How a change is classified

Each field says which way is stricter:

- **lower** or **higher**: a number, such as a lifetime or a threshold.
- \`true\` or \`false\`: a flag.
- **closer to** a value: an enum with an explicit order, from the loosest value to the strictest.
- **fewer entries**: a set of allowed values, such as scopes or trusted domains.
- **more entries**: a set of required values.
- **not ordered**: a change is neither a tightening nor a loosening.

A change is a tightening when it moves toward stricter, a loosening when it moves the other way,
and neutral when the field is not ordered. A change the schema cannot place counts as a loosening,
so an unknown direction fails closed: a value outside an enum's order, a set change that both adds
and removes an allowed value, and a direction the schema does not know.

The Class column says when a change needs \`qauth:admin:security\` instead of \`qauth:admin:write\`
([ADR-019](/reference/records/adr/019-deployment-topology-and-trust-boundaries/), Decision 7):
never, only when it loosens, or on any change, in either direction. A security change carries the
[effects](/reference/security-operations/#effects) that make it one. A change of several fields
needs what its strictest change needs.

## Defaults and seeding

- The Default column is the value of a realm whose environment does not set the key in Seeded
  from. The environment only seeds: changing a key later changes no existing realm.
- A field added within a schema version always has a default, so a stored document that predates
  it still parses.
- **Secret** fields, such as the SMTP password, are write-only. Their value is never stored in the
  policy document and never returned: the realm representation shows only whether one is set, as
  \`<name>Set\`, and the realm file never holds one. A write sets one with its value and clears it
  with \`null\`; leaving it out keeps it, and a \`<name>Set\` sent back from the representation
  changes nothing. Setting or clearing a secret is always a security operation.
- **Environment-bound** fields describe the environment a realm runs in, such as its mail transport
  or a trust list. Promoting a sandbox configuration to a live realm leaves them out unless each is
  selected ([ADR-019](/reference/records/adr/019-deployment-topology-and-trust-boundaries/),
  Decision 11).

## Groups

${groups.join('\n\n')}

## Versions

The schema version is a string. Until QAuth 1.0.0 it is \`1-rc.<M>\`, and nothing about it is
promised: a breaking change raises \`<M>\`
([ADR-018 §5](/reference/records/adr/018-1-0-scope-and-stability/)). From the release that ships
1.0.0 it is \`1\`, and inside version 1 every change is additive: a new field comes with a default,
and no field is removed. Other areas add their groups to the same schema, such as browser sessions
and sign-in methods; a group's name is taken once.

A realm keeps its policies under the schema version they were written in. A release that changes
the version reads a document of an older one through an upgrade it ships, which never reads a
field looser than stored, and its first boot stores the document under the new version. A
document of a later version, which a newer node wrote during a rolling upgrade, is read with the
older node's schema and never written by it.

The effects named above are the closed list of ${SECURITY_EFFECTS.length} effect tags on
[Security operations](/reference/security-operations/).
`;
}

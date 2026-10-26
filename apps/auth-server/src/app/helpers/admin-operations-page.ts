import {
  SECURITY_EFFECT_DESCRIPTIONS,
  SECURITY_EFFECTS,
  type SecurityEffect,
} from '@qauth-labs/shared-validation';

import type { AdminOperation, OperationRegistry } from './admin-operations';
import type { ReservedOperation } from './admin-operations-reserved';
import { ADMIN_SCOPES } from './admin-scopes';

/**
 * The docs page `reference/security-operations.md`, rendered from the
 * operation registry and the reserved table (#508). Generated, never edited by
 * hand: `pnpm nx test auth-server -- -u` rewrites it, and
 * `admin-operations-page.test.ts` fails while the committed page differs.
 */

/** The page, from the repository root. */
export const SECURITY_OPERATIONS_PAGE_PATH =
  'apps/docs-site/src/content/docs/reference/security-operations.md';

/** The date the page's hand-written prose was last checked; change it with the prose. */
export const SECURITY_OPERATIONS_PAGE_LAST_VERIFIED = '2026-10-26';

/** Where the registry lives, as the page names it. */
const REGISTRY_PATH = 'apps/auth-server/src/app/helpers/admin-operations.ts';
const RESERVED_PATH = 'apps/auth-server/src/app/helpers/admin-operations-reserved.ts';

const code = (value: string) => `\`${value}\``;
const codeList = (values: readonly string[]) =>
  values.length === 0 ? 'none' : values.map(code).join(', ');

/**
 * A table cell: backslashes and pipes escaped, newlines flattened. The
 * backslash goes first, or a `\|` in the text would end the cell.
 */
const tableCell = (value: string) =>
  value
    .replace(/\\/g, '\\\\')
    .replace(/\|/g, '\\|')
    .replace(/\s+/g, (run) => (run.includes('\n') ? ' ' : run));

/** The Effects table: each tag and what an operation with it changes. */
function effectTable(): string {
  return [
    '| Effect | An operation with it |',
    '| --- | --- |',
    ...SECURITY_EFFECTS.map(
      (effect) => `| ${code(effect)} | ${tableCell(SECURITY_EFFECT_DESCRIPTIONS[effect])} |`
    ),
  ].join('\n');
}

function operationRow(operation: AdminOperation): string {
  const decided = operation.classify === undefined ? '' : ' Decided per request.';
  return `| ${code(operation.id)} | ${operation.class} | ${codeList(operation.effects)} | ${codeList(operation.permissions)} | ${tableCell(operation.description + decided)} |`;
}

/** The Operations section: a table, or a sentence when none is registered. */
function operationSection(operations: readonly AdminOperation[]): string {
  if (operations.length === 0) {
    return 'No admin operation is registered yet.';
  }
  return [
    '| Operation | Class | Effects | Permissions | Description |',
    '| --- | --- | --- | --- | --- |',
    ...operations.map(operationRow),
  ].join('\n');
}

/** The Reserved operations section: one table per effect, an entry under each of its effects. */
function reservedSection(registry: OperationRegistry): string {
  const sections: string[] = [];
  for (const effect of SECURITY_EFFECTS) {
    const entries = registry.reserved.filter((entry) => entry.effects.includes(effect));
    if (entries.length === 0) continue;
    sections.push(
      [
        `### ${code(effect)}`,
        '',
        '| Operation | Effects | Registered | Source | Description |',
        '| --- | --- | --- | --- | --- |',
        ...entries.map(
          (entry: ReservedOperation) =>
            `| ${code(entry.id)} | ${codeList(entry.effects)} | ${registry.get(entry.id) === undefined ? 'no' : 'yes'} | ${tableCell(entry.source)} | ${tableCell(entry.description)} |`
        ),
      ].join('\n')
    );
  }
  return sections.join('\n\n');
}

/** Effects with no reserved operation, named so the page never hides a gap. */
function unreservedEffects(registry: OperationRegistry): SecurityEffect[] {
  return SECURITY_EFFECTS.filter(
    (effect) => !registry.reserved.some((entry) => entry.effects.includes(effect))
  );
}

/**
 * The whole page, before formatting, rendered from `registry` and its
 * reserved table. The test that generates the page formats it with Oxfmt and
 * compares it with the committed file.
 */
export function renderSecurityOperationsPage(registry: OperationRegistry): string {
  const gaps = unreservedEffects(registry);
  return `---
title: Security operations
description: What makes an admin operation a security operation, the effect tags, every admin operation with its class and effects, and the reserved operation ids, generated from the registry in apps/auth-server.
sidebar:
  order: 7
lastVerified: '${SECURITY_OPERATIONS_PAGE_LAST_VERIFIED}'
---

<!-- Generated from ${REGISTRY_PATH} by its tests. Do not edit by hand: change the registry and run \`pnpm nx test auth-server -- -u\`. -->

An admin API operation needs \`${ADMIN_SCOPES.security}\` because of what it does, not because of
the screen it sits on ([ADR-019](/reference/records/adr/019-deployment-topology-and-trust-boundaries/),
Decision 7). Each admin operation is defined once, in the registry in \`${REGISTRY_PATH}\`, with
its class, the effects that make it a security operation and the
[permissions](/reference/admin-permissions/) it needs. This page is generated from that registry.
No admin API route exists yet, so the rules below protect nothing today: they are in place for the
admin listener and its operations.

## Effects

${effectTable()}

The list is closed. A definition that names another value is refused, and a request whose
classification names one counts as a security operation. The tags are published on each admin
operation of the OpenAPI document as \`x-qauth-effects\`
([API conventions](/reference/api-conventions/#openapi)).

## Rules

- An operation is of class \`security\` if and only if it has at least one effect. The registry
  refuses a \`read\` or \`write\` operation with an effect, and a \`security\` operation with none.
- Its class is the strictest class among its permissions (\`read\` < \`write\` < \`security\`). So an
  operation with an effect needs a \`security\` permission, which only \`${ADMIN_SCOPES.security}\` lets a
  token use: no role reaches it through \`${ADMIN_SCOPES.write}\`.
- An operation whose request decides what it needs, such as a policy patch or a realm-file import,
  declares the strictest case (class \`security\`, every effect it may have and every permission it
  may need) and a \`classify\` function. \`classify\` is pure: it reads copies of the request's path
  parameters, query and body, and the operation's current state, and returns the class, the
  effects and the permissions that request needs, within the declaration.
- The admin pipeline classifies every request after validation and before the handler. The
  handler receives the classification and cannot lower it, and every later stage reads the same
  one.
- Fail closed: when \`classify\` throws, meets a field it has no rule for, or returns an unknown
  member, effect, class or permission, or more than the operation declares, the request needs the
  operation as declared: \`security\`, with every declared effect and permission.
- At boot, the admin listener refuses a route that names no registered operation, and one whose
  \`operationId\`, \`x-qauth-class\`, \`x-qauth-permission\`, \`x-qauth-effects\` or
  \`x-qauth-two-admin\` differs from the registry. In CI, the API conventions check fails when an
  admin operation of the OpenAPI document disagrees with the registry.

These are not security operations:

- Sending a set-up or reset link to the contact address already on the account. The link reaches
  only the person a self-service reset reaches. Copying the link is a security operation.
- Brand strings and links. They are display data, under \`${ADMIN_SCOPES.write}\`.
- Anything outside the admin API. The developer API's changes to a client the caller owns
  ([ADR-012](/reference/records/adr/012-dynamic-client-ownership/)) and the account API's changes
  to the caller's own account keep their own rules.

## Operations

${operationSection(registry.all)}

## Reserved operations

The operations below are not registered yet; other areas add them. When one is registered, the
registry refuses it unless it is a security operation that carries at least the effects listed. An
operation may carry more, and an operation whose request decides what it needs lists every effect
it may have. Each entry is listed under each of its effects. The table lives in
\`${RESERVED_PATH}\`.

${reservedSection(registry)}
${gaps.length === 0 ? '' : `\nNo operation is reserved yet for ${codeList(gaps)}.\n`}
## Stability

The effect tags and the operation ids will be part of the admin API's contract. Like every
QAuth-defined identifier, they are promised from 1.0.0 on
([ADR-018 §5](/reference/records/adr/018-1-0-scope-and-stability/)); until then a release may still
rename one, and says so in its changelog. A reserved entry may be renamed by the change that
registers its operation, but never weakened.
`;
}

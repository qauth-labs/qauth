import { headingAnchor } from './enabled';
import { evidenceKind } from './evidence';
import { type ExperimentalItem, PROMOTION_CONDITIONS } from './item';

/**
 * The docs page `reference/experimental-features.md`, rendered from the
 * registry. Generated, never edited by hand: `pnpm nx test shared-stability -- -u`
 * rewrites it, and the test fails while the committed page differs.
 */

/** The page, from the repository root. */
export const EXPERIMENTAL_FEATURES_PAGE_PATH =
  'apps/docs-site/src/content/docs/reference/experimental-features.md';

/** The date the page's hand-written prose was last checked; change it with the prose. */
export const EXPERIMENTAL_FEATURES_PAGE_LAST_VERIFIED = '2026-10-24';

/** This repository, where an issue number and a path evidence point. */
const REPOSITORY_URL = 'https://github.com/qauth-labs/qauth';

const code = (value: string) => `\`${value}\``;

/**
 * A table cell: backslashes and pipes escaped, newlines flattened. The
 * backslash goes first, or a `\|` in the text would end the cell.
 */
const tableCell = (value: string) =>
  value
    .replace(/\\/g, '\\\\')
    .replace(/\|/g, '\\|')
    .replace(/\s+/g, (run) => (run.includes('\n') ? ' ' : run));

/** The docs-site route of a decision record, from its repository path. */
function adrLink(path: string): string {
  const name = path.replace(/^docs\/adr\//, '').replace(/\.md$/, '');
  return `[ADR-${name.slice(0, 3)}](/reference/records/adr/${name}/)`;
}

/** One piece of evidence, as a link. */
export function evidenceLink(evidence: string): string {
  switch (evidenceKind(evidence)) {
    case 'rfc':
      return `[${evidence}](https://www.rfc-editor.org/rfc/rfc${evidence.slice(4)})`;
    case 'issue':
      return `[${evidence}](${REPOSITORY_URL}/issues/${evidence.slice(1)})`;
    case 'link':
      return `<${evidence}>`;
    case 'path':
      return `[${code(evidence)}](${REPOSITORY_URL}/blob/main/${evidence})`;
    default:
      return code(evidence);
  }
}

function summaryTable(items: readonly ExperimentalItem[]): string {
  const lines = ['| Item | Built | Switch | Spec |', '| --- | --- | --- | --- |'];
  for (const item of items) {
    lines.push(
      `| [${code(item.id)}](#${headingAnchor(item.id)}) | ${item.built ? 'yes' : 'no'} | ${tableCell(switchCell(item))} | ${item.spec.status} |`
    );
  }
  return lines.join('\n');
}

function switchCell(item: ExperimentalItem): string {
  if (item.switchKey === null) return 'none named yet';
  const setting =
    item.switchValue === null ? item.switchKey : `${item.switchKey}=${item.switchValue}`;
  return item.requires.length === 0
    ? code(setting)
    : `${code(setting)}, with ${item.requires.map(code).join(', ')}`;
}

function itemSection(item: ExperimentalItem): string {
  const facts = [
    `- Decided in ${adrLink(item.adr)}.`,
    `- Runs in: ${item.surface === 'server' ? 'the auth server' : 'an SDK'}.`,
    `- Switch: ${switchCell(item)}${
      item.switchKey !== null && !item.built
        ? '. A decision record names it; nothing reads it until the item is built'
        : ''
    }.`,
    `- Spec: [${item.spec.name}](${item.spec.url}), status ${code(item.spec.status)}.`,
    `- Built: ${item.built ? 'yes' : 'no'}. Stable: ${item.stable ? 'yes' : 'no'}.`,
  ];
  const conditions = ['| Condition | Holds | Evidence and notes |', '| --- | --- | --- |'];
  PROMOTION_CONDITIONS.forEach((condition, index) => {
    const entry = item.conditions[condition.id];
    const evidence = entry.evidence.map(evidenceLink).join(', ');
    const cell = [evidence, entry.note ?? ''].filter((part) => part !== '').join(' ');
    conditions.push(
      `| ${index + 1}. ${tableCell(condition.text)} | ${entry.evidence.length > 0 ? 'yes' : 'no'} | ${tableCell(cell) || '—'} |`
    );
  });
  return [
    `### ${item.id}`,
    `**${item.title}.** ${item.description}`,
    facts.join('\n'),
    conditions.join('\n'),
  ].join('\n\n');
}

/** Render the whole page. */
export function renderExperimentalFeaturesPage(items: readonly ExperimentalItem[]): string {
  const sections = [
    `---
title: Experimental features
description: Every experimental item of QAuth, its switch, and the four conditions it must meet to become stable, generated from the registry in libs/shared/stability.
sidebar:
  order: 5
lastVerified: '${EXPERIMENTAL_FEATURES_PAGE_LAST_VERIFIED}'
---`,
    `<!-- Generated from libs/shared/stability by its tests. Do not edit by hand: change the registry and run \`pnpm nx test shared-stability -- -u\`. -->`,
    `An experimental item ships, but it is outside the stability promise of QAuth 1.0
([ADR-018 §4 and §5](/reference/records/adr/018-1-0-scope-and-stability/)). This page lists every
experimental item, generated from the registry in \`libs/shared/stability\`. An item joins the
registry in the pull request that adds its switch; an item that a decision record names before it
is built is listed with **Built: no**.`,
    `## What experimental means`,
    `- The item sits behind a switch, and the switch is off by default.
- Discovery does not mention the item unless the switch is on.
- The server logs a warning at boot for each item that is on.
- The item may change in a minor release, without a deprecation window. Read the release notes
  before you upgrade a deployment that turns one on.`,
    `The boot warning is one \`warn\` line per item, with the item's id and a link to its section
below:`,
    `\`\`\`text\nExperimental feature <id> is on. It may change in a minor release, without a deprecation window. See https://docs.qauth.dev/reference/experimental-features/#<id>\n\`\`\``,
    `The configuration page marks the keys and values that switch an item on as experimental
([Configuration](/operate/configuration/)). For such a key, the warning of its item replaces the
warning of the key, so a deployment sees one line, and only once the item is on.`,
    `## Becoming stable`,
    `An item becomes stable in a minor release once four conditions hold (ADR-018 §5). Each
condition needs evidence: an RFC number, an issue, a link, or a path in the repository that exists,
such as a test file or a section of an audit report.`,
    PROMOTION_CONDITIONS.map((condition, index) => `${index + 1}. ${condition.text}`).join('\n'),
    `\`node scripts/experimental-status.mjs\` prints the four conditions of every item and names the
items that may become stable. With \`--check-stable\` it fails when an item marked stable lacks
evidence for a condition.`,
    `## Items`,
    summaryTable(items),
    ...items.map(itemSection),
  ];
  return `${sections.join('\n\n')}\n`;
}

import type { CollectionEntry } from 'astro:content';

import {
  type FlowGraph,
  GRAPH_PAGES_ROUTE,
  GRAPH_STATUS_MEANING,
  GRAPHS_TREE_BASE,
} from './graphs.ts';
import { CURRENT_RELEASE, DELIVERY_TRACKS, FEATURE_STATUS } from './status.ts';

/**
 * docs.qauth.dev in plain text for language models: /llms.txt (an index, per https://llmstxt.org)
 * and /llms-full.txt (the text of every docs page). Both are built from the docs collection and
 * the flow graphs at build time, so they cannot drift from the pages.
 */

export const SITE = 'https://docs.qauth.dev';
const REPO = 'https://github.com/qauth-labs/qauth';

const LANES = [
  ['integrate', 'Integrate', 'add QAuth-issued tokens to an app, an API or an MCP server'],
  ['operate', 'Operate', 'run and operate your own QAuth'],
  ['extend', 'Extend', 'work on QAuth itself'],
  ['portal', 'Portal & Dashboard', 'the developer portal'],
  ['reference', 'Reference', 'APIs, events, policies, status and design records'],
] as const;

const SUMMARY =
  'QAuth is an open-source (Apache 2.0), self-hosted OAuth 2.1 and OpenID Connect authorization server for apps, services and AI agents. Agents act for a person through RFC 8693 token exchange with capped scope modes, step-up before dangerous operations and a per-agent audit trail; MCP servers get the MCP authorization profile (revision 2026-07-28), with @qauth-labs/resource-guard on the resource-server side; tokens can carry a hybrid ML-DSA-65 + Ed25519 signature behind a default-off switch. QAuth is ready for production; it stays below 1.0 only because features planned for 1.0 are not finished.';

const GRAPHS_NOTE =
  "QAuth's flows are specified as delurio semantic graphs (ADR-021). None of them is approved yet: `captured` records what QAuth does today, `proposed` is a design under review. The YAML on GitHub is the source of record; each page here is a view rendered from it, and the graphs are outside QAuth's 1.0 stability promise.";

type DocsEntry = CollectionEntry<'docs'>;

export function pageUrl(entry: DocsEntry): string {
  return entry.id === 'index' ? `${SITE}/` : `${SITE}/${entry.id}/`;
}

function byLane(entries: DocsEntry[], lane: string): DocsEntry[] {
  return entries
    .filter((entry) => entry.id === lane || entry.id.startsWith(`${lane}/`))
    .sort(
      (a, b) =>
        (a.id === lane ? -1 : 0) - (b.id === lane ? -1 : 0) ||
        (a.data.sidebar?.order ?? Number.MAX_SAFE_INTEGER) -
          (b.data.sidebar?.order ?? Number.MAX_SAFE_INTEGER) ||
        a.data.title.localeCompare(b.data.title)
    );
}

function graphLine(graph: FlowGraph): string {
  const meaning = GRAPH_STATUS_MEANING[graph.status] ?? graph.status;
  return `- [${graph.title}](${SITE}${graph.pageHref}): status \`${graph.status}\` (${meaning}); source ${graph.sourceUrl}; diagram ${SITE}${graph.pageHref}flow.mmd`;
}

export function llmsTxt(entries: DocsEntry[], graphs: FlowGraph[]): string {
  const lanes = LANES.flatMap(([lane, label, about]) => [
    `## ${label}`,
    '',
    `Pages that ${about}.`,
    '',
    ...byLane(entries, lane).map((entry) =>
      entry.data.description
        ? `- [${entry.data.title}](${pageUrl(entry)}): ${entry.data.description}`
        : `- [${entry.data.title}](${pageUrl(entry)})`
    ),
    '',
  ]);
  return [
    '# QAuth documentation',
    '',
    `> ${SUMMARY}`,
    '',
    `The full text of every page below is at ${SITE}/llms-full.txt. The product site is https://qauth.dev (summary for language models: https://qauth.dev/llms.txt).`,
    '',
    ...lanes,
    '## Flow graphs',
    '',
    GRAPHS_NOTE,
    '',
    `- [All graphs](${SITE}${GRAPH_PAGES_ROUTE}/): the rendered pages, one per flow`,
    `- [About the graphs](${SITE}/reference/flow-graphs/)`,
    `- [Graph sources on GitHub](${GRAPHS_TREE_BASE})`,
    ...graphs.map(graphLine),
    '',
    '## Source',
    '',
    `- [Repository](${REPO})`,
    `- [Design records (ADRs)](${SITE}/reference/records/)`,
    `- [Releases](${REPO}/releases)`,
    `- [Security policy](${REPO}/security/policy)`,
    '',
  ].join('\n');
}

const MDX_IMPORT = /^import .+ from .+;?$/gm;

function statusAsText(): string {
  return [
    `Current release: ${CURRENT_RELEASE.version} (${CURRENT_RELEASE.stage}, ${CURRENT_RELEASE.date}).`,
    '',
    '### Delivery tracks',
    '',
    ...DELIVERY_TRACKS.map(
      (track) => `- ${track.id} ${track.name} (${track.state}): ${track.summary}`
    ),
    '',
    '### Feature status',
    '',
    ...FEATURE_STATUS.map(
      (feature) =>
        `- ${feature.feature} (${feature.state}${feature.flag ? `, flag ${feature.flag.name} default ${feature.flag.default}` : ''}): ${feature.summary}`
    ),
  ].join('\n');
}

function pageText(entry: DocsEntry): string {
  if (entry.id === 'reference/status') {
    return statusAsText();
  }
  return (entry.body ?? '').replace(MDX_IMPORT, '').trim();
}

export function llmsFullTxt(entries: DocsEntry[], graphs: FlowGraph[]): string {
  const pages = LANES.flatMap(([lane]) => byLane(entries, lane));
  const index = entries.find((entry) => entry.id === 'index');
  return [
    '# QAuth documentation, full text',
    '',
    `> ${SUMMARY}`,
    '',
    ...[...(index ? [index] : []), ...pages].flatMap((entry) => [
      `# ${entry.data.title}`,
      '',
      `URL: ${pageUrl(entry)}`,
      '',
      pageText(entry),
      '',
      '---',
      '',
    ]),
    '# Flow graphs',
    '',
    GRAPHS_NOTE,
    '',
    ...graphs.map(graphLine),
    '',
  ].join('\n');
}

export function robotsTxt(): string {
  const aiAgents = [
    'GPTBot',
    'OAI-SearchBot',
    'ChatGPT-User',
    'ClaudeBot',
    'Claude-SearchBot',
    'Claude-User',
    'PerplexityBot',
    'Perplexity-User',
    'Google-Extended',
    'Applebot-Extended',
    'CCBot',
  ];
  return [
    '# Every crawler is welcome, AI crawlers and assistants included.',
    `# A plain-text index for language models: ${SITE}/llms.txt (full text: ${SITE}/llms-full.txt)`,
    '',
    'User-agent: *',
    'Allow: /',
    '',
    ...aiAgents.flatMap((agent) => [`User-agent: ${agent}`, 'Allow: /', '']),
    `Sitemap: ${SITE}/sitemap-index.xml`,
    '',
  ].join('\n');
}

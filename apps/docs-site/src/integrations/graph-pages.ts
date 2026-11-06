import { execFile } from 'node:child_process';
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import type { AstroIntegration } from 'astro';

import {
  type FlowGraph,
  GRAPH_PAGES_ROUTE,
  GRAPH_STATUS_MEANING,
  GRAPHS_TREE_BASE,
  loadFlowGraphs,
} from '../lib/graphs.ts';
import { resolveRepoRoot } from '../lib/repo-root.ts';

const run = promisify(execFile);

const BODY_OPEN = '<body>';

/**
 * delurio explores each graph's whole state space to render its page. Measured on 2026-11-06,
 * most graphs take a few seconds and a few hundred megabytes, but `flows/core/sign-in` takes about
 * 50 seconds and 2.9 GB, and `flows/core/consent-page` 1.3 GB. The graphs are therefore rendered
 * one at a time, so the peak is the largest graph rather than a sum, and delurio gets an explicit
 * heap ceiling instead of whatever default the build machine's memory would give Node.
 */
const DELURIO_HEAP_MB = 4096;

const BANNER_STYLE =
  'margin:0;padding:12px 16px;border-bottom:1px solid var(--line,#d6d3d1);background:var(--accent-bg,#eef3ff);color:var(--ink,#1c1917);font:14px/1.5 system-ui,sans-serif';

const HTML_ESCAPES: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
};
const HTML_SPECIAL = /[&<>"']/g;

function escapeHtml(text: string): string {
  return text.replace(HTML_SPECIAL, (char) => HTML_ESCAPES[char] ?? char);
}

function statusText(graph: FlowGraph): string {
  return GRAPH_STATUS_MEANING[graph.status] ?? graph.status;
}

function flowBanner(graph: FlowGraph): string {
  return [
    `<aside aria-label="About this page" style="${BANNER_STYLE}">`,
    `<strong>Status: ${escapeHtml(graph.status)}</strong> (${escapeHtml(statusText(graph))}). `,
    "This page is rendered by delurio from the graph's YAML, which stays the source of record: ",
    `<a href="${graph.sourceUrl}">graphs/${graph.id} on GitHub</a>. `,
    `<a href="${GRAPH_PAGES_ROUTE}/">All graphs</a> · <a href="/reference/flow-graphs/">About the graphs</a> · <a href="/">QAuth documentation</a>`,
    '</aside>',
  ].join('');
}

/** The /graphs/ index: every graph with its status, its page and its source. */
function indexPage(graphs: FlowGraph[]): string {
  const rows = graphs
    .map(
      (graph) =>
        `<tr><td><a href="${GRAPH_PAGES_ROUTE}/${graph.id}/">${escapeHtml(graph.title)}</a></td>` +
        `<td><code>${escapeHtml(graph.status)}</code><br><small>${escapeHtml(statusText(graph))}</small></td>` +
        `<td><a href="${graph.sourceUrl}"><code>graphs/${graph.id}</code></a></td></tr>`
    )
    .join('\n');
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>QAuth flow graphs</title>
<meta name="description" content="QAuth's flows as delurio semantic graphs. None is approved yet; each links its YAML on GitHub.">
<style>
body{margin:0;background:#fafaf9;color:#1c1917;font:16px/1.55 system-ui,sans-serif}
main{max-width:1000px;margin:0 auto;padding:28px 16px 80px}
table{border-collapse:collapse;width:100%}th,td{text-align:left;vertical-align:top;padding:10px 8px;border-bottom:1px solid #d6d3d1}
a{color:#1d4ed8}code{font:13px ui-monospace,Menlo,Consolas,monospace}small{color:#6b6560}
@media (prefers-color-scheme:dark){body{background:#161513;color:#f2efec}a{color:#8fb0ff}th,td{border-color:#44403c}small{color:#a8a29e}}
</style></head><body>
<aside aria-label="About these pages" style="${BANNER_STYLE}"><strong>None of these graphs is approved yet.</strong> A graph marked <code>captured</code> records what QAuth does today; one marked <code>proposed</code> is a design under review. Each page is rendered by delurio from YAML on GitHub, which stays the source of record: <a href="${GRAPHS_TREE_BASE}">graphs/ on GitHub</a>. <a href="/reference/flow-graphs/">About the graphs</a> · <a href="/">QAuth documentation</a></aside>
<main><h1>QAuth flow graphs</h1>
<table><thead><tr><th>Flow</th><th>Status</th><th>Source of record</th></tr></thead><tbody>
${rows}
</tbody></table></main></body></html>
`;
}

/**
 * Netlify serves `.mmd` under an unrelated media type, so a language model fetching a graph's
 * Mermaid source would not read it as text. One `_headers` rule per diagram fixes that; a
 * `_headers` file copied from public/ is kept and extended, not replaced.
 */
function writeDiagramHeaders(siteDir: string, graphs: FlowGraph[]): void {
  const file = join(siteDir, '_headers');
  const existing = existsSync(file) ? `${readFileSync(file, 'utf8').trimEnd()}\n\n` : '';
  const rules = graphs
    .map(
      (graph) =>
        `${GRAPH_PAGES_ROUTE}/${graph.id}/flow.mmd\n  Content-Type: text/plain; charset=utf-8`
    )
    .join('\n');
  writeFileSync(file, `${existing}${rules}\n`);
}

function injectAfterBody(file: string, html: string): void {
  const page = readFileSync(file, 'utf8');
  if (!page.includes(BODY_OPEN)) {
    throw new Error(`graph-pages: ${file} has no ${BODY_OPEN}; delurio's page layout changed`);
  }
  writeFileSync(file, page.replace(BODY_OPEN, `${BODY_OPEN}${html}`));
}

async function renderAll(
  delurio: string,
  repoRoot: string,
  graphs: FlowGraph[],
  out: string
): Promise<void> {
  const env = {
    ...process.env,
    NODE_OPTIONS:
      `${process.env.NODE_OPTIONS ?? ''} --max-old-space-size=${DELURIO_HEAP_MB}`.trim(),
  };
  for (const graph of graphs) {
    await run(delurio, ['page', `graphs/${graph.id}`, '--out', join(out, graph.id)], {
      cwd: repoRoot,
      env,
    });
  }
}

/**
 * Publishes the rendered flow graphs at /graphs/ after every static build (ADR-021). delurio writes
 * each page (`delurio page graphs/<flow>`); this only adds a banner that names the graph's status and
 * links its YAML on GitHub, since no graph is approved and the YAML stays the source of record, and
 * writes the index that lists them.
 *
 * A build that cannot run delurio fails instead of publishing a site without the pages.
 */
export function graphPages(): AstroIntegration {
  return {
    name: 'qauth-graph-pages',
    hooks: {
      'astro:build:done': async ({ dir, logger }) => {
        const repoRoot = resolveRepoRoot();
        const delurio = join(repoRoot, 'node_modules', '.bin', 'delurio');
        if (!existsSync(delurio)) {
          throw new Error(
            'graph-pages: @delurio/cli is not installed; run pnpm install at the repository root'
          );
        }
        const graphs = loadFlowGraphs(repoRoot);
        const out = mkdtempSync(join(tmpdir(), 'qauth-graph-pages-'));
        try {
          await renderAll(delurio, repoRoot, graphs, out);
          for (const graph of graphs) {
            injectAfterBody(join(out, graph.id, 'index.html'), flowBanner(graph));
          }
          writeFileSync(join(out, 'index.html'), indexPage(graphs));
          const siteDir = fileURLToPath(dir);
          cpSync(out, join(siteDir, GRAPH_PAGES_ROUTE.slice(1)), { recursive: true });
          writeDiagramHeaders(siteDir, graphs);
          logger.info(`published ${graphs.length} flow graph pages at ${GRAPH_PAGES_ROUTE}/`);
        } finally {
          rmSync(out, { recursive: true, force: true });
        }
      },
    },
  };
}

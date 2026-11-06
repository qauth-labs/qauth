import { execFileSync } from 'node:child_process';
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import type { AstroIntegration } from 'astro';

import {
  type FlowGraph,
  GRAPH_PAGES_ROUTE,
  GRAPH_STATUS_MEANING,
  GRAPHS_TREE_BASE,
  loadFlowGraphs,
} from '../lib/graphs.ts';
import { resolveRepoRoot } from '../lib/repo-root.ts';

const BODY_OPEN = '<body>';

const BANNER_STYLE =
  'margin:0;padding:12px 16px;border-bottom:1px solid var(--line,#d6d3d1);background:var(--accent-bg,#eef3ff);color:var(--ink,#1c1917);font:14px/1.5 system-ui,sans-serif';

function flowBanner(graph: FlowGraph): string {
  const meaning = GRAPH_STATUS_MEANING[graph.status] ?? graph.status;
  return [
    `<aside aria-label="About this page" style="${BANNER_STYLE}">`,
    `<strong>Status: ${graph.status}</strong> (${meaning}). `,
    `This page is rendered by delurio from the graph's YAML, which stays the source of record: `,
    `<a href="${graph.sourceUrl}">graphs/${graph.id} on GitHub</a>. `,
    `<a href="${GRAPH_PAGES_ROUTE}/">All graphs</a> · <a href="/reference/flow-graphs/">About the graphs</a> · <a href="/">QAuth documentation</a>`,
    '</aside>',
  ].join('');
}

function indexBanner(): string {
  return [
    `<aside aria-label="About these pages" style="${BANNER_STYLE}">`,
    '<strong>None of these graphs is approved yet.</strong> ',
    'A graph marked <code>captured</code> records what QAuth does today; one marked <code>proposed</code> is a design under review. ',
    `Each page is rendered by delurio from YAML on GitHub, which stays the source of record: <a href="${GRAPHS_TREE_BASE}">graphs/ on GitHub</a>. `,
    '<a href="/reference/flow-graphs/">About the graphs</a> · <a href="/">QAuth documentation</a>',
    '</aside>',
  ].join('');
}

function injectAfterBody(file: string, html: string): void {
  const page = readFileSync(file, 'utf8');
  if (!page.includes(BODY_OPEN)) {
    throw new Error(`graph-pages: ${file} has no ${BODY_OPEN}; delurio's page layout changed`);
  }
  writeFileSync(file, page.replace(BODY_OPEN, `${BODY_OPEN}${html}`));
}

/**
 * Publishes the rendered flow graphs at /graphs/ after every static build (ADR-021). delurio writes
 * the pages (`delurio page graphs`); this only adds a banner that names each graph's status and links
 * its YAML on GitHub, since no graph is approved and the YAML stays the source of record.
 *
 * A build that cannot run delurio fails instead of publishing a site without the pages.
 */
export function graphPages(): AstroIntegration {
  return {
    name: 'qauth-graph-pages',
    hooks: {
      'astro:build:done': ({ dir, logger }) => {
        const repoRoot = resolveRepoRoot();
        const delurio = join(repoRoot, 'node_modules', '.bin', 'delurio');
        if (!existsSync(delurio)) {
          throw new Error(
            'graph-pages: @delurio/cli is not installed; run pnpm install at the repository root'
          );
        }
        const out = mkdtempSync(join(tmpdir(), 'qauth-graph-pages-'));
        try {
          execFileSync(delurio, ['page', 'graphs', '--out', out], { cwd: repoRoot, stdio: 'pipe' });
          const graphs = loadFlowGraphs(repoRoot);
          for (const graph of graphs) {
            injectAfterBody(join(out, graph.id, 'index.html'), flowBanner(graph));
          }
          injectAfterBody(join(out, 'index.html'), indexBanner());
          cpSync(out, join(fileURLToPath(dir), GRAPH_PAGES_ROUTE.slice(1)), { recursive: true });
          logger.info(`published ${graphs.length} flow graph pages at ${GRAPH_PAGES_ROUTE}/`);
        } finally {
          rmSync(out, { recursive: true, force: true });
        }
      },
    },
  };
}

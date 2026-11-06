import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join, relative, sep } from 'node:path';

/**
 * The flow graphs under `graphs/flows/` (ADR-021), as the docs site lists and publishes them.
 *
 * This reads two top-level scalars of each `flow.yaml`, `title` and `status`, and nothing else.
 * It is not graph tooling: delurio owns the format and every tool that reads it (ADR-021,
 * amendment of 2026-10-22), and the pages themselves are written by `delurio page`. A graph's
 * YAML on GitHub stays its source of record; the rendered page is a view of it.
 */

export const GRAPHS_TREE_BASE = 'https://github.com/qauth-labs/qauth/tree/main/graphs';

/** Where the rendered pages are served on docs.qauth.dev. */
export const GRAPH_PAGES_ROUTE = '/graphs';

/**
 * What each status means. `approved` is listed so a graph can reach it; today no graph has it.
 * A status outside this table fails `graphs.test.ts`, so a new one is described here first.
 */
export const GRAPH_STATUS_MEANING: Record<string, string> = {
  captured: 'records what QAuth does today; not approved',
  proposed: 'a design under review; not approved',
  approved: 'approved',
};

export interface FlowGraph {
  /** The graph's directory relative to `graphs/`, such as `flows/core/logout`. */
  id: string;
  title: string;
  status: string;
  /** The rendered page on this site. */
  pageHref: string;
  /** The directory on GitHub that holds the graph's YAML. */
  sourceUrl: string;
}

const TOP_LEVEL_SCALAR = /^(title|status):[ \t]*(.+?)[ \t]*$/gm;

function unquote(value: string): string {
  const quote = value[0];
  if ((quote === "'" || quote === '"') && value.endsWith(quote) && value.length >= 2) {
    const inner = value.slice(1, -1);
    return quote === "'" ? inner.replaceAll("''", "'") : inner.replaceAll('\\"', '"');
  }
  return value;
}

/** `title` and `status` of a flow.yaml, read from its top-level lines only. */
export function readFlowHeader(yaml: string): { title: string; status: string } {
  const found: Record<string, string> = {};
  for (const match of yaml.matchAll(TOP_LEVEL_SCALAR)) {
    const [, key, value] = match;
    if (key && value && !(key in found)) {
      found[key] = unquote(value);
    }
  }
  return { title: found.title ?? '', status: found.status ?? '' };
}

function flowDirectories(dir: string): string[] {
  if (!existsSync(dir)) {
    return [];
  }
  const entries = readdirSync(dir, { withFileTypes: true });
  const here = entries.some((entry) => entry.isFile() && entry.name === 'flow.yaml') ? [dir] : [];
  return [
    ...here,
    ...entries
      .filter((entry) => entry.isDirectory() && entry.name !== 'viz')
      .flatMap((entry) => flowDirectories(join(dir, entry.name))),
  ];
}

/** Every flow graph under `<repoRoot>/graphs/flows`, sorted by id. */
export function loadFlowGraphs(repoRoot: string): FlowGraph[] {
  const graphsRoot = join(repoRoot, 'graphs');
  return flowDirectories(join(graphsRoot, 'flows'))
    .map((dir) => {
      const id = relative(graphsRoot, dir).split(sep).join('/');
      const { title, status } = readFlowHeader(readFileSync(join(dir, 'flow.yaml'), 'utf8'));
      return {
        id,
        title,
        status,
        pageHref: `${GRAPH_PAGES_ROUTE}/${id}/`,
        sourceUrl: `${GRAPHS_TREE_BASE}/${id}`,
      };
    })
    .sort((a, b) => a.id.localeCompare(b.id));
}

/**
 * The docs site lists and publishes every flow graph with its status (src/lib/graphs.ts, ADR-021).
 * These cases keep that list honest against graphs/ on disk.
 */
import { existsSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { GRAPH_STATUS_MEANING, GRAPHS_TREE_BASE, loadFlowGraphs, readFlowHeader } from './graphs';
import { resolveRepoRoot } from './repo-root';

const repoRoot = resolveRepoRoot();
const graphs = loadFlowGraphs(repoRoot);

describe('readFlowHeader', () => {
  it('reads plain and quoted top-level title and status, and ignores nested keys', () => {
    const yaml = [
      'schema: delurio-graph/0',
      'kind: flow',
      "title: 'Sign in, or sign up'",
      'status: proposed',
      'states:',
      '  start:',
      '    title: not this one',
      '    status: 401',
    ].join('\n');
    expect(readFlowHeader(yaml)).toEqual({ title: 'Sign in, or sign up', status: 'proposed' });
  });
});

describe('the flow graphs under graphs/flows', () => {
  it('finds every directory that holds a flow.yaml', () => {
    expect(graphs.length).toBeGreaterThan(0);
    for (const graph of graphs) {
      expect(existsSync(join(repoRoot, 'graphs', graph.id, 'flow.yaml')), graph.id).toBe(true);
    }
  });

  it('gives every graph a title and a status the docs can describe', () => {
    for (const graph of graphs) {
      expect(graph.title, graph.id).not.toBe('');
      expect(Object.keys(GRAPH_STATUS_MEANING), `${graph.id} has status ${graph.status}`).toContain(
        graph.status
      );
    }
  });

  it('links each graph to its page and to its directory on GitHub', () => {
    for (const graph of graphs) {
      expect(graph.pageHref).toBe(`/graphs/${graph.id}/`);
      expect(graph.sourceUrl).toBe(`${GRAPHS_TREE_BASE}/${graph.id}`);
    }
  });
});

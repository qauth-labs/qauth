import type { APIRoute } from 'astro';
import { getCollection } from 'astro:content';

import { loadFlowGraphs } from '../lib/graphs.ts';
import { llmsTxt } from '../lib/llms.ts';
import { resolveRepoRoot } from '../lib/repo-root.ts';

export const prerender = true;

export const GET: APIRoute = async () =>
  new Response(llmsTxt(await getCollection('docs'), loadFlowGraphs(resolveRepoRoot())), {
    headers: { 'Content-Type': 'text/plain; charset=utf-8' },
  });

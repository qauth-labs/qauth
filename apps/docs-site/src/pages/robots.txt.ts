import type { APIRoute } from 'astro';

import { robotsTxt } from '../lib/llms.ts';

export const prerender = true;

export const GET: APIRoute = () =>
  new Response(robotsTxt(), { headers: { 'Content-Type': 'text/plain; charset=utf-8' } });

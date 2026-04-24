/**
 * Integration test for the @fastify/formbody registration in `app.ts`.
 *
 * Without this plugin, Fastify's default content-type parser only handles
 * `application/json` — and RFC-compliant OAuth clients (fastmcp's
 * IntrospectionTokenVerifier, any stock OAuth library) send
 * `application/x-www-form-urlencoded` per RFC 6749 §3.2 and RFC 7662
 * §2.1. The server returned 415 Unsupported Media Type until this plugin
 * was registered.
 */
import formbody from '@fastify/formbody';
import Fastify from 'fastify';
import { describe, expect, it } from 'vitest';

describe('@fastify/formbody registration', () => {
  it('decodes application/x-www-form-urlencoded request bodies', async () => {
    const app = Fastify();
    await app.register(formbody);
    app.post('/echo', async (req) => req.body);

    const response = await app.inject({
      method: 'POST',
      url: '/echo',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      payload: 'token=abc&client_id=x&client_secret=y',
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      token: 'abc',
      client_id: 'x',
      client_secret: 'y',
    });

    await app.close();
  });

  it('preserves json parsing when content-type is application/json', async () => {
    const app = Fastify();
    await app.register(formbody);
    app.post('/echo', async (req) => req.body);

    const response = await app.inject({
      method: 'POST',
      url: '/echo',
      headers: { 'content-type': 'application/json' },
      payload: JSON.stringify({ token: 'abc', client_id: 'x' }),
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ token: 'abc', client_id: 'x' });

    await app.close();
  });
});

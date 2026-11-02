/**
 * Integration test for the @fastify/formbody registration in `app.ts`.
 *
 * Without this plugin, Fastify's default content-type parser only handles
 * `application/json` — and RFC-compliant OAuth clients (fastmcp's
 * IntrospectionTokenVerifier, any stock OAuth library) send
 * `application/x-www-form-urlencoded` per RFC 6749 §3.2 and RFC 7662
 * §2.1. The server returned 415 Unsupported Media Type until this plugin
 * was registered.
 *
 * The parsing facts the token, revocation, introspection and authorization
 * endpoints depend on are pinned here too, so a parser change surfaces on the
 * plugin's next upgrade (#798): a repeated parameter becomes an array of every
 * value in the order sent, which RFC 8707 §2 `resource` and RFC 8693 §2.1
 * `audience` rely on, and which the token body schema refuses for a parameter
 * RFC 6749 §3.2 says must not repeat (pinned on the assembled app in
 * `error-handler-wiring.test.ts`).
 */
import formbody from '@fastify/formbody';
import Fastify from 'fastify';
import { describe, expect, it } from 'vitest';

/**
 * The body the plugin hands a route for `payload`, read inside the handler.
 * The route answers a constant rather than the body, so nothing a client sent
 * is reflected.
 */
async function parsedFormBody(contentType: string, payload: string): Promise<unknown> {
  const app = Fastify();
  await app.register(formbody);
  let parsed: unknown;
  app.post('/parse', async (req) => {
    parsed = req.body;
    return { parsed: true };
  });

  const response = await app.inject({
    method: 'POST',
    url: '/parse',
    headers: { 'content-type': contentType },
    payload,
  });
  await app.close();

  expect(response.statusCode).toBe(200);
  return parsed;
}

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

  it('parses a repeated parameter into an array of every value, in the order sent', async () => {
    const body = await parsedFormBody(
      'application/x-www-form-urlencoded',
      'grant_type=client_credentials&grant_type=authorization_code' +
        '&resource=https%3A%2F%2Fb.example&resource=https%3A%2F%2Fa.example&scope=read'
    );

    expect(body).toEqual({
      grant_type: ['client_credentials', 'authorization_code'],
      resource: ['https://b.example', 'https://a.example'],
      scope: 'read',
    });
  });

  it('parses a body sent with a charset parameter, decoding percent-escapes as UTF-8', async () => {
    const body = await parsedFormBody(
      'application/x-www-form-urlencoded; charset=UTF-8',
      'client_id=%C3%A7lient+one&state=a%2Bb'
    );

    expect(body).toEqual({ client_id: '\u00e7lient one', state: 'a+b' });
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

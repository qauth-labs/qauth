import Fastify, { type FastifyReply } from 'fastify';
import { describe, expect, it, vi } from 'vitest';

vi.mock('../../config/env', () => ({
  env: { SESSION_COOKIE_SECURE: true, INTERACTION_TTL: 1800 },
}));

import {
  clearFlowCookie,
  FLOW_COOKIE_MAX_BINDINGS,
  flowBindingOf,
  matchFlowSecret,
  mintFlowSecret,
  nextFlowSecrets,
  parseFlowSecrets,
  readFlowSecrets,
  setFlowCookie,
} from './flow-cookie';

/**
 * THE FLOW COOKIE (#592, ADR-019 Decision 6): `__Host-qauth_flow`, which binds
 * an interaction of the Interaction API to the browser that started it.
 */

/** The `Set-Cookie` header one call writes, as a browser would receive it. */
async function setCookieOf(write: (reply: FastifyReply) => void): Promise<string> {
  const app = Fastify();
  app.get('/', async (_request, reply) => {
    write(reply);
    return 'ok';
  });
  const response = await app.inject({ method: 'GET', url: '/' });
  await app.close();
  const header = response.headers['set-cookie'];
  if (typeof header !== 'string') throw new Error('expected one Set-Cookie header');
  return header;
}

/** A cookie's attributes, by lower-case name, and its name and value. */
function parseSetCookie(header: string) {
  const [pair, ...attributes] = header.split(';').map((part) => part.trim());
  const eq = pair.indexOf('=');
  return {
    name: pair.slice(0, eq),
    value: pair.slice(eq + 1),
    attributes: new Map(
      attributes.map((attribute) => {
        const at = attribute.indexOf('=');
        return at === -1
          ? [attribute.toLowerCase(), '']
          : [attribute.slice(0, at).toLowerCase(), attribute.slice(at + 1)];
      })
    ),
  };
}

describe('the flow cookie (#592)', () => {
  it('is __Host-qauth_flow with HttpOnly, Secure, SameSite=Lax, Path=/ and no Domain', async () => {
    const secret = mintFlowSecret();
    const cookie = parseSetCookie(
      await setCookieOf((reply) => setFlowCookie(reply, [secret], 1800))
    );

    expect(cookie.name).toBe('__Host-qauth_flow');
    expect(cookie.value).toBe(secret);
    expect(cookie.attributes.has('httponly')).toBe(true);
    expect(cookie.attributes.has('secure')).toBe(true);
    expect(cookie.attributes.get('samesite')).toBe('Lax');
    expect(cookie.attributes.get('path')).toBe('/');
    expect(cookie.attributes.has('domain')).toBe(false);
    expect(cookie.attributes.get('max-age')).toBe('1800');
    // Exactly these attributes, so a later edit cannot add a Domain or drop one unseen.
    expect([...cookie.attributes.keys()].sort()).toEqual(
      ['httponly', 'max-age', 'path', 'samesite', 'secure'].sort()
    );
  });

  it('is cleared with the same attributes and Max-Age=0, also when no binding is left', async () => {
    for (const write of [
      (reply: FastifyReply) => clearFlowCookie(reply),
      (reply: FastifyReply) => setFlowCookie(reply, [], 1800),
    ]) {
      const cookie = parseSetCookie(await setCookieOf(write));
      expect(cookie.name).toBe('__Host-qauth_flow');
      expect(cookie.value).toBe('');
      expect(cookie.attributes.get('max-age')).toBe('0');
      expect(cookie.attributes.has('secure')).toBe(true);
      expect(cookie.attributes.has('httponly')).toBe(true);
      expect(cookie.attributes.get('samesite')).toBe('Lax');
      expect(cookie.attributes.get('path')).toBe('/');
      expect(cookie.attributes.has('domain')).toBe(false);
    }
  });

  it('holds a random 32-byte secret per interaction; the record keeps only its SHA-256', () => {
    const secret = mintFlowSecret();
    expect(secret).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(mintFlowSecret()).not.toBe(secret);
    const binding = flowBindingOf(secret);
    expect(binding).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(binding).not.toBe(secret);
  });

  it('matches a binding only with the secret it was made from', () => {
    const [a, b, c] = [mintFlowSecret(), mintFlowSecret(), mintFlowSecret()];
    expect(matchFlowSecret(flowBindingOf(b), [a, b, c])).toBe(b);
    expect(matchFlowSecret(flowBindingOf(b), [a, c])).toBeUndefined();
    expect(matchFlowSecret(flowBindingOf(b), [])).toBeUndefined();
  });

  it('keeps one secret per ceremony of the browser, newest last, at most the cap', () => {
    const secrets = Array.from({ length: FLOW_COOKIE_MAX_BINDINGS + 2 }, () => mintFlowSecret());
    let held: string[] = [];
    for (const secret of secrets) held = nextFlowSecrets(held, { add: secret });
    expect(held).toEqual(secrets.slice(-FLOW_COOKIE_MAX_BINDINGS));

    const [first, second] = held;
    const replacement = mintFlowSecret();
    expect(nextFlowSecrets(held, { remove: first, add: replacement })).toEqual([
      ...held.slice(1),
      replacement,
    ]);
    expect(nextFlowSecrets(held, { remove: second })).not.toContain(second);
  });

  it('reads only well-formed secrets, once each, and an unreadable cookie as none', () => {
    const [a, b] = [mintFlowSecret(), mintFlowSecret()];
    expect(parseFlowSecrets(`${a}.${b}`)).toEqual([a, b]);
    expect(parseFlowSecrets(`${a}.junk.${a}..${b}`)).toEqual([a, b]);
    expect(parseFlowSecrets('')).toEqual([]);
    expect(parseFlowSecrets(undefined)).toEqual([]);

    const request = (cookie: string) => ({ headers: { cookie } }) as never;
    expect(readFlowSecrets(request(`__Host-qauth_flow=${a}`))).toEqual([a]);
    // A malformed escape is a cookie no answer of QAuth set: none, never a 500.
    expect(readFlowSecrets(request('__Host-qauth_flow=%zz'))).toEqual([]);
    // Only the __Host- cookie counts.
    expect(readFlowSecrets(request(`qauth_flow=${a}`))).toEqual([]);
  });
});

/**
 * Integration test for the security-headers plugin (issue #113).
 *
 * Verifies the strict, nonce-based Content-Security-Policy plus HSTS,
 * X-Frame-Options, X-Content-Type-Options and Referrer-Policy are applied to
 * every response, the per-request style nonce is fresh, and the /docs (Swagger
 * UI) prefix receives the relaxed CSP instead.
 */
import Fastify, { type FastifyInstance } from 'fastify';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../config/env', () => ({
  env: {
    SECURITY_HSTS_ENABLED: true,
    SECURITY_HSTS_MAX_AGE: 31536000,
  },
}));

import { markRelaxedCsp, securityHeadersPlugin } from './security-headers';

async function buildApp(): Promise<FastifyInstance> {
  const app = Fastify();
  await app.register(securityHeadersPlugin);
  app.get('/page', async (_req, reply) => {
    reply.header('content-type', 'text/html');
    return `<style nonce="${reply.cspNonce.style}">body{}</style>`;
  });
  // ADR-008 §5 (#197): stand-in for a development-profile consent screen that
  // requests the relaxed CSP via markRelaxedCsp.
  app.get('/dev-consent', async (_req, reply) => {
    markRelaxedCsp(reply);
    reply.header('content-type', 'text/html');
    return '<style>body{}</style>';
  });
  // Stand-in for Swagger UI's served HTML at the /docs prefix.
  app.get('/docs', async (_req, reply) => {
    reply.header('content-type', 'text/html');
    return '<html>swagger</html>';
  });
  app.get('/docs/static/index.js', async () => 'console.log(1)');
  await app.ready();
  return app;
}

describe('security-headers plugin (#113)', () => {
  let app: FastifyInstance;

  beforeEach(async () => {
    app = await buildApp();
  });

  afterEach(async () => {
    await app.close();
  });

  it('sets a strict, nonce-based CSP on normal routes', async () => {
    const res = await app.inject({ method: 'GET', url: '/page' });
    const csp = res.headers['content-security-policy'] as string;
    expect(csp).toBeTruthy();
    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain("object-src 'none'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("base-uri 'self'");
    expect(csp).toContain("form-action 'self'");
    // No inline-script escape hatch.
    expect(csp).not.toContain("'unsafe-inline'");
    // style-src and script-src carry a generated nonce.
    expect(csp).toMatch(/style-src [^;]*'nonce-/);
    expect(csp).toMatch(/script-src [^;]*'nonce-/);
  });

  it('emits a fresh CSP nonce per request and the page embeds it', async () => {
    const res1 = await app.inject({ method: 'GET', url: '/page' });
    const res2 = await app.inject({ method: 'GET', url: '/page' });

    const nonce1 = /style-src [^;]*'nonce-([^']+)'/.exec(
      res1.headers['content-security-policy'] as string
    )?.[1];
    const nonce2 = /style-src [^;]*'nonce-([^']+)'/.exec(
      res2.headers['content-security-policy'] as string
    )?.[1];

    expect(nonce1).toBeTruthy();
    expect(nonce2).toBeTruthy();
    expect(nonce1).not.toBe(nonce2);
    // The rendered <style nonce> matches the header nonce for this same request.
    expect(res1.body).toContain(`nonce="${nonce1}"`);
  });

  it('sets HSTS with one-year max-age, includeSubDomains and preload', async () => {
    const res = await app.inject({ method: 'GET', url: '/page' });
    const hsts = res.headers['strict-transport-security'] as string;
    expect(hsts).toContain('max-age=31536000');
    expect(hsts).toContain('includeSubDomains');
    expect(hsts).toContain('preload');
  });

  it('sets X-Frame-Options, X-Content-Type-Options and Referrer-Policy', async () => {
    const res = await app.inject({ method: 'GET', url: '/page' });
    expect(res.headers['x-frame-options']).toBe('DENY');
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['referrer-policy']).toBe('no-referrer');
  });

  it('serves a relaxed CSP on the /docs (Swagger UI) prefix', async () => {
    const root = await app.inject({ method: 'GET', url: '/docs' });
    const asset = await app.inject({ method: 'GET', url: '/docs/static/index.js' });

    for (const res of [root, asset]) {
      const csp = res.headers['content-security-policy'] as string;
      // Swagger UI needs its own inline scripts/styles.
      expect(csp).toContain("script-src 'self' 'unsafe-inline'");
      expect(csp).toContain("style-src 'self' 'unsafe-inline'");
      // The strict per-request nonce policy must NOT leak onto /docs.
      expect(csp).not.toContain("'nonce-");
    }

    // Non-/docs routes keep the strict policy (no unsafe-inline).
    const page = await app.inject({ method: 'GET', url: '/page' });
    expect(page.headers['content-security-policy']).not.toContain("'unsafe-inline'");
  });

  it('serves the relaxed development CSP when a route marks the reply (ADR-008 §5, #197)', async () => {
    const res = await app.inject({ method: 'GET', url: '/dev-consent' });
    const csp = res.headers['content-security-policy'] as string;
    // Inline styles permitted without a nonce for the development consent screen.
    expect(csp).toContain("style-src 'self' 'unsafe-inline'");
    // Scripts stay strict — the dev relaxation never loosens script-src.
    expect(csp).toContain("script-src 'self'");
    expect(csp).not.toMatch(/script-src [^;]*'unsafe-inline'/);
    // No nonce policy leaks onto the relaxed response.
    expect(csp).not.toContain("'nonce-");

    // An UNMARKED route still gets the strict nonce-based policy — relaxation is
    // opt-in per reply and never bleeds across requests (default-to-strict).
    const strict = await app.inject({ method: 'GET', url: '/page' });
    expect(strict.headers['content-security-policy']).not.toContain("'unsafe-inline'");
    expect(strict.headers['content-security-policy']).toMatch(/style-src [^;]*'nonce-/);
  });
});

describe('security-headers plugin — HSTS disabled (#113 dev override)', () => {
  it('omits HSTS when SECURITY_HSTS_ENABLED is false', async () => {
    vi.resetModules();
    vi.doMock('../../config/env', () => ({
      env: { SECURITY_HSTS_ENABLED: false, SECURITY_HSTS_MAX_AGE: 31536000 },
    }));
    const { securityHeadersPlugin: plugin } = await import('./security-headers');
    const app = Fastify();
    await app.register(plugin);
    app.get('/page', async () => 'ok');
    await app.ready();

    const res = await app.inject({ method: 'GET', url: '/page' });
    expect(res.headers['strict-transport-security']).toBeUndefined();

    await app.close();
    vi.doUnmock('../../config/env');
  });
});

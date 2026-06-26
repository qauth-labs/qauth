import helmet from '@fastify/helmet';
import type { FastifyInstance, FastifyPluginOptions, FastifyReply, FastifyRequest } from 'fastify';
import fp from 'fastify-plugin';

import { env } from '../../config/env';

/**
 * Security headers & browser hardening (issue #113).
 *
 * Registers `@fastify/helmet` with a strict, nonce-based Content-Security-Policy
 * plus HSTS, X-Frame-Options, X-Content-Type-Options and Referrer-Policy.
 *
 * ## CSP design
 *
 * The server-rendered login/consent pages (issues #150, #112) ship inline
 * `<style>` blocks. Rather than weaken the policy with `'unsafe-inline'`,
 * `@fastify/helmet`'s `enableCSPNonces` generates a fresh per-request nonce
 * exposed on `reply.cspNonce.style`; the page renderers stamp it onto each
 * `<style nonce>` tag. `script-src` stays `'self'` (plus its own unused nonce)
 * — the pages contain no JavaScript, so any injected `<script>` (reflected or
 * stored XSS) is refused by the browser.
 *
 * `'unsafe-inline'` is intentionally NOT listed for scripts. It IS effectively
 * neutralised for styles too: when a nonce is present, browsers ignore an
 * accompanying `'unsafe-inline'` style fallback, so only the nonced styles run.
 *
 * ## Swagger UI exception
 *
 * Swagger UI at `/docs` bundles its own inline scripts and styles and cannot
 * use our nonce, so the strict CSP would break it. The `/docs` prefix is
 * excluded from the global CSP and served a relaxed policy instead. The
 * exception is scoped to that prefix only; every other route keeps the strict
 * policy.
 *
 * ## Environment-aware posture (ADR-008, kept compatible)
 *
 * Strict-by-default. HSTS can be turned off for local plain-HTTP dev via
 * `SECURITY_HSTS_ENABLED=false` (mirrors the existing `SESSION_COOKIE_SECURE`
 * gate); production MUST keep it on.
 */

/** Prefix served by Swagger UI; excluded from the strict CSP. */
const SWAGGER_PREFIX = '/docs';

/** Relaxed CSP for Swagger UI, which needs its own inline scripts/styles. */
const SWAGGER_CSP =
  "default-src 'self'; " +
  "base-uri 'self'; " +
  "script-src 'self' 'unsafe-inline'; " +
  "style-src 'self' 'unsafe-inline'; " +
  "img-src 'self' data: https:; " +
  "font-src 'self' data:; " +
  "connect-src 'self'; " +
  "object-src 'none'; " +
  "frame-ancestors 'self'";

function isSwaggerRequest(request: FastifyRequest): boolean {
  // url includes the query string; compare against the path prefix only.
  const path = request.url.split('?', 1)[0];
  return path === SWAGGER_PREFIX || path.startsWith(`${SWAGGER_PREFIX}/`);
}

/**
 * Register security headers. Wrapped with `fastify-plugin` so the `cspNonce`
 * reply decorator and the global helmet hooks apply to every route registered
 * by the parent app, not just this plugin's encapsulated context.
 */
export const securityHeadersPlugin = fp<FastifyPluginOptions>(
  async (fastify: FastifyInstance) => {
    await fastify.register(helmet, {
      global: true,
      // Generates a fresh per-request nonce on `reply.cspNonce.{script,style}`
      // and appends `'nonce-<value>'` to the script-src/style-src directives.
      enableCSPNonces: true,
      contentSecurityPolicy: {
        useDefaults: false,
        directives: {
          'default-src': ["'self'"],
          'base-uri': ["'self'"],
          // No inline scripts: the rendered pages contain none, so an injected
          // <script> is refused outright (defence-in-depth behind html.ts escaping).
          // enableCSPNonces still appends a script nonce; we never emit it, so
          // inline scripts remain effectively blocked.
          'script-src': ["'self'"],
          // Inline <style> is allowed ONLY when carrying the per-request nonce
          // (appended by enableCSPNonces).
          'style-src': ["'self'"],
          'img-src': ["'self'", 'data:'],
          'font-src': ["'self'", 'data:'],
          'connect-src': ["'self'"],
          'form-action': ["'self'"],
          'object-src': ["'none'"],
          'frame-ancestors': ["'none'"],
        },
      },
      // HSTS: one-year max-age, subdomains, preload (issue #113). Gated so local
      // plain-HTTP dev does not pin the host to HTTPS. Browsers ignore HSTS over
      // plain HTTP, so this is also harmless when accidentally left on in dev.
      strictTransportSecurity: env.SECURITY_HSTS_ENABLED
        ? {
            maxAge: env.SECURITY_HSTS_MAX_AGE,
            includeSubDomains: true,
            preload: true,
          }
        : false,
      // Clickjacking + MIME-sniffing protection.
      frameguard: { action: 'deny' },
      xContentTypeOptions: true,
      referrerPolicy: { policy: 'no-referrer' },
      // We are an API/auth server, not a cross-origin resource provider for
      // browser apps; keep COEP off so it never interferes with redirects, and
      // let CORS (registered separately) govern cross-origin reads.
      crossOriginEmbedderPolicy: false,
    });

    // Swagger UI exception: replace the strict CSP with the relaxed policy on
    // the /docs prefix only. Runs after helmet's own onSend has set the strict
    // header, so we overwrite rather than append.
    fastify.addHook(
      'onSend',
      async (request: FastifyRequest, reply: FastifyReply, payload: unknown) => {
        if (isSwaggerRequest(request)) {
          reply.header('Content-Security-Policy', SWAGGER_CSP);
        }
        return payload;
      }
    );

    fastify.log.info('Security headers plugin registered');
  },
  {
    name: '@qauth-labs/security-headers',
  }
);

export default securityHeadersPlugin;

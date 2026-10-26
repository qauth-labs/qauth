import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

import { describe, expect, it } from 'vitest';

/**
 * Guards the two conditional security invariants recorded in `main.ts` (#323).
 *
 * Both Dependabot findings below were floored in `pnpm-workspace.yaml` rather than
 * fixed upstream, and both are inert only because of a design choice made in `main.ts`.
 * These assertions are source-level on purpose: `main.ts` calls `start()` at module
 * scope, so it cannot be imported and inspected as a value without booting a listener.
 */
/**
 * Locate `main.ts` without `import.meta` — `tsconfig.app.json` compiles this project
 * (tests included) as `module: commonjs`, under which `import.meta` is a syntax error.
 * Walk up from the cwd so the lookup works whether the runner was launched from the
 * project directory or the workspace root.
 */
function resolveMainPath(): string {
  let dir = process.cwd();
  for (let depth = 0; depth < 8; depth += 1) {
    for (const candidate of [
      join(dir, 'src', 'main.ts'),
      join(dir, 'apps', 'auth-server', 'src', 'main.ts'),
    ]) {
      if (existsSync(candidate)) return candidate;
    }
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  throw new Error('Could not locate apps/auth-server/src/main.ts from cwd ' + process.cwd());
}

const mainSource = readFileSync(resolveMainPath(), 'utf8');

/** Strip line and block comments so the assertions read code, not the comments about it. */
const mainCode = mainSource.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');

describe('main.ts security invariants', () => {
  it('installs a global Zod validator compiler so ajv (and thus fast-uri) never validates a request', () => {
    // fast-uri host confusion (CVE-2026-13676, CVE-2026-16221) reaches the tree via ajv.
    // Fastify only loads ajv when a route has no non-ajv validator compiler.
    expect(mainCode).toMatch(/server\.setValidatorCompiler\(\s*validatorCompiler\s*\)/);
  });

  it('serves HTTP/1.1, keeping the find-my-way HTTP/2 DoS (CVE-2026-47219) unreachable', () => {
    expect(mainCode).not.toMatch(/\bhttp2\b/);
    expect(mainCode).not.toMatch(/\bserverFactory\b/);
  });

  // Behaviour is tested in `app/helpers/request-bounds.test.ts`; these pin that
  // the server is actually built with it.
  it('bounds how long an unfinished request is held (REQUEST_TIMEOUT_MS)', () => {
    // Fastify's default of 0 holds a request whose body never finishes, with
    // everything buffered so far, for ever.
    expect(mainCode).toMatch(/\.\.\.requestDeadlineOptions\(\s*env\.REQUEST_TIMEOUT_MS\s*\)/);
  });

  it('answers an unknown route on the ROOT instance before its body is read', () => {
    // The default 404 belongs to the root, outside the scope the rate limiter
    // is registered in, and Fastify still parses its body.
    expect(mainCode).toMatch(
      /server\.addHook\(\s*'onRequest'\s*,\s*answerUnknownRouteBeforeBody\s*\)/
    );
  });
});

/**
 * A deprecated config name still works, so nothing else tells the operator to
 * rename it before the deprecation window closes, and an experimental setting
 * may change in any release. `config/env.ts` collects the warnings (tested in
 * `env.test.ts`); this pins that `main.ts` logs them at boot.
 */
describe('main.ts boot warnings', () => {
  it("answers the router's refusals and unreadable requests with problem documents (#513)", () => {
    // Without them Fastify sends its own { error, code, message, statusCode }
    // envelope for a path that is not valid percent-encoding, an over-long
    // path parameter, a malformed request or a request timeout.
    expect(mainCode).toMatch(/frameworkErrors:\s*answerFrameworkError/);
    expect(mainCode).toMatch(/clientErrorHandler:\s*answerClientError/);
  });

  it("answers the root instance's own routes and callNotFound with problem documents (#513)", () => {
    // Swagger UI's static files are root routes: a missing one reaches the
    // root not-found handler, and a failure the root error handler. Fastify's
    // defaults answer its `{ message, error, statusCode }` envelope.
    expect(mainCode).toMatch(/server\.setNotFoundHandler\(\s*answerRouteNotFound\s*\)/);
    expect(mainCode).toMatch(/await server\.register\(\s*errorHandler\s*\)/);
    // Registered before the root's own routes, so they answer through it.
    expect(mainCode.indexOf('server.register(errorHandler)')).toBeLessThan(
      mainCode.indexOf('server.register(swagger')
    );
  });

  it('logs every env deprecation warning through the server logger', () => {
    expect(mainCode).toMatch(
      /for \(const \w+ of envDeprecationWarnings\)\s*\{\s*server\.log\.warn\(/
    );
  });

  it('logs every experimental key or value the deployment sets (ADR-018 §5)', () => {
    expect(mainCode).toMatch(
      /for \(const \w+ of envExperimentalWarnings\)\s*\{\s*server\.log\.warn\(/
    );
  });
});

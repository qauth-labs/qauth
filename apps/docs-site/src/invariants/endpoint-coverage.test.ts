import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  extractDocumentedPaths,
  extractRegisteredRoutes,
  findOpenApiPathsMissingFromReference,
  findReferencePathsMissingFromOpenApi,
  findRoutesMissingFromOpenApi,
  type OpenApiDocument,
} from './endpoint-coverage';
import { resolveWorkspaceRoot } from './workspace-root';

/**
 * Guard 3: three legs of endpoint documentation coverage.
 *
 *   1. Every route Fastify registers appears in the committed OpenAPI spec — LIVE.
 *   2. Every OpenAPI path is documented on the API reference page — LIVE.
 *   3. The reference page documents no path the OpenAPI spec lacks — LIVE.
 *
 * Legs 2 and 3 now have a real-tree assertion below, added by Task 5 (#351)
 * once `apps/docs-site/src/content/docs/integrate/api-reference.md` landed.
 *
 * Read `extractDocumentedPaths`'s own doc comment in `endpoint-coverage.ts`
 * before over-trusting legs 2/3: they prove PATH-STRING set equality between
 * the reference page and `openapi.json`, not method coverage and not that
 * anything said about a path is accurate.
 */

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), '__fixtures__', 'endpoint-coverage');
const REPO_ROOT = resolveWorkspaceRoot();

function loadOpenApi(name: string): OpenApiDocument {
  return JSON.parse(readFileSync(join(FIXTURES, name), 'utf8'));
}

describe('leg 1 — extractRegisteredRoutes / findRoutesMissingFromOpenApi (fixtures)', () => {
  const routesRoot = join(FIXTURES, 'routes-ok');

  it('extracts a directory prefix, an autoPrefix override, and the root-level empty prefix', () => {
    const routes = extractRegisteredRoutes(routesRoot);
    const asStrings = routes.map((r) => `${r.method} ${r.path}`).sort();
    expect(asStrings).toEqual([
      'GET /',
      'GET /widgets/',
      'GET /widgets/{id}',
      'POST /api/gadgets/',
    ]);
  });

  it('passes when the OpenAPI spec covers every extracted route', () => {
    const routes = extractRegisteredRoutes(routesRoot);
    const violations = findRoutesMissingFromOpenApi(routes, loadOpenApi('openapi-complete.json'));
    expect(violations).toEqual([]);
  });

  it('MUTATION: fails when the OpenAPI spec is missing a registered route', () => {
    const routes = extractRegisteredRoutes(routesRoot);
    const violations = findRoutesMissingFromOpenApi(routes, loadOpenApi('openapi-incomplete.json'));
    expect(violations).toEqual([expect.objectContaining({ method: 'GET', path: '/widgets/{id}' })]);
  });

  it('does not mistake a same-named non-route call for a route (e.g. `redis.get(identifier)`)', () => {
    // Guards against the METHOD_CALL_RE regex matching any `.get(`/`.post(` —
    // only a call whose first argument is a STRING LITERAL counts. A file
    // whose only `.get(` call takes an identifier must extract zero routes.
    const routes = extractRegisteredRoutes(join(FIXTURES, 'routes-non-literal-get'));
    expect(routes).toEqual([]);
  });
});

describe('leg 1 — real route tree vs. the committed openapi.json', () => {
  it('every route under apps/auth-server/src/app/routes registers in openapi.json', () => {
    const routes = extractRegisteredRoutes(
      join(REPO_ROOT, 'apps', 'auth-server', 'src', 'app', 'routes')
    );
    const openApi: OpenApiDocument = JSON.parse(
      readFileSync(join(REPO_ROOT, 'apps', 'docs-site', 'public', 'openapi.json'), 'utf8')
    );

    expect(findRoutesMissingFromOpenApi(routes, openApi)).toEqual([]);

    // Cross-check the extraction itself, not just the guard's verdict: the
    // set of distinct paths this static analysis found must be exactly the
    // 28 paths already committed to openapi.json — proving the directory
    // prefix / autoPrefix / root-level reconciliation the brief asked for,
    // not just that no violation happened to slip through.
    //
    // This is also this leg's non-vacuity assertion, for free: it is SET
    // EQUALITY against a fixed, non-empty 28-path list, not "no violations
    // found". A broken walker returning zero routes would make
    // `distinctExtractedPaths` `[]`, which fails equality against 28 known
    // paths just as loudly as a real missing route would — unlike a
    // "no violations" check, an empty extraction cannot pass this silently.
    const distinctExtractedPaths = [...new Set(routes.map((r) => r.path))].sort();
    expect(distinctExtractedPaths).toEqual(Object.keys(openApi.paths).sort());
  });
});

describe('legs 2 & 3 — real API reference page vs. the committed openapi.json', () => {
  const REFERENCE_PATH = join(
    REPO_ROOT,
    'apps',
    'docs-site',
    'src',
    'content',
    'docs',
    'integrate',
    'api-reference.md'
  );

  it('the API reference page documents every openapi.json path, and nothing else', () => {
    const openApi: OpenApiDocument = JSON.parse(
      readFileSync(join(REPO_ROOT, 'apps', 'docs-site', 'public', 'openapi.json'), 'utf8')
    );
    const openApiPaths = Object.keys(openApi.paths);

    // Non-vacuity: a missing or empty reference file must fail loudly rather
    // than pass by vacuously satisfying both legs (no paths to be missing,
    // no paths to be extra). readFileSync throws if the file doesn't exist,
    // and this length check catches an empty (or near-empty) file — the
    // same failure mode the other real-tree tests guard against.
    const referenceContent = readFileSync(REFERENCE_PATH, 'utf8');
    expect(referenceContent.length).toBeGreaterThan(500);

    const documentedPaths = extractDocumentedPaths(referenceContent);
    expect(documentedPaths.length).toBeGreaterThan(0);

    expect(findOpenApiPathsMissingFromReference(openApiPaths, referenceContent)).toEqual([]);
    expect(findReferencePathsMissingFromOpenApi(openApiPaths, referenceContent)).toEqual([]);

    // Cross-check, as leg 1's real-tree test does above: exact set equality
    // against the same 28 known paths, not just "no violations found". An
    // extraction regex that silently stopped matching anything would make
    // `documentedPaths` `[]`, which fails this equality just as loudly as a
    // real coverage gap would.
    expect([...new Set(documentedPaths)].sort()).toEqual([...new Set(openApiPaths)].sort());
  });
});

describe('legs 2 & 3 — extractDocumentedPaths / reference-vs-openapi (fixtures only)', () => {
  const openApiPaths = ['/health', '/oauth/token', '/widgets/{id}'];

  it('extracts inline-code paths, with or without a leading HTTP method', () => {
    const content = readFileSync(join(FIXTURES, 'reference-ok.md'), 'utf8');
    expect(extractDocumentedPaths(content).sort()).toEqual(
      ['/health', '/oauth/token', '/widgets/{id}'].sort()
    );
  });

  it('leg 2 passes when every OpenAPI path is documented', () => {
    const content = readFileSync(join(FIXTURES, 'reference-ok.md'), 'utf8');
    expect(findOpenApiPathsMissingFromReference(openApiPaths, content)).toEqual([]);
  });

  it('leg 2 MUTATION: fails when the reference page omits a documented OpenAPI path', () => {
    const content = readFileSync(join(FIXTURES, 'reference-missing.md'), 'utf8');
    expect(findOpenApiPathsMissingFromReference(openApiPaths, content)).toEqual(['/widgets/{id}']);
  });

  it('leg 3 passes when the reference page documents nothing extra', () => {
    const content = readFileSync(join(FIXTURES, 'reference-ok.md'), 'utf8');
    expect(findReferencePathsMissingFromOpenApi(openApiPaths, content)).toEqual([]);
  });

  it('leg 3 MUTATION: fails when the reference page documents a path OpenAPI lacks', () => {
    const content = readFileSync(join(FIXTURES, 'reference-extra.md'), 'utf8');
    expect(findReferencePathsMissingFromOpenApi(openApiPaths, content)).toEqual(['/ghost']);
  });
});

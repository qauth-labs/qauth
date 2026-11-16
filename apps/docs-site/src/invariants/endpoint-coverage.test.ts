import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  API_FAMILIES,
  type ApiFamily,
  documentOperations,
  extractConstantPathRoutes,
  extractDocumentedOperations,
  extractDocumentedPaths,
  extractRegisteredRoutes,
  FAMILY_REFERENCE_PAGES,
  type FamilyDocument,
  familyDocumentPath,
  familyPrefix,
  findFamilyOperationsMissingFromPage,
  findFamilyRoutesMissingFromDocument,
  findOpenApiPathsMissingFromReference,
  findPageOperationsMissingFromDocument,
  findReferencePathsMissingFromOpenApi,
  findRoutesMissingFromOpenApi,
  type OpenApiDocument,
  type RouteEntry,
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

/** A family's document as the docs site publishes it, every experimental switch on (#525). */
function loadFamilyDocument(family: ApiFamily): FamilyDocument {
  return JSON.parse(
    readFileSync(join(REPO_ROOT, 'apps', 'docs-site', 'public', `openapi-${family}.json`), 'utf8')
  );
}

function readFamilyPage(family: ApiFamily): string {
  return readFileSync(
    join(REPO_ROOT, 'apps', 'docs-site', 'src', 'content', 'docs', FAMILY_REFERENCE_PAGES[family]),
    'utf8'
  );
}

const AUTH_SERVER_APP = join(REPO_ROOT, 'apps', 'auth-server', 'src', 'app');

/**
 * The routes of a family, extracted from the auth server's source: the admin
 * API's from `admin/`, written as path constants, and the account and
 * developer APIs' from `routes/`, written as literals.
 */
function familyRoutes(family: ApiFamily, document: FamilyDocument): RouteEntry[] {
  const prefix = `${familyPrefix(family, document)}/`;
  if (family === 'admin') return extractConstantPathRoutes(join(AUTH_SERVER_APP, 'admin'), prefix);
  return extractRegisteredRoutes(join(AUTH_SERVER_APP, 'routes')).filter((route) =>
    route.path.startsWith(prefix)
  );
}

const asOperations = (routes: RouteEntry[]) =>
  routes.map((route) => `${route.method} ${route.path}`).sort();

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
    // The account and developer APIs' own documents (#525) are served beside
    // their operations and described in no document, the whole one included,
    // so the page may name their paths too, and must.
    const familyDocumentPaths = (['account', 'developer'] as const).map((family) =>
      familyDocumentPath(family, loadFamilyDocument(family))
    );
    const servedPaths = [...openApiPaths, ...familyDocumentPaths];

    // Non-vacuity: a missing or empty reference file must fail loudly rather
    // than pass by vacuously satisfying both legs (no paths to be missing,
    // no paths to be extra). readFileSync throws if the file doesn't exist,
    // and this length check catches an empty (or near-empty) file — the
    // same failure mode the other real-tree tests guard against.
    const referenceContent = readFileSync(REFERENCE_PATH, 'utf8');
    expect(referenceContent.length).toBeGreaterThan(500);

    const documentedPaths = extractDocumentedPaths(referenceContent);
    expect(documentedPaths.length).toBeGreaterThan(0);

    expect(findOpenApiPathsMissingFromReference(servedPaths, referenceContent)).toEqual([]);
    expect(findReferencePathsMissingFromOpenApi(servedPaths, referenceContent)).toEqual([]);

    // Cross-check, as leg 1's real-tree test does above: exact set equality
    // against the same 28 known paths, not just "no violations found". An
    // extraction regex that silently stopped matching anything would make
    // `documentedPaths` `[]`, which fails this equality just as loudly as a
    // real coverage gap would.
    expect([...new Set(documentedPaths)].sort()).toEqual([...new Set(servedPaths)].sort());
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

describe('the API families — extractConstantPathRoutes (fixtures)', () => {
  const root = join(FIXTURES, 'constant-routes');

  it("resolves a module's path constants and the templates built on them, and nothing else", () => {
    expect(asOperations(extractConstantPathRoutes(root, '/admin/'))).toEqual([
      'GET /admin/v1-rc.0/realms/{realmId}/gadgets',
      'GET /admin/v1-rc.0/realms/{realmId}/widgets',
      'PATCH /admin/v1-rc.0/realms/{realmId}/widgets/{widgetId}',
      'POST /admin/v1-rc.0/realms/{realmId}/widgets',
      'POST /admin/v1-rc.0/realms/{realmId}/widgets/{widgetId}/enable',
    ]);
  });

  it('keeps only the paths under the prefix it is given', () => {
    expect(asOperations(extractConstantPathRoutes(root, '/health'))).toEqual(['GET /health']);
  });
});

describe('the API families — each family document against its routes and its page (fixtures)', () => {
  const document: FamilyDocument = {
    info: { version: 'v1-rc.0' },
    paths: {
      '/developer/v1-rc.0/widgets': { get: {}, post: {} },
      '/developer/v1-rc.0/widgets/{widgetId}': { delete: {} },
    },
  };
  const page = [
    '### `GET /developer/v1-rc.0/widgets`',
    '### `POST /developer/v1-rc.0/widgets`',
    '| `DELETE /developer/v1-rc.0/widgets/{widgetId}` | Delete a widget. |',
    'The document: `GET /developer/v1-rc.0/openapi.json`. Elsewhere: `GET /oauth/token`.',
  ].join('\n');

  it("reads the family's prefix and document path from the document's contract version", () => {
    expect(familyPrefix('developer', document)).toBe('/developer/v1-rc.0');
    expect(familyDocumentPath('developer', document)).toBe('/developer/v1-rc.0/openapi.json');
    expect(() => familyPrefix('developer', { paths: {} })).toThrow(/contract version/);
  });

  it('reads operations, a method with its path, from inline code', () => {
    expect(documentOperations(document)).toEqual([
      'GET /developer/v1-rc.0/widgets',
      'POST /developer/v1-rc.0/widgets',
      'DELETE /developer/v1-rc.0/widgets/{widgetId}',
    ]);
    expect(extractDocumentedOperations('`GET|POST /oauth/userinfo` and `/health`')).toEqual([
      'GET /oauth/userinfo',
      'POST /oauth/userinfo',
    ]);
  });

  it('passes when the page names every operation, and no other under the prefix', () => {
    expect(findFamilyOperationsMissingFromPage(document, page)).toEqual([]);
    expect(findPageOperationsMissingFromDocument('developer', document, page)).toEqual([]);
  });

  it('MUTATION: fails when a family route has no docs page entry', () => {
    const withoutDelete = page
      .split('\n')
      .filter((line) => !line.includes('DELETE'))
      .join('\n');
    expect(findFamilyOperationsMissingFromPage(document, withoutDelete)).toEqual([
      'DELETE /developer/v1-rc.0/widgets/{widgetId}',
    ]);
    // The path alone, without its method, does not document the operation.
    expect(
      findFamilyOperationsMissingFromPage(
        document,
        `${withoutDelete}\nSee \`/developer/v1-rc.0/widgets/{widgetId}\`.`
      )
    ).toEqual(['DELETE /developer/v1-rc.0/widgets/{widgetId}']);
  });

  it('MUTATION: fails when the page names an operation of the family the document lacks', () => {
    expect(
      findPageOperationsMissingFromDocument(
        'developer',
        document,
        `${page}\n### \`PATCH /developer/v1-rc.0/widgets/{widgetId}\``
      )
    ).toEqual(['PATCH /developer/v1-rc.0/widgets/{widgetId}']);
  });

  it('MUTATION: fails when a family route is not in its document', () => {
    const routes: RouteEntry[] = [
      { method: 'GET', path: '/developer/v1-rc.0/widgets', sourceFile: 'widgets.ts' },
      { method: 'PATCH', path: '/developer/v1-rc.0/widgets/{widgetId}', sourceFile: 'widgets.ts' },
    ];
    expect(findFamilyRoutesMissingFromDocument(routes, document)).toEqual([
      expect.objectContaining({ method: 'PATCH', path: '/developer/v1-rc.0/widgets/{widgetId}' }),
    ]);
  });
});

describe('the API families — real routes vs. the published family documents and their pages', () => {
  it.each(API_FAMILIES)(
    'every %s route is in its family document, and the document lists no route the source lacks',
    (family) => {
      const document = loadFamilyDocument(family);
      const routes = familyRoutes(family, document);
      expect(findFamilyRoutesMissingFromDocument(routes, document)).toEqual([]);
      // Set equality, not "no violation": an extraction that found nothing
      // fails against the document's non-empty list as loudly as a missing route.
      expect(documentOperations(document).length).toBeGreaterThan(0);
      expect(asOperations(routes)).toEqual(documentOperations(document).sort());
    }
  );

  it.each(API_FAMILIES)(
    "every operation of the %s document is documented on its family's page, and the page names no other",
    (family) => {
      const document = loadFamilyDocument(family);
      const page = readFamilyPage(family);
      expect(findFamilyOperationsMissingFromPage(document, page)).toEqual([]);
      expect(findPageOperationsMissingFromDocument(family, document, page)).toEqual([]);
    }
  );

  it('MUTATION: the real check fails when a family route loses its docs page entry', () => {
    const document = loadFamilyDocument('developer');
    // Every mention of the operation goes, as when a new route is never documented.
    const page = readFamilyPage('developer').replaceAll(
      '`DELETE /developer/v1-rc.0/consents/{consentId}`',
      'revoking a consent'
    );
    expect(findFamilyOperationsMissingFromPage(document, page)).toEqual([
      'DELETE /developer/v1-rc.0/consents/{consentId}',
    ]);
  });

  it('the admin document lists the two reference operations with their extensions', () => {
    const document = loadFamilyDocument('admin');
    const byId = new Map(
      Object.values(document.paths).flatMap((item) =>
        Object.values(item).map((operation) => {
          const op = operation as Record<string, unknown>;
          return [op['operationId'], op] as const;
        })
      )
    );
    expect(document.paths['/admin/v1-rc.0/realms/{realmId}']?.['get']).toBe(byId.get('realms.get'));
    expect(byId.get('realms.get')).toMatchObject({
      'x-qauth-class': 'read',
      'x-qauth-permission': 'realms.read',
      'x-qauth-stability': 'experimental',
      security: [{ dpopAuth: [] }],
    });
    expect(byId.get('realms.get')).not.toHaveProperty('x-qauth-effects');
    expect(byId.get('realms.get')).not.toHaveProperty('x-qauth-two-admin');

    expect(document.paths['/admin/v1-rc.0/realms/{realmId}/policies']?.['patch']).toBe(
      byId.get('realms.policies.update')
    );
    expect(byId.get('realms.policies.update')).toMatchObject({
      'x-qauth-class': 'security',
      'x-qauth-permission': expect.arrayContaining([
        'realms.policies.write',
        'realms.policies.security',
      ]),
      'x-qauth-effects': expect.arrayContaining(['posture-loosening']),
      'x-qauth-two-admin': 'recommended',
      'x-qauth-stability': 'experimental',
      security: [{ dpopAuth: [] }],
    });

    // And the admin API's page names both, with their ids.
    const page = readFamilyPage('admin');
    for (const text of [
      '`GET /admin/v1-rc.0/realms/{realmId}`',
      '`realms.get`',
      '`PATCH /admin/v1-rc.0/realms/{realmId}/policies`',
      '`realms.policies.update`',
    ]) {
      expect(page).toContain(text);
    }
  });
});

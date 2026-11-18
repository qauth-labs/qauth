import { readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, relative, sep } from 'node:path';

export interface RouteEntry {
  method: string;
  /** OpenAPI-style path — Fastify's `:param` segments rendered as `{param}`. */
  path: string;
  /** Route file the entry was extracted from, relative to the routes root. */
  sourceFile: string;
}

export interface OpenApiDocument {
  paths: Record<string, Record<string, unknown>>;
}

function walkTsFiles(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const stat = statSync(full);
    if (stat.isDirectory()) {
      walkTsFiles(full, out);
    } else if (
      entry.endsWith('.ts') &&
      !entry.endsWith('.test.ts') &&
      !entry.endsWith('.spec.ts')
    ) {
      out.push(full);
    }
  }
  return out;
}

function groupByDirectory(routesRoot: string): Map<string, string[]> {
  const groups = new Map<string, string[]>();
  for (const file of walkTsFiles(routesRoot)) {
    const dirRel = relative(routesRoot, dirname(file)) || '.';
    const bucket = groups.get(dirRel) ?? [];
    bucket.push(file);
    groups.set(dirRel, bucket);
  }
  return groups;
}

const AUTO_PREFIX_RE = /export const autoPrefix\s*=\s*['"]([^'"]+)['"]/;

/**
 * `.get(`, `.post(`, an optional `<Generic>` in between (`fastify.get<{
 * Reply: HealthResponse }>('/health', ...)` in `health.ts`), then a string
 * literal FIRST argument. Requiring the literal is what keeps this from
 * matching unrelated calls that happen to share a method name — e.g.
 * `fastify.redis.get(lastSentKey)` in `auth/resend-verification.ts`, whose
 * first argument is an identifier, not a quoted string.
 *
 * That literal requirement is a deliberate tradeoff, not an oversight, and it
 * leaves a KNOWN GAP: a route registered in any other shape —
 * `fastify.route({ method, url })`, a path held in a constant, a template
 * literal — extracts nothing here, so leg 1 never sees it. Loosening the
 * regex to reach those shapes brings back exactly the false positives the
 * literal requirement exists to suppress (the `redis.get` case above, pinned
 * by the `routes-non-literal-get` fixture in `endpoint-coverage.test.ts`),
 * and reviewers have concluded that trade is worth keeping. The residual
 * exposure is closed outside this guard: a contributor who uses a
 * non-literal registration shape AND skips the OpenAPI export no longer ships
 * an undocumented endpoint past it, because CI's stable-surface drift check
 * (`scripts/stable-surface/`, #451) regenerates `public/openapi.json` from the
 * running app and fails when it differs from the committed copy. Do not widen
 * this regex without a plan for the false positives; add the missing route to
 * the spec instead.
 */
const METHOD_CALL_RE =
  /\.(get|post|put|patch|delete|head|options)\s*(?:<[^>]*>)?\s*\(\s*\n?\s*['"]([^'"]*)['"]/g;

function toOpenApiPath(fastifyPath: string): string {
  return fastifyPath.replace(/:([A-Za-z0-9_]+)/g, '{$1}');
}

/**
 * Statically extract every route Fastify would register under `routesRoot`,
 * without booting the app. The route manifest (`route-manifest.ts`, #495)
 * registers each module under its DIRECTORY's prefix, as the folder autoload
 * it replaced did, and its test pins that — `routes/auth/login.ts`
 * registering `'/login'` serves `/auth/login` — with one override: a
 * directory whose entry file exports `autoPrefix` (see
 * `routes/clients/index.ts`) uses that instead of its directory name, and
 * every file in that directory (including a helper like `api-keys.ts` with
 * no default export of its own, registered manually from `index.ts`) shares
 * it. Grouping extraction by directory rather than by "is this an autoload
 * entry point" gets that sharing for free.
 *
 * `routes/root.ts` — a file directly in `routesRoot`, no subdirectory —
 * gets an empty prefix, so its own `'/'` literal serves `/`.
 */
export function extractRegisteredRoutes(routesRoot: string): RouteEntry[] {
  const entries: RouteEntry[] = [];
  const seen = new Set<string>();

  for (const [dirRel, files] of groupByDirectory(routesRoot)) {
    let prefix = dirRel === '.' ? '' : '/' + dirRel.split(sep).join('/');
    for (const file of files) {
      const source = readFileSync(file, 'utf8');
      const overrideMatch = source.match(AUTO_PREFIX_RE);
      if (overrideMatch) prefix = overrideMatch[1];
    }

    for (const file of files) {
      const source = readFileSync(file, 'utf8');
      const pattern = new RegExp(METHOD_CALL_RE.source, METHOD_CALL_RE.flags);
      let match: RegExpExecArray | null;
      while ((match = pattern.exec(source))) {
        const [, method, rawPath] = match;
        const fullPath = toOpenApiPath(prefix + rawPath);
        const key = `${method.toUpperCase()} ${fullPath}`;
        if (seen.has(key)) continue;
        seen.add(key);
        entries.push({
          method: method.toUpperCase(),
          path: fullPath,
          sourceFile: relative(routesRoot, file).replace(/\\/g, '/'),
        });
      }
    }
  }

  return entries;
}

/** Leg 1 — every registered route must appear in the committed OpenAPI spec. */
export function findRoutesMissingFromOpenApi(
  routes: RouteEntry[],
  openApi: OpenApiDocument
): RouteEntry[] {
  return routes.filter((route) => {
    const pathItem = openApi.paths[route.path];
    if (!pathItem) return true;
    return !(route.method.toLowerCase() in pathItem);
  });
}

/**
 * Paths are documented on the (Task 5) API reference page as inline code,
 * optionally prefixed with the HTTP method — `` `/oauth/token` `` or
 * `` `POST /oauth/token` `` — matching the OpenAPI spec's own `{param}`
 * placeholder style for path parameters.
 *
 * The HTTP method, if present, is matched only to be skipped — it is NOT
 * captured, and legs 2/3 below therefore check PATH coverage only, never
 * method coverage. `` `GET /oauth/revoke` `` (revoke is POST-only) would
 * satisfy leg 2 for `/oauth/revoke` exactly as well as the correct method
 * would. This function also cannot tell a real explanation from a passing
 * mention: a path named once in a "not yet supported" aside or a "see also"
 * list counts as "documented" identically to a full request/response
 * section. What legs 2/3 actually prove is narrow and worth stating
 * plainly: the SET of path strings mentioned on the reference page is
 * exactly equal to the SET of path keys in `openapi.json` — real anti-rot
 * value (an endpoint added to the spec and never mentioned, or a documented
 * endpoint removed from the spec, both get caught), but not a correctness
 * check on what the page says about any one of them. (qauth-labs/qauth#351
 * fix round 1.)
 */
export function extractDocumentedPaths(referenceContent: string): string[] {
  const re = /`(?:[A-Z]+\s+)?(\/[^\s`]*)`/g;
  const paths = new Set<string>();
  let match: RegExpExecArray | null;
  while ((match = re.exec(referenceContent))) {
    paths.add(match[1]);
  }
  return [...paths];
}

/** Leg 2 — every OpenAPI path must be documented on the reference page. */
export function findOpenApiPathsMissingFromReference(
  openApiPaths: string[],
  referenceContent: string
): string[] {
  const documented = new Set(extractDocumentedPaths(referenceContent));
  return openApiPaths.filter((path) => !documented.has(path));
}

/** Leg 3 — the reference page must document no path the OpenAPI spec lacks. */
export function findReferencePathsMissingFromOpenApi(
  openApiPaths: string[],
  referenceContent: string
): string[] {
  const known = new Set(openApiPaths);
  return extractDocumentedPaths(referenceContent).filter((path) => !known.has(path));
}

// ---------------------------------------------------------------------------
// The API families (ADR-019 Decision 7, #525)
// ---------------------------------------------------------------------------

/** The three API families, each with an OpenAPI document of its own. */
export const API_FAMILIES = ['admin', 'account', 'developer'] as const;
export type ApiFamily = (typeof API_FAMILIES)[number];

/**
 * The docs page that documents each family's operations, relative to
 * `src/content/docs`. Every operation of a family's document is written there
 * as inline code with its method, `` `GET /developer/v1-rc.0/clients` ``.
 */
export const FAMILY_REFERENCE_PAGES: Readonly<Record<ApiFamily, string>> = Object.freeze({
  admin: 'reference/admin-api.md',
  account: 'integrate/api-reference.md',
  developer: 'integrate/api-reference.md',
});

/** A family's document: an OpenAPI document whose `info.version` is its contract version. */
export interface FamilyDocument extends OpenApiDocument {
  info?: { version?: string };
}

/** The family's path prefix, `/<family>/<contract version>`, from its document's `info.version`. */
export function familyPrefix(family: ApiFamily, document: FamilyDocument): string {
  const version = document.info?.version;
  if (typeof version !== 'string' || version === '') {
    throw new Error(`The ${family} document names no contract version in info.version`);
  }
  return `/${family}/${version}`;
}

/** Where a listener serves the family's own document: `<prefix>/openapi.json`. */
export function familyDocumentPath(family: ApiFamily, document: FamilyDocument): string {
  return `${familyPrefix(family, document)}/openapi.json`;
}

const OPERATION_METHODS = ['get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace'];

/** Every operation of a document, as `METHOD /path`. */
export function documentOperations(document: OpenApiDocument): string[] {
  return Object.entries(document.paths).flatMap(([path, item]) =>
    OPERATION_METHODS.filter((method) => method in item).map(
      (method) => `${method.toUpperCase()} ${path}`
    )
  );
}

/**
 * The operations a page documents: inline code holding a method and a path,
 * `` `PATCH /admin/v1-rc.0/realms/{realmId}/policies` ``, or several methods
 * joined by `|`, `` `GET|POST /oauth/userinfo` ``. Unlike
 * {@link extractDocumentedPaths}, the method counts: a family's page must
 * name each operation, not only each path.
 */
export function extractDocumentedOperations(content: string): string[] {
  const re = /`([A-Z]+(?:\|[A-Z]+)*)\s+(\/[^\s`]*)`/g;
  const operations = new Set<string>();
  let match: RegExpExecArray | null;
  while ((match = re.exec(content))) {
    for (const method of match[1].split('|')) operations.add(`${method} ${match[2]}`);
  }
  return [...operations];
}

/** A family leg — every operation of the family's document is documented on its page. */
export function findFamilyOperationsMissingFromPage(
  document: OpenApiDocument,
  pageContent: string
): string[] {
  const documented = new Set(extractDocumentedOperations(pageContent));
  return documentOperations(document).filter((operation) => !documented.has(operation));
}

/**
 * A family leg — the page documents no operation under the family's prefix
 * that its document lacks. The `GET` of the family's own document is a route
 * too, served beside the operations and described in none of them.
 */
export function findPageOperationsMissingFromDocument(
  family: ApiFamily,
  document: FamilyDocument,
  pageContent: string
): string[] {
  const prefix = `${familyPrefix(family, document)}/`;
  const known = new Set([
    ...documentOperations(document),
    `GET ${familyDocumentPath(family, document)}`,
  ]);
  return extractDocumentedOperations(pageContent).filter(
    (operation) => operation.split(' ')[1].startsWith(prefix) && !known.has(operation)
  );
}

/** A family leg — every route of the family is in the family's document. */
export function findFamilyRoutesMissingFromDocument(
  routes: RouteEntry[],
  document: OpenApiDocument
): RouteEntry[] {
  return findRoutesMissingFromOpenApi(routes, document);
}

/** A string constant of a module: `const NAME = '…'`, or a template of other constants. */
const PATH_CONSTANT_RE =
  /\bconst\s+([A-Z][A-Z0-9_]*)\s*=\s*(?:'([^'\n]*)'|"([^"\n]*)"|`([^`\n]*)`)\s*;/g;

/**
 * A route registration whose first argument is a path constant, a string or a
 * template: `typed.patch(`, `admin.get(`. A constant must be one of the
 * module's own, so `registry.get(APPROVAL_OPERATION_IDS.create)` (an
 * identifier followed by a member access) and
 * `repositories.oauthClients.delete(realm.id, …)` match nothing.
 */
const ROUTE_CALL_RE =
  /\.(get|post|put|patch|delete)\s*(?:<[^>]*>)?\s*\(\s*(?:([A-Z][A-Z0-9_]*)|'([^'\n]*)'|"([^"\n]*)"|`([^`\n]*)`)\s*,/g;

/** `${NAME}` placeholders resolved from `constants`; undefined when one names no constant. */
function resolveTemplate(template: string, constants: Map<string, string>): string | undefined {
  let unresolved = false;
  const resolved = template.replace(/\$\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}/g, (_whole, name) => {
    const value = constants.get(name);
    if (value === undefined) unresolved = true;
    return value ?? '';
  });
  return unresolved || resolved.includes('${') ? undefined : resolved;
}

function pathConstants(source: string): Map<string, string> {
  const raw = new Map<string, string>();
  for (const match of source.matchAll(PATH_CONSTANT_RE)) {
    raw.set(match[1], match[2] ?? match[3] ?? match[4] ?? '');
  }
  // A constant may be built from one declared before it, as `${CLIENTS_PATH}/:clientId` is.
  const constants = new Map<string, string>();
  for (const [name, value] of raw) {
    const resolved = resolveTemplate(value, constants);
    if (resolved !== undefined) constants.set(name, resolved);
  }
  return constants;
}

/**
 * Statically extract every route under `prefix` that the modules under
 * `root` register, without booting the admin listener (#525). The admin
 * routes are written as path constants of their module and templates built on
 * them (`admin/clients/routes.ts`: `CLIENTS_PATH`, `` `${CLIENT_PATH}/enable` ``),
 * which {@link extractRegisteredRoutes}' literal-only rule does not reach, so
 * this extraction resolves a module's own constants first. A path it cannot
 * resolve, such as one a function returns, extracts nothing: the real-tree
 * test then finds the operation in the document and not here, and fails.
 */
export function extractConstantPathRoutes(root: string, prefix: string): RouteEntry[] {
  const entries: RouteEntry[] = [];
  const seen = new Set<string>();
  for (const file of walkTsFiles(root).sort()) {
    const source = readFileSync(file, 'utf8');
    const constants = pathConstants(source);
    for (const match of source.matchAll(ROUTE_CALL_RE)) {
      const [, method, constant, single, double, template] = match;
      const rawPath =
        constant !== undefined
          ? constants.get(constant)
          : (single ?? double ?? resolveTemplate(template ?? '', constants));
      if (rawPath === undefined || !rawPath.startsWith(prefix)) continue;
      const path = toOpenApiPath(rawPath);
      const key = `${method.toUpperCase()} ${path}`;
      if (seen.has(key)) continue;
      seen.add(key);
      entries.push({
        method: method.toUpperCase(),
        path,
        sourceFile: relative(root, file).replace(/\\/g, '/'),
      });
    }
  }
  return entries;
}

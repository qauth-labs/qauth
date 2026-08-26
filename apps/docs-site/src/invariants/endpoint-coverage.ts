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
 * exposure is worth stating plainly rather than rediscovering: a contributor
 * who uses a non-literal registration shape AND skips the OpenAPI export
 * ships an undocumented endpoint past all three legs of this guard, since
 * `apps/docs-site/public/openapi.json` is a hand-regenerated committed
 * snapshot that no workflow diffs against the running app. Do not widen this
 * regex without a plan for the false positives; add the missing route to the
 * spec instead.
 */
const METHOD_CALL_RE =
  /\.(get|post|put|patch|delete|head|options)\s*(?:<[^>]*>)?\s*\(\s*\n?\s*['"]([^'"]*)['"]/g;

function toOpenApiPath(fastifyPath: string): string {
  return fastifyPath.replace(/:([A-Za-z0-9_]+)/g, '{$1}');
}

/**
 * Statically extract every route Fastify would register under `routesRoot`,
 * without booting the app. `@fastify/autoload` derives each plugin's path
 * prefix from its DIRECTORY, not the file — `routes/auth/login.ts`
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

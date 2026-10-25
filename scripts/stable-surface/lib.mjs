/**
 * The stable-surface guard (#451, ADR-018 §5): the logic, without the process
 * glue. `check.mjs` is the CLI that wires it to git, the shell and oasdiff;
 * this module takes those as arguments so the tests can drive every branch
 * offline.
 *
 * A surface is one committed, generated file that clients depend on: today the
 * auth server's OpenAPI document, later the event schemas, the Interaction API
 * steps, the realm file schema and the documented configuration keys. Each is
 * one entry in `stable-surface/surfaces.json`, and nothing here names any of
 * them. Three checks run over the registry:
 *
 *   - drift:  run each generator and fail when its output differs from the
 *             committed file;
 *   - tags:   every OpenAPI operation carries `x-qauth-stability`, and an
 *             operation that only a switch registers is `experimental`;
 *   - breaks: compare each `stable` surface with the same file at the latest
 *             release tag and fail on a break that
 *             `stable-surface/approved-breaks.json` does not approve.
 *
 * Zero runtime dependencies — Node's standard library only.
 */

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

export const REGISTRY_PATH = 'stable-surface/surfaces.json';
export const APPROVALS_PATH = 'stable-surface/approved-breaks.json';

/** The OpenAPI extension every operation carries (ADR-018 §5). */
export const STABILITY_EXTENSION = 'x-qauth-stability';

export const STABILITIES = ['stable', 'experimental'];
export const FORMATS = ['openapi', 'json-schema'];

/**
 * What a JSON Schema surface describes, which decides the direction a change
 * breaks in:
 *
 *   - `input`:  documents clients send and QAuth validates (a realm file, an
 *               Interaction API step). Accepting less is a break.
 *   - `output`: documents QAuth emits (an event payload). Emitting something an
 *               old client does not expect is a break.
 *   - `both`:   both rules apply.
 */
export const ROLES = ['input', 'output', 'both'];

export const HTTP_METHODS = ['get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace'];

/** oasdiff's numeric levels in its JSON output. */
export const LEVEL = Object.freeze({ ERR: 3, WARN: 2, INFO: 1 });

/**
 * What counts as a break (#451): a removed operation, a removed or renamed
 * response field, a new required request field, a narrowed enum, a changed
 * type and a new required scope.
 *
 * oasdiff already rates most of these as errors: `api-removed-without-deprecation`,
 * `response-required-property-removed`, `new-required-request-property`,
 * `request-property-became-required`, `request-property-enum-value-removed`,
 * `request-parameter-enum-value-removed`, `request-property-type-changed`,
 * `response-property-type-changed`, `api-security-scope-added`, and the rest
 * of its error-level checks, which all stay breaks. The rules below are the
 * ones it rates lower and the definition above does not:
 *
 *   - a removed response field that was optional (oasdiff: info);
 *   - a removed operation that had been deprecated first (oasdiff: info). ADR-018
 *     §5 removes a stable operation only in a new major release, so the
 *     removal still needs an approval;
 *   - a changed type of an object parameter's property (oasdiff: warning);
 *   - a security requirement added to an operation that had none, which makes
 *     a credential (and its scopes) newly required (oasdiff: info).
 *
 * oasdiff reads this list as a severity-levels file (`<rule> err` per line).
 */
export const RAISED_TO_BREAK = Object.freeze([
  'response-optional-property-removed',
  'api-removed-with-deprecation',
  'api-path-removed-with-deprecation',
  'request-parameter-property-type-changed',
  'api-security-added',
  'api-global-security-added',
]);

/** The severity-levels file oasdiff reads, built from {@link RAISED_TO_BREAK}. */
export function severityLevelsFile() {
  return RAISED_TO_BREAK.map((rule) => `${rule} err`).join('\n') + '\n';
}

/** A problem with the inputs themselves: the check could not run. Exits 2. */
export class InputError extends Error {}

const isObject = (value) => typeof value === 'object' && value !== null && !Array.isArray(value);

const clone = (value) => JSON.parse(JSON.stringify(value));

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

const SURFACE_KEYS = new Set([
  'name',
  'description',
  'format',
  'generator',
  'path',
  'stability',
  'role',
  'formerPaths',
  'formerExperimental',
  'maximalOf',
]);

const OPERATION_KEY = /^(GET|PUT|POST|DELETE|OPTIONS|HEAD|PATCH|TRACE) \/\S*$/;

const NAME_SHAPE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

/** A forward-slash path inside the repository: no absolute path, no `..`. */
export function isRepoRelativePath(value) {
  if (typeof value !== 'string' || value === '') return false;
  if (value.startsWith('/') || value.includes('\\') || /^[A-Za-z]:/.test(value)) return false;
  return value.split('/').every((segment) => segment !== '' && segment !== '.' && segment !== '..');
}

/**
 * Validate `stable-surface/surfaces.json` and return its entries, normalised
 * (`formerPaths` and `formerExperimental` default to `[]`). Unknown keys are
 * refused, so a typo in a field name cannot quietly switch a check off.
 *
 * @returns {Array<{name: string, description?: string, format: 'openapi'|'json-schema',
 *   generator: string, path: string, stability: 'stable'|'experimental',
 *   role?: 'input'|'output'|'both', formerPaths: string[], formerExperimental: string[],
 *   maximalOf?: string}>}
 */
export function parseRegistry(data, source = REGISTRY_PATH) {
  if (!isObject(data) || !Array.isArray(data.surfaces)) {
    throw new InputError(`${source}: expected an object with a "surfaces" array`);
  }
  const errors = [];
  for (const key of Object.keys(data)) {
    if (key !== 'surfaces' && key !== '$schema') errors.push(`unknown top-level key "${key}"`);
  }

  const surfaces = data.surfaces.map((entry, index) => {
    const at = `surfaces[${index}]${isObject(entry) && typeof entry.name === 'string' ? ` (${entry.name})` : ''}`;
    if (!isObject(entry)) {
      errors.push(`${at}: expected an object`);
      return null;
    }
    for (const key of Object.keys(entry)) {
      if (!SURFACE_KEYS.has(key)) errors.push(`${at}: unknown key "${key}"`);
    }
    if (typeof entry.name !== 'string' || !NAME_SHAPE.test(entry.name)) {
      errors.push(`${at}: "name" must be kebab-case`);
    }
    if (!FORMATS.includes(entry.format)) {
      errors.push(`${at}: "format" must be one of ${FORMATS.join(', ')}`);
    }
    if (typeof entry.generator !== 'string' || entry.generator.trim() === '') {
      errors.push(`${at}: "generator" must be the command that writes the file`);
    }
    if (!isRepoRelativePath(entry.path)) {
      errors.push(`${at}: "path" must be a repository-relative path`);
    }
    if (!STABILITIES.includes(entry.stability)) {
      errors.push(`${at}: "stability" must be one of ${STABILITIES.join(', ')}`);
    }
    if (entry.description !== undefined && typeof entry.description !== 'string') {
      errors.push(`${at}: "description" must be a string`);
    }
    if (entry.format === 'json-schema' && !ROLES.includes(entry.role)) {
      errors.push(`${at}: a json-schema surface needs "role": one of ${ROLES.join(', ')}`);
    }
    if (entry.format === 'openapi' && entry.role !== undefined) {
      errors.push(`${at}: "role" applies to json-schema surfaces only`);
    }
    const formerPaths = entry.formerPaths ?? [];
    if (!Array.isArray(formerPaths) || !formerPaths.every(isRepoRelativePath)) {
      errors.push(`${at}: "formerPaths" must be an array of repository-relative paths`);
    }
    const formerExperimental = entry.formerExperimental ?? [];
    if (
      !Array.isArray(formerExperimental) ||
      !formerExperimental.every((key) => typeof key === 'string' && OPERATION_KEY.test(key))
    ) {
      errors.push(`${at}: "formerExperimental" must be an array of operations, as "METHOD /path"`);
    } else if (formerExperimental.length > 0 && entry.format !== 'openapi') {
      errors.push(`${at}: "formerExperimental" applies to openapi surfaces only`);
    }
    return {
      ...entry,
      formerPaths: Array.isArray(formerPaths) ? formerPaths : [],
      formerExperimental: Array.isArray(formerExperimental) ? formerExperimental : [],
    };
  });

  const byName = new Map();
  const byPath = new Map();
  for (const surface of surfaces) {
    if (!surface) continue;
    if (byName.has(surface.name)) errors.push(`surface name "${surface.name}" is used twice`);
    byName.set(surface.name, surface);
    if (byPath.has(surface.path)) {
      errors.push(
        `"${surface.path}" is registered by both ${byPath.get(surface.path)} and ${surface.name}`
      );
    }
    byPath.set(surface.path, surface.name);
  }

  for (const surface of surfaces) {
    if (!surface || surface.maximalOf === undefined) continue;
    const base = byName.get(surface.maximalOf);
    if (surface.format !== 'openapi') {
      errors.push(`${surface.name}: "maximalOf" applies to openapi surfaces only`);
    } else if (!base || base === surface || base.format !== 'openapi' || base.maximalOf) {
      errors.push(
        `${surface.name}: "maximalOf" must name another openapi surface that is not itself a maximal export`
      );
    }
    if (surface.stability !== 'experimental') {
      errors.push(
        `${surface.name}: a maximal export is never break-checked, so its "stability" must be "experimental"`
      );
    }
  }

  if (errors.length > 0) {
    throw new InputError(`${source} is invalid:\n  - ${errors.join('\n  - ')}`);
  }
  return surfaces;
}

/** Read and parse a JSON file under `root`; a missing or broken file is an {@link InputError}. */
export function readJsonFile(root, relativePath) {
  let raw;
  try {
    raw = readFileSync(join(root, relativePath), 'utf8');
  } catch (error) {
    throw new InputError(`cannot read ${relativePath}: ${error.message}`);
  }
  return parseJsonText(raw, relativePath);
}

export function parseJsonText(raw, what) {
  try {
    return JSON.parse(raw);
  } catch (error) {
    throw new InputError(`${what} is not valid JSON: ${error.message}`);
  }
}

// ---------------------------------------------------------------------------
// Release tags
// ---------------------------------------------------------------------------

const IDENTIFIER = '(?:0|[1-9]\\d*|\\d*[A-Za-z-][0-9A-Za-z-]*)';
const RELEASE_TAG = new RegExp(
  `^v(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)(?:-(${IDENTIFIER}(?:\\.${IDENTIFIER})*))?$`
);

/** Parse a `vMAJOR.MINOR.PATCH[-PRERELEASE]` tag, or return null for any other name. */
export function parseReleaseTag(tag) {
  const match = RELEASE_TAG.exec(tag);
  if (!match) return null;
  return {
    tag,
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3]),
    prerelease: match[4] ? match[4].split('.') : [],
  };
}

/** Semantic Versioning 2.0.0 §11 precedence. */
export function compareReleases(a, b) {
  for (const key of ['major', 'minor', 'patch']) {
    if (a[key] !== b[key]) return a[key] < b[key] ? -1 : 1;
  }
  // A release sorts after every pre-release of the same version.
  if (a.prerelease.length === 0 && b.prerelease.length === 0) return 0;
  if (a.prerelease.length === 0) return 1;
  if (b.prerelease.length === 0) return -1;
  const length = Math.max(a.prerelease.length, b.prerelease.length);
  for (let i = 0; i < length; i++) {
    const x = a.prerelease[i];
    const y = b.prerelease[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    if (x === y) continue;
    const xNumeric = /^\d+$/.test(x);
    const yNumeric = /^\d+$/.test(y);
    if (xNumeric && yNumeric) return Number(x) < Number(y) ? -1 : 1;
    if (xNumeric !== yNumeric) return xNumeric ? -1 : 1;
    return x < y ? -1 : 1;
  }
  return 0;
}

/**
 * The release the break check compares with: the latest release that is not
 * a pre-release. A release candidate (`vX.Y.Z-rc.N`) never becomes the
 * baseline, before or after 1.0: operators upgrade from releases, so a break
 * an rc shipped is still measured against the last release until the release
 * that contains it is tagged, and a 2.0 release candidate is held to the
 * promise of the 1.x line until 2.0 itself ships. Only a history with no
 * release at all falls back to the latest pre-release.
 *
 * @param {string[]} tags tag names reachable from the commit under check
 * @returns {string|null}
 */
export function selectBaselineTag(tags) {
  const releases = tags.map(parseReleaseTag).filter(Boolean);
  const stable = releases.filter((r) => r.prerelease.length === 0);
  const pool = stable.length > 0 ? stable : releases;
  if (pool.length === 0) return null;
  return pool.reduce((latest, r) => (compareReleases(r, latest) > 0 ? r : latest)).tag;
}

// ---------------------------------------------------------------------------
// OpenAPI operations and stability tags
// ---------------------------------------------------------------------------

/** Every operation of an OpenAPI document, keyed `METHOD /path`. */
export function listOperations(doc) {
  const operations = [];
  for (const [path, item] of Object.entries(doc?.paths ?? {})) {
    if (!isObject(item)) continue;
    for (const method of HTTP_METHODS) {
      if (isObject(item[method])) {
        operations.push({
          key: `${method.toUpperCase()} ${path}`,
          method,
          path,
          operation: item[method],
        });
      }
    }
  }
  return operations;
}

/** `METHOD /path` → its valid `x-qauth-stability` value; untagged operations are absent. */
export function stabilityIndex(doc) {
  const index = new Map();
  for (const { key, operation } of listOperations(doc)) {
    const value = operation[STABILITY_EXTENSION];
    if (STABILITIES.includes(value)) index.set(key, value);
  }
  return index;
}

/**
 * The tag check. Every operation of every OpenAPI surface must carry a valid
 * `x-qauth-stability`. A maximal export (`maximalOf`) adds two rules: an
 * operation it has and its default export lacks is registered only behind a
 * switch, and must be `experimental`; an operation both have carries the same
 * tag in both. And the default export it names has no `experimental`
 * operation at all: an experimental route is registered only while its switch
 * is on, and every switch is off there (ADR-018 §5, #477).
 *
 * @param {ReturnType<typeof parseRegistry>} surfaces
 * @param {Map<string, object>} docs surface name → parsed current document
 * @returns {{ problems: Array<{surface: string, file: string, message: string}>,
 *   counts: Map<string, {stable: number, experimental: number}> }}
 */
export function checkStabilityTags(surfaces, docs) {
  const problems = [];
  const counts = new Map();
  const maximalOf = new Map(
    surfaces.filter((surface) => surface.maximalOf).map((surface) => [surface.maximalOf, surface])
  );
  for (const surface of surfaces) {
    if (surface.format !== 'openapi' || !docs.has(surface.name)) continue;
    const doc = docs.get(surface.name);
    const count = { stable: 0, experimental: 0 };
    counts.set(surface.name, count);
    const report = (message) =>
      problems.push({ surface: surface.name, file: surface.path, message });

    for (const { key, operation } of listOperations(doc)) {
      const value = operation[STABILITY_EXTENSION];
      if (value === undefined) {
        report(`${key} has no ${STABILITY_EXTENSION}`);
      } else if (!STABILITIES.includes(value)) {
        report(
          `${key} has ${STABILITY_EXTENSION}: ${JSON.stringify(value)}; expected stable or experimental`
        );
      } else {
        count[value]++;
        if (value === 'experimental' && maximalOf.has(surface.name)) {
          report(
            `${key} is ${STABILITY_EXTENSION}: experimental, but ${surface.name} is the default-flag export of ${maximalOf.get(surface.name).name}; an experimental operation is registered only while its switch is on`
          );
        }
      }
    }

    if (surface.maximalOf && docs.has(surface.maximalOf)) {
      const defaults = stabilityIndex(docs.get(surface.maximalOf));
      const defaultKeys = new Set(listOperations(docs.get(surface.maximalOf)).map((op) => op.key));
      for (const { key, operation } of listOperations(doc)) {
        const value = operation[STABILITY_EXTENSION];
        if (!defaultKeys.has(key)) {
          if (value !== 'experimental') {
            report(
              `${key} is registered only behind a switch (it is not in ${surface.maximalOf}), so it must be ${STABILITY_EXTENSION}: experimental`
            );
          }
        } else if (
          defaults.has(key) &&
          STABILITIES.includes(value) &&
          defaults.get(key) !== value
        ) {
          report(`${key} is ${value} here but ${defaults.get(key)} in ${surface.maximalOf}`);
        }
      }
    }
  }
  return { problems, counts };
}

/** A copy of `doc` without the operations `isExperimental(key, operation)` selects. */
export function withoutOperations(doc, isExperimental) {
  const copy = clone(doc);
  for (const [path, item] of Object.entries(copy.paths ?? {})) {
    if (!isObject(item)) continue;
    for (const method of HTTP_METHODS) {
      if (
        isObject(item[method]) &&
        isExperimental(`${method.toUpperCase()} ${path}`, item[method])
      ) {
        delete item[method];
      }
    }
    if (!HTTP_METHODS.some((method) => isObject(item[method]))) delete copy.paths[path];
  }
  return copy;
}

/**
 * The two documents oasdiff compares for an OpenAPI surface, with the
 * experimental operations taken out of both (ADR-018 §5: experimental items
 * may change in a minor release).
 *
 * Each side is judged by its own tags, so a stable operation that turns
 * experimental leaves the compared baseline with an operation the revision
 * lacks, and is reported as removed. A baseline from a release older than the
 * tags (v0.1.0) has none. Its operations are then stable unless the registry
 * entry's `formerExperimental` names them: a record of what that release kept
 * behind a switch. Today's tags never decide it, or tagging an operation
 * `experimental` in the pull request under check would exempt it.
 *
 * `info` is set alike on both sides: the release tag is the baseline, not
 * `info.version`, and a title or description is no part of the wire contract.
 *
 * @param {{baseline: object, current: object, formerExperimental?: string[]}} documents
 */
export function prepareOpenApiPair({ baseline, current, formerExperimental = [] }) {
  const untaggedExperimental = new Set(formerExperimental);
  const baselineStability = (key, operation) => {
    const own = operation[STABILITY_EXTENSION];
    if (STABILITIES.includes(own)) return own;
    return untaggedExperimental.has(key) ? 'experimental' : 'stable';
  };
  const base = withoutOperations(
    baseline,
    (key, op) => baselineStability(key, op) === 'experimental'
  );
  const revision = withoutOperations(
    current,
    (key, op) => op[STABILITY_EXTENSION] === 'experimental'
  );
  const info = { title: 'QAuth stable surface', version: 'compared' };
  base.info = info;
  revision.info = clone(info);
  return { base, revision };
}

// ---------------------------------------------------------------------------
// JSON Schema surfaces
// ---------------------------------------------------------------------------

const DEFINITION_REF = /^#\/(\$defs|definitions)\/([^/]+)$/;

/**
 * Wrap a JSON Schema file in a one-operation OpenAPI 3.1 document, so oasdiff
 * compares it with the same rules as the API: as the request body for an
 * `input` schema, as the 200 response for an `output` schema, as both for
 * `both`. OpenAPI 3.1 schemas are JSON Schema 2020-12, so the schema goes in
 * unchanged apart from three moves:
 *
 *   - `$defs` (and draft-07 `definitions`) move to `components.schemas`, and
 *     each `#/$defs/Name` reference is rewritten to match; a name defined in
 *     both is refused, since the two references would meet in one place;
 *   - `$id` and `$schema` are dropped from the root: identifiers, not shape,
 *     and a root `$id` would re-base the rewritten references;
 *   - any other reference (`#`, `#/properties/...`, another file) is refused
 *     rather than compared wrongly.
 *
 * @param {object} schema the parsed JSON Schema file
 * @param {{name: string, role: 'input'|'output'|'both'}} surface
 */
export function wrapJsonSchema(schema, { name, role }) {
  if (!isObject(schema)) {
    throw new InputError(`${name}: a json-schema surface must hold one schema object`);
  }
  const { $defs, definitions, ...root } = clone(schema);
  delete root.$id;
  delete root.$schema;
  const clash = Object.keys(definitions ?? {}).filter((key) => Object.hasOwn($defs ?? {}, key));
  if (clash.length > 0) {
    throw new InputError(
      `${name}: ${clash.join(', ')} is defined in both $defs and definitions; keep one`
    );
  }
  const schemas = { ...(definitions ?? {}), ...($defs ?? {}) };

  const rewrite = (node) => {
    if (Array.isArray(node)) return node.map(rewrite);
    if (!isObject(node)) return node;
    const out = {};
    for (const [key, value] of Object.entries(node)) {
      if (key === '$ref' && typeof value === 'string') {
        const match = DEFINITION_REF.exec(value);
        if (!match) {
          throw new InputError(
            `${name}: $ref "${value}" is not supported; reference a definition as #/$defs/<Name>`
          );
        }
        out.$ref = `#/components/schemas/${match[2]}`;
      } else {
        out[key] = rewrite(value);
      }
    }
    return out;
  };

  const body = rewrite(root);
  const content = { 'application/json': { schema: body } };
  const operation = {
    responses:
      role === 'input'
        ? { 204: { description: 'Accepted' } }
        : { 200: { description: 'Emitted', content } },
  };
  if (role !== 'output') operation.requestBody = { required: true, content: clone(content) };

  const doc = {
    openapi: '3.1.0',
    info: { title: name, version: 'compared' },
    paths: { [`/${name}`]: { post: operation } },
  };
  if (Object.keys(schemas).length > 0) {
    doc.components = {
      schemas: Object.fromEntries(Object.entries(schemas).map(([k, v]) => [k, rewrite(v)])),
    };
  }
  return doc;
}

// ---------------------------------------------------------------------------
// Approvals
// ---------------------------------------------------------------------------

const APPROVAL_KEYS = new Set(['surface', 'change', 'ref', 'release']);
const CHANGE_KEYS = new Set(['rule', 'operation', 'fingerprint', 'text']);
const REF_SHAPE = /^(?:#\d+|ADR-\d{3}(?: §\d+(?:\.\d+)*)?)$/;
const FINGERPRINT_SHAPE = /^[0-9a-f]{12}$/;

/**
 * Validate `stable-surface/approved-breaks.json`. An entry names the surface,
 * the change (oasdiff's rule, the operation, the change's fingerprint and its
 * text), the issue or ADR that decided it, and the release that will ship it.
 *
 * An entry is refused — a gate failure, and it approves nothing — when it is
 * malformed, names a surface that is not stable now and was not stable at the
 * baseline, or names a release that is already tagged or is not later than
 * the baseline: a break approved for a release that has shipped can no longer
 * be approved, because clients already have the release without it.
 *
 * @param {unknown} data the parsed file
 * @param {{surfaces: ReturnType<typeof parseRegistry>, tagExists: (tag: string) => boolean,
 *   baselineTag: string|null, baselineSurfaces?: ReturnType<typeof parseRegistry>|null}} context
 */
export function validateApprovals(data, { surfaces, tagExists, baselineTag, baselineSurfaces }) {
  if (!isObject(data) || !Array.isArray(data.approvals)) {
    throw new InputError(`${APPROVALS_PATH}: expected an object with an "approvals" array`);
  }
  const baseline = baselineTag ? parseReleaseTag(baselineTag) : null;
  const stableNow = new Set(surfaces.filter((s) => s.stability === 'stable').map((s) => s.name));
  const stableThen = new Set(
    (baselineSurfaces ?? []).filter((s) => s.stability === 'stable').map((s) => s.name)
  );
  const accepted = [];
  const problems = [];

  data.approvals.forEach((entry, index) => {
    const at = `approvals[${index}]`;
    const reasons = [];
    if (!isObject(entry)) {
      problems.push({ index, message: `${at}: expected an object` });
      return;
    }
    for (const key of Object.keys(entry)) {
      if (!APPROVAL_KEYS.has(key)) reasons.push(`unknown key "${key}"`);
    }
    if (!stableNow.has(entry.surface) && !stableThen.has(entry.surface)) {
      reasons.push(
        `"surface" must name a stable surface, or one that was stable at the baseline (got ${JSON.stringify(entry.surface)})`
      );
    }

    const change = entry.change;
    if (!isObject(change)) {
      reasons.push('"change" must be an object with rule, operation, fingerprint and text');
    } else {
      for (const key of Object.keys(change)) {
        if (!CHANGE_KEYS.has(key)) reasons.push(`unknown key "change.${key}"`);
      }
      if (typeof change.rule !== 'string' || change.rule === '')
        reasons.push('"change.rule" must be the oasdiff rule id');
      if (typeof change.operation !== 'string' || change.operation === '') {
        reasons.push('"change.operation" must be the operation, as "METHOD /path"');
      }
      if (typeof change.fingerprint !== 'string' || !FINGERPRINT_SHAPE.test(change.fingerprint)) {
        reasons.push('"change.fingerprint" must be the 12-character fingerprint the check printed');
      }
      if (typeof change.text !== 'string' || change.text === '') {
        reasons.push('"change.text" must be the text the check printed');
      }
    }
    if (typeof entry.ref !== 'string' || !REF_SHAPE.test(entry.ref)) {
      reasons.push('"ref" must be an issue ("#123") or an ADR ("ADR-018", "ADR-018 §5")');
    }

    const release = typeof entry.release === 'string' ? parseReleaseTag(entry.release) : null;
    if (!release) {
      reasons.push('"release" must be a release tag such as "v0.2.0"');
    } else if (tagExists(entry.release)) {
      reasons.push(
        `release ${entry.release} is already tagged; a break cannot be approved for a release that has shipped`
      );
    } else if (baseline && compareReleases(release, baseline) <= 0) {
      reasons.push(`release ${entry.release} is not later than the baseline ${baselineTag}`);
    }

    if (reasons.length > 0) {
      problems.push({ index, message: `${at}: ${reasons.join('; ')}` });
      return;
    }
    accepted.push({ index, ...entry });
  });

  return { approvals: accepted, problems };
}

/** `METHOD /path` for an oasdiff finding, or its section when it has no operation. */
export function findingOperation(finding) {
  return finding.operation && finding.path
    ? `${finding.operation} ${finding.path}`
    : (finding.section ?? '');
}

/**
 * Split a surface's breaking findings into the approved and the unapproved.
 * An approval lets through exactly one change: one whose fingerprint, rule,
 * operation and text it names, on its surface. Each approval is spent on the
 * first change it matches, so two changes oasdiff cannot tell apart (its
 * fingerprint leaves out the media type) need two entries, and an entry that
 * is never spent is refused by the caller.
 *
 * @param {Set<object>} [used] approvals spent already, shared across surfaces
 */
export function matchApprovals(surfaceName, breaking, approvals, used = new Set()) {
  const approved = [];
  const unapproved = [];
  for (const finding of breaking) {
    const approval = approvals.find(
      (a) =>
        !used.has(a) &&
        a.surface === surfaceName &&
        a.change.fingerprint === finding.fingerprint &&
        a.change.rule === finding.id &&
        a.change.operation === findingOperation(finding) &&
        a.change.text === finding.text
    );
    if (approval) {
      approved.push({ finding, approval });
      used.add(approval);
    } else {
      unapproved.push(finding);
    }
  }
  return { approved, unapproved, used };
}

/** The entry a contributor pastes into approved-breaks.json to approve `finding`. */
export function approvalTemplate(surfaceName, finding) {
  return {
    surface: surfaceName,
    change: {
      rule: finding.id,
      operation: findingOperation(finding),
      fingerprint: finding.fingerprint,
      text: finding.text,
    },
    ref: '#<issue>',
    release: 'v<next release>',
  };
}

// ---------------------------------------------------------------------------
// Break-rule fixtures (the self-test)
// ---------------------------------------------------------------------------

function decodePointer(pointer) {
  if (pointer === '') return [];
  if (!pointer.startsWith('/')) throw new InputError(`"${pointer}" is not a JSON Pointer`);
  return pointer
    .slice(1)
    .split('/')
    .map((token) => token.replace(/~1/g, '/').replace(/~0/g, '~'));
}

/**
 * Apply an RFC 6902 patch limited to `add`, `remove` and `replace` — enough
 * to describe each fixture's change from its base document — to a copy of
 * `doc`. A path that does not resolve throws, so a fixture whose base has
 * moved on cannot silently test nothing.
 */
export function applyJsonPatch(doc, operations) {
  const out = clone(doc);
  for (const { op, path, value } of operations) {
    const tokens = decodePointer(path);
    const last = tokens.pop();
    let parent = out;
    for (const token of tokens) {
      if (parent === null || typeof parent !== 'object' || !(token in parent)) {
        throw new InputError(`patch path ${path} does not resolve`);
      }
      parent = parent[token];
    }
    if (parent === null || typeof parent !== 'object')
      throw new InputError(`patch path ${path} does not resolve`);
    if (Array.isArray(parent)) {
      const index = last === '-' ? parent.length : Number(last);
      if (!Number.isInteger(index) || index < 0 || index > parent.length) {
        throw new InputError(`patch path ${path} does not resolve`);
      }
      if (op === 'add') parent.splice(index, 0, clone(value));
      else if (index >= parent.length) throw new InputError(`patch path ${path} does not resolve`);
      else if (op === 'remove') parent.splice(index, 1);
      else if (op === 'replace') parent[index] = clone(value);
      else throw new InputError(`unsupported patch op "${op}"`);
    } else {
      if (op !== 'add' && !(last in parent))
        throw new InputError(`patch path ${path} does not resolve`);
      if (op === 'add' || op === 'replace') parent[last] = clone(value);
      else if (op === 'remove') delete parent[last];
      else throw new InputError(`unsupported patch op "${op}"`);
    }
  }
  return out;
}

/**
 * Run one break-rule fixture: patch the base document of its format, compare
 * the two exactly as the break check compares a surface, and report whether
 * the error-level rule ids are the ones the fixture expects (`[]`: the change
 * must pass).
 *
 * @param {{name: string, format: 'openapi'|'json-schema', role?: string,
 *   basePatch?: object[], patch: object[], breaks: string[]}} testCase
 *   `basePatch` adjusts the shared base first, for a case that needs a
 *   baseline the base document does not have (a deprecated operation).
 * @param {{openapi: object, 'json-schema': object}} bases
 */
export async function runBreakRuleCase(testCase, bases, differ) {
  const base = applyJsonPatch(bases[testCase.format], testCase.basePatch ?? []);
  const revised = applyJsonPatch(base, testCase.patch);
  const pair =
    testCase.format === 'openapi'
      ? prepareOpenApiPair({ baseline: base, current: revised })
      : {
          base: wrapJsonSchema(base, { name: 'fixture', role: testCase.role }),
          revision: wrapJsonSchema(revised, { name: 'fixture', role: testCase.role }),
        };
  const findings = await differ(pair.base, pair.revision);
  const actual = [
    ...new Set(findings.filter((f) => f.level === LEVEL.ERR).map((f) => f.id)),
  ].sort();
  const expected = [...testCase.breaks].sort();
  return {
    name: testCase.name,
    expected,
    actual,
    ok: actual.length === expected.length && actual.every((id, i) => id === expected[i]),
  };
}

// ---------------------------------------------------------------------------
// The checks, end to end
// ---------------------------------------------------------------------------

/**
 * Run the selected checks against the repository at `root`.
 *
 * @param {object} options
 * @param {string} options.root repository root
 * @param {{drift?: boolean, tags?: boolean, breaks?: boolean}} options.steps
 * @param {string} [options.baselineRef] compare with this ref instead of the latest release tag
 * @param {{ releaseTags: () => string[], tagExists: (tag: string) => boolean,
 *   show: (ref: string, path: string) => string|null,
 *   diff: (before: string, after: string, path: string) => string }} options.git
 * @param {(command: string) => {status: number, output: string}} options.runCommand
 * @param {(base: object, revision: object) => Promise<Array<object>>} options.differ
 *   oasdiff's `changelog` findings for two OpenAPI documents
 * @param {boolean} [options.requireBaseline] fail, rather than pass, when no
 *   release tag is reachable: CI sets it, so a checkout without tags cannot
 *   turn the break check into a no-op
 */
export async function runChecks({
  root,
  steps,
  baselineRef,
  requireBaseline = false,
  git,
  runCommand,
  differ,
}) {
  const surfaces = parseRegistry(readJsonFile(root, REGISTRY_PATH));
  const approvalsData = readJsonFile(root, APPROVALS_PATH);
  const report = {
    surfaces: surfaces.map((surface) => ({ surface })),
    baseline: null,
    tagProblems: [],
    withdrawn: [],
    approvalProblems: [],
    approvalsUsed: [],
    errors: [],
  };
  const entry = (name) => report.surfaces.find((s) => s.surface.name === name);

  if (steps.drift) checkDrift({ root, surfaces, git, runCommand, entry, report });

  const docs = new Map();
  for (const surface of surfaces) {
    try {
      docs.set(surface.name, readJsonFile(root, surface.path));
    } catch (error) {
      report.errors.push(`${surface.name}: ${error.message}`);
    }
  }

  if (steps.tags) {
    const { problems, counts } = checkStabilityTags(surfaces, docs);
    report.tagProblems = problems;
    for (const [name, count] of counts) entry(name).tags = count;
  }

  if (steps.breaks) {
    const tag = baselineRef ? null : selectBaselineTag(git.releaseTags());
    const ref = baselineRef ?? tag;
    report.baseline = ref
      ? { ref, reason: baselineRef ? 'given with --baseline' : 'latest release tag' }
      : null;
    if (!ref && requireBaseline) {
      report.errors.push(
        'no release tag is reachable from HEAD, so there is nothing to compare with; fetch the tags (a full-history checkout)'
      );
    }

    // The registry as the baseline release had it. A surface that was stable
    // there cannot leave the check by being renamed, demoted or deleted here.
    const baselineSurfaces = ref ? readBaselineRegistry(git, ref) : null;

    const { approvals, problems } = validateApprovals(approvalsData, {
      surfaces,
      tagExists: git.tagExists,
      baselineTag: baselineRef && parseReleaseTag(baselineRef) ? baselineRef : tag,
      baselineSurfaces,
    });
    report.approvalProblems = problems.map((p) => p.message);

    const used = new Set();
    for (const former of baselineSurfaces ?? []) {
      const now = surfaces.find((s) => s.name === former.name);
      if (now?.stability === 'stable') continue;
      const finding = withdrawnFinding(former.name, now);
      const { approved } = matchApprovals(former.name, [finding], approvals, used);
      report.withdrawn.push({
        name: former.name,
        path: former.path,
        finding,
        approval: approved[0]?.approval ?? null,
      });
    }

    for (const surface of surfaces) {
      const result = entry(surface.name);
      if (surface.stability !== 'stable') {
        result.breaks = { status: 'not-checked' };
        continue;
      }
      if (!docs.has(surface.name)) continue;
      if (!ref) {
        result.breaks = { status: 'no-baseline', note: 'no release tag to compare with' };
        continue;
      }
      try {
        result.breaks = await compareSurface({
          surface,
          formerPath: baselineSurfaces?.find((s) => s.name === surface.name)?.path,
          docs,
          ref,
          git,
          differ,
          approvals,
          used,
        });
      } catch (error) {
        report.errors.push(`${surface.name}: ${error.message}`);
      }
    }
    for (const approval of approvals) {
      if (!used.has(approval)) {
        report.approvalProblems.push(
          `approvals[${approval.index}]: approves ${approval.change.rule} on ${approval.change.operation} in ${approval.surface}, but the check found no such break; remove the entry`
        );
      } else {
        report.approvalsUsed.push(approval);
      }
    }
  }

  return report;
}

function checkDrift({ root, surfaces, git, runCommand, entry, report }) {
  const before = new Map();
  for (const surface of surfaces) {
    try {
      before.set(surface.name, readFileSync(join(root, surface.path), 'utf8'));
    } catch {
      before.set(surface.name, null);
    }
  }

  const failedGenerators = new Set();
  for (const generator of [...new Set(surfaces.map((s) => s.generator))]) {
    const { status, output } = runCommand(generator);
    if (status !== 0) {
      failedGenerators.add(generator);
      const tail = output.trimEnd().split('\n').slice(-40).join('\n');
      report.errors.push(`generator failed (exit ${status}): ${generator}\n${tail}`);
    }
  }

  for (const surface of surfaces) {
    const result = entry(surface.name);
    if (failedGenerators.has(surface.generator)) {
      result.drift = { status: 'error' };
      continue;
    }
    let after = null;
    try {
      after = readFileSync(join(root, surface.path), 'utf8');
    } catch {
      // Reported below.
    }
    const committed = before.get(surface.name);
    if (after === null) {
      result.drift = { status: 'error' };
      report.errors.push(`${surface.name}: the generator did not write ${surface.path}`);
    } else if (committed === null) {
      result.drift = {
        status: 'drift',
        diff: git.diff('', after, surface.path),
        note: 'not committed',
      };
    } else if (committed !== after) {
      result.drift = { status: 'drift', diff: git.diff(committed, after, surface.path) };
    } else {
      result.drift = { status: 'ok' };
    }
  }
}

/**
 * The stable surfaces of the registry at `ref`, or null when that release had
 * no registry (v0.1.0). Read leniently — only `name`, `path` and `stability`
 * — so a later change to the registry's shape cannot make an old release
 * unreadable.
 */
function readBaselineRegistry(git, ref) {
  const text = git.show(ref, REGISTRY_PATH);
  if (text === null) return null;
  const data = parseJsonText(text, `${ref}:${REGISTRY_PATH}`);
  if (!isObject(data) || !Array.isArray(data.surfaces)) {
    throw new InputError(`${ref}:${REGISTRY_PATH}: expected an object with a "surfaces" array`);
  }
  return data.surfaces
    .filter((s) => isObject(s) && s.stability === 'stable')
    .map((s) => ({ name: s.name, path: s.path, stability: s.stability }));
}

/** The break of a surface that was stable at the baseline and is not stable now. */
export function withdrawnFinding(name, now) {
  const id = 'surface-withdrawn';
  return {
    id,
    text: now
      ? 'stable at the baseline, experimental now'
      : 'stable at the baseline, no longer registered',
    level: LEVEL.ERR,
    section: 'surface',
    fingerprint: createHash('sha256').update(`${id}:${name}`).digest('hex').slice(0, 12),
  };
}

async function compareSurface({ surface, formerPath, docs, ref, git, differ, approvals, used }) {
  // The registry's own record of where the file was comes last, after the
  // paths an entry lists, so a rename needs no `formerPaths` entry.
  const candidates = [
    ...new Set([surface.path, ...surface.formerPaths, formerPath].filter(Boolean)),
  ];
  let baselineText = null;
  let baselinePath = null;
  for (const candidate of candidates) {
    baselineText = git.show(ref, candidate);
    if (baselineText !== null) {
      baselinePath = candidate;
      break;
    }
  }
  if (baselineText === null) {
    if (formerPath) {
      throw new InputError(`stable at ${ref}, but none of ${candidates.join(', ')} is in ${ref}`);
    }
    return {
      status: 'no-baseline',
      note: `${surface.path} is not in ${ref}; the first release that contains it becomes its baseline`,
    };
  }
  const baseline = parseJsonText(baselineText, `${ref}:${baselinePath}`);
  const current = docs.get(surface.name);

  const pair =
    surface.format === 'openapi'
      ? prepareOpenApiPair({ baseline, current, formerExperimental: surface.formerExperimental })
      : { base: wrapJsonSchema(baseline, surface), revision: wrapJsonSchema(current, surface) };

  const findings = await differ(pair.base, pair.revision);
  const breaking = findings.filter((f) => f.level === LEVEL.ERR);
  const { approved, unapproved } = matchApprovals(surface.name, breaking, approvals, used);
  return {
    status: unapproved.length > 0 ? 'breaks' : 'ok',
    source: `${ref}:${baselinePath}`,
    approved,
    unapproved,
    warnings: findings.filter((f) => f.level === LEVEL.WARN),
    changes: findings.filter((f) => f.level === LEVEL.INFO),
  };
}

/** 0 clean, 1 a gate failure, 2 the check could not run. */
export function exitCodeOf(report) {
  if (report.errors.length > 0) return 2;
  const failed =
    report.tagProblems.length > 0 ||
    report.approvalProblems.length > 0 ||
    report.withdrawn.some((w) => !w.approval) ||
    report.surfaces.some((s) => s.drift?.status === 'drift' || s.breaks?.status === 'breaks');
  return failed ? 1 : 0;
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

const MAX_DIFF_LINES = 400;

/** One Markdown table cell. Backslashes go first, so a `\` already before a `|` cannot unescape it. */
export const escapeCell = (text) =>
  String(text).replace(/\\/g, '\\\\').replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');

function truncate(diff) {
  const lines = diff.split('\n');
  if (lines.length <= MAX_DIFF_LINES) return diff;
  return `${lines.slice(0, MAX_DIFF_LINES).join('\n')}\n… ${lines.length - MAX_DIFF_LINES} more lines`;
}

function driftCell(result) {
  if (!result.drift) return 'not run';
  return { ok: 'none', drift: '**drift**', error: '**error**' }[result.drift.status];
}

function tagsCell(result) {
  if (result.surface.format !== 'openapi') return 'n/a';
  if (!result.tags) return 'not run';
  return `${result.tags.stable} stable, ${result.tags.experimental} experimental`;
}

function breaksCell(result) {
  const breaks = result.breaks;
  if (!breaks) return 'not run';
  switch (breaks.status) {
    case 'not-checked':
      return 'not checked (experimental)';
    case 'no-baseline':
      return 'no baseline';
    case 'ok':
      return breaks.approved.length > 0
        ? `none unapproved (${breaks.approved.length} approved)`
        : 'none';
    default:
      return `**${breaks.unapproved.length} unapproved**`;
  }
}

/** The Markdown job summary. */
export function renderSummary(report) {
  const lines = ['## Stable surface', ''];
  lines.push(
    report.baseline
      ? `Baseline: \`${report.baseline.ref}\` (${report.baseline.reason}).`
      : 'Baseline: none (the break check did not run, or no release tag exists).',
    ''
  );
  lines.push(
    '| Surface | Path | Stability | Drift | Stability tags | Breaks |',
    '| --- | --- | --- | --- | --- | --- |'
  );
  for (const result of report.surfaces) {
    const { surface } = result;
    lines.push(
      `| ${surface.name} | \`${surface.path}\` | ${surface.stability} | ${driftCell(result)} | ${tagsCell(result)} | ${breaksCell(result)} |`
    );
  }
  lines.push('');

  if (report.errors.length > 0) {
    lines.push('### Errors', '');
    for (const error of report.errors) lines.push('```', error, '```', '');
  }

  if (report.tagProblems.length > 0) {
    lines.push('### Stability tags', '');
    for (const p of report.tagProblems) lines.push(`- \`${p.file}\`: ${p.message}`);
    lines.push('');
  }

  if (report.withdrawn.length > 0) {
    lines.push(`### Surfaces stable at \`${report.baseline.ref}\` and not stable now`, '');
    for (const w of report.withdrawn) {
      lines.push(
        w.approval
          ? `- ✅ ${w.name} (\`${w.path}\`): ${w.finding.text}; approved for ${w.approval.release}, ${w.approval.ref}`
          : `- ❌ ${w.name} (\`${w.path}\`): ${w.finding.text}; not approved`
      );
    }
    const unapproved = report.withdrawn.filter((w) => !w.approval);
    if (unapproved.length > 0) {
      lines.push(
        '',
        `To withdraw a stable surface on purpose, add its entry to \`${APPROVALS_PATH}\`:`,
        '',
        '```json',
        JSON.stringify(
          unapproved.map((w) => approvalTemplate(w.name, w.finding)),
          null,
          2
        ),
        '```'
      );
    }
    lines.push('');
  }

  if (report.approvalProblems.length > 0) {
    lines.push(`### Refused approvals (\`${APPROVALS_PATH}\`)`, '');
    for (const message of report.approvalProblems) lines.push(`- ${message}`);
    lines.push('');
  }

  for (const result of report.surfaces) {
    const breaks = result.breaks;
    if (!breaks || breaks.status === 'not-checked') continue;
    if (breaks.status === 'no-baseline') {
      lines.push(`### ${result.surface.name}: no baseline`, '', breaks.note, '');
      continue;
    }
    const all = [
      ...breaks.unapproved,
      ...breaks.approved.map((a) => a.finding),
      ...breaks.warnings,
      ...breaks.changes,
    ];
    lines.push(`### ${result.surface.name}: changes since \`${breaks.source}\``, '');
    if (all.length === 0) {
      lines.push('No change to the stable operations.', '');
      continue;
    }
    lines.push('| | Rule | Operation | Change | Approval |', '| --- | --- | --- | --- | --- |');
    for (const f of breaks.unapproved) {
      lines.push(
        `| ❌ break | \`${f.id}\` | ${escapeCell(findingOperation(f))} | ${escapeCell(f.text)} | not approved |`
      );
    }
    for (const { finding: f, approval } of breaks.approved) {
      lines.push(
        `| ✅ approved break | \`${f.id}\` | ${escapeCell(findingOperation(f))} | ${escapeCell(f.text)} | ${approval.release}, ${approval.ref} |`
      );
    }
    for (const f of breaks.warnings) {
      lines.push(
        `| ⚠️ warning | \`${f.id}\` | ${escapeCell(findingOperation(f))} | ${escapeCell(f.text)} | |`
      );
    }
    for (const f of breaks.changes) {
      lines.push(
        `| compatible | \`${f.id}\` | ${escapeCell(findingOperation(f))} | ${escapeCell(f.text)} | |`
      );
    }
    lines.push('');
    if (breaks.unapproved.length > 0) {
      lines.push(
        `To approve a break, add its entry to \`${APPROVALS_PATH}\` with the issue or ADR that decided it and the release that will ship it:`,
        '',
        '```json'
      );
      lines.push(
        JSON.stringify(
          breaks.unapproved.map((f) => approvalTemplate(result.surface.name, f)),
          null,
          2
        )
      );
      lines.push('```', '');
    }
  }

  for (const result of report.surfaces) {
    if (result.drift?.status !== 'drift') continue;
    lines.push(
      `### Drift: \`${result.surface.path}\``,
      '',
      `The committed file is not what \`${result.surface.generator}\` writes. Run it and commit the result.`,
      '',
      '```diff',
      truncate(result.drift.diff),
      '```',
      ''
    );
  }
  return lines.join('\n');
}

/** CI log annotations: one `{level, file, message}` per failure or warning. */
export function annotations(report) {
  const out = [];
  for (const error of report.errors)
    out.push({ level: 'error', file: undefined, message: error.split('\n')[0] });
  for (const p of report.tagProblems)
    out.push({ level: 'error', file: p.file, message: p.message });
  for (const message of report.approvalProblems)
    out.push({ level: 'error', file: APPROVALS_PATH, message });
  for (const w of report.withdrawn) {
    if (w.approval) continue;
    out.push({
      level: 'error',
      file: REGISTRY_PATH,
      message: `${w.name} was ${w.finding.text} [${w.finding.id}, fingerprint ${w.finding.fingerprint}] — not approved in ${APPROVALS_PATH}`,
    });
  }
  for (const { surface, drift, breaks } of report.surfaces) {
    if (drift?.status === 'drift') {
      out.push({
        level: 'error',
        file: surface.path,
        message: `${surface.path} differs from what \`${surface.generator}\` writes; run it and commit the result`,
      });
    }
    for (const f of breaks?.unapproved ?? []) {
      out.push({
        level: 'error',
        file: surface.path,
        message: `${surface.name}: ${findingOperation(f)} ${f.text} [${f.id}, fingerprint ${f.fingerprint}] — not approved in ${APPROVALS_PATH}`,
      });
    }
    for (const f of breaks?.warnings ?? []) {
      out.push({
        level: 'warning',
        file: surface.path,
        message: `${surface.name}: ${findingOperation(f)} ${f.text} [${f.id}]`,
      });
    }
  }
  return out;
}

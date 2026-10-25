/**
 * SDK releases to npm (#596, ADR-018 §6): the rules a packed SDK tarball must
 * pass before it is staged, without the process glue. `check-package.mjs` and
 * `smoke.mjs` are the CLIs the `release-npm` workflow runs; this module takes
 * plain values so the tests can drive every rule offline.
 *
 * An SDK lives in `libs/sdk/<project>`, is released on its own version, and is
 * tagged `<project>@<version>`.
 *
 * Zero runtime dependencies — Node's standard library only.
 */

/** A version QAuth releases before 1.0: `0.Y.Z` or the release candidate `0.Y.Z-rc.N`. */
const VERSION = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-rc\.(0|[1-9]\d*))?$/;

/** A problem with a tag, a version or a packed package. */
export class SdkReleaseError extends Error {
  constructor(message) {
    super(message);
    this.name = 'SdkReleaseError';
  }
}

/**
 * The npm dist-tag a version goes to. A release candidate goes to `next`, a
 * release to `latest`. Before 1.0 nothing is covered by the stability promise
 * (ADR-018 §5), so a 1.x version is refused until that review has happened.
 */
export function distTagFor(version) {
  const match = VERSION.exec(version);
  if (!match) {
    throw new SdkReleaseError(`${version} is not a release version (X.Y.Z or X.Y.Z-rc.N)`);
  }
  if (match[1] !== '0') {
    throw new SdkReleaseError(
      `${version}: an SDK stays on 0.x until the 1.0 stability review (ADR-018 §5)`
    );
  }
  return match[4] === undefined ? 'latest' : 'next';
}

/** `<project>@<version>` → `{ project, version }`, for a project in `projects`. */
export function parseReleaseTag(tag, projects) {
  const at = tag.lastIndexOf('@');
  if (at <= 0) throw new SdkReleaseError(`${tag} is not an SDK release tag (<project>@<version>)`);
  const project = tag.slice(0, at);
  const version = tag.slice(at + 1);
  if (!projects.includes(project)) {
    throw new SdkReleaseError(
      `${tag}: ${project} is not an SDK project (${projects.join(', ') || 'none'})`
    );
  }
  distTagFor(version);
  return { project, version };
}

/** Only these files may be in a tarball: the manifest, README, LICENSE and compiled `dist/`. */
const ALLOWED_FILE =
  /^package\/(package\.json|README\.md|LICENSE|dist\/(?:[\w.-]+\/)*[\w.-]+\.(?:js|d\.ts))$/;

/**
 * Files that never belong in a published package, wherever they sit (even
 * under `dist/`), with the reason a message names.
 */
function forbiddenReason(file) {
  if (/(^|\/)\.env(\.|$)/.test(file)) return 'an environment file';
  if (
    /\.(test|spec)\.(?:d\.)?[cm]?[jt]sx?$/.test(file) ||
    /(^|\/)__(tests|fixtures)__\//.test(file)
  ) {
    return 'a test file';
  }
  if (/\.map$/.test(file)) return 'a source map';
  return undefined;
}

/** Why a file outside the allowed set is there, for a message that says what to fix. */
function reasonFor(file) {
  if (/\.[cm]?tsx?$/.test(file) && !/\.d\.ts$/.test(file)) return 'a TypeScript source';
  return 'not in the allowed set (package.json, README.md, LICENSE, dist/**/*.js, dist/**/*.d.ts)';
}

/** Problems with the list of files a tarball holds (paths as `tar -t` prints them). */
export function checkFileList(files) {
  const problems = [];
  for (const file of files) {
    if (file.endsWith('/')) continue;
    const forbidden = forbiddenReason(file);
    if (forbidden) problems.push(`${file}: ${forbidden}`);
    else if (!ALLOWED_FILE.test(file)) problems.push(`${file}: ${reasonFor(file)}`);
  }
  for (const required of ['package/package.json', 'package/README.md', 'package/LICENSE']) {
    if (!files.includes(required)) problems.push(`${required} is missing`);
  }
  if (!files.some((file) => /^package\/dist\/.+\.js$/.test(file))) {
    problems.push('package/dist holds no JavaScript: was the npm build run before packing?');
  }
  return problems;
}

/** Problems with the content of one packed file. */
export function checkFileContent(file, text) {
  const problems = [];
  if (/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(text))
    problems.push(`${file}: holds a private key`);
  if (/sourceMappingURL=/.test(text)) problems.push(`${file}: points at a source map`);
  if (/(?:^|[\s'"(])\/(?:home|Users|tmp|runner)\/[\w.-]+\//m.test(text)) {
    problems.push(`${file}: holds an absolute build-machine path`);
  }
  return problems;
}

const isObject = (value) => typeof value === 'object' && value !== null && !Array.isArray(value);

/** A path in the manifest that must point into `./dist`. */
const inDist = (path) => typeof path === 'string' && path.startsWith('./dist/');

/** Problems with a packed `package.json` (the published manifest, not the workspace one). */
export function checkManifest(manifest, { projectRoot, version }) {
  const problems = [];
  const need = (ok, message) => {
    if (!ok) problems.push(message);
  };

  need(
    typeof manifest.name === 'string' && manifest.name.startsWith('@qauth-labs/'),
    'name must be in the @qauth-labs scope'
  );
  need(manifest.version === version, `version is ${manifest.version}, the tag says ${version}`);
  need(manifest.private !== true, 'private: true cannot be published');
  need(manifest.type === 'module', 'type must be "module": the build is ESM');
  need(manifest.license === 'Apache-2.0', 'license must be Apache-2.0');
  need(
    isObject(manifest.engines) && typeof manifest.engines.node === 'string',
    'engines.node is missing'
  );
  need(
    isObject(manifest.repository) &&
      typeof manifest.repository.url === 'string' &&
      manifest.repository.directory === projectRoot,
    `repository needs url and directory "${projectRoot}"`
  );
  need(typeof manifest.homepage === 'string', 'homepage is missing');
  need(inDist(manifest.main), 'main must point into ./dist');
  need(inDist(manifest.types), 'types must point into ./dist');
  need(Array.isArray(manifest.files) && manifest.files.includes('dist'), 'files must list dist');

  if (!isObject(manifest.exports) || !isObject(manifest.exports['.'])) {
    problems.push('exports must map "." to { types, import }');
  } else {
    for (const [entry, target] of Object.entries(manifest.exports)) {
      if (entry === './package.json') continue;
      if (!isObject(target) || !inDist(target.types) || !inDist(target.import)) {
        problems.push(`exports["${entry}"] must give types and import inside ./dist`);
      }
    }
  }

  for (const field of ['dependencies', 'peerDependencies', 'optionalDependencies']) {
    for (const [name, range] of Object.entries(manifest[field] ?? {})) {
      if (name.startsWith('@qauth-labs/')) {
        problems.push(`${field}.${name}: an SDK depends on no workspace package`);
      }
      if (/^(workspace|catalog|link|file):/.test(String(range))) {
        problems.push(`${field}.${name}: "${range}" was not resolved by pnpm pack`);
      }
    }
  }
  for (const name of Object.keys(manifest.peerDependenciesMeta ?? {})) {
    need(
      Object.hasOwn(manifest.peerDependencies ?? {}, name),
      `peerDependenciesMeta.${name} has no peerDependencies entry`
    );
  }
  return problems;
}

/**
 * The value exports `api-report.md` lists per entry point:
 * `{ '@qauth-labs/x': ['A', 'b'], '@qauth-labs/x/sub': [...] }`. Type-only names
 * are left out: they do not exist at run time.
 */
export function valueExportsFromReport(markdown) {
  const report = {};
  let entry;
  for (const line of markdown.split('\n')) {
    const heading = /^## `([^`]+)`/.exec(line);
    if (heading) {
      entry = heading[1];
      report[entry] = [];
      continue;
    }
    const item = /^- `([^`]+)`( \(type\))?$/.exec(line);
    if (item && entry !== undefined && item[2] === undefined) report[entry].push(item[1]);
  }
  return report;
}

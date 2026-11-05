/**
 * SDK releases to npm (#596, ADR-018 §6): the rules a packed SDK tarball must
 * pass before it is staged, without the process glue. `plan.mjs`,
 * `check-package.mjs` and `smoke.mjs` are the CLIs the `release-npm` workflow
 * runs; this module takes plain values so the tests can drive every rule
 * offline.
 *
 * Every SDK in `libs/sdk/<project>` is published at QAuth's own version, from
 * QAuth's release tag `vX.Y.Z` or `vX.Y.Z-rc.N`, the tag that also publishes
 * the server images. Its release notes are QAuth's CHANGELOG section for that
 * version. The workspace package.json files stay at 0.0.0; the release job
 * writes the tag's version into the package it packs.
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

/** QAuth's release tag `vX.Y.Z` or `vX.Y.Z-rc.N` → its version, checked by {@link distTagFor}. */
export function parseReleaseTag(tag) {
  if (!tag.startsWith('v')) {
    throw new SdkReleaseError(`${tag} is not a QAuth release tag (vX.Y.Z or vX.Y.Z-rc.N)`);
  }
  const version = tag.slice(1);
  distTagFor(version);
  return version;
}

/**
 * The name in a `## [X.Y.Z]` heading, or in its escaped Markdown form
 * `## \\[X.Y.Z\\]`; `undefined` for any other line.
 */
const headingName = (line) => /^## \\?\[([^\\\]]+)\\?\]/.exec(line)?.[1];

/** The `## [X.Y.Z]` release headings of QAuth's CHANGELOG, newest first. */
function releaseHeadings(changelog) {
  return changelog
    .split('\n')
    .map(headingName)
    .filter((version) => version !== undefined && version !== 'Unreleased');
}

/** The newest version the CHANGELOG has a section for (the dry run stamps this one). */
export function latestReleasedVersion(changelog) {
  const [latest] = releaseHeadings(changelog);
  if (latest === undefined) throw new SdkReleaseError('CHANGELOG.md has no `## [X.Y.Z]` section');
  return latest;
}

/** Whether the CHANGELOG has the `## [version]` section a stable release needs. */
export function hasReleaseSection(changelog, version) {
  return releaseHeadings(changelog).includes(version);
}

/** The CHANGELOG heading that holds `version`'s notes: its own, or `Unreleased` for a candidate. */
const notesHeading = (version) => (version.includes('-rc.') ? 'Unreleased' : version);

/** The index of the `## [heading]` line in `lines`; throws when there is none. */
function sectionStart(lines, heading) {
  const start = lines.findIndex((line) => headingName(line) === heading);
  if (start === -1) throw new SdkReleaseError(`CHANGELOG.md has no \`## [${heading}]\` section`);
  return start;
}

/**
 * The release notes for `version`: its CHANGELOG section, or for a release
 * candidate (which has none) the `## [Unreleased]` section it ships.
 */
export function releaseNotes(changelog, version) {
  const lines = changelog.split('\n');
  const start = sectionStart(lines, notesHeading(version));
  const end = lines.findIndex((line, i) => i > start && line.startsWith('## '));
  return lines
    .slice(start + 1, end === -1 ? undefined : end)
    .join('\n')
    .trim();
}

/**
 * The anchor the repository host gives a heading's text: lowercased, with
 * every character but letters, digits, `_`, `-` and spaces dropped, then each
 * space a hyphen. Brackets and backslash escapes go with the punctuation, so
 * `[0.1.3] - 2026-10-21` and its escaped form both give `013---2026-10-21`.
 */
const headingAnchor = (text) =>
  text
    .trim()
    .toLowerCase()
    .replace(/[^\p{L}\p{M}\p{N}_ -]/gu, '')
    .replace(/ /g, '-');

/**
 * Where `version`'s notes start in CHANGELOG.md as the repository host
 * renders it: `unreleased` for a release candidate, and for a release the
 * anchor of its own heading, date included (`## [0.1.3] - 2026-10-21` →
 * `013---2026-10-21`).
 */
export function changelogAnchor(changelog, version) {
  const lines = changelog.split('\n');
  return headingAnchor(lines[sectionStart(lines, notesHeading(version))].slice(3));
}

/** The file the draft release attaches with `version`'s notes in full. */
export const releaseNotesFileName = (version) => `release-notes-${version}.md`;

/** The docs page every upgrade follows: back up, run the migration runner, start. */
export const UPGRADE_GUIDE_URL = 'https://docs.qauth.dev/operate/upgrades/';

/** A repository's web address, `https://<host>/<owner>/<name>`, as the workflow builds it. */
const REPOSITORY_URL = /^https:\/\/[\w.-]+(?::\d+)?(?:\/[\w.-]+){2}$/;

/**
 * The body of the draft release for `version`. The repository host refuses a
 * release body over 125,000 characters and the 0.2 notes are past that, so the
 * body never holds the notes: it links their section of CHANGELOG.md at the
 * tag and names the attached file that carries them in full. Its length does
 * not depend on the CHANGELOG's. `repositoryUrl` is the repository's web
 * address, `https://<host>/<owner>/<name>`.
 */
export function releaseBody(changelog, version, repositoryUrl) {
  const distTag = distTagFor(version);
  if (!REPOSITORY_URL.test(repositoryUrl)) {
    throw new SdkReleaseError(
      `${repositoryUrl} is not a repository address (https://<host>/<owner>/<name>)`
    );
  }
  const tag = `v${version}`;
  const kind =
    distTag === 'next'
      ? `a release candidate for ${version.replace(/-rc\.\d+$/, '')}`
      : 'a release';
  const notesUrl = `${repositoryUrl}/blob/${tag}/CHANGELOG.md#${changelogAnchor(changelog, version)}`;
  return [
    `QAuth \`${version}\` is ${kind}.`,
    '',
    `**Release notes:** the [\`${notesHeading(version)}\` section of CHANGELOG.md](${notesUrl}) ` +
      `at \`${tag}\`, attached in full to this release as \`${releaseNotesFileName(version)}\`.`,
    '',
    `**Upgrading:** follow the [upgrade guide](${UPGRADE_GUIDE_URL}): back up the database, ` +
      "run the new version's migration runner, then start the new version.",
    '',
    '---',
    '',
    `The SDK packages are staged on npm as \`${version}\` (dist-tag \`${distTag}\`), with ` +
      'provenance. They go live when a maintainer approves each stage on npmjs.com with 2FA; ' +
      'publish this draft after that. The server images and their digests are in the ' +
      'release-images run of the same tag.',
    '',
  ].join('\n');
}

/**
 * The two files the draft release is made from: `release-body.md`, the short
 * body {@link releaseBody} builds, and `release-notes-<version>.md`, the
 * notes {@link releaseNotes} gives, attached beside the SDK tarballs.
 */
export function releaseFiles(changelog, version, repositoryUrl) {
  return [
    { name: 'release-body.md', text: releaseBody(changelog, version, repositoryUrl) },
    { name: releaseNotesFileName(version), text: `${releaseNotes(changelog, version)}\n` },
  ];
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

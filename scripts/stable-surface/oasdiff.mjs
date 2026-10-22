/**
 * oasdiff (https://github.com/oasdiff/oasdiff, Apache-2.0), pinned.
 *
 * The break check compares OpenAPI documents with oasdiff, a maintained Go
 * tool with full OpenAPI 3.1 / JSON Schema 2020-12 support since v1.15.0. It
 * ships as a release binary, not an npm package — the `oasdiff` name on npm is
 * a security placeholder for a removed malicious package, so never install
 * that. This module downloads the pinned asset from the project's release
 * page, caches it under `node_modules/.cache/oasdiff/`, and checks it against
 * the SHA-256 recorded below each time before unpacking it.
 *
 * Version choice: 1.33.0 (2026-10-01). Both published advisories are fixed
 * well before it — GHSA-2jcc-mxv7-p3f9 (`--allow-external-refs=false` not
 * enforced on the git-revision load path, fixed in 1.18.1) and
 * GHSA-m3wq-w7x2-4q6m (a git revision parsed as a git option, fixed in
 * 1.26.1). This module also never hands oasdiff a git revision: it writes both
 * documents to a temporary directory and passes file paths, with
 * `--allow-external-refs=false`.
 *
 * To upgrade: change OASDIFF_VERSION and every hash below to the new
 * release's `checksums.txt`, and run `node scripts/stable-surface/check.mjs
 * --self-test`, which pins the rule ids each fixture must produce.
 */

import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { InputError, severityLevelsFile } from './lib.mjs';

export const OASDIFF_VERSION = '1.33.0';

/** Release assets by `${process.platform}-${process.arch}`, with their SHA-256. */
const ASSETS = {
  'linux-x64': {
    file: 'oasdiff_1.33.0_linux_amd64.tar.gz',
    sha256: '43a4e328e2d13ba1552d760aa68d2485c75c5621f309f6ff64ae895188345247',
  },
  'linux-arm64': {
    file: 'oasdiff_1.33.0_linux_arm64.tar.gz',
    sha256: '4ae3c362d6074d919aada2dea82d0ee84366591600384455d0bdc658ddf8f7ae',
  },
  'darwin-x64': {
    file: 'oasdiff_1.33.0_darwin_all.tar.gz',
    sha256: '2a479337c15afdcbf0b1e89c0b4d0cf0176472dbc11483358fed1f831d1e46c5',
  },
  'darwin-arm64': {
    file: 'oasdiff_1.33.0_darwin_all.tar.gz',
    sha256: '2a479337c15afdcbf0b1e89c0b4d0cf0176472dbc11483358fed1f831d1e46c5',
  },
  'win32-x64': {
    file: 'oasdiff_1.33.0_windows_amd64.tar.gz',
    sha256: '22f98c7247075f8a446e783595802d6d38637de1760df264f3d4b3309f766c5b',
  },
  'win32-arm64': {
    file: 'oasdiff_1.33.0_windows_arm64.tar.gz',
    sha256: 'd51bd1ea4b05ff9b314245d1e97f84c222b22ce34a930e8e305c68c32edbe951',
  },
};

const BINARY = process.platform === 'win32' ? 'oasdiff.exe' : 'oasdiff';

function reportedVersion(binary) {
  const result = spawnSync(binary, ['--version'], { encoding: 'utf8' });
  return result.status === 0 ? result.stdout.trim() : null;
}

/**
 * The path of a verified oasdiff binary at {@link OASDIFF_VERSION}.
 *
 * The cache under `node_modules/.cache/oasdiff/` keeps the release archive,
 * not the binary, and the archive is checked against its pinned SHA-256 on
 * every run before it is unpacked into a fresh temporary directory, so a
 * binary that something else wrote into the cache is never run.
 *
 * `OASDIFF_BIN` may point at an installed binary instead, for a machine with no
 * network; it must report exactly the pinned version, because the rule ids
 * and levels the gate relies on change between releases.
 */
export async function ensureOasdiff(root) {
  const expected = `oasdiff version ${OASDIFF_VERSION}`;
  if (process.env.OASDIFF_BIN) {
    const version = reportedVersion(process.env.OASDIFF_BIN);
    if (version !== expected) {
      throw new InputError(
        `OASDIFF_BIN=${process.env.OASDIFF_BIN} reports "${version ?? 'nothing'}"; the check needs ${expected}`
      );
    }
    return process.env.OASDIFF_BIN;
  }

  const asset = ASSETS[`${process.platform}-${process.arch}`];
  if (!asset) {
    throw new InputError(
      `no pinned oasdiff build for ${process.platform}-${process.arch}; install oasdiff ${OASDIFF_VERSION} and set OASDIFF_BIN`
    );
  }
  const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
  const cacheDir = join(root, 'node_modules', '.cache', 'oasdiff');
  const cached = join(cacheDir, asset.file);

  let archive = existsSync(cached) ? readFileSync(cached) : null;
  if (archive === null || sha256(archive) !== asset.sha256) {
    const url = `https://github.com/oasdiff/oasdiff/releases/download/v${OASDIFF_VERSION}/${asset.file}`;
    try {
      const response = await fetch(url);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      archive = Buffer.from(await response.arrayBuffer());
    } catch (error) {
      throw new InputError(`cannot download ${url}: ${error.message}`);
    }
    const digest = sha256(archive);
    if (digest !== asset.sha256) {
      throw new InputError(
        `${asset.file} has SHA-256 ${digest}, expected ${asset.sha256}; refusing to run it`
      );
    }
    mkdirSync(cacheDir, { recursive: true });
    writeFileSync(cached, archive);
  }

  const dir = mkdtempSync(join(tmpdir(), 'oasdiff-'));
  process.once('exit', () => rmSync(dir, { recursive: true, force: true }));
  writeFileSync(join(dir, asset.file), archive);
  const untar = spawnSync('tar', ['-xzf', asset.file, BINARY], { cwd: dir, encoding: 'utf8' });
  if (untar.status !== 0) throw new InputError(`cannot unpack ${asset.file}: ${untar.stderr}`);
  const binary = join(dir, BINARY);
  chmodSync(binary, 0o755);
  if (reportedVersion(binary) !== expected) {
    throw new InputError(`the unpacked ${binary} does not report ${expected}`);
  }
  return binary;
}

/**
 * A differ for `runChecks`: oasdiff's `changelog` of two OpenAPI documents,
 * every level included, with {@link RAISED_TO_BREAK} raised to errors.
 *
 * oasdiff runs in an empty temporary directory with `OASDIFF_CONFIG` removed
 * from its environment, so no `.oasdiff.*` file can change its rules.
 */
export function oasdiffDiffer(binary) {
  return async (base, revision) => {
    const dir = mkdtempSync(join(tmpdir(), 'stable-surface-'));
    try {
      writeFileSync(join(dir, 'base.json'), JSON.stringify(base));
      writeFileSync(join(dir, 'revision.json'), JSON.stringify(revision));
      writeFileSync(join(dir, 'levels.txt'), severityLevelsFile());
      const env = { ...process.env };
      delete env.OASDIFF_CONFIG;
      const result = spawnSync(
        binary,
        [
          'changelog',
          'base.json',
          'revision.json',
          '--format',
          'json',
          '--severity-levels',
          'levels.txt',
          '--allow-external-refs=false',
        ],
        { cwd: dir, env, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 }
      );
      if (result.status !== 0) {
        throw new InputError(`oasdiff failed (exit ${result.status}): ${result.stderr.trim()}`);
      }
      const findings = JSON.parse(result.stdout.trim() === '' ? '[]' : result.stdout);
      if (!Array.isArray(findings))
        throw new InputError('oasdiff returned something other than a JSON array');
      return findings;
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  };
}

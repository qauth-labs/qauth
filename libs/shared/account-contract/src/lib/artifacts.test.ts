import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join, resolve } from 'node:path';

import { beforeAll, describe, expect, it } from 'vitest';

import {
  ACCOUNT_PAGE_PATH,
  type Artifact,
  contractArtifacts,
  contractFiles,
  EXPORT_COMMAND,
  OPENAPI_PATH,
} from './artifacts';
import { ACCOUNT_OPENAPI } from './openapi';
import {
  ACT_CHAIN_RULES_TEXT,
  API_RULES,
  FRESH_AUTHENTICATION_RULES_TEXT,
  STATUS_RULES,
  TOKEN_RULES,
  VERSIONING_RULES,
} from './rules';

const REPO_ROOT = resolve(__dirname, '..', '..', '..', '..', '..');
const read = (path: string) => readFileSync(join(REPO_ROOT, path), 'utf8');

const REGENERATE = `run \`${EXPORT_COMMAND.replace(' --skip-nx-cache', '')}\` and commit the result`;

/** Oxfmt's command line, which formats with the repository's `.oxfmtrc.json`. */
const OXFMT = join(
  dirname(createRequire(__filename).resolve('oxfmt/package.json')),
  'bin',
  'oxfmt'
);

/** The files as they are committed: the export script runs the page through Oxfmt, so the test does too. */
function generatedFiles(): Artifact[] {
  const pagePath = join(REPO_ROOT, ACCOUNT_PAGE_PATH);
  return contractArtifacts().map((artifact) =>
    artifact.path === ACCOUNT_PAGE_PATH
      ? {
          ...artifact,
          content: execFileSync(process.execPath, [OXFMT, `--stdin-filepath=${pagePath}`], {
            cwd: REPO_ROOT,
            input: artifact.content,
            encoding: 'utf8',
          }),
        }
      : artifact
  );
}

describe('the published account API contract files', () => {
  let generated: Artifact[] = [];
  beforeAll(() => {
    generated = generatedFiles();
  });

  // A contract changed without regenerating its published files fails here,
  // and so does a published file edited by hand.
  it.each(contractArtifacts().map((artifact) => [artifact.path] as const))(
    '%s equals its generator output',
    (path) => {
      const artifact = generated.find((file) => file.path === path);
      expect(read(path), `${path} is stale: ${REGENERATE}`).toBe(artifact?.content);
    }
  );

  it('publishes the document the contract builds', () => {
    expect(JSON.parse(read(OPENAPI_PATH))).toEqual(ACCOUNT_OPENAPI);
  });

  it('registers the document with the stable-surface check', () => {
    const registry = JSON.parse(read('stable-surface/surfaces.json')) as {
      surfaces: Array<{
        name: string;
        format: string;
        generator: string;
        path: string;
        stability: string;
      }>;
    };
    const contract = registry.surfaces.filter((surface) => surface.generator === EXPORT_COMMAND);
    expect(contract.map((surface) => surface.path)).toEqual(
      contractFiles().map((file) => file.path)
    );
    expect(contract.map((surface) => [surface.format, surface.stability])).toEqual([
      ['openapi', 'stable'],
    ]);
  });
});

describe('the rules', () => {
  const description = String((ACCOUNT_OPENAPI['info'] as { description: string }).description);

  it.each(
    [
      ...STATUS_RULES,
      ...TOKEN_RULES,
      ...FRESH_AUTHENTICATION_RULES_TEXT,
      ...ACT_CHAIN_RULES_TEXT,
      ...API_RULES,
      ...VERSIONING_RULES,
    ].map((rule) => [rule] as const)
  )('appear in the document and on the docs page: %s', (rule) => {
    expect(description).toContain(rule);
    expect(read(ACCOUNT_PAGE_PATH).replace(/\s+/g, ' ')).toContain(rule.replace(/\s+/g, ' '));
  });

  it('state the rc rule and the 12-month overlap of ADR-018 §5', () => {
    const rules = VERSIONING_RULES.join(' ');
    expect(rules).toContain('/account/v1-rc.<M>');
    expect(rules).toContain('urn:qauth:aud:account:v1-rc.<M>');
    expect(rules).toContain('/account/v1');
    expect(rules).toContain('at least 12 months');
    expect(rules).toContain('additive only');
  });

  it('describe the replacement of the old consent routes', () => {
    const status = STATUS_RULES.join(' ');
    for (const route of [
      'GET /consents',
      'DELETE /consents/{id}',
      'GET /api/consents',
      'DELETE /api/consents/{id}',
    ]) {
      expect(status).toContain(route);
    }
  });
});

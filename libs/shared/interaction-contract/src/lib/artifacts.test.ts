import { execFileSync } from 'node:child_process';
import { readdirSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join, resolve } from 'node:path';

import { beforeAll, describe, expect, it } from 'vitest';

import {
  type Artifact,
  contractArtifacts,
  contractFiles,
  EXPORT_COMMAND,
  INTERACTION_PAGE_PATH,
  OPENAPI_PATH,
  STEP_SCHEMA_DIR,
} from './artifacts';
import { INTERACTION_OPENAPI } from './openapi';
import { API_RULES, DOCUMENT_PATH_RULE, RESERVED_PREFIX_RULE, VERSIONING_RULES } from './rules';
import { STEPS } from './steps';

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
  const pagePath = join(REPO_ROOT, INTERACTION_PAGE_PATH);
  return contractArtifacts().map((artifact) =>
    artifact.path === INTERACTION_PAGE_PATH
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

describe('the published Interaction API contract files', () => {
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

  it('publishes exactly one schema per step', () => {
    const committed = readdirSync(join(REPO_ROOT, STEP_SCHEMA_DIR)).sort();
    expect(committed).toEqual(STEPS.map((step) => `${step.name}.json`).sort());
    expect(contractFiles().map((file) => file.path)).toContain(OPENAPI_PATH);
  });

  it('publishes the document the auth server serves', () => {
    expect(JSON.parse(read(OPENAPI_PATH))).toEqual(INTERACTION_OPENAPI);
  });

  it('registers the document and every step schema with the stable-surface check', () => {
    const registry = JSON.parse(read('stable-surface/surfaces.json')) as {
      surfaces: Array<{
        name: string;
        format: string;
        generator: string;
        path: string;
        stability: string;
        role?: string;
      }>;
    };
    const contract = registry.surfaces.filter((surface) => surface.generator === EXPORT_COMMAND);
    expect(contract.map((surface) => surface.path).sort()).toEqual(
      contractFiles()
        .map((file) => file.path)
        .sort()
    );
    for (const surface of contract) {
      expect(surface.stability, surface.name).toBe('stable');
      expect(surface.format, surface.name).toBe(
        surface.path === OPENAPI_PATH ? 'openapi' : 'json-schema'
      );
      if (surface.format === 'json-schema') expect(surface.role, surface.name).toBe('output');
    }
  });
});

describe('the versioning rules', () => {
  const description = String((INTERACTION_OPENAPI['info'] as { description: string }).description);

  // The acceptance criterion: the versioning rules appear in the document and
  // on the docs site. Both render the same sentences.
  it.each(
    [...API_RULES, ...VERSIONING_RULES, RESERVED_PREFIX_RULE, DOCUMENT_PATH_RULE].map(
      (rule) => [rule] as const
    )
  )('appears in the document and on the docs page: %s', (rule) => {
    expect(description).toContain(rule);
    expect(read(INTERACTION_PAGE_PATH).replace(/\s+/g, ' ')).toContain(rule.replace(/\s+/g, ' '));
  });

  it('state the rc rule and the 12-month overlap of ADR-018 §5', () => {
    const rules = VERSIONING_RULES.join(' ');
    expect(rules).toContain('/interaction/v1-rc.<M>');
    expect(rules).toContain('/interaction/v1');
    expect(rules).toContain('at least 12 months');
    expect(rules).toContain('additive only');
  });
});

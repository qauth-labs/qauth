import { execFileSync } from 'node:child_process';
import { readdirSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join, resolve } from 'node:path';

import { beforeAll, describe, expect, it } from 'vitest';

import {
  type Artifact,
  eventArtifacts,
  EVENTS_PAGE_PATH,
  EXPORT_COMMAND,
  GENERATED_PAGE_PATHS,
  SCHEMA_DIR,
  schemaArtifacts,
} from './artifacts';
import { headingAnchor, typeHeading } from './docs-page';
import { ENVELOPE_SCHEMA_FILE, eventSchemaFile } from './json-schema';
import { EVENT_TYPES } from './registry';

const REPO_ROOT = resolve(__dirname, '..', '..', '..', '..', '..');
const read = (path: string) => readFileSync(join(REPO_ROOT, path), 'utf8');

const REGENERATE = 'run `pnpm exec nx run shared-events:schema-export` and commit the result';

/** Oxfmt's command line, which formats with the repository's `.oxfmtrc.json`. */
const OXFMT = join(
  dirname(createRequire(__filename).resolve('oxfmt/package.json')),
  'bin',
  'oxfmt'
);

/**
 * The files as they are committed: the export script runs the pages through
 * Oxfmt, so the test does too, with the repository's configuration.
 */
function generatedFiles(): Artifact[] {
  return eventArtifacts().map((artifact) =>
    GENERATED_PAGE_PATHS.includes(artifact.path)
      ? {
          ...artifact,
          content: execFileSync(
            process.execPath,
            [OXFMT, `--stdin-filepath=${join(REPO_ROOT, artifact.path)}`],
            { cwd: REPO_ROOT, input: artifact.content, encoding: 'utf8' }
          ),
        }
      : artifact
  );
}

describe('the generated event contract files', () => {
  let generated: Artifact[] = [];
  beforeAll(() => {
    generated = generatedFiles();
  });

  // The acceptance criterion of #456: the generated JSON Schema equals the
  // committed files, so a schema changed without regenerating fails here.
  it.each(eventArtifacts().map((artifact) => [artifact.path] as const))(
    '%s equals its generator output',
    (path) => {
      const artifact = generated.find((file) => file.path === path);
      expect(read(path), `${path} is stale: ${REGENERATE}`).toBe(artifact?.content);
    }
  );

  it('publishes no schema file the registry does not generate', () => {
    const committed = readdirSync(join(REPO_ROOT, SCHEMA_DIR)).sort();
    const generated = schemaArtifacts()
      .map((artifact) => artifact.path.slice(SCHEMA_DIR.length + 1))
      .sort();
    expect(committed).toEqual(generated);
  });

  it('publishes one schema per registered type, and the envelope', () => {
    const files = schemaArtifacts().map((artifact) => artifact.path);
    expect(files).toContain(`${SCHEMA_DIR}/${ENVELOPE_SCHEMA_FILE}`);
    for (const definition of EVENT_TYPES) {
      expect(files).toContain(`${SCHEMA_DIR}/${eventSchemaFile(definition)}`);
    }
    expect(files).toHaveLength(EVENT_TYPES.length + 1);
  });

  it('writes schemas the stable-surface check can compare: only local $defs references', () => {
    for (const artifact of schemaArtifacts()) {
      const refs = [...artifact.content.matchAll(/"\$ref":\s*"([^"]*)"/g)].map((m) => m[1]);
      expect(
        refs.filter((ref) => !/^#\/\$defs\/[^/]+$/.test(ref)),
        artifact.path
      ).toEqual([]);
    }
  });

  it('gives every schema file its own URL as $id and the type as its title', () => {
    for (const definition of EVENT_TYPES) {
      const schema = JSON.parse(read(`${SCHEMA_DIR}/${eventSchemaFile(definition)}`));
      expect(schema.$id).toBe(
        `https://docs.qauth.dev/schemas/events/${eventSchemaFile(definition)}`
      );
      expect(schema.title).toBe(definition.type);
      expect(schema.properties.type.const).toBe(definition.type);
      expect(schema.properties.category.const).toBe(definition.category);
    }
  });
});

describe('the stable-surface registration (CNF-02)', () => {
  const registry = JSON.parse(read('stable-surface/surfaces.json')) as {
    surfaces: Array<Record<string, unknown>>;
  };
  const eventSurfaces = registry.surfaces.filter(
    (surface) => typeof surface['path'] === 'string' && surface['path'].startsWith(`${SCHEMA_DIR}/`)
  );

  it('registers every schema file, once', () => {
    const registered = eventSurfaces.map((surface) => surface['path']).sort();
    const generated = schemaArtifacts()
      .map((artifact) => artifact.path)
      .sort();
    expect(registered).toEqual(generated);
  });

  // `both`: a schema is compared as a document QAuth emits and as one it must
  // still accept, since stored events of a type outlive a release. That is
  // what makes a new required member a break while a new optional one passes.
  it('registers each as a stable json-schema surface with role both, written by the export', () => {
    for (const surface of eventSurfaces) {
      expect(surface, String(surface['path'])).toMatchObject({
        format: 'json-schema',
        role: 'both',
        stability: 'stable',
        generator: EXPORT_COMMAND,
      });
      expect(String(surface['name'])).toMatch(/^event-[a-z0-9]+(?:-[a-z0-9]+)*$/);
    }
  });
});

describe('the generated docs page', () => {
  const page = read(EVENTS_PAGE_PATH);

  // The acceptance criterion of #456: the page lists every registered type.
  it.each(EVENT_TYPES.map((definition) => [definition.type, definition] as const))(
    'lists %s, with its section and its schema',
    (type, definition) => {
      expect(page).toContain(`[\`${type}\`](#${headingAnchor(typeHeading(definition))})`);
      expect(page).toContain(`\n### ${typeHeading(definition)}\n`);
      expect(page).toContain(`(/schemas/events/${eventSchemaFile(definition)})`);
    }
  );

  it('documents every envelope member', () => {
    const members = [
      'id',
      'type',
      'time',
      'realm',
      'category',
      'actor',
      'subject',
      'client',
      'request',
      'data',
    ];
    for (const member of members) {
      expect(page).toMatch(new RegExp(`^\\| \`${member}\` +\\|`, 'm'));
    }
  });

  it('carries the frontmatter the docs collection requires', () => {
    expect(page).toMatch(
      /^---\ntitle: Events\ndescription: .+\nsidebar:\n {2}order: \d+\nlastVerified: '\d{4}-\d{2}-\d{2}'\n---\n/
    );
  });
});

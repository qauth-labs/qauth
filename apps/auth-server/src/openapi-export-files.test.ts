import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import type { OpenApiDocument } from './app/api-conventions/family-documents';
import {
  EXPORT_LOCATIONS,
  exportFiles,
  familyDocumentFileName,
  writeExportFiles,
} from './openapi-export-files';

/**
 * The files the OpenAPI export writes for each flag surface (#525): the
 * server's whole document and one document per API family, the same bytes on
 * every run, so a second run changes nothing.
 */

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function tempRoot(): string {
  const root = mkdtempSync(join(tmpdir(), 'openapi-export-files-'));
  roots.push(root);
  return root;
}

function publicDocument(): OpenApiDocument {
  return {
    openapi: '3.1.0',
    info: { title: 'QAuth Auth Server API', version: '0.0.0-dev' },
    paths: {
      '/oauth/token': { post: { responses: { 200: { description: 'ok' } } } },
      '/account/v1-rc.0/consents': {
        get: { operationId: 'account.consents.list', responses: { 200: { description: 'ok' } } },
      },
      '/developer/v1-rc.0/clients': {
        get: { operationId: 'developer.clients.list', responses: { 200: { description: 'ok' } } },
      },
    },
    components: { securitySchemes: {}, schemas: {} },
  };
}

function adminDocument(): OpenApiDocument {
  return {
    openapi: '3.1.0',
    paths: {
      '/admin/v1-rc.0/realms/{realmId}': {
        get: { operationId: 'realms.get', responses: { 200: { description: 'ok' } } },
      },
    },
    components: { schemas: {} },
  };
}

describe('exportFiles', () => {
  it('writes the whole document and three family documents for each surface, in a fixed order', () => {
    expect([...exportFiles('default', { combined: publicDocument(), admin: null }).keys()]).toEqual(
      [
        'stable-surface/openapi.json',
        'docs/api-baseline/openapi-admin.json',
        'docs/api-baseline/openapi-account.json',
        'docs/api-baseline/openapi-developer.json',
      ]
    );
    expect([
      ...exportFiles('maximal', { combined: publicDocument(), admin: adminDocument() }).keys(),
    ]).toEqual([
      'apps/docs-site/public/openapi.json',
      'apps/docs-site/public/openapi-admin.json',
      'apps/docs-site/public/openapi-account.json',
      'apps/docs-site/public/openapi-developer.json',
    ]);
    expect(EXPORT_LOCATIONS.maximal.familyDirectory).toBe('apps/docs-site/public');
    expect(familyDocumentFileName('admin')).toBe('openapi-admin.json');
  });

  it("cuts each family's document from its own listener's", () => {
    const files = exportFiles('maximal', { combined: publicDocument(), admin: adminDocument() });
    const read = (family: string) =>
      JSON.parse(files.get(`apps/docs-site/public/openapi-${family}.json`) ?? '{}') as {
        paths: Record<string, unknown>;
        info: { version: string };
      };
    expect(Object.keys(read('admin').paths)).toEqual(['/admin/v1-rc.0/realms/{realmId}']);
    expect(Object.keys(read('account').paths)).toEqual(['/account/v1-rc.0/consents']);
    expect(Object.keys(read('developer').paths)).toEqual(['/developer/v1-rc.0/clients']);
    expect(read('admin').info.version).toBe('v1-rc.0');
  });

  it('writes an admin document with no operation when the surface runs no admin listener', () => {
    const files = exportFiles('default', { combined: publicDocument(), admin: null });
    const admin = JSON.parse(files.get('docs/api-baseline/openapi-admin.json') ?? '{}') as {
      openapi: string;
      paths: Record<string, unknown>;
    };
    expect(admin.paths).toEqual({});
    expect(admin.openapi).toBe('3.1.0');
  });

  it('is deterministic: the same sources give the same bytes', () => {
    const first = exportFiles('maximal', { combined: publicDocument(), admin: adminDocument() });
    const second = exportFiles('maximal', { combined: publicDocument(), admin: adminDocument() });
    expect([...second]).toEqual([...first]);
    for (const content of first.values()) expect(content.endsWith('}\n')).toBe(true);
  });
});

describe('writeExportFiles', () => {
  it('writes every file once, and nothing on a second run of the same export', () => {
    const root = tempRoot();
    const files = exportFiles('default', { combined: publicDocument(), admin: null });
    expect(writeExportFiles(root, files)).toEqual([...files.keys()]);
    for (const [path, content] of files) {
      expect(readFileSync(join(root, path), 'utf8')).toBe(content);
    }

    const again = exportFiles('default', { combined: publicDocument(), admin: null });
    expect(writeExportFiles(root, again)).toEqual([]);
  });

  it('rewrites only the file whose bytes differ', () => {
    const root = tempRoot();
    const files = exportFiles('default', { combined: publicDocument(), admin: null });
    writeExportFiles(root, files);
    writeFileSync(join(root, 'docs/api-baseline/openapi-account.json'), '{}\n');
    expect(writeExportFiles(root, files)).toEqual(['docs/api-baseline/openapi-account.json']);
  });
});

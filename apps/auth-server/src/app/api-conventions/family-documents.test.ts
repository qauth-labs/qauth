import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import swagger from '@fastify/swagger';
import {
  describeErrors,
  openApiDocumentValidator,
} from '@qauth-labs/shared-interaction-contract/src/testing/schema-validator';
import Fastify from 'fastify';
import {
  serializerCompiler,
  validatorCompiler,
  type ZodTypeProvider,
} from 'fastify-type-provider-zod';
import { describe, expect, it } from 'vitest';
import { z } from 'zod';

import { openapiOptions } from '../openapi-options';
import { API_FAMILIES, API_FAMILY_PREFIXES, type ApiFamily } from './families';
import {
  familyContractVersion,
  familyDocument,
  familyDocumentPath,
  familyTokenSecurity,
  type OpenApiDocument,
  serializeDocument,
} from './family-documents';
import { checkApiConventions } from './openapi-conventions';

/**
 * One OpenAPI document per API family (#525): the cut itself, and the
 * documents the exporter committed — `docs/api-baseline/` under default flags
 * and `apps/docs-site/public/` under the maximal surface.
 */

type Operation = Record<string, unknown>;
type Paths = Record<string, Record<string, Operation>>;

const REPO_ROOT = join(__dirname, '..', '..', '..', '..', '..');

function readDocument(path: string): OpenApiDocument {
  return JSON.parse(readFileSync(join(REPO_ROOT, path), 'utf8')) as OpenApiDocument;
}

function operationsOf(document: OpenApiDocument) {
  return Object.entries((document.paths ?? {}) as Paths).flatMap(([path, item]) =>
    Object.entries(item).map(([method, operation]) => ({ path, method, operation }))
  );
}

/** A small document of a listener, in `@fastify/swagger`'s shape, with two families and a stray path. */
function sourceDocument(): OpenApiDocument {
  const problem = { $ref: '#/components/schemas/Problem' };
  return {
    openapi: '3.1.0',
    info: { title: 'QAuth Auth Server API', version: '0.0.0-dev' },
    tags: [{ name: 'Account API' }, { name: 'Developer API' }, { name: 'OAuth' }],
    paths: {
      '/oauth/token': { post: { tags: ['OAuth'], responses: { 200: { description: 'ok' } } } },
      '/account/v1-rc.0/consents': {
        get: {
          operationId: 'account.consents.list',
          tags: ['Account API'],
          security: familyTokenSecurity(),
          responses: {
            200: {
              description: 'ok',
              content: { 'application/json': { schema: { $ref: '#/components/schemas/Page' } } },
            },
            401: {
              description: 'no',
              content: { 'application/problem+json': { schema: problem } },
            },
          },
        },
      },
      '/account/v1-rc.0/openapi.json': { get: { responses: { 200: { description: 'doc' } } } },
      '/account/v1-rc.0x/elsewhere': {
        get: { responses: { 200: { description: 'not a family path' } } },
      },
      '/developer/v1-rc.0/clients': {
        get: { operationId: 'developer.clients.list', tags: ['Developer API'], responses: {} },
      },
    },
    components: {
      securitySchemes: { bearerAuth: { type: 'http', scheme: 'bearer' } },
      schemas: {
        Page: { type: 'object', properties: { items: { $ref: '#/components/schemas/Item' } } },
        Item: { type: 'string' },
        Problem: { type: 'object' },
        Unused: { type: 'string' },
      },
    },
  };
}

describe('familyContractVersion and familyDocumentPath', () => {
  it.each(API_FAMILIES)(
    "%s: the version its path carries, a release candidate, and its document's path",
    (family) => {
      expect(familyContractVersion(family)).toBe('v1-rc.0');
      expect(API_FAMILY_PREFIXES[family].endsWith(`/${familyContractVersion(family)}`)).toBe(true);
      expect(familyDocumentPath(family)).toBe(`/${family}/v1-rc.0/openapi.json`);
    }
  );
});

describe('familyDocument', () => {
  it("keeps only the family's operation paths, never its own document's", () => {
    const account = familyDocument(sourceDocument(), 'account');
    expect(Object.keys(account.paths ?? {})).toEqual(['/account/v1-rc.0/consents']);
    const developer = familyDocument(sourceDocument(), 'developer');
    expect(Object.keys(developer.paths ?? {})).toEqual(['/developer/v1-rc.0/clients']);
  });

  it('gives each family its own info, contract version, server entry and security schemes', () => {
    const account = familyDocument(sourceDocument(), 'account');
    expect(account.openapi).toBe('3.1.0');
    expect(account.info).toMatchObject({ title: 'QAuth Account API', version: 'v1-rc.0' });
    expect(account.servers).toEqual([{ url: '/', description: expect.any(String) }]);
    expect(Object.keys(account.components?.securitySchemes ?? {})).toEqual([
      'bearerAuth',
      'dpopAuth',
    ]);
    expect(account.components?.securitySchemes?.['dpopAuth']).toMatchObject({
      type: 'http',
      scheme: 'DPoP',
    });

    const admin = familyDocument(sourceDocument(), 'admin');
    expect(admin.info).toMatchObject({ title: 'QAuth Admin API', version: 'v1-rc.0' });
    // No admin operation takes a Bearer token.
    expect(Object.keys(admin.components?.securitySchemes ?? {})).toEqual(['dpopAuth']);
    expect(admin.paths).toEqual({});
  });

  it('keeps the tags its operations use and the schemas they reach, and nothing else', () => {
    const account = familyDocument(sourceDocument(), 'account');
    expect(account.tags).toEqual([{ name: 'Account API' }]);
    expect(Object.keys(account.components?.schemas ?? {}).sort()).toEqual([
      'Item',
      'Page',
      'Problem',
    ]);
    expect(familyDocument(sourceDocument(), 'admin').tags).toBeUndefined();
  });

  it('is deterministic and never changes its source', () => {
    const source = sourceDocument();
    const before = structuredClone(source);
    const first = serializeDocument(familyDocument(source, 'account'));
    const second = serializeDocument(familyDocument(source, 'account'));
    expect(second).toBe(first);
    expect(source).toEqual(before);
    // The cut is its own fixed point: cutting a family document again gives it back.
    const cut = familyDocument(source, 'account');
    expect(serializeDocument(familyDocument(cut, 'account'))).toBe(first);
  });
});

describe('an experimental operation whose switch is off', () => {
  /** A listener with one stable family route and one experimental route behind `switchOn`. */
  async function listenerDocument(switchOn: boolean): Promise<OpenApiDocument> {
    const app = Fastify({ logger: false }).withTypeProvider<ZodTypeProvider>();
    app.setValidatorCompiler(validatorCompiler);
    app.setSerializerCompiler(serializerCompiler);
    await app.register(swagger, openapiOptions);
    app.get(
      `${API_FAMILY_PREFIXES.developer}/clients`,
      {
        schema: {
          operationId: 'developer.clients.list',
          tags: ['Developer API'],
          security: familyTokenSecurity(),
          'x-qauth-stability': 'stable',
          response: { 200: z.object({ items: z.array(z.string()) }) },
        },
      },
      async () => ({ items: [] })
    );
    if (switchOn) {
      app.get(
        `${API_FAMILY_PREFIXES.developer}/widgets`,
        {
          schema: {
            operationId: 'developer.widgets.list',
            tags: ['Developer API'],
            security: familyTokenSecurity(),
            'x-qauth-stability': 'experimental',
            response: { 200: z.object({ items: z.array(z.string()) }) },
          },
        },
        async () => ({ items: [] })
      );
    }
    await app.ready();
    const document = app.swagger() as OpenApiDocument;
    await app.close();
    return document;
  }

  it('is absent from its family document, and present and tagged once the switch is on', async () => {
    const off = familyDocument(await listenerDocument(false), 'developer');
    expect(Object.keys(off.paths ?? {})).toEqual(['/developer/v1-rc.0/clients']);

    const on = familyDocument(await listenerDocument(true), 'developer');
    expect(on.paths?.['/developer/v1-rc.0/widgets']?.['get']).toMatchObject({
      operationId: 'developer.widgets.list',
      'x-qauth-stability': 'experimental',
    });
  });

  it('leaves the default-flag admin document with no operation, the admin API being off by default', () => {
    const baseline = readDocument('docs/api-baseline/openapi-admin.json');
    expect(baseline.paths).toEqual({});
    const published = readDocument('apps/docs-site/public/openapi-admin.json');
    const operations = operationsOf(published);
    expect(operations.length).toBeGreaterThan(0);
    // Every admin operation is experimental while the admin API is.
    for (const { operation } of operations) {
      expect(operation['x-qauth-stability']).toBe('experimental');
    }
  });
});

/** The committed documents: the default-flag baselines and the published maximal ones. */
const COMMITTED: readonly { family: ApiFamily; path: string; combined: string }[] =
  API_FAMILIES.flatMap((family) => [
    {
      family,
      path: `docs/api-baseline/openapi-${family}.json`,
      combined: 'stable-surface/openapi.json',
    },
    {
      family,
      path: `apps/docs-site/public/openapi-${family}.json`,
      combined: 'apps/docs-site/public/openapi.json',
    },
  ]);

describe('the committed family documents', () => {
  it.each(COMMITTED.map((entry) => [entry.path, entry] as const))(
    '%s validates against the official OpenAPI 3.1 schema',
    (_path, { path }) => {
      const validate = openApiDocumentValidator();
      const document = readDocument(path);
      expect(validate(document), describeErrors(validate)).toBe(true);
      expect(document.openapi).toMatch(/^3\.1\./);
    }
  );

  it('are refused by that schema when broken, so the validation is not vacuous', () => {
    const validate = openApiDocumentValidator();
    const broken = readDocument('apps/docs-site/public/openapi-developer.json');
    const [first] = operationsOf(broken);
    if (first === undefined) throw new Error('the developer document has no operation');
    first.operation['responses'] = 'none';
    expect(validate(broken)).toBe(false);
  });

  it.each(COMMITTED.filter((entry) => entry.family !== 'admin').map((e) => [e.path, e] as const))(
    "%s is the family's cut of the server's document, byte for byte",
    (_path, { family, path, combined }) => {
      const committed = readFileSync(join(REPO_ROOT, path), 'utf8');
      expect(committed).toBe(serializeDocument(familyDocument(readDocument(combined), family)));
    }
  );

  it.each(COMMITTED.map((entry) => [entry.path, entry] as const))(
    "%s carries its family's info, version and only its family's paths",
    (_path, { family, path }) => {
      const document = readDocument(path);
      expect(document.info).toMatchObject({ version: familyContractVersion(family) });
      expect(document.info?.['version']).not.toBe('1.0.0');
      for (const key of Object.keys(document.paths ?? {})) {
        expect(key.startsWith(`${API_FAMILY_PREFIXES[family]}/`), key).toBe(true);
      }
    }
  );

  it('state the security each family takes: Bearer or DPoP, and DPoP alone on the admin API', () => {
    for (const { family, path } of COMMITTED) {
      for (const { method, path: at, operation } of operationsOf(readDocument(path))) {
        expect(operation['security'], `${method.toUpperCase()} ${at}`).toEqual(
          family === 'admin' ? [{ dpopAuth: [] }] : familyTokenSecurity()
        );
      }
    }
  });

  it('pass the API conventions check, every operation counted', () => {
    for (const { path } of COMMITTED) {
      const document = readDocument(path);
      const report = checkApiConventions(document);
      expect(report.violations, path).toEqual([]);
      expect(report.checkedOperations, path).toBe(operationsOf(document).length);
    }
  });
});

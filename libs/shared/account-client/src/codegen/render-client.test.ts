import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join, resolve } from 'node:path';

import { describe, expect, it } from 'vitest';

import { CLIENT_PATH, DOCUMENT_PATH } from './paths';
import { methodName, renderClient, typeOf } from './render-client';

const REPO_ROOT = resolve(__dirname, '..', '..', '..', '..', '..');
const read = (path: string) => readFileSync(join(REPO_ROOT, path), 'utf8');

/** Oxfmt's command line, which formats with the repository's `.oxfmtrc.json`. */
const OXFMT = join(
  dirname(createRequire(__filename).resolve('oxfmt/package.json')),
  'bin',
  'oxfmt'
);

describe('the generated account API client', () => {
  // The acceptance criterion: the typed client builds from the document, and
  // CI fails when the committed client is out of date. The typecheck target
  // then builds it (its inputs include the document).
  it('equals what the generator writes from the published document', () => {
    const document = JSON.parse(read(DOCUMENT_PATH));
    const generated = execFileSync(
      process.execPath,
      [OXFMT, `--stdin-filepath=${join(REPO_ROOT, CLIENT_PATH)}`],
      { cwd: REPO_ROOT, input: renderClient(document, DOCUMENT_PATH), encoding: 'utf8' }
    );
    expect(
      read(CLIENT_PATH),
      `${CLIENT_PATH} is stale: run \`pnpm exec nx run shared-account-client:generate\` and commit the result`
    ).toBe(generated);
  });

  it('declares one type per component and one method per operation', () => {
    const document = JSON.parse(read(DOCUMENT_PATH)) as {
      components: { schemas: Record<string, unknown> };
      paths: Record<string, Record<string, { operationId: string }>>;
    };
    const client = read(CLIENT_PATH);
    for (const name of Object.keys(document.components.schemas)) {
      expect(client, name).toMatch(new RegExp(`export (?:interface|type) ${name}\\b`));
    }
    for (const item of Object.values(document.paths)) {
      for (const operation of Object.values(item)) {
        expect(client).toContain(`${methodName(operation.operationId)}: (`);
      }
    }
  });
});

describe('the generator', () => {
  it('names a method after its operationId, without the family', () => {
    expect(methodName('account.profile.get')).toBe('profileGet');
    expect(methodName('account.totp.enrollment.confirm')).toBe('totpEnrollmentConfirm');
    expect(() => methodName('developer.clients.list')).toThrow(/not an account operation/);
  });

  it('types the constructs the contract uses', () => {
    expect(typeOf({ $ref: '#/components/schemas/Passkey' }, 'x')).toBe('Passkey');
    expect(typeOf({ type: 'string', const: 'SHA1' }, 'x')).toBe("'SHA1'");
    expect(typeOf({ type: 'string', enum: ['a', 'b'] }, 'x')).toBe("'a' | 'b'");
    expect(typeOf({ type: 'string', 'x-extensible-enum': ['a', 'b'] }, 'x')).toBe(
      "'a' | 'b' | (string & {})"
    );
    expect(typeOf({ type: ['string', 'null'], maxLength: 3 }, 'x')).toBe('string | null');
    expect(typeOf({ type: 'array', items: { type: 'string' } }, 'x')).toBe('string[]');
    expect(
      typeOf({ type: 'string', format: 'password', writeOnly: true, maxLength: 256 }, 'x')
    ).toBe('string');
    expect(
      typeOf(
        {
          type: 'object',
          properties: {},
          propertyNames: { pattern: '^[a-z]+$' },
          additionalProperties: { type: ['string', 'null'] },
        },
        'x'
      ).replace(/\s+/g, ' ')
    ).toBe('{ [key: string]: string | null; }');
    expect(typeOf({ not: {}, description: 'Never sent.' }, 'x')).toBe('never');
  });

  it('refuses what it cannot type, instead of widening it to unknown', () => {
    expect(() => typeOf({ type: 'string', maxLenght: 3 }, 'x')).toThrow(
      /does not know the keyword/
    );
    expect(() => typeOf({ type: ['string', 'integer'] }, 'x')).toThrow(/list of types/);
    expect(() => typeOf({ oneOf: [] }, 'x')).toThrow(/does not know the keyword oneOf/);
    expect(() => typeOf({ $ref: 'other.json#/x' }, 'x')).toThrow(/unsupported reference/);
    expect(() => typeOf({}, 'x')).toThrow(/cannot type/);
  });
});

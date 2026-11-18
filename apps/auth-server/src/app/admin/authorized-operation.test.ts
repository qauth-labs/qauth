import { readdirSync, readFileSync } from 'node:fs';
import { join, relative, sep } from 'node:path';

import type { FastifyRequest } from 'fastify';
import { describe, expect, it } from 'vitest';

import {
  type AuthorizedOperation,
  type AuthorizedOperationGrant,
  AuthorizedOperationRefusedError,
  issueAuthorizedOperation,
  retireAuthorizedOperation,
  spendAuthorizedOperation,
} from './authorized-operation';
import type { AdminCaller, AdminTransaction } from './pipeline';

const APP_SRC = join(__dirname, '..', '..');

/** A grant as the pipeline hands one over, for an approved `issue-for-other` operation. */
function grant(overrides: Partial<AuthorizedOperationGrant> = {}): AuthorizedOperationGrant {
  return {
    request: {} as FastifyRequest,
    transaction: {} as AdminTransaction,
    caller: {} as AdminCaller,
    operationId: 'fixtureUsers.actChainTokens.create',
    effects: ['issue-for-other'],
    permissions: ['users.security'],
    approvalId: '0192a000-0000-7000-8000-000000000001',
    adminToken: { issuer: 'https://auth.example.test', clientId: 'console', jkt: 'thumbprint' },
    params: { realmId: 'realm', userId: 'user' },
    body: { scopes: ['qauth:account:read'], nested: { kept: true } },
    ...overrides,
  };
}

/** Every source file of the app but tests. */
function sourceFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return sourceFiles(path);
    return entry.name.endsWith('.ts') && !entry.name.endsWith('.test.ts') ? [path] : [];
  });
}

describe('the capability of an approved security operation (#523)', () => {
  it('is spent once, for an effect its operation names, with a frozen copy of the request', () => {
    const issued = issueAuthorizedOperation(grant());
    expect(issued).toEqual({
      operationId: 'fixtureUsers.actChainTokens.create',
      effects: ['issue-for-other'],
      permissions: ['users.security'],
      approvalId: '0192a000-0000-7000-8000-000000000001',
    });
    expect(Object.isFrozen(issued)).toBe(true);

    const context = spendAuthorizedOperation(issued, 'issue-for-other');
    expect(context.params).toEqual({ realmId: 'realm', userId: 'user' });
    expect(Object.isFrozen(context.params)).toBe(true);
    expect(Object.isFrozen((context.body as { nested: object }).nested)).toBe(true);
    expect(context.adminToken).toEqual({
      issuer: 'https://auth.example.test',
      clientId: 'console',
      jkt: 'thumbprint',
    });

    expect(() => spendAuthorizedOperation(issued, 'issue-for-other')).toThrow(
      AuthorizedOperationRefusedError
    );
  });

  it('copies what the handler could change after the pipeline issued it', () => {
    const body = { scopes: ['qauth:account:read'] };
    const issued = issueAuthorizedOperation(grant({ body }));
    body.scopes.push('qauth:account:write');
    expect(spendAuthorizedOperation(issued, 'issue-for-other').body).toEqual({
      scopes: ['qauth:account:read'],
    });
  });

  it('refuses a forged, a copied, a retired one, and one for another effect', () => {
    const forged = {
      operationId: 'fixtureUsers.actChainTokens.create',
      effects: ['issue-for-other'],
      permissions: ['users.security'],
      approvalId: '0192a000-0000-7000-8000-000000000001',
    } as unknown as AuthorizedOperation;
    const issued = issueAuthorizedOperation(grant());
    const copied = { ...issued } as AuthorizedOperation;
    for (const candidate of [forged, copied, null, undefined, 'capability']) {
      expect(() =>
        spendAuthorizedOperation(candidate as unknown as AuthorizedOperation, 'issue-for-other')
      ).toThrow(/only the admin pipeline issues one/);
    }

    const retired = issueAuthorizedOperation(grant());
    retireAuthorizedOperation(retired);
    expect(() => spendAuthorizedOperation(retired, 'issue-for-other')).toThrow(
      /works only while its handler runs/
    );

    const other = issueAuthorizedOperation(grant({ effects: ['key-custody'] }));
    expect(() => spendAuthorizedOperation(other, 'issue-for-other')).toThrow(
      /names no 'issue-for-other' effect/
    );
  });

  it('is issued only for an approved operation with an effect, for a bound admin token', () => {
    expect(() => issueAuthorizedOperation(grant({ approvalId: '' }))).toThrow();
    expect(() => issueAuthorizedOperation(grant({ effects: [] }))).toThrow();
    expect(() =>
      issueAuthorizedOperation(
        grant({ adminToken: { issuer: 'https://auth.example.test', clientId: 'console', jkt: '' } })
      )
    ).toThrow();
  });

  it('cannot be written as a literal (type test)', () => {
    const typeOnly = (): AuthorizedOperation => {
      // @ts-expect-error The brand is a key no other module can name.
      return {
        operationId: 'fixtureUsers.actChainTokens.create',
        effects: ['issue-for-other'],
        permissions: ['users.security'],
        approvalId: 'approval',
      };
    };
    expect(typeof typeOnly).toBe('function');
  });

  it('is issued and retired by the admin pipeline alone', () => {
    const callers = sourceFiles(APP_SRC)
      .filter((file) =>
        /\b(issueAuthorizedOperation|retireAuthorizedOperation)\b/.test(readFileSync(file, 'utf8'))
      )
      .map((file) => relative(APP_SRC, file).split(sep).join('/'))
      .sort();
    expect(callers).toEqual(['app/admin/authorized-operation.ts', 'app/admin/pipeline.ts']);
  });
});

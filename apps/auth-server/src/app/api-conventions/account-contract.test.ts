import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import * as account from '@qauth-labs/shared-account-contract';
import { EVENT_TYPES } from '@qauth-labs/shared-events';
import * as interactionKit from '@qauth-labs/shared-interaction-contract/src/lib/schema-kit';
import {
  describeErrors,
  openApiDocumentValidator,
} from '@qauth-labs/shared-interaction-contract/src/testing/schema-validator';
import { describe, expect, it } from 'vitest';

import { API_FAMILY_AUDIENCES, API_FAMILY_PREFIXES } from './families';
import { checkApiConventions } from './openapi-conventions';
import { PROBLEM_CODES, PROBLEM_TYPE_BASE } from './problem';

/**
 * The account API v1 contract (#588, `libs/shared/account-contract`) against
 * the server and the other shared contracts. Shared libraries are leaves of
 * the module graph, so the contract imports none of these; the auth server,
 * which may depend on all of them, keeps them together here:
 *
 * - the document is a valid OpenAPI 3.1 document and passes the API
 *   conventions check (#506);
 * - its prefix, audience and problem codes are the server's;
 * - every account operation the server serves is the contract's;
 * - the security log's kinds match the event registry both ways;
 * - its copy of the Interaction API's schema builders equals the original.
 */

type Operations = Record<string, Record<string, Record<string, unknown>>>;

const REPO_ROOT = join(__dirname, '..', '..', '..', '..', '..');
const document = account.ACCOUNT_OPENAPI as Record<string, unknown>;
const paths = document['paths'] as Operations;

describe('the account API contract document', () => {
  it('validates against the official OpenAPI 3.1 schema, Schema Objects included', () => {
    const validate = openApiDocumentValidator();
    expect(validate(document), describeErrors(validate)).toBe(true);
  });

  it('is refused by that schema when broken, so the check is not vacuous', () => {
    const validate = openApiDocumentValidator();
    const broken = structuredClone(document) as { paths: Operations };
    const read = broken.paths['/account/v1-rc.0/profile']?.['get'];
    if (read === undefined) throw new Error('no profile read');
    read['responses'] = 'none';
    expect(validate(broken)).toBe(false);
  });

  it('passes the API conventions check, every operation counted', () => {
    const report = checkApiConventions(document);
    expect(report.violations).toEqual([]);
    expect(report.checkedOperations).toBe(account.ACCOUNT_OPERATIONS.length);
  });

  it('uses the prefix and the audience of the account family', () => {
    expect(account.ACCOUNT_API_PREFIX).toBe(API_FAMILY_PREFIXES.account);
    expect(account.ACCOUNT_API_AUDIENCE).toBe(API_FAMILY_AUDIENCES.account);
  });

  it('sends only codes the server publishes, with the same status, type and title', () => {
    expect(account.PROBLEM_TYPE_BASE).toBe(PROBLEM_TYPE_BASE);
    for (const [code, { status, type, title }] of Object.entries(account.ACCOUNT_PROBLEM_CODES)) {
      const entry = PROBLEM_CODES[code as keyof typeof PROBLEM_CODES];
      expect(entry, `${code} is published`).toBeDefined();
      expect({ status: entry.status, type: entry.type, title: entry.title }, code).toEqual({
        status,
        type,
        title,
      });
    }
  });

  it('holds every account operation the server serves, unchanged', () => {
    const served = JSON.parse(
      readFileSync(join(REPO_ROOT, 'stable-surface', 'openapi.json'), 'utf8')
    ) as { paths: Operations };
    const servedOperations = Object.entries(served.paths)
      .filter(([path]) => path.startsWith(`${API_FAMILY_PREFIXES.account}/`))
      .flatMap(([path, item]) =>
        Object.entries(item).map(([method, operation]) => ({ path, method, operation }))
      );
    expect(servedOperations.length).toBeGreaterThan(0);
    for (const { path, method, operation } of servedOperations) {
      const at = `${method.toUpperCase()} ${path}`;
      const contract = paths[path]?.[method];
      expect(contract, `${at} is in the contract`).toBeDefined();
      for (const key of ['operationId', 'x-qauth-class', 'x-qauth-permission']) {
        expect(contract?.[key], `${at} ${key}`).toEqual(operation[key]);
      }
    }
  });
});

describe('the security log kinds', () => {
  const sources = Object.values(account.SECURITY_LOG_KINDS).flatMap((kind) => kind.sources);
  const userTypes = EVENT_TYPES.filter((definition) => definition.subject === 'user').map(
    (definition) => definition.name as string
  );

  it('come from registered events about a user, where the event is registered', () => {
    const registered = sources.filter((source) => source.status === 'registered');
    expect(registered.length).toBeGreaterThan(4);
    for (const source of registered) {
      const definition = EVENT_TYPES.find((candidate) => candidate.name === source.event);
      expect(definition, `${source.event} is registered`).toBeDefined();
      expect(definition?.subject, `${source.event} is about a user`).toBe('user');
    }
  });

  it('name a planned event only while the registry lacks it', () => {
    // The pull request that registers the type marks it registered in the contract.
    for (const source of sources.filter((entry) => entry.status === 'planned')) {
      expect(
        EVENT_TYPES.some((definition) => definition.name === source.event),
        `${source.event} is registered now: mark it registered in security-log.ts`
      ).toBe(false);
      expect(source.event).toMatch(/^[a-z]+\.[a-z_]+$/);
    }
  });

  it('account for every registered event about a user: a source, or left out with a reason', () => {
    expect(userTypes.length).toBeGreaterThan(10);
    const used = new Set(sources.map((source) => source.event));
    for (const name of userTypes) {
      expect(
        used.has(name) || name in account.NOT_IN_SECURITY_LOG,
        `${name} is neither a security-log source nor left out`
      ).toBe(true);
      expect(used.has(name) && name in account.NOT_IN_SECURITY_LOG, `${name} is both`).toBe(false);
    }
    for (const name of Object.keys(account.NOT_IN_SECURITY_LOG)) {
      expect(userTypes, `${name} is left out but is not a registered user event`).toContain(name);
    }
  });

  it('list each event in at most one kind', () => {
    const events = sources.map((source) => source.event);
    expect(new Set(events).size).toBe(events.length);
  });
});

describe('the copies of the Interaction API contract', () => {
  it('apply the same display rule', () => {
    expect(account.DISPLAY_TEXT_PATTERN).toBe(interactionKit.DISPLAY_TEXT_PATTERN);
    expect(account.DISPLAY_SOURCES).toEqual(interactionKit.DISPLAY_SOURCES);
    expect(account.NEVER).toEqual(interactionKit.NEVER);
  });

  it('build the same schemas', () => {
    const string = { type: 'string' };
    const rule = account.whenEquals('kind', ['a'], { required: ['b'] });
    const pairs: Array<[string, unknown, unknown]> = [
      [
        'displayText',
        account.displayText('realm', 64, 'd'),
        interactionKit.displayText('realm', 64, 'd'),
      ],
      ['dateTime', account.dateTime('d'), interactionKit.dateTime('d')],
      ['absoluteUri', account.absoluteUri(2048, 'd'), interactionKit.absoluteUri(2048, 'd')],
      ['closedEnum', account.closedEnum(['a'], 'd'), interactionKit.closedEnum(['a'], 'd')],
      [
        'extensibleEnum',
        account.extensibleEnum(['a'], '^[a-z]+$', 8, 'd'),
        interactionKit.extensibleEnum(['a'], '^[a-z]+$', 8, 'd'),
      ],
      [
        'object',
        account.object({ a: string }, ['a'], 'd', [rule]),
        interactionKit.object({ a: string }, ['a'], 'd', [rule]),
      ],
      [
        'openObject',
        account.openObject({ a: string }, [], 'd'),
        interactionKit.openObject({ a: string }, [], 'd'),
      ],
      ['whenEquals', rule, interactionKit.whenEquals('kind', ['a'], { required: ['b'] })],
      [
        'closedObject',
        account.closedObject({ a: string }, [], 'd'),
        interactionKit.closedObject({ a: string }, [], 'd'),
      ],
      ['array', account.array(string, 0, 3, 'd'), interactionKit.array(string, 0, 3, 'd')],
    ];
    for (const [name, copy, original] of pairs) expect(copy, name).toEqual(original);
  });
});

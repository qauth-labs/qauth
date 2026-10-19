import { describe, expect, it } from 'vitest';

import { parseSuspensionArgs } from './client-suspension';

/**
 * Argument parsing for the operator suspension tool (ANT-2026-DR5XI3LV). The
 * database half, `setClientSuspension`, is covered against real Postgres in
 * `client-suspension.integration.test.ts`.
 */
describe('parseSuspensionArgs', () => {
  const argv = (...args: string[]) => ['node', 'suspend-oauth-client.ts', ...args];

  it('suspends by default', () => {
    expect(parseSuspensionArgs(argv('--realm=master', '--client-id=app-1'))).toEqual({
      realm: 'master',
      clientId: 'app-1',
      suspend: true,
    });
  });

  it('lifts with --lift', () => {
    expect(
      parseSuspensionArgs(argv('--lift', '--realm=master', '--client-id=https://a.example/c.json'))
    ).toEqual({ realm: 'master', clientId: 'https://a.example/c.json', suspend: false });
  });

  it.each([
    [[]],
    [['--realm=master']],
    [['--client-id=app-1']],
    [['--realm=', '--client-id=app-1']],
    [['--realm=master', '--client-id=app-1', '--force']],
    [['--realm=master', 'app-1']],
  ])('refuses %j instead of guessing', (args) => {
    expect(parseSuspensionArgs(argv(...args))).toBeNull();
  });
});

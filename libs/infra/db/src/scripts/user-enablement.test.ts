import { describe, expect, it } from 'vitest';

import { parseUserEnablementArgs } from './user-enablement';

/**
 * Argument parsing for the operator tool that disables and enables accounts
 * (#748). The database half, `setUserEnabled`, is covered against real
 * Postgres in `user-enablement.integration.test.ts`.
 */
describe('parseUserEnablementArgs', () => {
  const argv = (...args: string[]) => ['node', 'disable-user.ts', ...args];
  const USER_ID = '0199f9a1-0000-7000-8000-00000000000a';

  it('disables by default', () => {
    expect(parseUserEnablementArgs(argv('--realm=master', `--user-id=${USER_ID}`))).toEqual({
      realm: 'master',
      userId: USER_ID,
      enable: false,
    });
  });

  it('enables with --enable, and writes the id as Postgres prints it', () => {
    expect(
      parseUserEnablementArgs(
        argv('--enable', '--realm=master', `--user-id=${USER_ID.toUpperCase()}`)
      )
    ).toEqual({ realm: 'master', userId: USER_ID, enable: true });
  });

  it.each([
    [[]],
    [['--realm=master']],
    [[`--user-id=${USER_ID}`]],
    [['--realm=', `--user-id=${USER_ID}`]],
    [['--realm=master', '--user-id=alice@example.com']],
    [['--realm=master', `--user-id=${USER_ID}x`]],
    [['--realm=master', `--user-id=${USER_ID}`, '--force']],
    [['--realm=master', `--user-id=${USER_ID}`, '--disable']],
    [['--realm=master', USER_ID]],
  ])('refuses %j instead of guessing', (args) => {
    expect(parseUserEnablementArgs(argv(...args))).toBeNull();
  });
});

import { describe, expect, it } from 'vitest';

import { KEYS_CREATE_USAGE, KeysCreateUsageError, parseKeysCreateArguments } from './keys-create';

describe('parseKeysCreateArguments', () => {
  it('reads the purpose and algorithm, and takes the default realm', () => {
    expect(
      parseKeysCreateArguments(['--purpose=token_signing', '--algorithm', 'RS256'], 'master')
    ).toEqual({ realmName: 'master', purpose: 'token_signing', algorithm: 'RS256' });
  });

  it('reads the realm, status and scope', () => {
    expect(
      parseKeysCreateArguments(
        ['--purpose=webhook_signing', '--realm=acme', '--status=next', '--scope=subscription-1'],
        'master'
      )
    ).toEqual({
      realmName: 'acme',
      purpose: 'webhook_signing',
      status: 'next',
      scopeId: 'subscription-1',
    });
  });

  it.each([
    [[], '--purpose is required.'],
    [['--purpose=token_signing', '--status=retired'], '--status is active or next'],
    [['--purpose=token_signing', '--kid=mine'], "Unknown option '--kid'"],
    [['--purpose=token_signing', 'extra'], 'extra'],
  ])('refuses %j with the usage', (argv, problem) => {
    let error: unknown;
    try {
      parseKeysCreateArguments(argv, 'master');
    } catch (caught) {
      error = caught;
    }

    expect(error).toBeInstanceOf(KeysCreateUsageError);
    expect((error as Error).message).toContain(problem);
    expect((error as Error).message).toContain(KEYS_CREATE_USAGE);
  });
});

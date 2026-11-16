import { describe, expect, it } from 'vitest';

import { runsUnattended } from './unattended';

/**
 * Which calls the approval gate lets through with no approval (#1090): a
 * service account's `users.delete` under its `account-closer` grant on the
 * realm, while the realm needs one approval for it.
 */
describe('runsUnattended (#1090)', () => {
  const closer = {
    kind: 'service_account' as const,
    unattendedOperations: new Set(['users.delete']),
  };

  it('lets a service account delete under its grant where the realm needs one approval', () => {
    expect(runsUnattended(closer, 'users.delete', 1)).toBe(true);
  });

  it('never where the realm makes a second admin mandatory for the deletion', () => {
    expect(runsUnattended(closer, 'users.delete', 2)).toBe(false);
  });

  it('never for another security operation', () => {
    for (const operationId of ['users.verify', 'clients.delete', 'realms.policies.update']) {
      expect(runsUnattended(closer, operationId, 1), operationId).toBe(false);
    }
  });

  it('never for a person, whatever the authority stage named', () => {
    expect(runsUnattended({ ...closer, kind: 'human' }, 'users.delete', 1)).toBe(false);
  });

  it('never for a service account without the grant on the realm', () => {
    expect(
      runsUnattended(
        { kind: 'service_account', unattendedOperations: new Set() },
        'users.delete',
        1
      )
    ).toBe(false);
    expect(runsUnattended({ kind: 'service_account' }, 'users.delete', 1)).toBe(false);
  });
});

import { SERVICE_ROLE_NAMES, type ServiceRole } from '@qauth-labs/server-config';
import { describe, expect, it, vi } from 'vitest';

import { createReadinessRegistry } from '../helpers/readiness';
import {
  KEK_CHECK_REUSE_MS,
  registerRoleReadinessChecks,
  type RoleReadinessSource,
} from './readiness';

/** THE CHECKS EACH ROLE REGISTERS FOR `GET /ready` (#500). */

/** A source whose dependencies answer, each a spy. */
function source(overrides: Partial<RoleReadinessSource> = {}) {
  const dbQuery = vi.fn(async () => ({ rows: [] }));
  const ping = vi.fn(async () => 'PONG');
  const checkKeyCustody = vi.fn(async () => undefined);
  const deliveryLagSeconds = vi.fn(async () => 0);
  const built = {
    readiness: createReadinessRegistry(),
    dbPool: { query: dbQuery },
    redis: { ping },
    checkKeyCustody,
    repositories: { eventDeliveries: { deliveryLagSeconds } },
    ...overrides,
  } as unknown as RoleReadinessSource;
  return { built, dbQuery, ping, checkKeyCustody, deliveryLagSeconds };
}

describe('registerRoleReadinessChecks', () => {
  it('registers the checks of what each role needs', () => {
    const cases: [readonly ServiceRole[], string[]][] = [
      [SERVICE_ROLE_NAMES, ['database', 'redis', 'kek', 'outbox']],
      [['web'], ['database', 'redis']],
      [['api'], ['database', 'redis']],
      [['admin'], ['database', 'redis']],
      [['signer'], ['database', 'kek']],
      [['delivery'], ['database', 'outbox']],
      [
        ['api', 'signer'],
        ['database', 'redis', 'kek'],
      ],
    ];
    for (const [roles, names] of cases) {
      const { built } = source();
      registerRoleReadinessChecks(built, roles);
      expect(built.readiness.names(), roles.join()).toEqual(names);
    }
  });

  it('runs each check against its dependency', async () => {
    const { built, dbQuery, ping, checkKeyCustody, deliveryLagSeconds } = source();
    registerRoleReadinessChecks(built, SERVICE_ROLE_NAMES);

    await expect(built.readiness.run()).resolves.toEqual({
      ready: true,
      checks: {
        database: { status: 'ok' },
        redis: { status: 'ok' },
        kek: { status: 'ok' },
        outbox: { status: 'ok' },
      },
    });
    expect(dbQuery).toHaveBeenCalledWith('SELECT 1');
    expect(ping).toHaveBeenCalledTimes(1);
    expect(checkKeyCustody).toHaveBeenCalledTimes(1);
    expect(deliveryLagSeconds).toHaveBeenCalledWith(expect.any(Number));
  });

  it('names the dependency that fails', async () => {
    const { built, ping } = source();
    ping.mockRejectedValue(new Error('Connection is closed.'));
    registerRoleReadinessChecks(built, ['api']);

    await expect(built.readiness.run()).resolves.toEqual({
      ready: false,
      checks: { database: { status: 'ok' }, redis: { status: 'fail', reason: 'error' } },
    });
  });

  it('reuses a passing KEK check for a while: unwrapping may cost a KMS call', async () => {
    let clock = 0;
    const { built, checkKeyCustody } = source({
      readiness: createReadinessRegistry({ now: () => clock }),
    });
    registerRoleReadinessChecks(built, ['signer']);

    await built.readiness.run();
    clock = KEK_CHECK_REUSE_MS - 1;
    await built.readiness.run();
    expect(checkKeyCustody).toHaveBeenCalledTimes(1);
    clock = KEK_CHECK_REUSE_MS;
    await built.readiness.run();
    expect(checkKeyCustody).toHaveBeenCalledTimes(2);
  });

  it('refuses a signer without the custody check, and a delivery process without the outbox', () => {
    expect(() =>
      registerRoleReadinessChecks(source({ checkKeyCustody: undefined }).built, ['signer'])
    ).toThrow('The kek readiness check needs the signer plugin registered first');
    expect(() =>
      registerRoleReadinessChecks(source({ repositories: {} }).built, ['delivery'])
    ).toThrow('The outbox readiness check needs the eventDeliveries repository');
  });
});

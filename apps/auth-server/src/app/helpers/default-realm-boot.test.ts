import { describe, expect, it, vi } from 'vitest';

import {
  bootDefaultRealm,
  type DefaultRealmBootDependencies,
  DefaultRealmBootError,
  defaultRealmIssuerFrom,
  JWT_ISSUER_PATH_WARNING,
  JWT_ISSUER_TRAILING_SLASH_WARNING,
} from './default-realm-boot';
import type { RealmRow } from './realm';

/**
 * The default realm's boot step (#484), without a database: how `JWT_ISSUER`
 * becomes the stored issuer and primary host, and what the boot logs. The
 * steps against a real Postgres are in `default-realm-boot.integration.test.ts`.
 */

describe('defaultRealmIssuerFrom', () => {
  it('stores https://auth.example.com:8443/ as https://auth.example.com:8443 on the host auth.example.com', () => {
    expect(defaultRealmIssuerFrom('https://auth.example.com:8443/')).toEqual({
      issuer: 'https://auth.example.com:8443',
      host: 'auth.example.com',
      warnings: [JWT_ISSUER_TRAILING_SLASH_WARNING],
    });
  });

  it('keeps an origin with no trailing slash as it is, with no warning', () => {
    expect(defaultRealmIssuerFrom('https://auth.example.com')).toEqual({
      issuer: 'https://auth.example.com',
      host: 'auth.example.com',
      warnings: [],
    });
  });

  it('keeps a path, takes only the host for routing, and warns', () => {
    expect(defaultRealmIssuerFrom('https://example.com/auth')).toEqual({
      issuer: 'https://example.com/auth',
      host: 'example.com',
      warnings: [JWT_ISSUER_PATH_WARNING],
    });
  });

  it('warns twice for a path with a trailing slash, and drops the slash', () => {
    expect(defaultRealmIssuerFrom('https://example.com/auth/')).toEqual({
      issuer: 'https://example.com/auth',
      host: 'example.com',
      warnings: [JWT_ISSUER_TRAILING_SLASH_WARNING, JWT_ISSUER_PATH_WARNING],
    });
  });

  it('keeps the issuer as written and writes the host in stored form', () => {
    expect(defaultRealmIssuerFrom('http://LocalHost:3000')).toMatchObject({
      issuer: 'http://LocalHost:3000',
      host: 'localhost',
    });
  });

  it.each(['https://127.0.0.1:3000', 'https://[::1]'])(
    'refuses %s, whose host can be no primary host, naming JWT_ISSUER',
    (jwtIssuer) => {
      expect(() => defaultRealmIssuerFrom(jwtIssuer)).toThrow(DefaultRealmBootError);
      expect(() => defaultRealmIssuerFrom(jwtIssuer)).toThrow(
        `The host of JWT_ISSUER "${jwtIssuer}" cannot be the default realm's primary host`
      );
    }
  );
});

/** A realm row as the repository returns it. */
function realmRow(overrides: Partial<RealmRow> = {}): RealmRow {
  return {
    id: '019a0000-0000-7000-8000-000000000001',
    name: 'master',
    enabled: true,
    issuer: null,
    isOperator: false,
    ...overrides,
  } as RealmRow;
}

/**
 * The boot step's dependencies over an empty database: the realm is created,
 * and the transaction runs its callback with a stand-in handle.
 */
function emptyDatabase(): {
  deps: DefaultRealmBootDependencies;
  warn: ReturnType<typeof vi.fn>;
  info: ReturnType<typeof vi.fn>;
} {
  const created = realmRow({ issuer: 'https://auth.example.com' });
  const realms = {
    lockProvisioning: vi.fn(async () => undefined),
    findByName: vi.fn(async () => undefined),
    findByHost: vi.fn(async () => undefined),
    findOperator: vi.fn(async () => undefined),
    createWithPrimaryHost: vi.fn(async () => ({
      realm: created,
      host: { host: 'auth.example.com', realmId: created.id, kind: 'primary', createdAt: 0 },
    })),
    update: vi.fn(async (_id: string, data: Partial<RealmRow>) => ({ ...created, ...data })),
    addEndpointHost: vi.fn(async (realmId: string, host: string) => ({
      host,
      realmId,
      kind: 'endpoint',
      createdAt: 0,
    })),
  };
  const warn = vi.fn();
  const info = vi.fn();
  const deps = {
    db: { transaction: async (run: (tx: unknown) => Promise<unknown>) => run({}) },
    realms,
    log: { warn, info },
  } as unknown as DefaultRealmBootDependencies;
  return { deps, warn, info };
}

describe('bootDefaultRealm logging', () => {
  const settings = { realmName: 'master', endpointHosts: ['auth-server'] };

  it('logs a warning for a trailing slash', async () => {
    const { deps, warn } = emptyDatabase();

    await bootDefaultRealm(deps, { ...settings, jwtIssuer: 'https://auth.example.com/' });

    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn).toHaveBeenCalledWith(
      { variable: 'JWT_ISSUER', issuer: 'https://auth.example.com/' },
      JWT_ISSUER_TRAILING_SLASH_WARNING
    );
  });

  it('logs a warning for a path', async () => {
    const { deps, warn } = emptyDatabase();

    await bootDefaultRealm(deps, { ...settings, jwtIssuer: 'https://auth.example.com/qauth' });

    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn).toHaveBeenCalledWith(
      { variable: 'JWT_ISSUER', issuer: 'https://auth.example.com/qauth' },
      JWT_ISSUER_PATH_WARNING
    );
  });

  it('logs no warning for an origin', async () => {
    const { deps, warn } = emptyDatabase();

    await bootDefaultRealm(deps, { ...settings, jwtIssuer: 'https://auth.example.com' });

    expect(warn).not.toHaveBeenCalled();
  });

  it('logs one line with the realm name, issuer, host and operator flag', async () => {
    const { deps, info } = emptyDatabase();

    await bootDefaultRealm(deps, { ...settings, jwtIssuer: 'https://auth.example.com' });

    expect(info).toHaveBeenCalledTimes(1);
    expect(info).toHaveBeenCalledWith(
      {
        realm: 'master',
        issuer: 'https://auth.example.com',
        host: 'auth.example.com',
        operator: true,
        endpointHostsAdded: ['auth-server'],
      },
      'default realm ready'
    );
  });

  it('takes the provisioning lock before it reads a realm', async () => {
    const { deps } = emptyDatabase();
    const realms = deps.realms as unknown as Record<string, ReturnType<typeof vi.fn>>;

    await bootDefaultRealm(deps, { ...settings, jwtIssuer: 'https://auth.example.com' });

    expect(realms['lockProvisioning'].mock.invocationCallOrder[0]).toBeLessThan(
      realms['findByName'].mock.invocationCallOrder[0]
    );
  });
});

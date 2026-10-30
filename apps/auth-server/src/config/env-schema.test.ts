import {
  AUTH_SERVER_KEYS,
  CONFIG_KEY_REGISTRY,
  cryptoEnvSchema,
  envSchemaShape,
  findRegistryDrift,
  jwtEnvSchema,
  SERVER_CONFIG_KEYS,
} from '@qauth-labs/server-config';
import { describe, expect, it } from 'vitest';

import { envSchema } from './env-schema';

/**
 * The auth server's half of the configuration key registry contract
 * (ADR-018 §5). `server-config`'s own test covers the schemas it defines; it
 * cannot see this app, so the keys this app adds are checked here.
 */
describe('the auth server env schema and the configuration key registry', () => {
  const read = [
    ...Object.keys(envSchemaShape(envSchema)),
    ...Object.keys(envSchemaShape(jwtEnvSchema)),
    ...Object.keys(envSchemaShape(cryptoEnvSchema)),
  ];

  it('registers every key the auth server reads', () => {
    expect(findRegistryDrift(read, CONFIG_KEY_REGISTRY).unregistered).toEqual([]);
  });

  it("registers this app's own keys as AUTH_SERVER_KEYS, and nothing else there", () => {
    const library = new Set(SERVER_CONFIG_KEYS.map((key) => key.name));
    const own = read.filter((name) => !library.has(name));

    expect(findRegistryDrift(own, AUTH_SERVER_KEYS)).toEqual({ unregistered: [], orphaned: [] });
  });
});

/**
 * The OTLP exporter variables (#541) are process-wide, so they are checked
 * only when the event export, which reads them, is on.
 */
describe('the OTLP exporter variables', () => {
  const env = (extra: Record<string, string>) => ({
    DATABASE_URL: 'postgresql://qauth@127.0.0.1:5432/qauth',
    JWT_ISSUER: 'https://auth.example.com',
    EMAIL_FROM_ADDRESS: 'no-reply@auth.example.com',
    EMAIL_BASE_URL: 'https://auth.example.com',
    OTEL_EXPORTER_OTLP_HEADERS: 'x-api-key=s3cr3t;meta',
    ...extra,
  });
  const issuesOf = (extra: Record<string, string>) => {
    const result = envSchema.safeParse(env(extra));
    return result.success ? [] : result.error.issues.map((issue) => issue.path.join('.'));
  };

  it('leaves them to their owner when the export is off', () => {
    expect(issuesOf({})).not.toContain('OTEL_EXPORTER_OTLP_HEADERS');
  });

  it('refuses a malformed one when the export is on, without its value', () => {
    expect(issuesOf({ OTEL_EVENTS_ENABLED: 'true' })).toContain('OTEL_EXPORTER_OTLP_HEADERS');
    const result = envSchema.safeParse(env({ OTEL_EVENTS_ENABLED: 'true' }));
    expect(JSON.stringify(result.error?.issues)).not.toContain('s3cr3t');
  });
});

/**
 * The admin API's listener (#511) is a second server of the same process, so
 * it cannot share the public port.
 */
describe('the admin listener port', () => {
  const issuesOf = (extra: Record<string, string>) => {
    const result = envSchema.safeParse({
      DATABASE_URL: 'postgresql://qauth@127.0.0.1:5432/qauth',
      JWT_ISSUER: 'https://auth.example.com',
      EMAIL_FROM_ADDRESS: 'no-reply@auth.example.com',
      EMAIL_BASE_URL: 'https://auth.example.com',
      ...extra,
    });
    return result.success ? [] : result.error.issues.map((issue) => issue.path.join('.'));
  };

  it('refuses ADMIN_API_PORT equal to PORT on a process that runs the admin listener', () => {
    expect(issuesOf({ PORT: '3002', ADMIN_API_ENABLED: 'true' })).toContain('ADMIN_API_PORT');
    expect(issuesOf({ PORT: '4000', ADMIN_API_PORT: '4000', ADMIN_API_ENABLED: 'true' })).toContain(
      'ADMIN_API_PORT'
    );
  });

  it('accepts it where no admin listener runs: off, as by default, or no admin role', () => {
    expect(issuesOf({ PORT: '3002' })).not.toContain('ADMIN_API_PORT');
    expect(issuesOf({ PORT: '3002', ADMIN_API_ENABLED: 'false' })).not.toContain('ADMIN_API_PORT');
    expect(
      issuesOf({ PORT: '3002', ADMIN_API_ENABLED: 'true', SERVICE_ROLES: 'web,api' })
    ).not.toContain('ADMIN_API_PORT');
  });

  it('accepts the defaults', () => {
    expect(issuesOf({})).not.toContain('ADMIN_API_PORT');
    expect(issuesOf({ ADMIN_API_ENABLED: 'true' })).not.toContain('ADMIN_API_PORT');
  });
});

/**
 * Until admin tokens are DPoP-bound (#520), a production process runs the
 * admin listener on loopback only (#511).
 */
describe('the admin listener address', () => {
  const parse = (extra: Record<string, string>) =>
    envSchema.safeParse({
      DATABASE_URL: 'postgresql://qauth@127.0.0.1:5432/qauth',
      JWT_ISSUER: 'https://auth.example.com',
      EMAIL_FROM_ADDRESS: 'no-reply@auth.example.com',
      EMAIL_BASE_URL: 'https://auth.example.com',
      ...extra,
    });
  /** The issue on ADMIN_API_HOST, if any. */
  const hostIssue = (extra: Record<string, string>) => {
    const result = parse(extra);
    return result.success
      ? undefined
      : result.error.issues.find((issue) => issue.path.join('.') === 'ADMIN_API_HOST');
  };
  const production = { NODE_ENV: 'production', ADMIN_API_ENABLED: 'true' };

  it.each(['0.0.0.0', '10.0.4.12', '::', 'fd00::12', 'admin.internal', '::ffff:10.0.0.1'])(
    'refuses %s in production while the listener is on, naming the variable and #520',
    (host) => {
      const issue = hostIssue({ ...production, ADMIN_API_HOST: host });
      expect(issue?.message).toContain('ADMIN_API_HOST must be a loopback address');
      expect(issue?.message).toContain('#520');
    }
  );

  it.each(['127.0.0.1', '127.8.9.10', '::1', '0:0:0:0:0:0:0:1', 'localhost', 'LocalHost'])(
    'accepts the loopback address %s in production',
    (host) => {
      expect(hostIssue({ ...production, ADMIN_API_HOST: host })).toBeUndefined();
    }
  );

  it('accepts the default address in production', () => {
    expect(hostIssue(production)).toBeUndefined();
  });

  it('accepts any address outside production, with the listener off, or without the admin role', () => {
    const host = { ADMIN_API_HOST: '10.0.4.12' };
    expect(
      hostIssue({ ...host, ADMIN_API_ENABLED: 'true', NODE_ENV: 'development' })
    ).toBeUndefined();
    expect(hostIssue({ ...host, NODE_ENV: 'production' })).toBeUndefined();
    expect(
      hostIssue({ ...host, ...production, SERVICE_ROLES: 'web,api,signer,delivery' })
    ).toBeUndefined();
  });
});

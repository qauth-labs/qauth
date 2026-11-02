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
 * Admin tokens are DPoP-bound (#520): a process that runs the admin listener
 * needs DPoP and the base URL the proofs name, and listens wherever the
 * operator binds it, in production too (the loopback-only rule of #511 held
 * until then), behind an https base URL there.
 */
describe('the admin listener address, base URL and DPoP', () => {
  const parse = (extra: Record<string, string>) =>
    envSchema.safeParse({
      DATABASE_URL: 'postgresql://qauth@127.0.0.1:5432/qauth',
      JWT_ISSUER: 'https://auth.example.com',
      EMAIL_FROM_ADDRESS: 'no-reply@auth.example.com',
      EMAIL_BASE_URL: 'https://auth.example.com',
      ...extra,
    });
  /** The issue on `variable`, if any. */
  const issueOn = (variable: string, extra: Record<string, string>) => {
    const result = parse(extra);
    return result.success
      ? undefined
      : result.error.issues.find((issue) => issue.path.join('.') === variable);
  };
  const listener = {
    ADMIN_API_ENABLED: 'true',
    ADMIN_API_BASE_URL: 'https://admin.auth.example.com',
    DPOP_ENABLED: 'true',
  };

  it.each(['0.0.0.0', '10.0.4.12', '::', 'admin.internal', '127.0.0.1'])(
    'accepts the address %s in production',
    (host) => {
      expect(
        issueOn('ADMIN_API_HOST', { ...listener, NODE_ENV: 'production', ADMIN_API_HOST: host })
      ).toBeUndefined();
    }
  );

  it('refuses a plain http base URL in production, unless it and the listener are loopback', () => {
    const production = { ...listener, NODE_ENV: 'production' };
    for (const [baseUrl, host] of [
      ['http://admin.auth.example.com', '127.0.0.1'],
      ['http://10.0.4.12:3002', '0.0.0.0'],
      // A loopback URL names nothing a remote caller could not name too.
      ['http://127.0.0.1:3002', '0.0.0.0'],
    ]) {
      const issue = issueOn('ADMIN_API_BASE_URL', {
        ...production,
        ADMIN_API_BASE_URL: baseUrl,
        ADMIN_API_HOST: host,
      });
      expect(issue?.message).toContain('must be an https URL in production (#520)');
    }
    for (const [baseUrl, host] of [
      ['https://admin.auth.example.com', '0.0.0.0'],
      ['http://127.0.0.1:3002', '127.0.0.1'],
      ['http://localhost:3002', 'localhost'],
      ['http://[::1]:3002', '::1'],
    ]) {
      expect(
        issueOn('ADMIN_API_BASE_URL', {
          ...production,
          ADMIN_API_BASE_URL: baseUrl,
          ADMIN_API_HOST: host,
        })
      ).toBeUndefined();
    }
    // Outside production, any http base URL.
    expect(
      issueOn('ADMIN_API_BASE_URL', {
        ...listener,
        ADMIN_API_BASE_URL: 'http://admin.qauth.test',
        ADMIN_API_HOST: '0.0.0.0',
      })
    ).toBeUndefined();
  });

  it('accepts a process that runs the listener with DPoP on and a base URL', () => {
    expect(issueOn('ADMIN_API_BASE_URL', listener)).toBeUndefined();
    expect(issueOn('DPOP_ENABLED', listener)).toBeUndefined();
  });

  it('refuses a process that runs the listener without a base URL, naming the variable and #520', () => {
    const issue = issueOn('ADMIN_API_BASE_URL', { ...listener, ADMIN_API_BASE_URL: '' });
    expect(issue?.message).toContain('ADMIN_API_BASE_URL is required where the admin API runs');
    expect(issue?.message).toContain('#520');
  });

  it('refuses a process that runs the listener with DPoP off, naming the variable and #520', () => {
    for (const dpop of [{ DPOP_ENABLED: 'false' }, { DPOP_ENABLED: '' }]) {
      const issue = issueOn('DPOP_ENABLED', { ...listener, ...dpop });
      expect(issue?.message).toContain('DPOP_ENABLED must be true where the admin API runs');
      expect(issue?.message).toContain('#520');
    }
  });

  it('asks for neither with the listener off, as by default, or without the admin role', () => {
    for (const extra of [
      {},
      { ADMIN_API_ENABLED: 'false' },
      { ADMIN_API_ENABLED: 'true', SERVICE_ROLES: 'web,api,signer,delivery' },
    ] as Record<string, string>[]) {
      expect(issueOn('ADMIN_API_BASE_URL', extra)).toBeUndefined();
      expect(issueOn('DPOP_ENABLED', extra)).toBeUndefined();
    }
  });

  it('refuses a base URL that is not an absolute http or https URL', () => {
    expect(
      issueOn('ADMIN_API_BASE_URL', { ...listener, ADMIN_API_BASE_URL: 'admin.example.com' })
        ?.message
    ).toContain('an absolute http or https URL');
  });
});

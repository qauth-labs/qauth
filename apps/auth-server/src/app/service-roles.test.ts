/**
 * THE SERVICE ROLES (#495): what each role loads, and what a process without
 * the signer refuses.
 */
import {
  databasePlugin,
  hasRepository,
  REPOSITORY_NAMES,
  type RepositoryName,
} from '@qauth-labs/fastify-plugin-db';
import Fastify, { type FastifyInstance } from 'fastify';
import { describe, expect, it } from 'vitest';

import { createUnavailableSigner } from './helpers/unavailable-signer';
import { SERVER_JOBS, serverJobs } from './jobs';
import {
  checkServiceRoles,
  describeServiceRoles,
  isKeyMaterialVariable,
  pluginsFor,
  repositoriesFor,
  routeRolesProblem,
  SERVICE_ROLE_NAMES,
  ServiceRoleBootError,
  type ServiceRoleSettings,
} from './service-roles';

/** The settings of a process with `roles` that reaches the signer service. */
function splitSettings(roles: ServiceRoleSettings['SERVICE_ROLES']): ServiceRoleSettings {
  return {
    SERVICE_ROLES: roles,
    SIGNER_URL: 'https://signer.internal:3443',
    INTERNAL_TLS_CERT_PATH: '/run/secrets/internal.crt',
    INTERNAL_TLS_KEY_PATH: '/run/secrets/internal.key',
    INTERNAL_TLS_CA_PATH: '/run/secrets/internal-ca.crt',
    JWT_PUBLIC_KEY: '-----BEGIN PUBLIC KEY-----',
  };
}

describe('the route-to-role check', () => {
  const route = { method: 'GET', url: '/oauth/example' };

  it('passes a route that names its roles', () => {
    expect(routeRolesProblem({ ...route, config: { serviceRoles: ['api'] } })).toBeUndefined();
    expect(routeRolesProblem({ ...route, config: { serviceRoles: SERVICE_ROLE_NAMES } })).toBe(
      undefined
    );
  });

  it('fails a route with no role, and names the route and the manifest', () => {
    for (const config of [undefined, {}, { serviceRoles: undefined }]) {
      const problem = routeRolesProblem({ ...route, config });
      expect(problem).toContain('GET /oauth/example');
      expect(problem).toContain('route-manifest.ts');
    }
  });

  it('fails an empty or unknown role list', () => {
    expect(routeRolesProblem({ ...route, config: { serviceRoles: [] } })).toContain(
      'GET /oauth/example'
    );
    expect(routeRolesProblem({ ...route, config: { serviceRoles: ['frontend'] } })).toContain(
      'no known service role'
    );
    expect(routeRolesProblem({ ...route, config: { serviceRoles: 'api' } })).toBeDefined();
  });
});

describe('what each role loads (the boot-time list)', () => {
  /** The repositories no process builds: nothing reads them. */
  const UNUSED: readonly RepositoryName[] = ['auditLogs'];

  it('builds every repository but the unused ones in a single process', () => {
    expect(repositoriesFor(SERVICE_ROLE_NAMES)).toEqual(
      REPOSITORY_NAMES.filter((name) => !UNUSED.includes(name))
    );
  });

  it('gives signer and admin only the realms the resolver reads', () => {
    expect(repositoriesFor(['signer'])).toEqual(['realms']);
    expect(repositoriesFor(['admin'])).toEqual(['realms']);
    expect([...pluginsFor(['signer'])]).toEqual([]);
    expect([...pluginsFor(['admin'])]).toEqual([]);
  });

  it('gives delivery the event store and the SSF streams, and no identity data', () => {
    expect(repositoriesFor(['delivery'])).toEqual([
      'realms',
      'events',
      'eventDeliveries',
      'eventRetention',
      'ssfStreams',
    ]);
    expect([...pluginsFor(['delivery'])]).toEqual(['ssf', 'eventDelivery']);
  });

  it('keeps the API-only stores out of web', () => {
    const web = repositoriesFor(['web']);
    for (const name of [
      'apiKeys',
      'emailVerificationTokens',
      'eventDeliveries',
      'eventRetention',
      'ssfStreams',
    ] as const) {
      expect(web).not.toContain(name);
    }
    expect(web).toContain('sessions');
    expect([...pluginsFor(['web'])]).toEqual(['dpop', 'jwt', 'password', 'federation', 'sessions']);
  });

  it('keeps the delivery state out of api, which purges the expired rows', () => {
    const api = repositoriesFor(['api']);
    for (const name of ['eventDeliveries', 'eventRetention'] as const) {
      expect(api).not.toContain(name);
    }
    for (const name of [
      'authorizationCodes',
      'refreshTokens',
      'emailVerificationTokens',
      'oid4vpRequestStates',
    ] as const) {
      expect(api).toContain(name);
    }
    expect(pluginsFor(['api']).has('eventDelivery')).toBe(false);
    expect(pluginsFor(['api']).has('pkce')).toBe(true);
  });

  it('loads the DPoP plugin wherever the JWT plugin loads', () => {
    for (const role of SERVICE_ROLE_NAMES) {
      const plugins = pluginsFor([role]);
      if (plugins.has('jwt')) expect(plugins.has('dpop'), role).toBe(true);
    }
  });

  it('writes all for every role and the list otherwise', () => {
    expect(describeServiceRoles(SERVICE_ROLE_NAMES)).toBe('all');
    expect(describeServiceRoles(['web', 'api'])).toBe('web,api');
  });
});

describe('the jobs of each role', () => {
  it('places purge-expired on api and event retention on delivery', () => {
    expect(Object.fromEntries(SERVER_JOBS.map((job) => [job.name, job.role]))).toEqual({
      'purge-expired': 'api',
      'event-retention': 'delivery',
    });
  });

  it('builds only the jobs of the roles it is given', () => {
    // A process without the event retention repository: building the
    // retention job would read it and throw.
    const fastify = {
      repositories: new Proxy(
        {},
        {
          get(_target, name) {
            throw new Error(`read ${String(name)}`);
          },
        }
      ),
      metrics: {},
    } as unknown as FastifyInstance;
    expect(serverJobs(fastify, {}, ['web', 'admin', 'signer'])).toEqual([]);
    expect(serverJobs(fastify, {}, ['api']).map((job) => job.name)).toEqual(['purge-expired']);
    expect(() => serverJobs(fastify, {}, ['delivery'])).toThrow('read eventRetention');
  });
});

describe('isKeyMaterialVariable', () => {
  it.each([
    ['KEK', 'a2V5'],
    ['KEK_PATH', '/run/secrets/kek'],
    ['KEK_PREVIOUS', 'a2V5'],
    ['KEK_PREVIOUS_PATH', '/run/secrets/kek-previous'],
    ['KEK_PROVIDER', 'cloud-kms'],
    ['KEK_CLOUD_KMS_KEY_ID', 'key-1'],
    ['JWT_PRIVATE_KEY', 'pem'],
    ['JWT_PRIVATE_KEY_PATH', '/run/secrets/ed25519.pem'],
    ['JWT_RS256_PRIVATE_KEY', 'pem'],
    ['JWT_RS256_PRIVATE_KEY_PATH', '/run/secrets/rs256.pem'],
    ['JWT_MLDSA_PRIVATE_KEY', 'seed'],
    ['JWT_MLDSA_PRIVATE_KEY_PATH', '/run/secrets/mldsa'],
    ['OID4VP_VERIFIER_SIGNING_KEY', 'pem'],
    ['OID4VP_VERIFIER_SIGNING_KEY_PATH', '/run/secrets/verifier.pem'],
  ])('counts %s as key material', (name, value) => {
    expect(isKeyMaterialVariable(name, value)).toBe(true);
  });

  it.each([
    ['KEK_PROVIDER', 'local'],
    ['KEK', ''],
    ['JWT_PRIVATE_KEY', '   '],
    ['JWT_PUBLIC_KEY', 'pem'],
    ['JWT_RS256_PUBLIC_KEY', 'pem'],
    ['JWT_RS256_KID', 'rs-1'],
    ['JWT_MLDSA_KID', 'ml-1'],
    ['OID4VP_VERIFIER_CERTIFICATE_CHAIN', 'pem'],
    ['SESSION_COOKIE_SECRET', 'secret'],
    ['KEKS', 'x'],
  ])('does not count %s=%j', (name, value) => {
    expect(isKeyMaterialVariable(name, value)).toBe(false);
  });
});

describe('checkServiceRoles', () => {
  it('accepts a single process as it is, key variables included', () => {
    expect(
      checkServiceRoles(
        { SERVICE_ROLES: SERVICE_ROLE_NAMES },
        { KEK: 'a2V5', JWT_PRIVATE_KEY: 'p' }
      )
    ).toEqual({ problems: [], warnings: [] });
  });

  it('warns that a process with the signer ignores SIGNER_URL', () => {
    const check = checkServiceRoles(
      { SERVICE_ROLES: ['api', 'signer'], SIGNER_URL: 'https://signer.internal' },
      {}
    );
    expect(check.problems).toEqual([]);
    expect(check.warnings.map((warning) => warning.variable)).toEqual(['SIGNER_URL']);
  });

  it('refuses each key variable on a process without the signer, by name', () => {
    const check = checkServiceRoles(splitSettings(['api']), {
      KEK: 'a2V5',
      KEK_PROVIDER: 'local',
      JWT_PRIVATE_KEY_PATH: '/run/secrets/ed25519.pem',
      OID4VP_VERIFIER_SIGNING_KEY: 'pem',
      JWT_PUBLIC_KEY: 'pem',
    });
    expect(check.problems.map((problem) => problem.variable)).toEqual([
      'JWT_PRIVATE_KEY_PATH',
      'KEK',
      'OID4VP_VERIFIER_SIGNING_KEY',
    ]);
    expect(check.problems[1]?.message).toMatch(/^KEK is set, but SERVICE_ROLES=api/);
  });

  it('requires SIGNER_URL and the internal TLS files without the signer', () => {
    const check = checkServiceRoles({ SERVICE_ROLES: ['delivery'], JWT_PUBLIC_KEY: undefined }, {});
    expect(check.problems.map((problem) => problem.variable)).toEqual([
      'SIGNER_URL',
      'INTERNAL_TLS_CERT_PATH',
      'INTERNAL_TLS_KEY_PATH',
      'INTERNAL_TLS_CA_PATH',
    ]);
  });

  it('requires the public key only where tokens are verified', () => {
    const { JWT_PUBLIC_KEY: _publicKey, ...withoutPublicKey } = splitSettings(['api']);
    expect(
      checkServiceRoles({ ...withoutPublicKey, SERVICE_ROLES: ['api'] }, {}).problems.map(
        (problem) => problem.variable
      )
    ).toEqual(['JWT_PUBLIC_KEY']);
    expect(
      checkServiceRoles({ ...withoutPublicKey, SERVICE_ROLES: ['delivery'] }, {}).problems
    ).toEqual([]);
  });

  it('warns that a process without the signer cannot sign yet', () => {
    const check = checkServiceRoles(splitSettings(['web']), {});
    expect(check.problems).toEqual([]);
    expect(check.warnings.map((warning) => warning.message)).toEqual([
      expect.stringContaining('answers 503'),
    ]);
  });

  it('refuses the boot with every problem in one error', () => {
    const error = new ServiceRoleBootError(
      checkServiceRoles({ SERVICE_ROLES: ['api'] }, { KEK: 'a2V5' }).problems
    );
    expect(error.message).toContain('KEK is set');
    expect(error.message).toContain('SIGNER_URL is required');
    expect(error.problems.length).toBeGreaterThan(2);
  });
});

describe('the database plugin under a repository list', () => {
  async function databaseWith(repositories?: readonly RepositoryName[]) {
    const app = Fastify({ logger: false });
    // Never dialled: building a repository sends no query.
    await app.register(databasePlugin, {
      config: { connectionString: 'postgres://qauth:qauth@127.0.0.1:1/unreachable' },
      ...(repositories === undefined ? {} : { repositories }),
    });
    return app;
  }

  it('builds every repository without a list', async () => {
    const app = await databaseWith();
    for (const name of REPOSITORY_NAMES) {
      expect(hasRepository(app.repositories, name), name).toBe(true);
    }
    await app.close();
  });

  it('builds only the listed ones and refuses a read of another, naming it', async () => {
    const app = await databaseWith(['realms', 'events']);
    expect(hasRepository(app.repositories, 'realms')).toBe(true);
    expect(hasRepository(app.repositories, 'users')).toBe(false);
    expect(Object.keys(app.repositories).sort()).toEqual(['events', 'realms']);
    expect(typeof app.repositories.realms.findByHost).toBe('function');
    expect(() => app.repositories.users).toThrow(/The users repository is not loaded/);
    await app.close();
  });
});

describe('the signer of a process without the signer role', () => {
  it('refuses every operation with a 503', async () => {
    const signer = createUnavailableSigner('https://signer.internal');
    const operations = Object.entries(signer) as [string, () => Promise<unknown>][];
    expect(operations).toHaveLength(10);
    for (const [name, operation] of operations) {
      await expect(operation(), name).rejects.toMatchObject({
        statusCode: 503,
        code: 'TEMPORARILY_UNAVAILABLE',
        details: { operation: name, signerUrl: 'https://signer.internal' },
      });
    }
  });
});

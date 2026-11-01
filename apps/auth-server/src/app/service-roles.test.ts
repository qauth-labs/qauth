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
import { internalListenerEnvSchema } from '@qauth-labs/server-config';
import Fastify, { type FastifyInstance } from 'fastify';
import { describe, expect, it } from 'vitest';

import { createUnavailableSigner } from './helpers/unavailable-signer';
import { SERVER_JOBS, serverJobs } from './jobs';
import {
  checkServiceRoles,
  describeServiceRoles,
  internalListenerPlan,
  isKeyMaterialVariable,
  isSingleProcess,
  pluginsFor,
  repositoriesFor,
  routeRolesProblem,
  servesApiDocs,
  servesInternalListener,
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
  };
}

/** INTERNAL_PEER_ROLES as the configuration reads it. */
const PEER_ROLES = internalListenerEnvSchema.parse({
  INTERNAL_PEER_ROLES: JSON.stringify({ 'spiffe://qauth.test/web': 'web' }),
}).INTERNAL_PEER_ROLES;

/** A split process holding the signer, with its internal listener's mutual TLS. */
function signerSettings(roles: ServiceRoleSettings['SERVICE_ROLES']): ServiceRoleSettings {
  return {
    SERVICE_ROLES: roles,
    INTERNAL_TLS_CERT_PATH: '/run/secrets/signer.crt',
    INTERNAL_TLS_KEY_PATH: '/run/secrets/signer.key',
    INTERNAL_TLS_CA_PATH: '/run/secrets/internal-ca.crt',
    INTERNAL_PEER_ROLES: PEER_ROLES,
  };
}

describe('the route-to-role check', () => {
  const route = { method: 'GET', url: '/oauth/example' };

  it('passes a route that names a role of the process', () => {
    expect(
      routeRolesProblem({ ...route, config: { serviceRoles: ['api'] } }, SERVICE_ROLE_NAMES)
    ).toBeUndefined();
    expect(
      routeRolesProblem({ ...route, config: { serviceRoles: ['web', 'api'] } }, ['api'])
    ).toBeUndefined();
    expect(
      routeRolesProblem({ ...route, config: { serviceRoles: SERVICE_ROLE_NAMES } }, ['signer'])
    ).toBe(undefined);
  });

  it('fails a route whose roles the process does not hold, naming them', () => {
    const problem = routeRolesProblem({ ...route, config: { serviceRoles: ['admin'] } }, ['web']);
    expect(problem).toContain('GET /oauth/example');
    expect(problem).toContain('belongs to admin');
    expect(problem).toContain('SERVICE_ROLES=web');
  });

  it('fails a route with no role, and names the route and the manifest', () => {
    for (const config of [undefined, {}, { serviceRoles: undefined }]) {
      const problem = routeRolesProblem({ ...route, config }, SERVICE_ROLE_NAMES);
      expect(problem).toContain('GET /oauth/example');
      expect(problem).toContain('route-manifest.ts');
    }
  });

  it('fails an empty or unknown role list', () => {
    expect(
      routeRolesProblem({ ...route, config: { serviceRoles: [] } }, SERVICE_ROLE_NAMES)
    ).toContain('GET /oauth/example');
    expect(
      routeRolesProblem({ ...route, config: { serviceRoles: ['frontend'] } }, SERVICE_ROLE_NAMES)
    ).toContain('no known service role');
    expect(
      routeRolesProblem({ ...route, config: { serviceRoles: 'api' } }, SERVICE_ROLE_NAMES)
    ).toBeDefined();
  });
});

describe('what each role loads (the boot-time list)', () => {
  /**
   * The repositories no process builds: nothing reads them. Custom admin
   * roles are read only through the grants until the admin API's role routes
   * ship (#679).
   */
  const UNUSED: readonly RepositoryName[] = ['auditLogs', 'adminRoles'];

  it('builds every repository but the unused ones in a single process', () => {
    expect(repositoriesFor(SERVICE_ROLE_NAMES)).toEqual(
      REPOSITORY_NAMES.filter((name) => !UNUSED.includes(name))
    );
  });

  it('gives signer the realms the resolver reads, their published keys and their secrets', () => {
    // The secrets for the boot's seed of the default realm (#529), which only
    // a process that can encrypt runs.
    expect(repositoriesFor(['signer'])).toEqual(['realms', 'realmPublicKeys', 'realmSecrets']);
    expect([...pluginsFor(['signer'])]).toEqual([]);
  });

  it("gives admin what the admin listener's pipeline reads and writes (#511, #512)", () => {
    expect(repositoriesFor(['admin'])).toEqual([
      'users',
      'realms',
      'adminGrants',
      'adminAuditLog',
      'adminApprovals',
      'realmPublicKeys',
      'realmSecrets',
    ]);
    // The token guard verifies with the JWT plugin, which reads `fastify.dpop`.
    expect([...pluginsFor(['admin'])]).toEqual(['dpop', 'jwt']);
  });

  it('gives delivery the event store and the SSF streams, and no identity data', () => {
    expect(repositoriesFor(['delivery'])).toEqual([
      'realms',
      'events',
      'eventDeliveries',
      'eventRetention',
      'ssfStreams',
      'realmPublicKeys',
    ]);
    expect([...pluginsFor(['delivery'])]).toEqual(['ssf', 'eventDelivery']);
  });

  it('keeps the API-only stores out of web', () => {
    const web = repositoriesFor(['web']);
    // `emailVerificationTokens` is web's too: the verification page posts to
    // `/ui/verify` (#885).
    for (const name of ['apiKeys', 'eventDeliveries', 'eventRetention', 'ssfStreams'] as const) {
      expect(web).not.toContain(name);
    }
    expect(web).toContain('sessions');
    // It sends no mail, so it reads no realm secret (#529).
    expect(web).not.toContain('realmSecrets');
    // No web route reads an access token since the authorization endpoint's
    // Bearer path was retired (#524).
    expect([...pluginsFor(['web'])]).toEqual([
      'dpop',
      'password',
      'federation',
      'email',
      'sessions',
      'egress',
      'failureLadder',
    ]);
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

  it('loads the failure ladder where a login route counts on it, and nowhere else (#615)', () => {
    for (const role of SERVICE_ROLE_NAMES) {
      expect(pluginsFor([role]).has('failureLadder'), role).toBe(role === 'web' || role === 'api');
    }
    // Its hard action writes the password's disabled mark, in the repository
    // the login routes it serves read anyway.
    expect(repositoriesFor(['web'])).toContain('userCredentials');
    expect(repositoriesFor(['api'])).toContain('userCredentials');
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
  it('places purge-expired and the SSF subject sweep on api, event retention on delivery, and the interaction sweep and the session expiry and purge on web', () => {
    expect(Object.fromEntries(SERVER_JOBS.map((job) => [job.name, job.role]))).toEqual({
      'purge-expired': 'api',
      'event-retention': 'delivery',
      'ssf-subject-sweep': 'api',
      'interaction-expiry': 'web',
      'session-expiry': 'web',
      'session-purge': 'web',
    });
  });

  it('registers the session service wherever the session jobs run', () => {
    expect(pluginsFor(['web']).has('sessions')).toBe(true);
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
    expect(serverJobs(fastify, {}, ['admin', 'signer'])).toEqual([]);
    // The session jobs read no repository: they run through the session
    // service, and refuse to be built without it.
    const withEvents = {
      repositories: { events: {} },
      redis: {},
      metrics: {},
    } as unknown as FastifyInstance;
    expect(() => serverJobs(withEvents, {}, ['web'])).toThrow('fastify.sessionService');
    const withSessions = { ...withEvents, sessionService: {} } as unknown as FastifyInstance;
    expect(serverJobs(withSessions, {}, ['web']).map((job) => job.name)).toEqual([
      'interaction-expiry',
      'session-expiry',
      'session-purge',
    ]);
    expect(serverJobs(fastify, {}, ['api']).map((job) => job.name)).toEqual([
      'purge-expired',
      'ssf-subject-sweep',
    ]);
    expect(() => serverJobs(fastify, {}, ['delivery'])).toThrow('read eventRetention');
    expect(() => serverJobs(fastify, {}, ['web'])).toThrow('read events');
  });
});

describe('servesApiDocs', () => {
  it('serves /docs only on a process holding api, and only with ENABLE_SWAGGER', () => {
    expect(servesApiDocs(SERVICE_ROLE_NAMES, true)).toBe(true);
    expect(servesApiDocs(['web', 'api'], true)).toBe(true);
    for (const role of ['web', 'admin', 'signer', 'delivery'] as const) {
      expect(servesApiDocs([role], true), role).toBe(false);
    }
    expect(servesApiDocs(SERVICE_ROLE_NAMES, false)).toBe(false);
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
    // The Vault adapter's settings (#876): its address names where the KEK
    // lives, its credentials unwrap it.
    ['KEK_PROVIDER', 'vault'],
    ['KEK_VAULT_ADDR', 'https://vault.internal:8200'],
    ['KEK_VAULT_TOKEN_FILE', '/run/secrets/vault-token'],
    ['KEK_VAULT_ROLE_ID', 'role-1'],
    ['KEK_VAULT_SECRET_ID_FILE', '/run/secrets/vault-secret-id'],
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
    ['EGRESS_ALLOWLIST_PATH', '/etc/qauth/egress.json'],
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
      { ...signerSettings(['api', 'signer']), SIGNER_URL: 'https://signer.internal' },
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
    const check = checkServiceRoles({ SERVICE_ROLES: ['delivery'] }, {});
    expect(check.problems.map((problem) => problem.variable)).toEqual([
      'SIGNER_URL',
      'INTERNAL_TLS_CERT_PATH',
      'INTERNAL_TLS_KEY_PATH',
      'INTERNAL_TLS_CA_PATH',
    ]);
  });

  it('needs no public key variable where tokens are verified: the published keys verify them (#491)', () => {
    for (const roles of [['api'], ['web'], ['delivery']] as const) {
      expect(checkServiceRoles(splitSettings(roles), {}).problems, roles.join()).toEqual([]);
    }
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

describe('the internal listener (#496)', () => {
  it('runs on a process that holds the signer while the roles are split, and only there', () => {
    expect(isSingleProcess(SERVICE_ROLE_NAMES)).toBe(true);
    expect(isSingleProcess(['web', 'api', 'admin', 'signer'])).toBe(false);
    expect(servesInternalListener(SERVICE_ROLE_NAMES)).toBe(false);
    for (const roles of [
      ['signer'],
      ['api', 'signer'],
      ['web', 'api', 'admin', 'signer'],
    ] as const) {
      expect(servesInternalListener(roles), roles.join()).toBe(true);
    }
    for (const roles of [['web'], ['api'], ['admin'], ['delivery'], ['web', 'api']] as const) {
      expect(servesInternalListener(roles), roles.join()).toBe(false);
    }
    expect(internalListenerPlan({ SERVICE_ROLES: SERVICE_ROLE_NAMES })).toEqual({ serves: false });
    expect(internalListenerPlan(splitSettings(['web']))).toEqual({ serves: false });
  });

  it('serves mutual TLS with the three files and the peer roles, on loopback by default', () => {
    const plan = internalListenerPlan(signerSettings(['signer']));
    expect(plan).toEqual({
      serves: true,
      problems: [],
      host: '127.0.0.1',
      port: 3443,
      peerRoles: PEER_ROLES,
      tls: {
        certPath: '/run/secrets/signer.crt',
        keyPath: '/run/secrets/signer.key',
        caPath: '/run/secrets/internal-ca.crt',
      },
    });
    expect(checkServiceRoles(signerSettings(['signer']), {}).problems).toEqual([]);
  });

  it('may bind another address with mutual TLS', () => {
    const plan = internalListenerPlan({ ...signerSettings(['signer']), INTERNAL_HOST: '0.0.0.0' });
    expect(plan.serves && plan.problems).toEqual([]);
  });

  it('refuses to serve the signer without mutual TLS while the roles are split, naming each setting', () => {
    const check = checkServiceRoles({ SERVICE_ROLES: ['api', 'signer'] }, {});
    expect(check.problems.map((problem) => problem.variable)).toEqual([
      'INTERNAL_TLS_CERT_PATH',
      'INTERNAL_TLS_KEY_PATH',
      'INTERNAL_TLS_CA_PATH',
      'INTERNAL_PEER_ROLES',
    ]);
    const error = new ServiceRoleBootError(check.problems);
    expect(error.message).toContain(
      'INTERNAL_TLS_CERT_PATH is required: SERVICE_ROLES=api,signer serves the signer to the other roles on the internal listener, over mutual TLS only while the roles are split, so the signer routes are not registered without it'
    );
  });

  it('refuses plain HTTP on loopback too while the roles are split', () => {
    const check = checkServiceRoles(
      { SERVICE_ROLES: ['signer'], INTERNAL_HOST: '127.0.0.1', INTERNAL_PEER_ROLES: PEER_ROLES },
      {}
    );
    expect(check.problems.map((problem) => problem.variable)).toEqual([
      'INTERNAL_TLS_CERT_PATH',
      'INTERNAL_TLS_KEY_PATH',
      'INTERNAL_TLS_CA_PATH',
    ]);
  });

  it('names the TLS files missing beside the others', () => {
    const settings = { ...signerSettings(['signer']), INTERNAL_TLS_KEY_PATH: undefined };
    const check = checkServiceRoles(settings, {});
    expect(check.problems.map((problem) => problem.variable)).toEqual(['INTERNAL_TLS_KEY_PATH']);
    expect(check.problems[0]?.message).toContain('needs all three internal TLS files');
    // Every missing setting in one boot.
    expect(
      checkServiceRoles({ ...settings, INTERNAL_PEER_ROLES: new Map() }, {}).problems.map(
        (problem) => problem.variable
      )
    ).toEqual(['INTERNAL_TLS_KEY_PATH', 'INTERNAL_PEER_ROLES']);
  });

  it('refuses mutual TLS with no peer it could admit', () => {
    const check = checkServiceRoles(
      { ...signerSettings(['signer']), INTERNAL_PEER_ROLES: new Map() },
      {}
    );
    expect(check.problems.map((problem) => problem.variable)).toEqual(['INTERNAL_PEER_ROLES']);
    expect(check.problems[0]?.message).toContain('refuses every peer');
  });

  it('refuses the public port and the admin listener port', () => {
    const settings = { ...signerSettings(['admin', 'signer']), INTERNAL_PORT: 3000, PORT: 3000 };
    expect(checkServiceRoles(settings, {}).problems.map((problem) => problem.message)).toEqual([
      expect.stringContaining('INTERNAL_PORT must differ from PORT (3000)'),
    ]);
    expect(
      checkServiceRoles(
        {
          ...settings,
          PORT: 3000,
          INTERNAL_PORT: 3002,
          ADMIN_API_ENABLED: true,
          ADMIN_API_PORT: 3002,
        },
        {}
      ).problems.map((problem) => problem.message)
    ).toEqual([expect.stringContaining('INTERNAL_PORT must differ from ADMIN_API_PORT')]);
    // The admin listener off, its port is free.
    expect(
      checkServiceRoles(
        {
          ...settings,
          PORT: 3000,
          INTERNAL_PORT: 3002,
          ADMIN_API_ENABLED: false,
          ADMIN_API_PORT: 3002,
        },
        {}
      ).problems
    ).toEqual([]);
  });

  it('runs no internal listener in a single process, even once a role of its own serves an internal route', () => {
    // No module ships until #497; a signer module and an api one stand in.
    const load = async () => ({ default: async () => undefined });
    const modules = [
      {
        module: 'signer',
        prefix: '/internal/signer/v1-rc.0',
        roles: ['signer'] as const,
        peerRoles: ['web'] as const,
        load,
      },
      {
        module: 'api',
        prefix: '/internal/api/v1-rc.0',
        roles: ['api'] as const,
        peerRoles: ['web'] as const,
        load,
      },
    ];
    expect(servesInternalListener(SERVICE_ROLE_NAMES, modules)).toBe(false);
    for (const host of [undefined, '127.0.0.1', '0.0.0.0']) {
      expect(
        internalListenerPlan({ SERVICE_ROLES: SERVICE_ROLE_NAMES, INTERNAL_HOST: host }, modules),
        String(host)
      ).toEqual({ serves: false });
    }
    // Split, a process whose roles serve a module runs it, over mutual TLS only.
    expect(servesInternalListener(['web', 'api'], modules)).toBe(true);
    const plan = internalListenerPlan({ SERVICE_ROLES: ['web', 'api'] }, modules);
    expect(plan.serves && plan.problems.map((problem) => problem.variable)).toEqual([
      'INTERNAL_TLS_CERT_PATH',
      'INTERNAL_TLS_KEY_PATH',
      'INTERNAL_TLS_CA_PATH',
      'INTERNAL_PEER_ROLES',
    ]);
  });

  it('keeps a process without the signer as it was: no listener, its client settings only', () => {
    expect(checkServiceRoles(splitSettings(['web']), {}).problems).toEqual([]);
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

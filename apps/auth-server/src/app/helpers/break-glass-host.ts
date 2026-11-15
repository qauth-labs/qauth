import { readFileSync } from 'node:fs';
import { hostname, userInfo } from 'node:os';

import { cachePlugin } from '@qauth-labs/fastify-plugin-cache';
import { databasePlugin } from '@qauth-labs/fastify-plugin-db';
import { sessionServicePlugin } from '@qauth-labs/fastify-plugin-sessions';
import { proveHostKeyCustody } from '@qauth-labs/fastify-plugin-signer';
import Fastify, { type FastifyBaseLogger, type FastifyInstance } from 'fastify';

import { ADMIN_ROLE_CATALOG } from './admin-roles';
import {
  BREAK_GLASS_EXIT,
  BREAK_GLASS_USAGE,
  type BreakGlassDependencies,
  type BreakGlassOperator,
  BreakGlassUsageError,
  parseBreakGlassArguments,
  runBreakGlass,
} from './break-glass';
import {
  keysRetireDependencies,
  type KeysRetireHost,
  type KeysRetireSettings,
} from './keys-retire';

/**
 * The break-glass CLI's process (#602): what `src/break-glass.ts` runs, and
 * what the integration test runs in the test's process to check it opens no
 * listener.
 *
 * The process registers the database plugin and, for `retire-key`, the
 * cache and session plugins, whose Redis the retirement ends the realm's
 * sessions through. It registers no route and never calls `listen`: no
 * port is opened. It makes no HTTP call of its own (a KEK adapter calls its
 * key service). It reads the environment twice:
 * `DATABASE_URL` and the KEK provider's settings from `environ`, before
 * anything connects; for `retire-key` the server's configuration
 * (`config/env`), loaded only then, for the signing algorithms, Redis and
 * the session settings.
 */

/** The process's audit login uid, or `null` where the kernel keeps none. */
function loginUid(): number | null {
  try {
    const value = readFileSync('/proc/self/loginuid', 'utf8').trim();
    // 4294967295, (uid_t)-1, is "not set".
    return /^[0-9]{1,10}$/.test(value) && Number(value) < 4_294_967_295 ? Number(value) : null;
  } catch {
    return null;
  }
}

/**
 * Who runs the command and where, from the operating system. Only the sudo
 * user comes from the environment, and is recorded as reported.
 */
export function hostOperator(
  environ: Readonly<Record<string, string | undefined>> = process.env
): BreakGlassOperator {
  let name = '';
  let uid: number | null = null;
  try {
    const info = userInfo();
    name = info.username;
    if (info.uid >= 0) uid = info.uid;
  } catch {
    // No passwd entry for the uid.
  }
  if (uid === null) uid = process.getuid?.() ?? null;
  if (name === '') name = uid === null ? 'unknown' : `uid:${uid}`;
  const sudoUser = environ['SUDO_USER']?.trim().slice(0, 255);
  return Object.freeze({
    name: name.slice(0, 255),
    uid,
    loginUid: loginUid(),
    sudoUser: sudoUser ? sudoUser : null,
    host: hostname(),
  });
}

/** The decorators of the process the group reads. */
export interface BreakGlassHost {
  readonly db: FastifyInstance['db'];
  readonly log: FastifyBaseLogger;
  readonly repositories: Pick<
    FastifyInstance['repositories'],
    | 'realms'
    | 'adminEnrolments'
    | 'adminGrants'
    | 'adminAuditLog'
    | 'events'
    | 'refreshTokens'
    | 'realmPublicKeys'
  >;
  /** Only for `retire-key`. */
  readonly redis?: FastifyInstance['redis'];
  /** Only for `retire-key`. */
  readonly sessionService?: FastifyInstance['sessionService'];
}

/** What the group reads from the environment, and where it writes. */
export interface BreakGlassSettings {
  /** The KEK provider's settings: the process environment. */
  readonly kekEnv: KeysRetireSettings['kekEnv'];
  /** `retire-key`'s signing settings. Absent: the process cannot retire a key. */
  readonly signing?: Pick<KeysRetireSettings, 'enabledSignatureAlgorithms' | 'hybridSigning'>;
  readonly operator: () => BreakGlassOperator;
  /** The clock, in epoch ms. Default: `Date.now`. */
  readonly now?: () => number;
  readonly out: (line: string) => void;
  readonly err: (line: string) => void;
}

/** The group's dependencies over a process's plugins. */
export function breakGlassDependencies(
  host: BreakGlassHost,
  settings: BreakGlassSettings
): BreakGlassDependencies {
  const warn = ({ variable, message }: { variable: string; message: string }) =>
    host.log.warn({ variable }, message);
  const records = () => ({
    adminAuditLog: host.repositories.adminAuditLog,
    events: host.repositories.events,
  });
  return {
    proveKeyCustody: () => proveHostKeyCustody({ db: host.db, kekEnv: settings.kekEnv, warn }),
    operator: settings.operator,
    records,
    enrolment: () => ({
      ...records(),
      transaction: (work) => host.db.transaction(work),
      realms: host.repositories.realms,
      adminEnrolments: host.repositories.adminEnrolments,
      adminGrants: host.repositories.adminGrants,
      now: settings.now ?? Date.now,
    }),
    keysRetire: () => {
      const { redis, sessionService } = host;
      if (settings.signing === undefined || redis === undefined || sessionService === undefined) {
        throw new Error('retire-key needs the signing settings, Redis and the session service');
      }
      return keysRetireDependencies({ ...host, redis, sessionService } as KeysRetireHost, {
        kekEnv: settings.kekEnv,
        ...settings.signing,
        operatingSystemUser: () => settings.operator().name,
        out: settings.out,
        err: settings.err,
      });
    },
    out: settings.out,
    err: settings.err,
  };
}

/** Whether the process runs as an Nx task, which sets these for every task it runs. */
export function runsUnderNx(environ: Readonly<Record<string, string | undefined>>): boolean {
  return ['NX_TASK_TARGET_PROJECT', 'NX_TASK_TARGET_TARGET', 'NX_TASK_HASH'].some(
    (variable) => environ[variable] !== undefined
  );
}

/** Where the process writes. */
export interface BreakGlassIo {
  readonly out: (line: string) => void;
  readonly err: (line: string) => void;
}

/**
 * Run the group as its own process: `argv` is the arguments after the
 * script's name, `environ` the process environment.
 *
 * @returns the exit code ({@link BREAK_GLASS_EXIT})
 */
export async function runBreakGlassProcess(
  argv: readonly string[],
  environ: Readonly<Record<string, string | undefined>>,
  io: BreakGlassIo
): Promise<number> {
  // A usage error exits before anything connects or reads the configuration.
  let command;
  try {
    command = parseBreakGlassArguments(argv);
  } catch (error) {
    if (!(error instanceof BreakGlassUsageError)) throw error;
    io.err(error.message);
    return BREAK_GLASS_EXIT.usage;
  }
  if (command === 'help') {
    io.out(BREAK_GLASS_USAGE);
    return BREAK_GLASS_EXIT.done;
  }
  // Nx keeps every task's terminal output on disk: the enrolment URL, the
  // only copy of a live token, would outlive the run there.
  if (command.name === 'enrol-admin' && runsUnderNx(environ)) {
    io.err(
      'break-glass: enrol-admin prints a live enrolment token, which Nx keeps on disk with the ' +
        "task's output. Run it with tsx directly (pnpm exec tsx src/break-glass.ts from " +
        'apps/auth-server, or tsx src/break-glass.ts in the image). Nothing was done.'
    );
    return BREAK_GLASS_EXIT.usage;
  }
  const databaseUrl = environ['DATABASE_URL']?.trim();
  if (!databaseUrl) {
    io.err(
      'break-glass: set DATABASE_URL in the environment: the command runs only on a host that ' +
        'holds the database credentials. Nothing was done.'
    );
    return BREAK_GLASS_EXIT.usage;
  }

  // The database, and for retire-key Redis and the sessions: no route, no
  // listening port.
  const server = Fastify({ logger: { level: 'warn' } });
  try {
    await server.register(databasePlugin, {
      config: { connectionString: databaseUrl, pool: { max: 2, min: 0 } },
      // The built-in admin roles a grant may name.
      adminRoleCatalog: ADMIN_ROLE_CATALOG,
    });
    let signing: BreakGlassSettings['signing'];
    if (command.name === 'retire-key') {
      const { env } = await import('../../config/env');
      signing = {
        enabledSignatureAlgorithms: env.enabledSignatureAlgorithms,
        hybridSigning: env.HYBRID_SIGNING_ENABLED,
      };
      await server.register(cachePlugin, {
        config: {
          url: env.REDIS_URL,
          host: env.REDIS_HOST,
          port: env.REDIS_PORT,
          password: env.REDIS_PASSWORD,
          db: env.REDIS_DB,
          maxRetriesPerRequest: env.REDIS_MAX_RETRIES,
          connectTimeout: env.REDIS_CONNECTION_TIMEOUT,
          commandTimeout: env.REDIS_COMMAND_TIMEOUT,
          lazyConnect: true,
        },
      });
      await server.register(sessionServicePlugin, {
        settings: {
          defaultMaxLifespanSeconds: env.SESSION_COOKIE_TTL,
          lastSeenIntervalSeconds: env.SESSION_LAST_SEEN_INTERVAL,
        },
      });
    }
    await server.ready();
    return await runBreakGlass(
      command,
      breakGlassDependencies(server, {
        kekEnv: environ,
        ...(signing === undefined ? {} : { signing }),
        operator: () => hostOperator(environ),
        out: io.out,
        err: io.err,
      })
    );
  } finally {
    await server.close();
  }
}

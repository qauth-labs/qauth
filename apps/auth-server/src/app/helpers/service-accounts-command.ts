/**
 * The host's `service-accounts` command (ADR-019 Decision 7, issue #522):
 * create a service account for the admin API, list them, and disable or
 * enable one, on a host that holds the database credentials. The admin API's
 * own `serviceAccounts.create` arrives with the admin console work (#679).
 *
 * ```console
 * pnpm nx run auth-server:service-accounts -- create --name ci-realm-import \
 *   --client-id ci-realm-import --jwks-uri https://ci.example.com/jwks.json \
 *   --grant security-admin@*
 * pnpm nx run auth-server:service-accounts -- disable --name ci-realm-import
 * ```
 *
 * `create` writes, in one transaction, the account (a user with no
 * credential, in the operator realm), its OAuth client (`private_key_jwt`
 * with the given public keys, `client_credentials`, DPoP-bound, the admin
 * API's audience), the service account, its admin grants, and one row of the
 * operator realm's admin audit log: `serviceAccounts.create`, actor kind
 * `host_operator`, with the operating-system user. No secret is made or
 * printed: the private key stays with the automation, and only its public
 * half is given here.
 *
 * `disable` and `enable` switch the service account: a disabled one gets no
 * token, and its tokens make no admin call, from the next request on.
 *
 * The logic lives here, apart from the entry in `service-accounts.ts`, so it
 * can be tested without a process.
 */
import { BadRequestError, UniqueConstraintError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';

import { BUILT_IN_ROLE_NAMES } from './admin-roles';

/** The operation the audit row of a creation names: reserved for the admin API too (#508). */
export const SERVICE_ACCOUNT_CREATE_OPERATION = 'serviceAccounts.create';

export const SERVICE_ACCOUNTS_USAGE = `Usage: service-accounts create --name <name> --client-id <client_id>
                         (--jwks <file> | --jwks-uri <https URL>)
                         [--grant <role>@<realm name> | --grant <role>@*]...
       service-accounts disable --name <name>
       service-accounts enable --name <name>
       service-accounts list

Creates a service account for the admin API in the operator realm, lists them,
or disables or enables one. Set DATABASE_URL to a role that may write users,
OAuth clients, service accounts, admin grants and the admin audit log: the
owner's, not one service role's in a split deployment.

  --name       lower-case words joined by hyphens, unique in the operator realm
  --client-id  the client_id its private_key_jwt assertions name
  --jwks       a file holding the client's public JWK Set, {"keys": [...]}
  --jwks-uri   an https URL that serves the client's public JWK Set
  --grant      a built-in admin role (${BUILT_IN_ROLE_NAMES.join(', ')}) on the realm named,
               or on every realm with *; repeat for more than one

A service account signs in with client_credentials, private_key_jwt and a
DPoP proof, for the admin API's audience. Its token names its account, and
its security operations run only after a human admin approves them.

Exits 0 on success, 1 when the change was refused, 2 on a usage error.`;

/** A usage error: nothing was read or written. */
export class ServiceAccountsUsageError extends Error {
  constructor(problem: string) {
    super(`${problem}\n\n${SERVICE_ACCOUNTS_USAGE}`);
    this.name = 'ServiceAccountsUsageError';
  }
}

/** A grant the command writes: a built-in role, on a realm by name or on every realm. */
export interface GrantArgument {
  readonly role: string;
  /** The realm's name, or `null` for every realm. */
  readonly realm: string | null;
}

/** What the command was asked to do. */
export type ServiceAccountsCommand =
  | {
      readonly kind: 'create';
      readonly name: string;
      readonly clientId: string;
      readonly jwks?: { readonly keys: readonly Readonly<Record<string, unknown>>[] };
      readonly jwksUri?: string;
      readonly grants: readonly GrantArgument[];
    }
  | { readonly kind: 'disable' | 'enable'; readonly name: string }
  | { readonly kind: 'list' };

/** Reads the file `--jwks` names. */
export type ReadTextFile = (path: string) => string;

/** The flags each command takes; `grant` may repeat. */
const FLAGS: Readonly<Record<ServiceAccountsCommand['kind'], readonly string[]>> = {
  create: ['name', 'client-id', 'jwks', 'jwks-uri', 'grant'],
  disable: ['name'],
  enable: ['name'],
  list: [],
};

/** Parse `--flag value` and `--flag=value` pairs, `grant` repeatable, every other flag once. */
function flagsOf(argv: readonly string[], allowed: readonly string[]): Map<string, string[]> {
  const values = new Map<string, string[]>();
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i] as string;
    const name = allowed.find((flag) => arg === `--${flag}` || arg.startsWith(`--${flag}=`));
    if (name === undefined) throw new ServiceAccountsUsageError(`Unknown argument: ${arg}`);
    const value = arg.includes('=') ? arg.slice(arg.indexOf('=') + 1) : argv[++i];
    if (value === undefined || value === '' || value.startsWith('--')) {
      throw new ServiceAccountsUsageError(`--${name} needs a value`);
    }
    const seen = values.get(name) ?? [];
    if (seen.length > 0 && name !== 'grant') {
      throw new ServiceAccountsUsageError(`--${name} is given twice`);
    }
    values.set(name, [...seen, value]);
  }
  return values;
}

/** A `--grant` value: `<role>@<realm name>`, or `<role>@*` for every realm. */
function grantOf(value: string): GrantArgument {
  const at = value.lastIndexOf('@');
  const role = at < 0 ? '' : value.slice(0, at);
  const realm = at < 0 ? '' : value.slice(at + 1);
  if (role === '' || realm === '') {
    throw new ServiceAccountsUsageError(
      `--grant ${value}: write <role>@<realm name>, or <role>@* for every realm`
    );
  }
  if (!(BUILT_IN_ROLE_NAMES as readonly string[]).includes(role)) {
    throw new ServiceAccountsUsageError(
      `--grant ${value}: "${role}" is not a built-in admin role (${BUILT_IN_ROLE_NAMES.join(', ')})`
    );
  }
  return { role, realm: realm === '*' ? null : realm };
}

/**
 * Parse the command's arguments (after the program's name).
 *
 * @throws ServiceAccountsUsageError on anything it cannot read, before
 *   anything connects
 */
export function parseServiceAccountsArguments(
  argv: readonly string[],
  readTextFile: ReadTextFile
): ServiceAccountsCommand | 'help' {
  const [command, ...rest] = argv;
  if (command === undefined || command === '--help' || command === '-h' || command === 'help') {
    return 'help';
  }
  if (!Object.hasOwn(FLAGS, command)) {
    throw new ServiceAccountsUsageError(`Unknown command: ${command}`);
  }
  const kind = command as ServiceAccountsCommand['kind'];
  const flags = flagsOf(rest, FLAGS[kind]);
  const one = (flag: string) => flags.get(flag)?.[0];
  if (kind === 'list') return { kind };
  const name = one('name');
  if (name === undefined) throw new ServiceAccountsUsageError('--name is required');
  if (kind !== 'create') return { kind, name };

  const clientId = one('client-id');
  if (clientId === undefined) throw new ServiceAccountsUsageError('--client-id is required');
  const jwksFile = one('jwks');
  const jwksUri = one('jwks-uri');
  if ((jwksFile === undefined) === (jwksUri === undefined)) {
    throw new ServiceAccountsUsageError(
      "Give exactly one of --jwks and --jwks-uri: the client's public keys"
    );
  }
  let jwks: { keys: Record<string, unknown>[] } | undefined;
  if (jwksFile !== undefined) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(readTextFile(jwksFile));
    } catch (error) {
      throw new ServiceAccountsUsageError(
        `--jwks ${jwksFile}: not a readable JSON file (${error instanceof Error ? error.message : String(error)})`
      );
    }
    const keys = (parsed as { keys?: unknown } | null)?.keys;
    if (!Array.isArray(keys)) {
      throw new ServiceAccountsUsageError(`--jwks ${jwksFile}: write a JWK Set, {"keys": [...]}`);
    }
    jwks = { keys: keys as Record<string, unknown>[] };
  }
  return {
    kind,
    name,
    clientId,
    ...(jwks === undefined ? {} : { jwks }),
    ...(jwksUri === undefined ? {} : { jwksUri }),
    grants: (flags.get('grant') ?? []).map(grantOf),
  };
}

/** What the command reaches: the server's repositories and database, and its terminal. */
export interface ServiceAccountsDependencies {
  readonly fastify: Pick<FastifyInstance, 'db' | 'repositories'>;
  /** The operating-system user the command runs as: the audit row's actor. */
  readonly operatingSystemUser: string;
  readonly out: (line: string) => void;
  readonly err: (line: string) => void;
}

/** Thrown inside the transaction to roll it back with an operator's message. */
class Refusal extends Error {}

/** The realm the grant names, or `null` for every realm. */
async function grantTarget(
  fastify: ServiceAccountsDependencies['fastify'],
  grant: GrantArgument,
  tx: Parameters<FastifyInstance['repositories']['realms']['findByName']>[1]
): Promise<string | null> {
  if (grant.realm === null) return null;
  const realm = await fastify.repositories.realms.findByName(grant.realm, tx);
  if (realm === undefined) throw new Refusal(`--grant ${grant.role}@${grant.realm}: no such realm`);
  return realm.id;
}

async function create(
  command: Extract<ServiceAccountsCommand, { kind: 'create' }>,
  deps: ServiceAccountsDependencies
): Promise<number> {
  const { fastify } = deps;
  const { repositories } = fastify;
  const created = await fastify.db.transaction(async (tx) => {
    const operator = await repositories.realms.findOperator(tx);
    if (operator === undefined) {
      throw new Refusal(
        'This database has no operator realm yet: start the auth server once, so that its first boot creates and marks it'
      );
    }
    const account = await repositories.serviceAccounts.create(
      {
        realmId: operator.id,
        name: command.name,
        clientId: command.clientId,
        ...(command.jwks === undefined ? {} : { jwks: command.jwks }),
        ...(command.jwksUri === undefined ? {} : { jwksUri: command.jwksUri }),
        createdBy: null,
      },
      tx
    );
    const grants = [];
    for (const grant of command.grants) {
      const target = await grantTarget(fastify, grant, tx);
      const row = await repositories.adminGrants.create(
        {
          userId: account.userId,
          role: { kind: 'built-in', name: grant.role },
          targetRealmId: target,
          createdBy: null,
        },
        tx
      );
      grants.push({ id: row.id, role: grant.role, targetRealmId: target });
    }
    // Creating a service account is a security operation (ADR-019 Decision
    // 7): the operator realm's chain records it, with who ran the command.
    await repositories.adminAuditLog.appendAdminAudit(tx, {
      realmId: operator.id,
      actorKind: 'host_operator',
      actorId: deps.operatingSystemUser,
      actorRealmId: null,
      actChain: null,
      operationId: SERVICE_ACCOUNT_CREATE_OPERATION,
      operationClass: 'security',
      effects: ['administration'],
      outcome: 'succeeded',
      diff: {
        change: {
          before: null,
          after: {
            id: account.serviceAccount.id,
            name: account.serviceAccount.name,
            userId: account.userId,
            clientId: account.client.clientId,
            enabled: account.serviceAccount.enabled,
            grants,
          },
        },
        annotations: {},
      },
      approvals: [],
      requestDigest: null,
      traceId: null,
    });
    return { account, grants };
  });
  const { account, grants } = created;
  deps.out(
    `Created the service account "${account.serviceAccount.name}" in the operator realm: ` +
      `user ${account.userId}, client "${account.client.clientId}" (private_key_jwt, client_credentials, DPoP-bound).`
  );
  for (const grant of grants) {
    deps.out(`  grant ${grant.role} on ${grant.targetRealmId ?? 'every realm'}`);
  }
  if (grants.length === 0) {
    deps.out('  no admin grant: it gets no admin token until one is granted to its user id.');
  }
  return 0;
}

async function setEnabled(
  command: Extract<ServiceAccountsCommand, { kind: 'disable' | 'enable' }>,
  deps: ServiceAccountsDependencies
): Promise<number> {
  const { repositories } = deps.fastify;
  const operator = await repositories.realms.findOperator();
  const account =
    operator === undefined
      ? undefined
      : await repositories.serviceAccounts.findByName(operator.id, command.name);
  if (operator === undefined || account === undefined) {
    throw new Refusal(`The operator realm holds no service account "${command.name}"`);
  }
  const enabled = command.kind === 'enable';
  if (account.enabled === enabled) {
    deps.out(`The service account "${account.name}" is already ${command.kind}d; nothing changed.`);
    return 0;
  }
  await repositories.serviceAccounts.setEnabled(operator.id, account.id, enabled);
  deps.out(
    enabled
      ? `The service account "${account.name}" is enabled.`
      : `The service account "${account.name}" is disabled: it gets no token, and its tokens make no admin call from the next request on.`
  );
  return 0;
}

async function list(deps: ServiceAccountsDependencies): Promise<number> {
  const { repositories } = deps.fastify;
  const operator = await repositories.realms.findOperator();
  const accounts =
    operator === undefined ? [] : await repositories.serviceAccounts.list(operator.id);
  if (accounts.length === 0) deps.out('The operator realm holds no service account.');
  for (const account of accounts) {
    deps.out(
      `${account.name}\t${account.enabled ? 'enabled' : 'disabled'}\tuser ${account.userId}`
    );
  }
  return 0;
}

/**
 * Run a parsed command. A refusal (an unknown realm or service account, a
 * name or client id already taken, a malformed key set) is printed and
 * answers 1, with nothing written.
 */
export async function runServiceAccountsCommand(
  command: ServiceAccountsCommand,
  deps: ServiceAccountsDependencies
): Promise<number> {
  try {
    switch (command.kind) {
      case 'create':
        return await create(command, deps);
      case 'disable':
      case 'enable':
        return await setEnabled(command, deps);
      case 'list':
        return await list(deps);
    }
  } catch (error) {
    if (error instanceof Refusal || error instanceof BadRequestError) {
      deps.err(`service-accounts: ${error.message}. Nothing was changed.`);
      return 1;
    }
    if (error instanceof UniqueConstraintError) {
      deps.err(
        'service-accounts: the operator realm already holds a service account of this name or a client with this client id, or a grant is given twice. Nothing was changed.'
      );
      return 1;
    }
    throw error;
  }
}

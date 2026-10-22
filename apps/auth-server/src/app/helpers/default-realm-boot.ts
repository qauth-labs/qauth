import { BadRequestError, UniqueConstraintError } from '@qauth-labs/shared-errors';
import { InvalidRealmHostError, normaliseRealmHost } from '@qauth-labs/shared-validation';
import type { FastifyBaseLogger, FastifyInstance } from 'fastify';

import { resolveIssuerIdentifier } from './discovery';
import type { RealmRow } from './realm';

/**
 * The default realm's boot step (ADR-019 Decision 1 and its answer on existing
 * issuers, issue #484).
 *
 * In simple mode one realm serves the deployment. `DEFAULT_REALM_NAME` names
 * it and `JWT_ISSUER` gives it its issuer, and its host is the realm's primary
 * host. Every node runs this step after the migrations and before it listens:
 *
 * 1. find the realm by name, and create it when it is missing;
 * 2. when its issuer is NULL (a realm from before migration 0025), store the
 *    issuer and the primary host; when its issuer is set and differs, refuse to
 *    boot, because a realm's issuer host is permanent;
 * 3. when no realm is the operator realm yet, mark this one (simple mode);
 * 4. add each `DEFAULT_REALM_ENDPOINT_HOSTS` name the realm lacks as an
 *    endpoint host, and remove none;
 * 5. log one line naming the realm, its issuer and host, and the operator flag.
 *
 * All of it runs in one transaction under the realm provisioning lock, so nodes
 * that start together do it one at a time: the first creates the realm, the
 * others find it.
 *
 * `getOrCreateDefaultRealm` (`./realm.ts`) still creates the realm by name at
 * request time, should a request find none, until host routing replaces it.
 */

/** The transaction the realms repository's provisioning lock takes. */
type ProvisioningTransaction = Parameters<
  FastifyInstance['repositories']['realms']['lockProvisioning']
>[0];

/** What the default realm takes from `JWT_ISSUER`. */
export interface DefaultRealmIssuer {
  /** `JWT_ISSUER` without a trailing slash, as discovery publishes it. */
  readonly issuer: string;
  /** The issuer's host in its stored form: lower case, ASCII, no port. */
  readonly host: string;
  /** What the operator should know about `JWT_ISSUER`, one line each. */
  readonly warnings: readonly string[];
}

/** Logged when `JWT_ISSUER` ends with a slash. */
export const JWT_ISSUER_TRAILING_SLASH_WARNING =
  'JWT_ISSUER ends with a slash: the default realm stores its issuer without it, as discovery publishes it, but tokens carry JWT_ISSUER as written; remove the slash';

/** Logged when `JWT_ISSUER` has a path. */
export const JWT_ISSUER_PATH_WARNING =
  "JWT_ISSUER has a path: it keeps working, since only its host routes requests to the default realm, but a new realm's issuer is an origin with no path";

/**
 * A boot refusal of the default realm step. The message names the values the
 * operator has to change: they come from the deployment's own configuration
 * and database, and a boot error reaches the log only, never a response.
 */
export class DefaultRealmBootError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'DefaultRealmBootError';
  }
}

/**
 * Read the default realm's issuer and primary host from `JWT_ISSUER`.
 *
 * The issuer loses one trailing slash, the same canonical form discovery
 * publishes (`resolveIssuerIdentifier`). A path stays: only the host routes
 * requests. `https://auth.example.com:8443/` gives the issuer
 * `https://auth.example.com:8443` on the host `auth.example.com`.
 *
 * @throws DefaultRealmBootError when the host cannot be a primary host, such as
 * an IP address, which can be no passkey RP ID
 */
export function defaultRealmIssuerFrom(jwtIssuer: string): DefaultRealmIssuer {
  let url: URL;
  try {
    url = new URL(jwtIssuer);
  } catch (error) {
    throw new DefaultRealmBootError(`JWT_ISSUER "${jwtIssuer}" is not a URL`, { cause: error });
  }

  let host: string;
  try {
    host = normaliseRealmHost(url.host, 'primary');
  } catch (error) {
    if (!(error instanceof InvalidRealmHostError)) throw error;
    throw new DefaultRealmBootError(
      `The host of JWT_ISSUER "${jwtIssuer}" cannot be the default realm's primary host: ${error.message}`,
      { cause: error }
    );
  }

  const warnings: string[] = [];
  if (jwtIssuer.endsWith('/')) warnings.push(JWT_ISSUER_TRAILING_SLASH_WARNING);
  if (url.pathname !== '/') warnings.push(JWT_ISSUER_PATH_WARNING);

  return { issuer: resolveIssuerIdentifier(jwtIssuer), host, warnings };
}

/** The configuration the boot step reads. */
export interface DefaultRealmBootSettings {
  /** `DEFAULT_REALM_NAME`. */
  readonly realmName: string;
  /** `JWT_ISSUER`, as written. */
  readonly jwtIssuer: string;
  /** `DEFAULT_REALM_ENDPOINT_HOSTS`, parsed. */
  readonly endpointHosts: readonly string[];
}

/** What the boot step works through: `fastify.db`, `fastify.repositories.realms` and a logger. */
export interface DefaultRealmBootDependencies {
  readonly db: Pick<FastifyInstance['db'], 'transaction'>;
  readonly realms: FastifyInstance['repositories']['realms'];
  readonly log: Pick<FastifyBaseLogger, 'info' | 'warn'>;
}

/** The default realm as the boot step left it. */
export interface DefaultRealmBootResult {
  readonly realm: RealmRow;
  /** The realm's primary host. */
  readonly host: string;
  /** The endpoint hosts this boot added, in stored form. */
  readonly endpointHostsAdded: readonly string[];
}

/**
 * Run the default realm's boot step. See the module comment for the steps.
 *
 * @throws DefaultRealmBootError when the stored issuer differs from
 * `JWT_ISSUER`, when `JWT_ISSUER` cannot be a realm issuer, or when its host or
 * an endpoint host belongs to another realm. The message names the values.
 */
export async function bootDefaultRealm(
  deps: DefaultRealmBootDependencies,
  settings: DefaultRealmBootSettings
): Promise<DefaultRealmBootResult> {
  const identity = defaultRealmIssuerFrom(settings.jwtIssuer);
  for (const warning of identity.warnings) {
    deps.log.warn({ variable: 'JWT_ISSUER', issuer: settings.jwtIssuer }, warning);
  }

  const result = await deps.db.transaction(async (tx: ProvisioningTransaction) => {
    await deps.realms.lockProvisioning(tx);
    let realm = await provisionIssuer(deps.realms, tx, settings, identity);

    if (!realm.isOperator && !(await deps.realms.findOperator(tx))) {
      realm = await deps.realms.update(realm.id, { isOperator: true }, tx);
    }

    const endpointHostsAdded = await addEndpointHosts(deps.realms, tx, realm, settings);
    return { realm, host: identity.host, endpointHostsAdded };
  });

  deps.log.info(
    {
      realm: result.realm.name,
      issuer: result.realm.issuer,
      host: result.host,
      operator: result.realm.isOperator,
      endpointHostsAdded: result.endpointHostsAdded,
    },
    'default realm ready'
  );
  return result;
}

/** Steps 1 and 2: find or create the realm, and give it its issuer and primary host. */
async function provisionIssuer(
  realms: DefaultRealmBootDependencies['realms'],
  tx: ProvisioningTransaction,
  settings: DefaultRealmBootSettings,
  identity: DefaultRealmIssuer
): Promise<RealmRow> {
  const existing = await realms.findByName(settings.realmName, tx);

  if (existing && existing.issuer !== null && existing.issuer !== identity.issuer) {
    throw new DefaultRealmBootError(
      `The default realm "${settings.realmName}" has the issuer "${existing.issuer}", but JWT_ISSUER is "${settings.jwtIssuer}". A realm's issuer and its host are permanent: set JWT_ISSUER to "${existing.issuer}".`
    );
  }

  const owner = await realms.findByHost(identity.host, tx);
  if (owner && !(owner.realm.id === existing?.id && owner.host.kind === 'primary')) {
    throw new DefaultRealmBootError(
      `The host "${identity.host}" of JWT_ISSUER "${settings.jwtIssuer}" is already ${hostKindPhrase(owner.host.kind)} of the realm "${owner.realm.name}". A host belongs to one realm, as one kind.`
    );
  }

  try {
    const provisioned = existing
      ? await realms.assignIssuer(existing.id, identity.issuer, identity.host, tx)
      : await realms.createWithPrimaryHost(
          { name: settings.realmName, enabled: true, issuer: identity.issuer },
          identity.host,
          tx
        );
    return provisioned.realm;
  } catch (error) {
    if (error instanceof BadRequestError) {
      throw new DefaultRealmBootError(
        `JWT_ISSUER "${settings.jwtIssuer}" cannot be the issuer of the default realm "${settings.realmName}": ${error.message}.`,
        { cause: error }
      );
    }
    if (error instanceof UniqueConstraintError) {
      throw new DefaultRealmBootError(
        `JWT_ISSUER "${settings.jwtIssuer}" cannot be the issuer of the default realm "${settings.realmName}": another realm already has its issuer or its host (${error.constraint}).`,
        { cause: error }
      );
    }
    throw error;
  }
}

/** Step 4: add the endpoint hosts the realm lacks. A host of another realm stops the boot. */
async function addEndpointHosts(
  realms: DefaultRealmBootDependencies['realms'],
  tx: ProvisioningTransaction,
  realm: RealmRow,
  settings: DefaultRealmBootSettings
): Promise<string[]> {
  const added: string[] = [];
  for (const endpointHost of settings.endpointHosts) {
    const owner = await realms.findByHost(endpointHost, tx);
    if (!owner) {
      added.push((await realms.addEndpointHost(realm.id, endpointHost, tx)).host);
      continue;
    }
    if (owner.realm.id === realm.id && owner.host.kind === 'endpoint') continue;

    throw new DefaultRealmBootError(
      owner.realm.id === realm.id
        ? `DEFAULT_REALM_ENDPOINT_HOSTS names "${owner.host.host}", the primary host of the default realm "${realm.name}" (from JWT_ISSUER "${settings.jwtIssuer}"). A host is one kind only: remove it from DEFAULT_REALM_ENDPOINT_HOSTS.`
        : `DEFAULT_REALM_ENDPOINT_HOSTS names "${owner.host.host}", which is already ${hostKindPhrase(owner.host.kind)} of the realm "${owner.realm.name}". A host belongs to one realm: remove it from DEFAULT_REALM_ENDPOINT_HOSTS, or from that realm.`
    );
  }
  return added;
}

function hostKindPhrase(kind: 'primary' | 'endpoint'): string {
  return kind === 'primary' ? 'the primary host' : 'an endpoint host';
}

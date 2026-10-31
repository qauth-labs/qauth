import {
  assertRelyingPartyIdUnlockedOrSame,
  RelyingPartyIdLockedError,
} from '@qauth-labs/fastify-plugin-federation';
import {
  RealmPolicySeedRefusedError,
  type RealmPolicySeedReport,
  type SetSeedKey,
} from '@qauth-labs/fastify-plugin-realm-policy';
import { BadRequestError, UniqueConstraintError } from '@qauth-labs/shared-errors';
import {
  InvalidRealmHostError,
  normaliseRealmHost,
  resolveRpId,
} from '@qauth-labs/shared-validation';
import type { FastifyBaseLogger, FastifyInstance } from 'fastify';

import { resolveIssuerIdentifier } from './discovery';
import type { RealmRow } from './request-realm';
import {
  PasskeyRelyingPartyError,
  type PasskeyRelyingPartySettings,
  REALM_HOST_RELYING_PARTY,
  type RealmRelyingParty,
  resolveRealmRelyingParty,
} from './webauthn-relying-party';

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
 * 3. give every realm that has no policies yet its policies from the
 *    environment, and every realm whose policies lack fields of this release
 *    those fields' seeds (ADR-019 Decision 10, #516): a realm created before
 *    migration 0046 gets its fill here once, the first node to boot winning,
 *    and a realm that has its policies is not written, so changing an
 *    environment key later changes no realm. A new realm got its policies
 *    when step 1 created it;
 * 4. when no realm is the operator realm yet, mark this one (simple mode);
 * 5. add each `DEFAULT_REALM_ENDPOINT_HOSTS` name the realm lacks as an
 *    endpoint host, and remove none;
 * 6. resolve the passkey RP ID from the realm host and `WEBAUTHN_RP_ID`
 *    (ADR-019 Decision 2, #467), warn when it is a parent domain, and refuse to
 *    boot when the realm's passkeys are bound to another one. While no passkey
 *    has locked it, store it on the realm row (NULL for the realm host, #553),
 *    where `resolveRpId(realm)` reads it for every ceremony;
 * 7. log one line naming the realm, its issuer and host, the operator flag,
 *    the passkey RP ID and its policy version, and, when the realm already had
 *    its policies, one line for each seed key the environment still sets: a
 *    warning that the key only seeds new realms and is ignored when the server
 *    reads its policy from the realm row, and otherwise a line that the
 *    stored policy ignores it but the server still applies it to every realm
 *    until that policy moves to the row (`realm-policy-readers.ts`), and that
 *    the stored value applies from then on, whatever the key says. For each
 *    realm step 3 filled, a warning names each field its row kept that
 *    differs from the environment's seed (the ceiling, a non-empty allowlist).
 *
 * All of it runs in one transaction under the realm provisioning lock, so nodes
 * that start together do it one at a time: the first creates the realm, the
 * others find it.
 *
 * This step is the only place the server picks a realm by its name. A request
 * finds its realm through the host it names (`request.realm`, #486 and #487),
 * and `DEFAULT_REALM_NAME` is read nowhere else at request time: the lint
 * configuration refuses it (`.oxlintrc.json`).
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
  'JWT_ISSUER ends with a slash: the default realm stores its issuer without it, and its discovery documents and tokens name it that way; remove the slash';

/** Logged when `JWT_ISSUER` has a path. */
export const JWT_ISSUER_PATH_WARNING =
  "JWT_ISSUER has a path: it keeps working, since only its host routes requests to the default realm, but a new realm's issuer is an origin with no path";

/** Logged when `EMAIL_BASE_URL` is not the default realm's issuer. */
export const EMAIL_BASE_URL_IGNORED_WARNING =
  "EMAIL_BASE_URL is not read since 0.2.0: a link in mail starts at the issuer of the account's realm, which for the default realm is JWT_ISSUER without a trailing slash, so mailed links no longer point at EMAIL_BASE_URL";

/**
 * The warning to log when `EMAIL_BASE_URL` names another base than the default
 * realm's issuer (#490): mailed links used to start at `EMAIL_BASE_URL` and
 * now start at the realm's issuer, so a deployment that set the two apart
 * sees its links move. Undefined when `EMAIL_BASE_URL` is unset, the key being
 * optional, or when the two agree, a trailing slash aside.
 */
export function emailBaseUrlWarning(
  emailBaseUrl: string | undefined,
  jwtIssuer: string
): string | undefined {
  if (emailBaseUrl === undefined) return undefined;
  return resolveIssuerIdentifier(emailBaseUrl) === resolveIssuerIdentifier(jwtIssuer)
    ? undefined
    : EMAIL_BASE_URL_IGNORED_WARNING;
}

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

/**
 * Logged once per boot, as a warning, for each seed key the environment sets
 * while the default realm already has its policies and the server reads the
 * key's policy from the realm row (#516): the row owns the value, and the key
 * only seeds a realm created from then on.
 */
export function seedKeyIgnoredWarning(key: string, realmName: string, path: string): string {
  return `${key} only seeds new realms and is ignored: the realm "${realmName}" already has its policies, and its ${path} stays as stored`;
}

/**
 * Logged once per boot for each seed key the environment sets while the
 * default realm already has its policies, but whose policy the server does
 * not read from the realm row yet (#516): the stored policy ignores the key,
 * and the server still applies it to every realm, so it must stay set. A
 * change of the key never reaches the stored value, which applies once the
 * policy's area moves to the row (#527, #528, #529, #534): a key tightened in
 * the meantime would loosen again then, so the line says to change the
 * stored policy along with it.
 */
export function seedKeyStillAppliedNote(key: string, realmName: string, path: string): string {
  return `${key} only seeds new realms and is ignored by the stored policies of the realm "${realmName}", whose ${path} stays as stored: a change of ${key} never reaches it. The server still applies ${key} to every realm until it reads that policy from the realm row, so keep it set; once it does, the stored ${path} applies and ${key} is ignored, so change the stored policy along with ${key}`;
}

/**
 * Logged once, as a warning, for each field the boot's fill kept from a
 * realm's row although the environment seeds another value (#516): the
 * environment ceiling, or a dynamic registration allowlist that holds a scope.
 * The server read the row's value before the policies existed, so the fill
 * keeps it rather than the seed, and the operator learns the realm does not
 * follow the environment there.
 */
export function keptFromRowWarning(realmName: string, path: string): string {
  return `realm policies filled from the environment, but the realm "${realmName}" kept its ${path} from its row, which differs from the environment's seed: the server read that value before, and the realm row owns it from now on`;
}

/** A seed key the environment sets, and whether the server reads its policy from the realm row. */
export interface SeedKeyInEnvironment extends SetSeedKey {
  /** Whether the server reads the policy from the realm row (`POLICIES_READ_FROM_REALM_ROW`). */
  readonly readFromRealmRow: boolean;
}

/** The configuration the boot step reads. */
export interface DefaultRealmBootSettings {
  /** `DEFAULT_REALM_NAME`. */
  readonly realmName: string;
  /** `JWT_ISSUER`, as written. */
  readonly jwtIssuer: string;
  /** `DEFAULT_REALM_ENDPOINT_HOSTS`, parsed. */
  readonly endpointHosts: readonly string[];
  /**
   * `WEBAUTHN_RP_ID` and `WEBAUTHN_RP_ID_ALLOW_PARENT_DOMAIN` (#467). Absent
   * means the realm host. The lock check runs either way, and whatever
   * `WEBAUTHN_ENABLED` says: the lock is a fact about enrolled passkeys.
   */
  readonly passkeys?: PasskeyRelyingPartySettings;
  /**
   * The seed keys of realm policies the environment sets (`seedKeysSetIn` of
   * `process.env`, #516), each with whether the server reads its policy from
   * the realm row. Each one a realm that already has its policies ignores is
   * logged once. Absent, none.
   */
  readonly seedKeysSet?: readonly SeedKeyInEnvironment[];
}

/**
 * What the boot step works through: `fastify.db`, `fastify.repositories.realms`,
 * the realm policy store's boot fill (`fastify.policyStore`) and a logger.
 */
export interface DefaultRealmBootDependencies {
  readonly db: Pick<FastifyInstance['db'], 'transaction'>;
  readonly realms: FastifyInstance['repositories']['realms'];
  readonly policies: Pick<FastifyInstance['policyStore'], 'seedRealms'>;
  readonly log: Pick<FastifyBaseLogger, 'info' | 'warn'>;
}

/** The default realm as the boot step left it. */
export interface DefaultRealmBootResult {
  readonly realm: RealmRow;
  /** The realm's primary host. */
  readonly host: string;
  /** The endpoint hosts this boot added, in stored form. */
  readonly endpointHostsAdded: readonly string[];
  /** The realm's passkey RP ID. */
  readonly relyingParty: RealmRelyingParty;
  /** Whether this boot created the realm (step 1), which gave it its policies. */
  readonly created: boolean;
  /** What step 3 wrote, for every realm. */
  readonly policySeeding: RealmPolicySeedReport;
}

/**
 * Run the default realm's boot step. See the module comment for the steps.
 *
 * @throws DefaultRealmBootError when the stored issuer differs from
 * `JWT_ISSUER`, when `JWT_ISSUER` cannot be a realm issuer, when its host or
 * an endpoint host belongs to another realm, when `WEBAUTHN_RP_ID` cannot be
 * the realm's RP ID, or when the realm's passkeys are bound to another RP ID.
 * The message names the values.
 */
export async function bootDefaultRealm(
  deps: DefaultRealmBootDependencies,
  settings: DefaultRealmBootSettings
): Promise<DefaultRealmBootResult> {
  const identity = defaultRealmIssuerFrom(settings.jwtIssuer);
  for (const warning of identity.warnings) {
    deps.log.warn({ variable: 'JWT_ISSUER', issuer: settings.jwtIssuer }, warning);
  }
  const relyingParty = defaultRealmRelyingParty(identity.host, settings);
  if (relyingParty.warning !== undefined) {
    deps.log.warn({ variable: 'WEBAUTHN_RP_ID', rpId: relyingParty.rpId }, relyingParty.warning);
  }

  const result = await deps.db.transaction(async (tx: ProvisioningTransaction) => {
    await deps.realms.lockProvisioning(tx);
    const provisioned = await provisionIssuer(deps.realms, tx, settings, identity);
    let realm = provisioned.realm;

    const policySeeding = await seedRealmPolicies(deps.policies, tx);
    if (wrotePoliciesOf(policySeeding, realm.id)) {
      realm = (await deps.realms.findById(realm.id, tx)) ?? realm;
    }

    if (!realm.isOperator && !(await deps.realms.findOperator(tx))) {
      realm = await deps.realms.setOperator(realm.id, true, tx);
    }

    const endpointHostsAdded = await addEndpointHosts(deps.realms, tx, realm, settings);
    realm = await storePasskeyRpId(deps.realms, tx, realm, relyingParty);
    return {
      realm,
      host: identity.host,
      endpointHostsAdded,
      relyingParty,
      created: provisioned.created,
      policySeeding,
    };
  });

  for (const filled of result.policySeeding.filled) {
    deps.log.info(
      {
        realm: filled.realmName,
        realmId: filled.realmId,
        keptFromRow: filled.keptFromRow.map((kept) => kept.path),
      },
      'realm policies filled from the environment: the realm row owns them from now on'
    );
    for (const { path } of filled.keptFromRow.filter((kept) => kept.differsFromSeed)) {
      const key = settings.seedKeysSet?.find((set) => set.path === path)?.key;
      deps.log.warn(
        {
          realm: filled.realmName,
          realmId: filled.realmId,
          policy: path,
          ...(key === undefined ? {} : { variable: key }),
        },
        keptFromRowWarning(filled.realmName, path)
      );
    }
  }
  for (const completed of result.policySeeding.completed) {
    deps.log.info(
      { realm: completed.realmName, realmId: completed.realmId, policies: completed.paths },
      'realm policies of this release filled from the environment'
    );
  }
  for (const skipped of result.policySeeding.skipped) {
    deps.log.warn(
      { realm: skipped.realmName, realmId: skipped.realmId, schemaVersion: skipped.schemaVersion },
      'realm policies of another schema version left as they are: a node of this release does not complete them'
    );
  }
  for (const { key, path, readFromRealmRow } of ignoredSeedKeys(
    result,
    settings.seedKeysSet ?? []
  )) {
    const fields = { variable: key, realm: result.realm.name, policy: path };
    if (readFromRealmRow) {
      deps.log.warn(fields, seedKeyIgnoredWarning(key, result.realm.name, path));
    } else {
      deps.log.info(fields, seedKeyStillAppliedNote(key, result.realm.name, path));
    }
  }

  deps.log.info(
    {
      realm: result.realm.name,
      issuer: result.realm.issuer,
      host: result.host,
      operator: result.realm.isOperator,
      endpointHostsAdded: result.endpointHostsAdded,
      passkeyRpId: result.relyingParty.rpId,
      passkeyRpIdLocked: result.realm.webauthnRpIdLockedAt !== null,
      policiesVersion: result.realm.policiesVersion,
    },
    'default realm ready'
  );
  return result;
}

/** Whether step 3 wrote the policies of the realm `realmId`. */
function wrotePoliciesOf(report: RealmPolicySeedReport, realmId: string): boolean {
  return [...report.filled, ...report.completed].some((realm) => realm.realmId === realmId);
}

/**
 * Step 3: fill and complete the realms' policies. A realm whose stored values
 * the policy schema refuses stops the boot, naming the realm and the paths:
 * guessing another value could loosen it.
 */
async function seedRealmPolicies(
  policies: DefaultRealmBootDependencies['policies'],
  tx: ProvisioningTransaction
): Promise<RealmPolicySeedReport> {
  try {
    return await policies.seedRealms(tx);
  } catch (error) {
    if (!(error instanceof RealmPolicySeedRefusedError)) throw error;
    throw new DefaultRealmBootError(
      `${error.message}. Correct the stored values, or the environment keys that seed them, and start the server again.`,
      { cause: error }
    );
  }
}

/**
 * Step 7: the seed keys the environment sets that the default realm ignores.
 * None when this boot created the realm or filled its policies, which used
 * them; a key whose field this boot completed was used too.
 */
function ignoredSeedKeys(
  result: Pick<DefaultRealmBootResult, 'realm' | 'created' | 'policySeeding'>,
  seedKeysSet: readonly SeedKeyInEnvironment[]
): SeedKeyInEnvironment[] {
  const realmId = result.realm.id;
  if (result.created || result.policySeeding.filled.some((realm) => realm.realmId === realmId)) {
    return [];
  }
  const completed = new Set(
    result.policySeeding.completed
      .filter((realm) => realm.realmId === realmId)
      .flatMap((realm) => realm.paths)
  );
  return seedKeysSet.filter(({ path }) => !completed.has(path));
}

/** Steps 1 and 2: find or create the realm, and give it its issuer and primary host. */
async function provisionIssuer(
  realms: DefaultRealmBootDependencies['realms'],
  tx: ProvisioningTransaction,
  settings: DefaultRealmBootSettings,
  identity: DefaultRealmIssuer
): Promise<{ realm: RealmRow; created: boolean }> {
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
    return { realm: provisioned.realm, created: existing === undefined };
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

/** Step 5: add the endpoint hosts the realm lacks. A host of another realm stops the boot. */
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

/** Step 6: the passkey RP ID, from the realm host and the operator's settings. */
function defaultRealmRelyingParty(
  realmHost: string,
  settings: DefaultRealmBootSettings
): RealmRelyingParty {
  try {
    return resolveRealmRelyingParty(realmHost, settings.passkeys ?? REALM_HOST_RELYING_PARTY);
  } catch (error) {
    if (!(error instanceof PasskeyRelyingPartyError)) throw error;
    throw new DefaultRealmBootError(error.message, { cause: error });
  }
}

/**
 * Step 6: the realm row holds the RP ID (#553). While no passkey has locked
 * it, the configured one is written there: `null` for the realm host, the
 * parent domain otherwise. A locked realm keeps its RP ID, and the configured
 * one must be it.
 */
async function storePasskeyRpId(
  realms: DefaultRealmBootDependencies['realms'],
  tx: ProvisioningTransaction,
  realm: RealmRow,
  relyingParty: RealmRelyingParty
): Promise<RealmRow> {
  if (realm.webauthnRpIdLockedAt !== null) {
    assertPasskeyRpIdLock(realm, relyingParty);
    return realm;
  }
  const stored = relyingParty.scope === 'parent-domain' ? relyingParty.rpId : null;
  if (realm.webauthnRpId === stored) return realm;
  try {
    return await realms.setWebAuthnRpId(realm.id, stored, tx);
  } catch (error) {
    // A first enrolment on another node locked the realm since it was read:
    // explain the lock as at any other boot.
    if (!(error instanceof BadRequestError)) throw error;
    const current = await realms.findById(realm.id, tx);
    if (current) assertPasskeyRpIdLock(current, relyingParty);
    throw error;
  }
}

/**
 * Step 6: a realm whose first passkey is enrolled is locked to the RP ID it was
 * enrolled under. Another RP ID would orphan every passkey, so the boot stops
 * and says which value keeps them working.
 */
function assertPasskeyRpIdLock(realm: RealmRow, relyingParty: RealmRelyingParty): void {
  try {
    assertRelyingPartyIdUnlockedOrSame(
      realm.webauthnRpIdLockedAt === null ? null : resolveRpId(realm),
      relyingParty
    );
  } catch (error) {
    if (!(error instanceof RelyingPartyIdLockedError)) throw error;
    const remedy =
      error.lockedRpId === relyingParty.realmHost
        ? `Unset WEBAUTHN_RP_ID, or set it to "${error.lockedRpId}".`
        : `Set WEBAUTHN_RP_ID to "${error.lockedRpId}" and keep WEBAUTHN_RP_ID_ALLOW_PARENT_DOMAIN=true.`;
    throw new DefaultRealmBootError(
      `The default realm "${realm.name}" has passkeys bound to the RP ID "${error.lockedRpId}", but WEBAUTHN_RP_ID gives "${error.configuredRpId}". The RP ID is locked once a realm has a passkey: another one would orphan every passkey enrolled under "${error.lockedRpId}". ${remedy}`,
      { cause: error }
    );
  }
}

function hostKindPhrase(kind: 'primary' | 'endpoint'): string {
  return kind === 'primary' ? 'the primary host' : 'an endpoint host';
}

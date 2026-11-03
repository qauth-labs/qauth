import type { RealmPolicySnapshot } from '@qauth-labs/fastify-plugin-realm-policy';
import { BadRequestError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';

import type { RealmRow } from './request-realm';

/**
 * The paired sandbox realm (ADR-019 Decision 11, ADR-020 §4, issue #554).
 *
 * A live realm can have one sandbox realm. The sandbox is a realm in its own
 * right: its own host, issuer, keys and passkey RP ID, and none of the live
 * realm's users, which realm isolation already keeps apart. Its environment
 * ceiling is `staging`, so the developer portal's flow test console works
 * there, and a client set to `development` runs as `staging`. A token it
 * issues names its own issuer, so a resource server of the live realm refuses
 * it without any claim of its own.
 *
 * The twin shares the deployment's database, KEK and signer role with the
 * live realm; its trust domain is the deployment's.
 *
 * The rules of the pairing live in the database (migration 0056): one
 * sandbox per live realm, no sandbox of a sandbox or of the operator realm, a
 * pairing that never changes, never a `development` ceiling on a sandbox, and
 * no deleting a live realm while its sandbox exists. The repository answers a
 * broken rule with a `SandboxPairingError` naming it.
 *
 * The admin API's operation that creates a sandbox (#694), a realm-creation
 * security operation, calls {@link createSandboxRealm}.
 */

/** The transaction a sandbox is created in: the one `fastify.db.transaction` hands out. */
export type SandboxRealmTransaction = Parameters<
  FastifyInstance['repositories']['realms']['lockProvisioning']
>[0];

/** What {@link createSandboxRealm} works through. */
export interface SandboxRealmDependencies {
  /** `fastify.db`: the sandbox, its policies and its keys commit together, or nothing does. */
  readonly db: Pick<FastifyInstance['db'], 'transaction'>;
  /** `fastify.repositories.realms`. */
  readonly realms: Pick<
    FastifyInstance['repositories']['realms'],
    'lockProvisioning' | 'createSandboxWithPrimaryHost' | 'findById'
  >;
  /** `fastify.policyStore`: sets the sandbox's test mail transport. */
  readonly policies: Pick<FastifyInstance['policyStore'], 'update'>;
  /**
   * Give the new realm its standard keys in `tx`, as the key boot step gives
   * a realm with no key variables (#485): token signing (with RS256, as a
   * fresh realm gets), cookie, event signing and data at rest. It runs where
   * the KEK is, in the signer role: `bootRealmKeysByName` of
   * `@qauth-labs/fastify-plugin-signer` over `tx`, with no environment keys.
   * The sandbox's keys are its own; none is copied from the live realm.
   */
  readonly provisionKeys: (
    realm: Pick<RealmRow, 'id' | 'name'>,
    tx: SandboxRealmTransaction
  ) => Promise<unknown>;
}

/** What the operator asks for: the sandbox's own name and issuer. */
export interface SandboxRealmInput {
  /** The sandbox realm's name, unique across realms. */
  readonly name: string;
  /**
   * The sandbox realm's issuer, permanent as every realm's (ADR-019 Decision
   * 1). Its host becomes the sandbox's primary host, which no other realm may
   * have, the live realm included.
   */
  readonly issuer: string;
}

/** The sandbox {@link createSandboxRealm} created. */
export interface CreatedSandboxRealm {
  /** The sandbox realm as it was committed, its pairing and ceiling set. */
  readonly realm: RealmRow;
  /** Its primary host, in stored form. */
  readonly host: string;
  /** Its policies: the environment's seeds, the `staging` ceiling and the test mail transport. */
  readonly policies: RealmPolicySnapshot;
}

/**
 * What a new sandbox's policies change from the environment's seeds: the
 * test mail transport, which only logs, so no mail of the sandbox reaches a
 * mailbox through the deployment's transport (#554). The `staging` ceiling
 * is set with the pairing, when the row is created.
 */
export const SANDBOX_POLICY_PATCH = Object.freeze({
  mail: Object.freeze({ provider: 'mock' }),
});

/**
 * Create the paired sandbox realm of `liveRealmId` (#554), in one
 * transaction: the realm and its primary host from `input.issuer`, paired
 * with the live realm, with the `staging` ceiling; its policies from the
 * environment's seeds with the test mail transport; and its own keys. Its
 * passkey RP ID is its own host, the default of a new realm. Nothing is
 * copied from the live realm: no user, client, policy, secret or key.
 *
 * Runs under the realm provisioning lock, as the default realm's boot step
 * does, so a sandbox and a node's boot never create realms at the same time.
 *
 * @throws NotFoundError when there is no realm `liveRealmId`
 * @throws SandboxPairingError when the live realm already has a sandbox
 *   (`one_sandbox`), is a sandbox (`sandbox_of_sandbox`) or is the operator
 *   realm (`operator`)
 * @throws BadRequestError when `input.issuer` is not a URL, or not one a
 *   realm can have (see `createWithPrimaryHost`)
 * @throws InvalidRealmHostError when its host cannot be a realm's primary host
 * @throws UniqueConstraintError when another realm has the name, the issuer
 *   or the host
 */
export async function createSandboxRealm(
  deps: SandboxRealmDependencies,
  liveRealmId: string,
  input: SandboxRealmInput
): Promise<CreatedSandboxRealm> {
  const primaryHost = issuerHost(input.issuer);
  return deps.db.transaction(async (tx: SandboxRealmTransaction) => {
    await deps.realms.lockProvisioning(tx);
    const created = await deps.realms.createSandboxWithPrimaryHost(
      liveRealmId,
      { name: input.name, issuer: input.issuer, enabled: true },
      primaryHost,
      tx
    );
    const policies = await deps.policies.update(created.realm.id, SANDBOX_POLICY_PATCH, {
      expectedVersion: created.realm.policiesVersion,
      tx,
    });
    await deps.provisionKeys(created.realm, tx);
    const realm = (await deps.realms.findById(created.realm.id, tx)) ?? created.realm;
    return { realm, host: created.host.host, policies };
  });
}

/** The host of `issuer`, which `createSandboxWithPrimaryHost` checks against the issuer again. */
function issuerHost(issuer: string): string {
  try {
    return new URL(issuer).host;
  } catch {
    throw new BadRequestError('Realm issuer is not a URL');
  }
}

/**
 * The pairing as the admin API's realm representation shows it (API-16,
 * #554): read-only fields, each a realm id or `null`. A sandbox names its
 * live realm in `sandboxOf`; a live realm names its sandbox in `sandbox`. A
 * merge patch of the representation cannot change either: the pairing is
 * set when the sandbox is created and never changes.
 */
export interface RealmSandboxPairing {
  /** The live realm this realm is the sandbox of, or `null`. */
  readonly sandboxOf: string | null;
  /** This realm's sandbox realm, or `null`. */
  readonly sandbox: string | null;
}

/**
 * The `sandboxOf` and `sandbox` fields of `realm`'s representation. A sandbox
 * has no sandbox, so only a realm that is no sandbox is looked up.
 */
export async function sandboxPairingOf(
  realms: Pick<FastifyInstance['repositories']['realms'], 'findSandboxOf'>,
  realm: Pick<RealmRow, 'id' | 'sandboxOfRealmId'>,
  tx?: SandboxRealmTransaction
): Promise<RealmSandboxPairing> {
  if (realm.sandboxOfRealmId !== null) {
    return { sandboxOf: realm.sandboxOfRealmId, sandbox: null };
  }
  const sandbox = await realms.findSandboxOf(realm.id, tx);
  return { sandboxOf: null, sandbox: sandbox?.id ?? null };
}

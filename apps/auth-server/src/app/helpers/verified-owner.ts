import {
  credentialKindOf,
  decideVerifiedOwner,
  type UpstreamProviderSwitch,
  type VerifiedOwnerDecision,
} from '@qauth-labs/fastify-plugin-federation';
import { ForbiddenError } from '@qauth-labs/shared-errors';
import type { FastifyRequest } from 'fastify';

import { upstreamProviderCatalog, type UpstreamProviderServer } from './upstream-providers';
import { emitUserEvent } from './user-events';

/**
 * AN AGENT OWNER IS A VERIFIED ACCOUNT (ADR-015 Decision 8 and question 13,
 * amended 2026-11-08; #846).
 *
 * Only a verified account can own an agent, and an account is verified when
 * QAuth proved a strong credential it holds, whenever it was added: the
 * credential that created the account (`user_credentials.is_primary`) or any
 * later one. The rule itself, row by row of Decision 8's table, is
 * `decideVerifiedOwner` of `@qauth-labs/server-federation`; this reads what
 * it needs for one account: every credential it holds in its realm, and for
 * each upstream identity the realm's provider of its type while the realm
 * offers it, whose verified switch (ADR-020 §3) must be on.
 *
 * It never reads `REQUIRE_VERIFIED_ACCOUNT`: that setting governs sign-in,
 * not the ownership of an agent. An email address on its own counts for
 * nothing, and a passkey that verifies the account leaves its address
 * unverified.
 *
 * Every place where an account takes an agent calls {@link
 * assertVerifiedOwner}: today the dynamic registration of an agent client
 * attributed to a developer (`POST /oauth/register`); the agent routes of the
 * Authority Tree (#721) — creating an agent, accepting one by transfer,
 * rooting a tree in one, binding one to a platform, registering an agent-side
 * transmitter, approval channel or passkey — call it too.
 */

/** What the check reads: the repositories, and what the provider catalog builds a provider with. */
export type VerifiedOwnerServer = UpstreamProviderServer;

/** The account to check: a user of a realm. */
export interface OwnerAccount {
  readonly realmId: string;
  readonly userId: string;
}

/** What an account takes that only a verified owner may (the event's `action`). */
export type AgentOwnershipAction = 'client_registration';

/**
 * Whether `account` is a verified owner, and if not, why. A credential of
 * another realm is none of the account's (#489). An AuthMethod plugin's
 * identity is vouched for only by a process that loaded the plugin (one with
 * the `web` or `admin` role): elsewhere the catalog has no provider of its
 * type, and the identity proves nothing.
 */
export async function checkVerifiedOwner(
  fastify: VerifiedOwnerServer,
  account: OwnerAccount
): Promise<VerifiedOwnerDecision> {
  const credentials = (
    await fastify.repositories.userCredentials.findAllByUserId(account.userId)
  ).filter((credential) => credential.realmId === account.realmId);
  // The realm's providers of the account's upstream identities, read once per
  // type before the rule runs.
  const catalog = upstreamProviderCatalog(fastify);
  const providers = new Map<string, UpstreamProviderSwitch | undefined>();
  for (const credential of credentials) {
    if (credentialKindOf(credential) !== 'upstream' || providers.has(credential.providerType)) {
      continue;
    }
    providers.set(
      credential.providerType,
      await catalog.find(account.realmId, credential.providerType)
    );
  }
  return decideVerifiedOwner(credentials, (providerType) => providers.get(providerType));
}

/** Whether `account` is a verified owner of an agent (ADR-015 Decision 8). */
export async function isVerifiedOwner(
  fastify: VerifiedOwnerServer,
  account: OwnerAccount
): Promise<boolean> {
  return (await checkVerifiedOwner(fastify, account)).verified;
}

/**
 * Refuse, audited, an `action` that would make `account` the owner of an
 * agent unless it is a verified owner: `user.agent_ownership_refused` is
 * recorded, then a 403 `ForbiddenError` thrown, which names no scope, since
 * no token can lift it.
 *
 * @throws ForbiddenError when the account is not a verified owner
 */
export async function assertVerifiedOwner(
  request: FastifyRequest,
  account: OwnerAccount,
  action: AgentOwnershipAction
): Promise<void> {
  const decision = await checkVerifiedOwner(request.server, account);
  if (decision.verified) return;
  await emitUserEvent(
    request,
    'urn:qauth:event:user.agent_ownership_refused:v1-rc.0',
    { action, reason: decision.reason, primaryIdentity: decision.primaryIdentity },
    { realmId: account.realmId, userId: account.userId, actor: 'user' }
  );
  throw new ForbiddenError(
    'Only a verified account can own an agent: add a passkey to this account, or confirm one of its sign-in methods'
  );
}

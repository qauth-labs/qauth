/**
 * What an operator path does after it changes a client's first-party profile
 * (ADR-017 Decision 2, #631): the seed manifest and the system-client
 * provisioner both call {@link recordFirstPartyChange} in the transaction that
 * wrote the row, so the two can never record a change differently.
 *
 * - Removing a profile revokes every refresh token of the client not already
 *   revoked, in
 *   every family: tokens obtained while the client was trusted as first party
 *   (a waived consent, the authorization challenge endpoint) end with that
 *   trust.
 * - Any change of the profile, its policy or its written reason writes a
 *   `client.first_party_changed` event, which commits with the change.
 */
import { userInfo } from 'node:os';

import {
  type FirstPartyPolicy,
  firstPartyPolicySchema,
  type FirstPartyProfile,
} from '@qauth-labs/shared-validation';

import type { Database, DbTransaction } from '../../types';
import { createEventsRepository } from '../repositories/events.repository';
import { createRefreshTokensRepository } from '../repositories/refresh-tokens.repository';

/** The `revokedReason` of a token whose client lost its first-party profile. */
export const FIRST_PARTY_REMOVED_REVOKE_REASON = 'first_party_profile_removed';

/** A client's first-party columns, as `oauth_clients` holds them. */
export interface FirstPartyColumns {
  readonly profile: FirstPartyProfile | null;
  readonly policy: Readonly<Record<string, unknown>> | null;
  readonly reason: string | null;
}

/** The columns of a client that is not first party. */
export const NO_FIRST_PARTY: FirstPartyColumns = Object.freeze({
  profile: null,
  policy: null,
  reason: null,
});

export interface FirstPartyChange {
  /** The realm's id. */
  readonly realmId: string;
  /** The client row's id (`oauth_clients.id`). */
  readonly id: string;
  /** The client's `client_id`, the event's subject. */
  readonly clientId: string;
  /** The columns before the write, as read under the row lock. */
  readonly before: FirstPartyColumns;
  /** The columns the write left. */
  readonly after: FirstPartyColumns;
}

export interface FirstPartyChangeResult {
  /** Whether anything of the three columns changed, so an event was written. */
  readonly changed: boolean;
  /** How many refresh tokens a removal revoked; 0 otherwise. */
  readonly revokedTokenCount: number;
}

/**
 * Why an existing row can never carry a first-party profile because of who
 * wrote it, or `null` when it can: a developer owns it, or dynamic
 * registration or a CIMD document created it (the first CHECK of migration
 * 0048). The operator paths ask before they write, so they refuse such a row
 * by name instead of failing on the CHECK. Whether the row is an agent is the
 * caller's to check: the seed rewrites `is_agent` from its manifest, the
 * system-client provisioner refuses an agent.
 */
export function ownershipRefusalOf(row: {
  developerId: string | null;
  dynamicRegisteredAt: number | null;
  metadata: Readonly<Record<string, unknown>> | null;
}): 'developer_owned' | 'dynamic' | 'cimd' | null {
  if (row.developerId !== null) return 'developer_owned';
  const registrationType = row.metadata?.['registrationType'];
  if (registrationType === 'cimd') return 'cimd';
  if (row.dynamicRegisteredAt !== null || registrationType === 'dynamic') return 'dynamic';
  return null;
}

/** JSON with object keys sorted, so two equal values compare equal. */
export function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map(
        (key) => `${JSON.stringify(key)}:${canonicalJson((value as Record<string, unknown>)[key])}`
      )
      .join(',')}}`;
  }
  return JSON.stringify(value) ?? 'null';
}

/** Whether the first-party columns differ. */
export function firstPartyColumnsDiffer(a: FirstPartyColumns, b: FirstPartyColumns): boolean {
  return (
    a.profile !== b.profile ||
    a.reason !== b.reason ||
    canonicalJson(a.policy) !== canonicalJson(b.policy)
  );
}

/**
 * The operating-system user running the operator tool, the `actor.id` of its
 * event; `undefined` when the process has no user entry (a container without
 * one), so the event still names the tool as its actor.
 */
function operatorUser(): string | undefined {
  try {
    const name = userInfo().username;
    return name.length > 0 && name.length <= 255 ? name : undefined;
  } catch {
    return undefined;
  }
}

/** The members of a native policy the event carries, when the profile is `native_backend`. */
function policyMembers(after: FirstPartyColumns): {
  flows?: FirstPartyPolicy['flows'];
  pkceRequired?: boolean;
} {
  if (after.profile !== 'native_backend') return {};
  const policy = firstPartyPolicySchema.safeParse(after.policy);
  if (!policy.success) return {};
  return { flows: policy.data.flows, pkceRequired: policy.data.pkce_required };
}

/**
 * Record a change of a client's first-party columns that `tx` has just
 * written: revoke the client's refresh tokens when the profile was removed,
 * and write the `client.first_party_changed` event (actor `operator_cli`).
 * Writes nothing when the columns are unchanged.
 *
 * The caller must have read `before` under a `FOR NO KEY UPDATE` lock of the
 * client row in `tx` (see `revokeAllForClient`).
 */
export async function recordFirstPartyChange(
  db: Database,
  tx: DbTransaction,
  change: FirstPartyChange
): Promise<FirstPartyChangeResult> {
  const { before, after } = change;
  if (!firstPartyColumnsDiffer(before, after)) {
    return { changed: false, revokedTokenCount: 0 };
  }

  const revokedTokenCount =
    before.profile !== null && after.profile === null
      ? await createRefreshTokensRepository(db).revokeAllForClient(
          change.id,
          FIRST_PARTY_REMOVED_REVOKE_REASON,
          tx
        )
      : 0;

  const operator = operatorUser();
  await createEventsRepository(db).emit(tx, {
    type: 'urn:qauth:event:client.first_party_changed:v1-rc.0',
    realm: change.realmId,
    actor: { type: 'operator_cli', ...(operator === undefined ? {} : { id: operator }) },
    subject: { type: 'client', id: change.clientId },
    client: { id: change.clientId },
    data: {
      from: before.profile,
      to: after.profile,
      ...policyMembers(after),
      ...(after.profile !== null && after.reason !== null ? { writtenReason: after.reason } : {}),
      revokedTokenCount,
    },
  });

  return { changed: true, revokedTokenCount };
}

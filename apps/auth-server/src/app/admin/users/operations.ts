import { createHash } from 'node:crypto';

import { canonicalizeJson } from '@qauth-labs/fastify-plugin-db';
import {
  PASSWORD_PROVIDER_TYPE,
  primaryIdentityKindOf,
} from '@qauth-labs/fastify-plugin-federation';
import { NotFoundError } from '@qauth-labs/shared-errors';
import { isOperatorVerified } from '@qauth-labs/shared-validation';
import type { FastifyInstance, FastifyRequest } from 'fastify';

import { rfc3339 } from '../../api-conventions/time';
import { AccountVerificationConflictError } from '../../helpers/account-verification-errors';
import type {
  AdminOperationDefinition,
  ClassifyInput,
  RenderedField,
  RenderedOperation,
  RenderInput,
} from '../../helpers/admin-operations';

/**
 * THE ACCOUNT OPERATIONS OF THE ADMIN API (ADR-015 Decision 8, amended
 * 2026-11-08; ADR-019 Decision 7; issue #1052): an operator verifies an
 * account.
 *
 * `users.verify` records the operator's verification on the account
 * (`users.operator_verified_at` and `operator_verified_by`), which counts
 * beside the proof of its primary identity wherever QAuth asks for a verified
 * account: the sign-in gate under `REQUIRE_VERIFIED_ACCOUNT` (#1051) and the
 * verified owner of an agent (#846). It is the operator's attestation, so it
 * also claims an unclaimed account (ADR-017): another person's first mailbox
 * proof no longer ends it. It never sets `email_verified`, which says only
 * that an address's mailbox code was entered.
 *
 * Making an account verified grants it what only a verified account may do,
 * so `users.verify` is a security operation with the effect
 * `credential-path` (`admin-operations-reserved.ts`): it needs
 * `qauth:admin:security` (the permission `users.security`) and an approval,
 * and `qauth:admin:write` reaches it nowhere.
 *
 * It reads the account (`loadState`): what its approver is shown is the
 * account, its credentials and the proof each holds, as they stood when the
 * approval was filed, and the approval approves the verification of the
 * account in that state only. A credential added, removed or proved between
 * filing and the call is another state: the approval no longer matches it.
 * A disabled account, and one an operator already verified, are refused
 * (409) before anything is filed.
 *
 * The host's `verify-account` command of the migration runner records the
 * same verification where no admin API is set up
 * (`libs/infra/db/src/lib/account-verification/`).
 */

/** The ids of the account operations. */
export const USER_OPERATION_IDS = Object.freeze({
  verify: 'users.verify',
} as const);

/**
 * What one credential of the account proves, by Decision 8's table:
 *
 * - `proved`: its kind's proof holds (a confirmed address, a passkey
 *   registered with user verification, a wallet presentation QAuth verified);
 * - `not_proved`: it does not;
 * - `provider`: an upstream identity, which counts while the realm's provider
 *   is marked to vouch for its accounts (ADR-020 §3);
 * - `none`: a type with no proof of identity, such as TOTP.
 */
export type CredentialProof = 'proved' | 'not_proved' | 'provider' | 'none';

/** One credential of the account, as the approver is shown it. */
export interface AccountCredentialState {
  readonly id: string;
  /** Its `provider_type`. */
  readonly type: string;
  /** Whether it is the account's primary identity: the credential that created it. */
  readonly primary: boolean;
  /** Whether it is disabled. */
  readonly disabled: boolean;
  readonly proof: CredentialProof;
  /** The address a password credential answers to; `null` for any other type. */
  readonly identifier: string | null;
}

/** The account `users.verify` acts on, as its `loadState` reads it. */
export interface AccountVerificationState {
  readonly userId: string;
  /** When the account was created, in milliseconds. */
  readonly createdAt: number;
  /** Its credentials in the realm, by id. */
  readonly credentials: readonly AccountCredentialState[];
}

/** A credential, as `user_credential_proofs` returns it: nothing secret. */
type CredentialRow = Awaited<
  ReturnType<FastifyInstance['repositories']['userCredentials']['findProofsByUserId']>
>[number];

/**
 * What one credential proves, by its kind's row of Decision 8's table
 * (`decideVerifiedOwner` of federation), read off the keys of its data that
 * say so: a confirmed address, a passkey registered with user verification,
 * a wallet binding (made only after a presentation QAuth verified). The
 * admin role reads no more of the data (migration 0070), so a row whose data
 * is malformed otherwise is shown by these keys alone; what the account's
 * standing is decided by is the full rule, wherever it is checked.
 */
function proofOf(credential: CredentialRow): CredentialProof {
  const kind = primaryIdentityKindOf({
    providerType: credential.providerType,
    credentialData: credential.proofData,
  });
  switch (kind) {
    case 'password':
      return credential.proofData.email_verified === true ? 'proved' : 'not_proved';
    case 'passkey':
      return credential.proofData.user_verified !== false ? 'proved' : 'not_proved';
    case 'wallet':
      return 'proved';
    case 'upstream':
      return 'provider';
    case 'other':
      return 'none';
  }
}

function credentialStateOf(credential: CredentialRow): AccountCredentialState {
  return {
    id: credential.id,
    type: credential.providerType,
    primary: credential.isPrimary,
    disabled: credential.disabledAt !== null,
    proof: proofOf(credential),
    identifier: credential.providerType === PASSWORD_PROVIDER_TYPE ? credential.identifier : null,
  };
}

/** The repositories the state reads, with the transaction they read in. */
type StateServer = Pick<FastifyInstance, 'repositories'>;
type Transaction = Parameters<FastifyInstance['repositories']['users']['findById']>[2];

/**
 * The account `userId` of the realm as `users.verify` meets it, read in `tx`
 * when given.
 *
 * @throws NotFoundError when the realm has no such account
 * @throws AccountVerificationConflictError when the account is disabled, or
 *   an operator already verified it
 */
export async function readAccountVerificationState(
  server: StateServer,
  realmId: string,
  userId: string,
  tx?: Transaction
): Promise<AccountVerificationState> {
  const user = await server.repositories.users.findById(realmId, userId, tx);
  if (user === undefined) throw new NotFoundError('User', userId);
  if (!user.enabled) throw new AccountVerificationConflictError('disabled');
  if (isOperatorVerified(user)) throw new AccountVerificationConflictError('already_verified');
  // The realm's credentials of the account, through the function the admin
  // role may execute: it reads nothing secret of them.
  const rows = await server.repositories.userCredentials.findProofsByUserId(realmId, user.id, tx);
  const credentials = rows
    .map(credentialStateOf)
    .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  return { userId: user.id, createdAt: user.createdAt, credentials };
}

/**
 * The version of a state: the SHA-256 digest, base64url, of its canonical
 * JSON. An entity-tag's opaque value, which the approval binds.
 */
export function accountVerificationStateVersion(state: AccountVerificationState): string {
  return createHash('sha256').update(canonicalizeJson(state), 'utf8').digest('base64url');
}

/**
 * `users.verify`'s `loadState`: the account the path names, in the realm the
 * authority stage resolved. Inside an admin handler (`approvals.create`
 * files the verification from its own) it reads in the handler's
 * transaction.
 */
async function loadAccountVerificationState(
  request: FastifyRequest,
  input: ClassifyInput
): Promise<AccountVerificationState> {
  // Read off the pipeline's state, not through the pipeline module, which
  // imports the registry.
  const caller = request.adminPipeline?.authority;
  if (caller === undefined) {
    throw new Error('users.verify reads its account only behind the admin pipeline');
  }
  const { userId } = (input.params ?? {}) as { userId?: unknown };
  if (typeof userId !== 'string') throw new NotFoundError('User', String(userId));
  return readAccountVerificationState(
    request.server,
    caller.targetRealm.id,
    userId,
    request.adminPipeline?.transaction
  );
}

/** The most credentials one approval shows, under the display's cap of 50 lines. */
const MAX_RENDERED_CREDENTIALS = 40;

const PROOF_TEXT: Readonly<Record<CredentialProof, string>> = Object.freeze({
  proved: 'proved',
  not_proved: 'not proved',
  provider: "proved by its provider's sign-in while the realm's provider vouches for its accounts",
  none: 'proves no identity',
});

/** What the approver reads of one credential's proof, by its type. */
function proofText(credential: AccountCredentialState): string {
  if (credential.type === 'password') {
    return credential.proof === 'proved'
      ? `address ${credential.identifier ?? ''} confirmed by its mailbox code`
      : `address ${credential.identifier ?? ''} not confirmed`;
  }
  return PROOF_TEXT[credential.proof];
}

/** Where the account stands before the verification, by its primary identity. */
function standingOf(state: AccountVerificationState): string {
  const primary = state.credentials.find((credential) => credential.primary);
  if (primary === undefined) {
    return 'no primary identity: the verification lets it sign in where verified accounts are required, and own an agent';
  }
  switch (primary.proof) {
    case 'proved':
      return `verified by its primary identity (${primary.type}); the operator's verification is recorded beside it`;
    case 'provider':
      return `verified by its primary identity (${primary.type}) while the realm's provider vouches for its accounts`;
    default:
      return `not verified: its primary identity (${primary.type}) is not proved, so the account is unclaimed and this claims it`;
  }
}

/**
 * What an approver is shown of a verification (#1052): the account, where it
 * stands, what the verification does to it, and each credential with the
 * proof it holds, as they stood when the approval was filed
 * (`RenderInput.state`). The reason the requester typed is shown beside it
 * by the approval engine.
 */
function renderVerification(input: RenderInput): RenderedOperation {
  const state = input.state as AccountVerificationState | undefined;
  if (state === undefined) {
    throw new Error('A verification is shown against the account it was filed against');
  }
  const shown = state.credentials.slice(0, MAX_RENDERED_CREDENTIALS);
  const fields: RenderedField[] = [
    { label: 'account', value: state.userId },
    { label: 'created', value: rfc3339(state.createdAt) },
    { label: 'now', value: standingOf(state) },
    {
      label: 'effect',
      value:
        "The account counts as verified wherever QAuth asks for a verified account: signing in where verified accounts are required, and owning an agent. It is the operator's attestation, so it claims the account if it is unclaimed: another person's later mailbox proof no longer ends it. It attests the account, not its address: while the address is unconfirmed, no password reset by mail opens. email_verified is not changed.",
    },
    ...shown.map((credential): RenderedField => ({
      label: `credential ${credential.type}${credential.primary ? ' (primary)' : ''}${credential.disabled ? ' (disabled)' : ''}`,
      value: proofText(credential),
    })),
  ];
  if (state.credentials.length === 0) {
    fields.push({ label: 'credentials', value: 'none' });
  }
  if (state.credentials.length > shown.length) {
    fields.push({
      label: 'and more',
      value: `${state.credentials.length - shown.length} more credentials, not shown`,
    });
  }
  return { title: 'Verify an account as the operator', fields };
}

/** The definitions, for `ADMIN_OPERATIONS` (`helpers/admin-operations.ts`). */
export const USER_OPERATION_DEFINITIONS: readonly AdminOperationDefinition[] = Object.freeze([
  {
    id: USER_OPERATION_IDS.verify,
    class: 'security',
    effects: ['credential-path'],
    permissions: ['users.security'],
    description:
      'Verify an account as the operator: it counts as verified beside its primary identity, for sign-in and for owning an agent, and an unclaimed account is claimed; email_verified is not changed. The approval binds the account and its credentials as they stood when it was filed; a disabled account, and one an operator already verified, are refused.',
    loadState: loadAccountVerificationState,
    stateVersion: (state: unknown) =>
      accountVerificationStateVersion(state as AccountVerificationState),
    render: renderVerification,
  } as AdminOperationDefinition,
]);

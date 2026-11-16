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
import { AccountDeletionConflictError } from '../../helpers/account-deletion-errors';
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
 *
 * `users.delete` (ADR-020 §3, issues #681 and #1090) deletes an account at
 * once, with every credential, link and address that authenticates or
 * recovers it, so it is a security operation with the effect
 * `credential-path` too: it needs `qauth:admin:security` (the permission
 * `users.delete`, a permission of its own so a role can grant it alone) and
 * an approval. It reads the account (`loadState`) as `users.verify` does, and
 * the approval binds the account as it stood when it was filed. It is
 * idempotent by id: an id the realm does not hold, whether it is unknown,
 * deleted already or another realm's account, reads as one absent state,
 * which the call deletes nothing for and answers as a deletion
 * (`./deletion.ts`). A service account's account and an account that holds an
 * admin grant are refused (409) before anything is filed.
 *
 * A deletion's state, and so what its approver is shown and what the approval
 * keeps, names each credential's identifier masked (`maskIdentifier`), never
 * whole: the approval row outlives the account, and an identifier is the
 * person's, whatever kind it is. The approver tells the account by its id,
 * its creation time and its credentials, which holds for an account with no
 * identifier at all, such as one that signs in with a passkey alone.
 */

/** The ids of the account operations. */
export const USER_OPERATION_IDS = Object.freeze({
  verify: 'users.verify',
  delete: 'users.delete',
} as const);

/**
 * What one credential of the account proves, by Decision 8's table:
 *
 * - `proved`: its kind's proof holds (a confirmed address, a passkey
 *   registered with user verification, a wallet presentation QAuth verified);
 * - `not_proved`: it does not;
 * - `provider`: an upstream identity the account counts as verified by (its
 *   `verified`: the provider vouched as it was created, or QAuth confirmed
 *   its address since), which counts while the realm's provider is marked to
 *   vouch for its accounts (ADR-020 §3); one whose `verified` does not hold
 *   is `not_proved`, as the sign-in reads it;
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
 * a wallet binding (made only after a presentation QAuth verified), an
 * upstream identity's own `verified`, so the approval binds it too. The
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
      return credential.proofData.verified === true ? 'provider' : 'not_proved';
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

/**
 * One credential of an account `users.delete` deletes, as its approver is
 * shown it: its identifier masked.
 */
export interface DeletableCredentialState extends Omit<AccountCredentialState, 'identifier'> {
  /**
   * The identifier the credential answers to, masked (`maskIdentifier`);
   * `null` for a credential whose identifier the admin role does not read.
   */
  readonly maskedIdentifier: string | null;
}

/** The account `users.delete` deletes, as its `loadState` reads it. */
export interface DeletableAccount {
  /** When the account was created, in milliseconds. */
  readonly createdAt: number;
  readonly enabled: boolean;
  /** Its credentials in the realm, by id, each with the proof it holds. */
  readonly credentials: readonly DeletableCredentialState[];
}

/** What a masked identifier shows in place of what it hides, whatever its length. */
const MASK = '***';

/**
 * An identifier, masked for an approval that outlives the account (#681):
 * its first code point, the mask and, for an identifier of five code points
 * or more, its last one. The same for every kind of identifier, an address,
 * a username or a number alike, and its length is not told.
 */
export function maskIdentifier(identifier: string): string {
  const points = Array.from(identifier);
  if (points.length === 0) return MASK;
  const first = points[0];
  return points.length < 5 ? `${first}${MASK}` : `${first}${MASK}${points[points.length - 1]}`;
}

function deletableCredentialOf(credential: AccountCredentialState): DeletableCredentialState {
  const { identifier, ...rest } = credential;
  return { ...rest, maskedIdentifier: identifier === null ? null : maskIdentifier(identifier) };
}

/**
 * What `users.delete` meets: the account the path names, or `null` when the
 * realm holds no account with that id. An unknown id, an account deleted
 * already and another realm's account read alike, so the call, its approval
 * and its answer cannot tell them apart (#1090).
 */
export interface AccountDeletionState {
  readonly userId: string;
  readonly account: DeletableAccount | null;
}

/**
 * Refuse to delete a service account's account (#522), marked or bound, and
 * an account that holds an admin grant not revoked: a grant whose custom role
 * is disabled counts too, since enabling the role again would give it back.
 * Removing an admin is the administration's own operation, under the
 * two-admin rule (#521), which deleting the account would bypass.
 *
 * @throws AccountDeletionConflictError naming the refusal
 */
async function refuseUndeletableAccount(
  server: StateServer,
  realmId: string,
  user: { readonly id: string; readonly isServiceAccount?: boolean },
  tx?: Transaction
): Promise<void> {
  const boundAccount =
    user.isServiceAccount === true ||
    (await server.repositories.serviceAccounts.findByUser(realmId, user.id, tx)) !== undefined;
  if (boundAccount) throw new AccountDeletionConflictError('service_account');
  const grants = await server.repositories.adminGrants.listByUser(realmId, user.id, tx);
  if (grants.some((grant) => grant.revokedAt === null)) {
    throw new AccountDeletionConflictError('administrator');
  }
}

/**
 * The account `userId` of the realm as `users.delete` meets it, read in `tx`
 * when given: `account: null` when the realm holds none with that id.
 *
 * @throws AccountDeletionConflictError for a service account's account, and
 *   for an account that holds an admin grant
 */
export async function readAccountDeletionState(
  server: StateServer,
  realmId: string,
  userId: string,
  tx?: Transaction
): Promise<AccountDeletionState> {
  const user = await server.repositories.users.findById(realmId, userId, tx);
  // The stored form of an id is lower case; the path's may not be.
  if (user === undefined) return { userId: userId.toLowerCase(), account: null };
  await refuseUndeletableAccount(server, realmId, user, tx);
  const rows = await server.repositories.userCredentials.findProofsByUserId(realmId, user.id, tx);
  // Masked before the state is versioned: the approval binds, and keeps the
  // digest of, what its approver is shown, never a whole identifier.
  const credentials = rows
    .map((row) => deletableCredentialOf(credentialStateOf(row)))
    .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  return {
    userId: user.id,
    account: { createdAt: user.createdAt, enabled: user.enabled, credentials },
  };
}

/** The version of a deletion's state, as {@link accountVerificationStateVersion} takes one. */
export function accountDeletionStateVersion(state: AccountDeletionState): string {
  return createHash('sha256').update(canonicalizeJson(state), 'utf8').digest('base64url');
}

/**
 * `users.delete`'s `loadState`: the account the path names, in the realm the
 * authority stage resolved, read in the handler's transaction inside one.
 */
async function loadAccountDeletionState(
  request: FastifyRequest,
  input: ClassifyInput
): Promise<AccountDeletionState> {
  const caller = request.adminPipeline?.authority;
  if (caller === undefined) {
    throw new Error('users.delete reads its account only behind the admin pipeline');
  }
  const { userId } = (input.params ?? {}) as { userId?: unknown };
  // The route's schema holds the path to a UUID; anything else names nothing.
  if (typeof userId !== 'string') throw new NotFoundError('User', String(userId));
  return readAccountDeletionState(
    request.server,
    caller.targetRealm.id,
    userId,
    request.adminPipeline?.transaction
  );
}

/** What a deletion does, as its approver reads it. */
const DELETION_EFFECT =
  'The account is deleted at once, with its credentials, recovery codes, consents, attributes, upstream identities and refresh tokens: nothing can authenticate or recover it again. Every session it holds ends first, a sign-up or reset session included, and each app a session signed in to that has a back-channel logout URI is sent a logout token. Its access tokens no longer introspect. It cannot be undone.';

/** What the approver reads of one credential of an account to delete: its masked identifier, if any, and its proof. */
function deletableCredentialText(credential: DeletableCredentialState): string {
  const proof = PROOF_TEXT[credential.proof];
  return credential.maskedIdentifier === null
    ? proof
    : `identifier ${credential.maskedIdentifier}, ${proof}`;
}

/**
 * What an approver is shown of a deletion (#681): the account, whether it is
 * enabled, what the deletion does and each credential with the proof it
 * holds and its identifier masked, as they stood when the approval was filed;
 * or, for an id the realm does not hold, that nothing is deleted, without
 * saying why.
 */
function renderDeletion(input: RenderInput): RenderedOperation {
  const state = input.state as AccountDeletionState | undefined;
  if (state === undefined) {
    throw new Error('A deletion is shown against the account it was filed against');
  }
  const title = 'Delete an account';
  const { account } = state;
  if (account === null) {
    return {
      title,
      fields: [
        { label: 'account', value: state.userId },
        {
          label: 'now',
          value:
            'The realm holds no account with this id: it is unknown, deleted already, or of another realm.',
        },
        {
          label: 'effect',
          value:
            'Nothing is deleted and nothing is recorded but the call itself: it answers as a deletion does, so a retry of a deletion that went through answers the same.',
        },
      ],
    };
  }
  const shown = account.credentials.slice(0, MAX_RENDERED_CREDENTIALS);
  const fields: RenderedField[] = [
    { label: 'account', value: state.userId },
    { label: 'created', value: rfc3339(account.createdAt) },
    { label: 'now', value: account.enabled ? 'enabled' : 'disabled' },
    { label: 'effect', value: DELETION_EFFECT },
    ...shown.map((credential): RenderedField => ({
      label: `credential ${credential.type}${credential.primary ? ' (primary)' : ''}${credential.disabled ? ' (disabled)' : ''}`,
      value: deletableCredentialText(credential),
    })),
  ];
  if (account.credentials.length === 0) {
    fields.push({ label: 'credentials', value: 'none' });
  }
  if (account.credentials.length > shown.length) {
    fields.push({
      label: 'and more',
      value: `${account.credentials.length - shown.length} more credentials, not shown`,
    });
  }
  return { title, fields };
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
  {
    id: USER_OPERATION_IDS.delete,
    class: 'security',
    effects: ['credential-path'],
    permissions: ['users.delete'],
    description:
      "Delete an account of the realm at once, with its credentials, recovery codes, consents and everything else it holds; every session it holds ends first, and each client a session signed in to with a back-channel logout URI is sent a logout token. Idempotent by id: an id the realm does not hold, whether unknown, deleted already or another realm's, answers as a deletion does, changes nothing and records no event. The approval binds the account as it stood when it was filed; a service account's account and one that holds an admin grant are refused.",
    loadState: loadAccountDeletionState,
    stateVersion: (state: unknown) => accountDeletionStateVersion(state as AccountDeletionState),
    render: renderDeletion,
  } as AdminOperationDefinition,
]);

/**
 * Act-chain tokens for admins acting for a user (ADR-019 Decision 7, issue
 * #523).
 *
 * There is no impersonation. An admin who acts for a user gets an act-chain
 * token: `sub` is the user, `act` names the admin with its `sub`, `iss` and
 * `client_id`. The token is for the account API alone
 * (`urn:qauth:aud:account:v1-rc.0`), lives at most ten minutes, is bound to
 * the admin's own DPoP key and carries no `auth_time`, so it never counts as
 * the user's sign-in. No password, session or cookie of the user is created.
 *
 * Acting for a user is a security operation (`issue-for-other`): only the
 * handler of an approved one mints a token, with the capability the admin
 * pipeline issued it (`./authorized-operation.ts`). The mint writes the
 * token's `admin_act_sessions` row in the operation's transaction, which the
 * operation's audit row commits in too, so both are there or neither is. The
 * user sees the row on their account page (`listAdminAccess`), and the
 * account API reads it on every call made with the token
 * (`helpers/admin-access.ts`), so revoking the admin's grant or the approval
 * stops the token on its next use.
 *
 * The HTTP operation that mints a token comes later; tests use a fixture
 * operation.
 */
import { ForbiddenError, NotFoundError } from '@qauth-labs/shared-errors';

import { API_FAMILY_AUDIENCES, API_FAMILY_SCOPES } from '../api-conventions/families';
import { accountCredentialRefusal } from '../helpers/account-validity';
import { issueAccessToken } from '../helpers/hybrid-token';
import { type AuthorizedOperation, spendAuthorizedOperation } from './authorized-operation';
import { recordAdminChange } from './pipeline';

/** The longest an act-chain token lives, and its lifetime by default: ten minutes. */
export const ACT_CHAIN_TOKEN_MAX_LIFETIME_SECONDS = 600;

/** The scopes an act-chain token may carry: the account API's. */
const ACCOUNT_SCOPES: readonly string[] = Object.freeze(Object.values(API_FAMILY_SCOPES.account));

/** What an act-chain token carries unless its approval names more: reading the account. */
const ACCOUNT_READ_SCOPE = API_FAMILY_SCOPES.account.read;

/** What the handler asks of the token. */
export interface ActChainTokenParams {
  /**
   * The user to act for, in the operation's target realm: the approved
   * request's `userId` path parameter, which it must equal.
   */
  readonly userId: string;
  /**
   * The token's scopes, each an account API scope. By default reading the
   * account (`qauth:account:read`); any other scope must be one the approved
   * request's body names in its `scopes`, which its approvers saw.
   */
  readonly scopes?: readonly string[];
  /** Its lifetime in whole seconds, at most and by default ten minutes. */
  readonly lifetimeSeconds?: number;
}

/** A minted act-chain token. */
export interface MintedActChainToken {
  /** The token, bound to the admin's DPoP key: sent under the `DPoP` scheme. */
  readonly accessToken: string;
  readonly tokenType: 'DPoP';
  /** Seconds. */
  readonly expiresIn: number;
  /** Its scopes, space-separated. */
  readonly scope: string;
  /** Its `admin_act_sessions` row. */
  readonly sessionId: string;
  /** Epoch ms: its `exp`. */
  readonly expiresAt: number;
}

/** The scopes the approved request's body names, if any (`body.scopes`). */
function approvedScopesOf(body: unknown): readonly string[] {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) return [];
  const scopes = (body as Record<string, unknown>)['scopes'];
  return Array.isArray(scopes) ? scopes.filter((scope) => typeof scope === 'string') : [];
}

/** The token's scopes, as {@link ActChainTokenParams.scopes} rules them. */
function tokenScopes(asked: readonly string[] | undefined, body: unknown): string[] {
  const scopes = [...(asked ?? [ACCOUNT_READ_SCOPE])];
  if (
    scopes.length === 0 ||
    scopes.some((scope) => !ACCOUNT_SCOPES.includes(scope)) ||
    new Set(scopes).size !== scopes.length
  ) {
    throw new RangeError('An act-chain token carries account API scopes only, each once');
  }
  const approved = approvedScopesOf(body);
  const unapproved = scopes.filter(
    (scope) => scope !== ACCOUNT_READ_SCOPE && !approved.includes(scope)
  );
  if (unapproved.length > 0) {
    throw new ForbiddenError(
      'The approval names no scope beyond reading the account: an act-chain token gets no other'
    );
  }
  return scopes;
}

function tokenLifetime(asked: number | undefined): number {
  const lifetime = asked ?? ACT_CHAIN_TOKEN_MAX_LIFETIME_SECONDS;
  if (
    !Number.isSafeInteger(lifetime) ||
    lifetime <= 0 ||
    lifetime > ACT_CHAIN_TOKEN_MAX_LIFETIME_SECONDS
  ) {
    throw new RangeError(
      `An act-chain token lives at most ${ACT_CHAIN_TOKEN_MAX_LIFETIME_SECONDS} seconds`
    );
  }
  return lifetime;
}

/**
 * Mint an act-chain token for the admin who called the approved security
 * operation `operation`, to act for `params.userId`. See this module.
 *
 * It spends `operation`: one token per approved call. The token's row and the
 * change the operation records (`recordAdminChange`) are written in the
 * operation's transaction, so a handler that mints a token records no other
 * change.
 *
 * @param operation - the capability of the approved operation, from
 *   `requestAuthorizedOperation(request)`: only the admin pipeline issues one,
 *   and only for a security operation whose classification names
 *   `issue-for-other`
 * @throws {AuthorizedOperationRefusedError} for anything but such a capability,
 *   live and unspent
 * @throws {ForbiddenError} for a service account, which acts for no user, and
 *   for a scope the approval did not name
 * @throws {NotFoundError} when the user is not an active user of the target realm
 * @throws {RangeError} for a scope that is not the account API's, or a lifetime
 *   over ten minutes
 */
export async function mintActChainToken(
  operation: AuthorizedOperation,
  params: ActChainTokenParams
): Promise<MintedActChainToken> {
  const context = spendAuthorizedOperation(operation, 'issue-for-other');
  const { request, transaction, caller, adminToken } = context;
  if (caller.kind !== 'human' || caller.serviceAccount !== null) {
    throw new ForbiddenError('Only a person who is an admin may act for a user');
  }
  if (typeof params.userId !== 'string' || context.params['userId'] !== params.userId) {
    // The handler's error: the approvers saw the request's user, no other.
    throw new Error('An act-chain token acts for the user the approved request names');
  }
  const scopes = tokenScopes(params.scopes, context.body);
  const lifetime = tokenLifetime(params.lifetimeSeconds);

  const realm = caller.targetRealm;
  const user = await request.server.repositories.users.findById(
    realm.id,
    params.userId,
    transaction
  );
  if (user === undefined || accountCredentialRefusal(user, Date.now()) !== null) {
    throw new NotFoundError('User', params.userId);
  }

  const scope = scopes.join(' ');
  const accessToken = await issueAccessToken(request.server, realm, {
    sub: user.id,
    clientId: adminToken.clientId,
    aud: API_FAMILY_AUDIENCES.account,
    scope,
    act: { sub: caller.userId, iss: adminToken.issuer, client_id: adminToken.clientId },
    cnf: { jkt: adminToken.jkt },
    expiresInOverride: lifetime,
  });
  const { jti, iat, exp } = request.server.jwtUtils.decodeTokenUnsafe(accessToken);
  if (typeof jti !== 'string' || !Number.isSafeInteger(iat) || !Number.isSafeInteger(exp)) {
    throw new Error('The signed act-chain token has no jti, iat or exp');
  }
  const session = await request.server.repositories.adminActSessions.create(transaction, {
    realmId: realm.id,
    userId: user.id,
    adminRealmId: caller.issuerRealm.id,
    adminUserId: caller.userId,
    adminClientId: adminToken.clientId,
    approvalId: context.approvalId,
    operationId: context.operationId,
    permissionIds: context.permissions,
    tokenJti: jti,
    scopes,
    // The token's own times, so the row's lifetime is the token's.
    createdAt: (iat as number) * 1000,
    expiresAt: (exp as number) * 1000,
  });
  recordAdminChange(request, {
    change: {
      before: null,
      after: {
        id: session.id,
        userId: session.userId,
        scopes: [...session.scopes],
        approvalId: session.approvalId,
        expiresAt: session.expiresAt,
      },
    },
    annotations: {},
  });
  return Object.freeze({
    accessToken,
    tokenType: 'DPoP',
    expiresIn: (exp as number) - (iat as number),
    scope,
    sessionId: session.id,
    expiresAt: session.expiresAt,
  });
}

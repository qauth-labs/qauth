import { drizzle } from 'drizzle-orm/node-postgres';
import type { Pool } from 'pg';
import { describe, expect, it } from 'vitest';

import type { DbClient } from '../db';
import { createApiKeysRepository } from './api-keys.repository';
import { createAuthorizationCodesRepository } from './authorization-codes.repository';
import { createEmailVerificationTokensRepository } from './email-verification-tokens.repository';
import { createOAuthClientsRepository } from './oauth-clients.repository';
import { createOAuthConsentsRepository } from './oauth-consents.repository';
import { createOid4vpRequestStatesRepository } from './oid4vp-request-states.repository';
import { createRefreshTokensRepository } from './refresh-tokens.repository';
import { createSessionsRepository } from './sessions.repository';
import { createUserCredentialsRepository } from './user-credentials.repository';
import { createUsersRepository } from './users.repository';

/**
 * Every repository method that takes an id from outside the database — a
 * request, a token, a code or a cookie — takes the realm the request was
 * resolved to, as a REQUIRED argument, and puts it into the query (ADR-019
 * Decision 1, #489). A row of another realm is then no row: the same answer,
 * from the same single statement, as an unknown id.
 *
 * Two halves: `requiredRealmArgument` does not run, it fails `typecheck` if a
 * method stops requiring the realm; the table below runs every method against
 * a recording client and finds the realm in the statement's `WHERE`.
 */

interface CapturedQuery {
  readonly text: string;
  readonly values: readonly unknown[];
}

/** A `pg` client that records queries instead of running them; every query returns no row. */
function createRecordingDb(): { db: DbClient; queries: CapturedQuery[] } {
  const queries: CapturedQuery[] = [];
  const client = {
    query: (config: { text?: string; values?: unknown[] } | string, values?: unknown[]) => {
      const text = typeof config === 'string' ? config : (config.text ?? '');
      const params = typeof config === 'string' ? (values ?? []) : (config.values ?? values ?? []);
      queries.push({ text, values: params });
      return Promise.resolve({ rows: [], rowCount: 0, fields: [], command: '', oid: 0 });
    },
  };
  return { db: drizzle(client as unknown as Pool) as unknown as DbClient, queries };
}

const REALM_ID = '0190f5a8-7c3e-7d10-8a4b-3c2d1e0f9a8b';
const ID = '0190f5a8-7c3e-7d10-8a4b-3c2d1e0f0001';
const OTHER_ID = '0190f5a8-7c3e-7d10-8a4b-3c2d1e0f0002';
const RESPONSE_CODE = { codeHash: 'c'.repeat(64), codeExpiresAt: 1_800_000_180_000 } as const;

/**
 * Compile-time half: each call below omits the realm and must not compile.
 * An unused `@ts-expect-error` is itself an error, so making a realm argument
 * optional (or dropping it) fails `nx run infra-db:typecheck`. Never called.
 */
export function requiredRealmArgument(db: DbClient): void {
  const users = createUsersRepository(db);
  const clients = createOAuthClientsRepository(db);
  const consents = createOAuthConsentsRepository(db);
  const apiKeys = createApiKeysRepository(db);
  const credentials = createUserCredentialsRepository(db);
  const refreshTokens = createRefreshTokensRepository(db);
  const codes = createAuthorizationCodesRepository(db);
  const verificationTokens = createEmailVerificationTokensRepository(db);
  const sessions = createSessionsRepository(db);
  const walletRequests = createOid4vpRequestStatesRepository(db);

  // @ts-expect-error a user id is looked up in a realm (#489)
  void users.findById(ID);
  // @ts-expect-error a user id is looked up in a realm (#489)
  void users.findByIdOrThrow(ID);
  // @ts-expect-error a user id is looked up in a realm (#489)
  void users.update(ID, {});
  // @ts-expect-error a user id is looked up in a realm (#489)
  void users.updateLastLogin(ID);
  // @ts-expect-error a user id is looked up in a realm (#489)
  void users.delete(ID);

  // @ts-expect-error a client id is looked up in a realm (#489)
  void clients.findById(ID);
  // @ts-expect-error a client id is looked up in a realm (#489)
  void clients.findByIdOrThrow(ID);
  // @ts-expect-error a client id is looked up in a realm (#489)
  void clients.update(ID, {});
  // @ts-expect-error a client id is looked up in a realm (#489)
  void clients.delete(ID);
  // @ts-expect-error a client_id is looked up in a realm
  void clients.findByClientId('client-a');
  // @ts-expect-error a developer's clients are those of a realm (#489)
  void clients.listByDeveloper(ID);
  // @ts-expect-error a developer's clients are those of a realm (#489)
  void clients.countByDeveloper(ID);

  // @ts-expect-error a consent is looked up in a realm (#489)
  void consents.findActive(ID, OTHER_ID);
  // @ts-expect-error a consent is looked up in a realm (#489)
  void consents.findActiveForShare(ID, OTHER_ID, db);
  // @ts-expect-error a user's consents are those of a realm (#489)
  void consents.listActiveForUser(ID);
  // @ts-expect-error a user's consents are those of a realm (#489)
  void consents.listActiveForUserWithClient(ID);
  // @ts-expect-error a consent id is looked up in a realm (#489)
  void consents.revoke(ID);

  // @ts-expect-error an API key is looked up in a realm (#489)
  void apiKeys.findByPrefix('qauth_0123456789abcdef');
  // @ts-expect-error an API key is looked up in a realm (#489)
  void apiKeys.findById(ID);
  // @ts-expect-error a client's API keys are those of a realm (#489)
  void apiKeys.listByClient(ID);
  // @ts-expect-error an API key is looked up in a realm (#489)
  void apiKeys.revoke(ID);

  // @ts-expect-error a credential id is looked up in a realm (#489)
  void credentials.findById(ID);
  // @ts-expect-error a credential is looked up in a realm
  void credentials.findByRealmProviderSub('password', 'alice@example.com');

  // @ts-expect-error a refresh token is looked up in a realm, through its client (#489)
  void refreshTokens.findByTokenHash('a'.repeat(64));
  // @ts-expect-error a refresh token is looked up in a realm, through its client (#489)
  void refreshTokens.findByTokenHashIncludingRevoked('a'.repeat(64));

  // @ts-expect-error an authorization code is looked up in a realm, through its client (#489)
  void codes.findByCode('code');

  // @ts-expect-error a verification token is looked up in a realm, through its credential (#489)
  void verificationTokens.findByTokenHash('a'.repeat(64));

  // @ts-expect-error a browser session is looked up in a realm
  void sessions.findById(ID);

  // @ts-expect-error a wallet's state is redeemed in a realm (#489)
  void walletRequests.redeem('a'.repeat(64), RESPONSE_CODE);
  // @ts-expect-error a wallet's encryption kid is redeemed in a realm (#489)
  void walletRequests.redeemByEncryptionKid('kid', RESPONSE_CODE);
  // @ts-expect-error a Response Code is spent in a realm (#489)
  void walletRequests.redeemResponseCode('c'.repeat(64));
}

/** One method call, made with {@link REALM_ID}; it may reject (no row). */
type RealmScopedCall = readonly [name: string, call: (db: DbClient) => Promise<unknown>];

const CALLS: readonly RealmScopedCall[] = [
  ['users.findById', (db) => createUsersRepository(db).findById(REALM_ID, ID)],
  ['users.findByIdOrThrow', (db) => createUsersRepository(db).findByIdOrThrow(REALM_ID, ID)],
  ['users.update', (db) => createUsersRepository(db).update(REALM_ID, ID, { firstName: 'x' })],
  ['users.updateLastLogin', (db) => createUsersRepository(db).updateLastLogin(REALM_ID, ID)],
  ['users.delete', (db) => createUsersRepository(db).delete(REALM_ID, ID)],
  ['oauthClients.findById', (db) => createOAuthClientsRepository(db).findById(REALM_ID, ID)],
  [
    'oauthClients.findByIdOrThrow',
    (db) => createOAuthClientsRepository(db).findByIdOrThrow(REALM_ID, ID),
  ],
  [
    'oauthClients.update',
    (db) => createOAuthClientsRepository(db).update(REALM_ID, ID, { name: 'x' }),
  ],
  ['oauthClients.delete', (db) => createOAuthClientsRepository(db).delete(REALM_ID, ID)],
  [
    'oauthClients.findByClientId',
    (db) => createOAuthClientsRepository(db).findByClientId(REALM_ID, 'client-a'),
  ],
  [
    'oauthClients.listByDeveloper',
    (db) => createOAuthClientsRepository(db).listByDeveloper(REALM_ID, ID),
  ],
  [
    'oauthClients.countByDeveloper',
    (db) => createOAuthClientsRepository(db).countByDeveloper(REALM_ID, ID),
  ],
  [
    'oauthConsents.findActive',
    (db) => createOAuthConsentsRepository(db).findActive(REALM_ID, ID, OTHER_ID),
  ],
  [
    'oauthConsents.findActiveForShare',
    (db) => createOAuthConsentsRepository(db).findActiveForShare(REALM_ID, ID, OTHER_ID, db),
  ],
  [
    'oauthConsents.listActiveForUser',
    (db) => createOAuthConsentsRepository(db).listActiveForUser(REALM_ID, ID),
  ],
  [
    'oauthConsents.listActiveForUserWithClient',
    (db) => createOAuthConsentsRepository(db).listActiveForUserWithClient(REALM_ID, ID),
  ],
  ['oauthConsents.revoke', (db) => createOAuthConsentsRepository(db).revoke(REALM_ID, ID)],
  [
    'oauthConsents.upsertGrant',
    (db) => createOAuthConsentsRepository(db).upsertGrant(ID, OTHER_ID, REALM_ID, ['a'], [], db),
  ],
  [
    'apiKeys.findByPrefix',
    (db) => createApiKeysRepository(db).findByPrefix(REALM_ID, 'qauth_0123456789abcdef'),
  ],
  ['apiKeys.findById', (db) => createApiKeysRepository(db).findById(REALM_ID, ID)],
  ['apiKeys.listByClient', (db) => createApiKeysRepository(db).listByClient(REALM_ID, ID)],
  ['apiKeys.revoke', (db) => createApiKeysRepository(db).revoke(REALM_ID, ID)],
  ['userCredentials.findById', (db) => createUserCredentialsRepository(db).findById(REALM_ID, ID)],
  [
    'refreshTokens.findByTokenHash',
    (db) => createRefreshTokensRepository(db).findByTokenHash(REALM_ID, 'a'.repeat(64)),
  ],
  [
    'refreshTokens.findByTokenHashIncludingRevoked',
    (db) =>
      createRefreshTokensRepository(db).findByTokenHashIncludingRevoked(REALM_ID, 'a'.repeat(64)),
  ],
  [
    'authorizationCodes.findByCode',
    (db) => createAuthorizationCodesRepository(db).findByCode(REALM_ID, 'code'),
  ],
  [
    'oid4vpRequestStates.redeem',
    (db) => createOid4vpRequestStatesRepository(db).redeem(REALM_ID, 'a'.repeat(64), RESPONSE_CODE),
  ],
  [
    'oid4vpRequestStates.redeemByEncryptionKid',
    (db) =>
      createOid4vpRequestStatesRepository(db).redeemByEncryptionKid(REALM_ID, 'kid', RESPONSE_CODE),
  ],
  [
    'oid4vpRequestStates.redeemResponseCode',
    (db) => createOid4vpRequestStatesRepository(db).redeemResponseCode(REALM_ID, 'c'.repeat(64)),
  ],
  [
    'emailVerificationTokens.findByTokenHash',
    (db) => createEmailVerificationTokensRepository(db).findByTokenHash(REALM_ID, 'a'.repeat(64)),
  ],
];

describe('realm-scoped repository methods (#489)', () => {
  it.each(CALLS)('%s filters every statement on the realm', async (_name, call) => {
    const { db, queries } = createRecordingDb();

    await call(db).catch(() => undefined);

    // An INSERT carries the realm in its row (`upsertGrant` inserts when it
    // finds no active consent); every statement that reads, updates or
    // deletes by id must filter on it.
    const reads = queries.filter((query) => !/^insert /i.test(query.text));
    expect(reads.length).toBeGreaterThan(0);
    for (const query of reads) {
      // `"realm_id" = $n`, with the realm as the n-th parameter: a table
      // with no realm column is filtered through the joined client's or
      // credential's.
      const filters = [...query.text.matchAll(/"realm_id" = \$(\d+)/g)].map(
        (match) => query.values[Number(match[1]) - 1]
      );
      expect(filters, query.text).toContain(REALM_ID);
    }
  });
});

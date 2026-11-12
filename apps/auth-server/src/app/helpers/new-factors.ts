import type { FastifyInstance } from 'fastify';

/**
 * Factors bound after a password-only sign-in (#1064; ADR-017 Decision 8,
 * amended 2026-11-12).
 *
 * A passkey or an authenticator app bound right after a sign-in that proved
 * only the account's password is *new* until `user_credentials.new_until`.
 * While it is new it signs in as usual, but the account's password alone,
 * after a fresh sign-in, may remove it, and it is not the account's strongest
 * factor for a reset or for the fresh authentication a change needs. After
 * the window it is a full factor.
 */

/** One day, in milliseconds. */
const DAY_MS = 86_400_000;

/** The realm row the policy store reads. */
type RealmRow = Parameters<FastifyInstance['policyStore']['ofRealm']>[0];

/**
 * How long a factor bound after a password-only sign-in stays new in
 * `realm`, in milliseconds: the realm row's `accounts.newFactorWindowDays`.
 */
export function newFactorWindowOf(
  fastify: Pick<FastifyInstance, 'policyStore'>,
  realm: RealmRow
): number {
  return fastify.policyStore.ofRealm(realm).policies.accounts.newFactorWindowDays * DAY_MS;
}

/** A credential row's window, as the repositories read it. */
export interface NewFactorRow {
  readonly newUntil?: number | null;
}

/** Whether a stored credential is new at `now`: inside the window its binding opened. */
export function isNewCredential(row: NewFactorRow, now: number): boolean {
  return row.newUntil !== undefined && row.newUntil !== null && now < row.newUntil;
}

/**
 * What kind of authenticator a passkey or an authenticator app is, as the
 * `user.credential_added` and `user.credential_removed` events carry it
 * (#1064), so their CAEP `credential-change` names its `credential_type`:
 * `fido2-platform`, `fido2-roaming` or `app`.
 */
export type CredentialAuthenticator = 'platform' | 'roaming' | 'app';

/**
 * Whether a passkey lives on the device it was made on (`platform`) or on
 * one carried to it (`roaming`), from what the client reported at its
 * registration: an `internal` transport is the device's own authenticator,
 * any other transport a roaming one. A client that reported none leaves only
 * the backup flag: a passkey that may be synced is a platform's.
 */
export function passkeyAuthenticatorOf(data: {
  readonly transports: readonly string[];
  readonly backup_eligible: boolean;
}): 'platform' | 'roaming' {
  if (data.transports.includes('internal')) return 'platform';
  if (data.transports.length > 0) return 'roaming';
  return data.backup_eligible ? 'platform' : 'roaming';
}

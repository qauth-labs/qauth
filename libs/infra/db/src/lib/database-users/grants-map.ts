import type { TablePrivilege } from '../role-grants';
import type { DatabaseRole } from './roles';

/**
 * THE GRANTS MAP (ADR-019 Decisions 8 and 9, issue #498): for each table,
 * which service role's database user may `SELECT`, `INSERT`, `UPDATE` or
 * `DELETE` it. A role a table does not name holds nothing on it.
 *
 * Each role gets what its code runs: the repositories the auth server builds
 * for it (`repositoriesFor` in `apps/auth-server/src/app/service-roles.ts`),
 * the boot steps it runs, its jobs, and the signer's own key store. The
 * container suite `apps/auth-server/src/app/database-users.integration.test.ts`
 * runs each role's routes and jobs as its user and fails on a permission
 * error. A privilege a
 * repository method needs only through `RETURNING`, `ON CONFLICT`, a lock
 * (`FOR UPDATE`) or a trigger counts as needed.
 *
 * What the map keeps from a role, on purpose:
 *
 * - `realm_keys`, the private keys: only `signer` reads or writes it. Every
 *   other role verifies with `realm_public_keys`, which it may only read;
 *   only `signer` writes a published key.
 * - `events`: the roles that write events (`web`, `api`, and `admin` for the
 *   events of an admin operation, such as `user.verified`) may only insert,
 *   and read what they need through the functions of migrations 0033 and
 *   0055, never the table: it holds every realm's request IPs, user agents
 *   and admin diffs (`eventsWriterGrantStatements`).
 * - `delivery` gets its outbox and nothing beyond it (ADR-019 Decision 8):
 *   the event store, its queue and the columns that say where an event goes
 *   (`eventDeliveryGrantStatements`), and, since the retention job runs on
 *   it, what that job deletes (`eventRetentionGrantStatements`). It runs no
 *   default realm boot step, so it never writes `realms`.
 * - `admin_grants`, who administers: every role that reads it only reads it.
 * - `audit_logs`: read-only since #458, and nothing reads it at run time, so
 *   no role holds anything on it; `roles` and `user_roles` are unused.
 * - No role holds `TRUNCATE`, `REFERENCES` or `TRIGGER`, owns a table, or can
 *   create one: only the migration runner's user, the owner, changes the
 *   schema.
 *
 * `web`, `api`, `admin` and `signer` each run the default realm's boot step
 * (#484), which creates the realm on a fresh database, adds its hosts and
 * seeds its policies, so each may insert and update `realms` and insert
 * `realm_hosts`. No role deletes either.
 */

/** For each table, the privileges each role holds on it. */
export type TableGrants = Readonly<
  Record<string, Readonly<Partial<Record<DatabaseRole, readonly TablePrivilege[]>>>>
>;

/**
 * For each table, the columns each role may read, where it holds no
 * table-wide `SELECT` on it.
 */
export type ColumnGrants = Readonly<
  Record<string, Readonly<Partial<Record<DatabaseRole, readonly string[]>>>>
>;

/**
 * For each function a migration took `EXECUTE` from `PUBLIC` on, the roles
 * that may execute it, by the signature `GRANT` spells.
 */
export type FunctionGrants = Readonly<Record<string, readonly DatabaseRole[]>>;

/** The whole map. */
export interface DatabaseGrantsMap {
  readonly tables: TableGrants;
  readonly columns: ColumnGrants;
  readonly functions: FunctionGrants;
}

const S: readonly TablePrivilege[] = Object.freeze(['SELECT']);
const SI: readonly TablePrivilege[] = Object.freeze(['SELECT', 'INSERT']);
const SD: readonly TablePrivilege[] = Object.freeze(['SELECT', 'DELETE']);
const SIU: readonly TablePrivilege[] = Object.freeze(['SELECT', 'INSERT', 'UPDATE']);
const SID: readonly TablePrivilege[] = Object.freeze(['SELECT', 'INSERT', 'DELETE']);
const SIUD: readonly TablePrivilege[] = Object.freeze(['SELECT', 'INSERT', 'UPDATE', 'DELETE']);
const I: readonly TablePrivilege[] = Object.freeze(['INSERT']);

/** Every table of the schema, in name order, with the roles that hold anything on it. */
export const TABLE_GRANTS: TableGrants = Object.freeze({
  // Approval requests for security operations (#512): filed, approved,
  // consumed and expired on the admin listener.
  admin_approvals: { admin: SIU },
  // The admin audit log (#448): appended in the admin pipeline's
  // transaction; its trigger reads the chain head and the checkpoints.
  admin_audit_log: { admin: SI },
  admin_audit_log_checkpoints: { admin: S },
  // Who administers (#510): read on every admin request and at sign-in and
  // token issuance, written by no role yet.
  admin_grants: { web: S, api: S, admin: S },
  admin_roles: { web: S, api: S, admin: S },
  // The developer API's client API keys.
  api_keys: { api: SIU },
  // Read-only since #458 and read by nothing at run time.
  audit_logs: {},
  // Only the purge job, on `api`, deletes the expired rows of the four
  // short-lived token tables (`purge-expired.ts`).
  authorization_codes: { web: SIU, api: SIUD },
  email_verification_tokens: { web: SIU, api: SIUD },
  // The retention job's anchor of each realm's admin chain (#536).
  event_chain_anchors: { delivery: SIU },
  // The delivery queue (#460). `api` enqueues the SSF verification event for
  // a stream and reads a stream's delivery status.
  event_deliveries: { api: SI, delivery: SIU },
  event_delivery_positions: { delivery: SIUD },
  // The event store (#457): written by `web` and `api`, and by `admin` for
  // the events its operations record (`user.verified`, #1052); read and
  // pruned by `delivery` alone.
  events: { web: I, api: I, admin: I, delivery: SD },
  // `web` stores CIMD clients as it fetches their documents; `api` also
  // registers, updates and deletes clients. `delivery` reads columns only.
  oauth_clients: { web: SIU, api: SIUD },
  oauth_consents: { web: SIU, api: SIU },
  oid4vp_request_states: { web: SIU, api: SIUD },
  // Each realm's AuthMethod plugins (#600): enabled and configured by admin.
  realm_auth_method_plugins: { web: S, admin: SIU },
  realm_hosts: { web: SI, api: SI, admin: SI, signer: SI },
  // The private keys, wrapped under the KEK: the signer's alone.
  realm_keys: { signer: SIUD },
  // The published keys: every role verifies with them; only the signer
  // publishes. A key's deletion removes its row through the foreign key.
  realm_public_keys: { web: S, api: S, admin: S, signer: SIU, delivery: S },
  // The realms' secret policy values, as ciphertext (#529): the signer seeds
  // them, admin writes them, `api`'s mail sender reads them.
  realm_secrets: { api: S, admin: SIU, signer: SIU },
  // Each realm's generic upstream OIDC providers (#639): `web` lists them on
  // the sign-in pages and loads one at the upstream callback; `admin` adds,
  // changes and removes them (#714). `api` serves no sign-in page and reads
  // none, so it holds nothing.
  realm_upstream_providers: { web: S, admin: SIUD },
  realms: { web: SIU, api: SIU, admin: SIU, signer: SIU },
  refresh_tokens: { web: SIU, api: SIUD },
  roles: {},
  session_clients: { web: SID, api: SID },
  // Only the session purge, on `web`, deletes a session (`session-purge.ts`).
  sessions: { web: SIUD, api: SIU },
  // The SSF streams (#410): managed on `api`, read by the delivery route.
  ssf_stream_subjects: { api: SID },
  ssf_streams: { api: SIUD, delivery: S },
  user_attributes: { web: SIU, api: SIU },
  // `admin` reads nothing of it: what `users.verify` shows of an account's
  // credentials comes through `user_credential_proofs` (#1052).
  user_credentials: { web: SIU, api: SIU },
  // Each account's recovery codes (#649): the sign-in engine, on `web`,
  // reads an account's codes, takes one (an `UPDATE … WHERE used_at IS NULL`)
  // and replaces a set (a `DELETE` and an `INSERT` in one transaction) when
  // it shows a new one. Nothing else touches them yet; the account console's
  // regeneration (#687) adds `api`.
  user_recovery_codes: { web: SIUD },
  // The actions a user must take at the next sign-in (#635): the sign-in
  // engine, on `web`, reads and deletes a user's rows; `api` (the account
  // console's "this wasn't me") and `admin` (an admin's request) add them.
  // `SELECT` stays with `INSERT` for the `RETURNING` of the write. Nothing
  // updates a row.
  user_required_actions: { web: SID, api: SI, admin: SI },
  user_roles: {},
  // Each user's session epoch (#642): the owner's password reset, on `web`,
  // advances it (an upsert: `INSERT … ON CONFLICT DO UPDATE`), and the
  // browser-session lookup and the sign-in engine, on `web`, read it. Nothing
  // deletes a row but the user's or the realm's cascade.
  user_session_epochs: { web: SIU },
  // `api` creates accounts; `web` and `api` record sign-ins; `admin` finds
  // the account behind an admin token, and records an operator's
  // verification of one only through `users_record_operator_verification`
  // (`users.verify`, #1052). No role deletes one.
  users: { web: SIU, api: SIU, admin: S },
});

/**
 * The columns `delivery` reads of tables it may not read whole: whether a
 * stream may receive events and where its subjects point, and a client's
 * back-channel logout metadata (`EVENT_DELIVERY_COLUMNS`), and each realm's
 * event retention
 * (`EVENT_RETENTION_REALM_COLUMNS`).
 */
export const COLUMN_GRANTS: ColumnGrants = Object.freeze({
  oauth_clients: {
    delivery: [
      'id',
      'enabled',
      'suspended',
      'scopes',
      'realm_id',
      'client_id',
      'backchannel_logout_uri',
      'backchannel_logout_uri_source',
      'backchannel_logout_session_required',
    ],
  },
  realms: {
    delivery: [
      'id',
      'ssf_transmitter_enabled',
      'issuer',
      'name',
      'user_event_retention_days',
      'admin_event_retention_days',
    ],
  },
  ssf_stream_subjects: { delivery: ['stream_id', 'event_subject_type', 'event_subject_id'] },
});

/** The functions a migration took from PUBLIC, and the roles that execute them. */
export const FUNCTION_GRANTS: FunctionGrants = Object.freeze({
  // An admin event's chain head and the row the writer's own transaction
  // wrote (migration 0033): the event writers.
  '"events_admin_chain_head"(uuid)': ['web', 'api', 'admin'],
  '"events_own_row"(uuid)': ['web', 'api', 'admin'],
  // The event store's lag, which every process that builds the events
  // repository reports on its metrics: `admin` builds it too since it writes
  // the events of its operations (#1052).
  '"events_oldest_unread_time"()': ['web', 'api', 'admin', 'delivery'],
  // An operator's verification of an account (`users.verify`, migration
  // 0070, #1052): what the account's credentials prove, read without their
  // secrets, and the write of the verification's two columns alone.
  '"user_credential_proofs"(uuid, uuid)': ['admin'],
  '"users_record_operator_verification"(uuid, uuid, uuid, bigint)': ['admin'],
  // Whether an event about a user can still reach an SSF stream (migration
  // 0055): the subject sweep, an `api` job.
  '"ssf_subject_events_pending"(uuid, text)': ['api'],
  // The admin audit log's prune and the admin chain's trigger function stay
  // with the owner: no role runs them.
});

/** The map {@link databaseUserGrantStatements} applies. */
export const DATABASE_GRANTS: DatabaseGrantsMap = Object.freeze({
  tables: TABLE_GRANTS,
  columns: COLUMN_GRANTS,
  functions: FUNCTION_GRANTS,
});

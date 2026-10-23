import type { RegisteredEventType } from './registry';

/**
 * Today's event names, mapped to the registered types (#456). Before the
 * event contract, events were free strings: `audit_logs.event`, written by
 * `auditLogs.create` in `apps/auth-server/src` and by the client-suspension
 * script in `libs/infra/db`, and the log-only names of `logAuthEvent`. The
 * backfill of EVT-03 (#458) copies audit rows into the event store with this
 * map.
 *
 * Several old strings map to one type: the old names said which route or
 * page an event came from (`ui.login.*` beside `user.login.*`); a type says
 * what happened, and `data` carries the rest. `data` here holds the members
 * the old string alone implies, which the backfill sets on every copied row.
 */
export interface LegacyEventMapping {
  /** The old name, as `audit_logs.event` or `logAuthEvent` has it. */
  readonly event: string;
  /** The registered type it becomes. */
  readonly type: RegisteredEventType;
  /** The `data` members the old name implies. */
  readonly data?: Readonly<Record<string, string>>;
  /** Where the old name was written: an audit row, or only a log line. */
  readonly source: 'audit' | 'log';
}

export const LEGACY_EVENT_MAP: readonly LegacyEventMapping[] = [
  // Sign-in, through the JSON API, the hosted page and a wallet.
  {
    event: 'user.login.success',
    type: 'urn:qauth:event:user.signed_in:v1-rc.0',
    data: { method: 'password' },
    source: 'audit',
  },
  {
    event: 'user.login.failure',
    type: 'urn:qauth:event:user.sign_in_failed:v1-rc.0',
    data: { method: 'password' },
    source: 'audit',
  },
  {
    event: 'ui.login.success',
    type: 'urn:qauth:event:user.signed_in:v1-rc.0',
    data: { method: 'password' },
    source: 'audit',
  },
  {
    event: 'ui.login.failure',
    type: 'urn:qauth:event:user.sign_in_failed:v1-rc.0',
    data: { method: 'password' },
    source: 'audit',
  },
  {
    event: 'ui.login.csrf_failure',
    type: 'urn:qauth:event:request.csrf_rejected:v1-rc.0',
    data: { form: 'sign_in' },
    source: 'audit',
  },
  {
    event: 'ui.wallet_login.success',
    type: 'urn:qauth:event:user.signed_in:v1-rc.0',
    data: { method: 'wallet' },
    source: 'audit',
  },
  {
    event: 'ui.wallet_login.failure',
    type: 'urn:qauth:event:user.sign_in_failed:v1-rc.0',
    data: { method: 'wallet' },
    source: 'audit',
  },
  {
    event: 'ui.wallet_login.csrf_failure',
    type: 'urn:qauth:event:request.csrf_rejected:v1-rc.0',
    data: { form: 'wallet_sign_in' },
    source: 'audit',
  },

  // Sign-out and registration.
  {
    event: 'user.logout.success',
    type: 'urn:qauth:event:user.signed_out:v1-rc.0',
    source: 'audit',
  },
  {
    event: 'user.logout.failure',
    type: 'urn:qauth:event:user.sign_out_failed:v1-rc.0',
    source: 'audit',
  },
  {
    event: 'user.register.success',
    type: 'urn:qauth:event:user.registered:v1-rc.0',
    data: { method: 'password' },
    source: 'log',
  },
  {
    event: 'user.register.failure',
    type: 'urn:qauth:event:user.registration_failed:v1-rc.0',
    source: 'log',
  },

  // The authorization endpoint, consent and step-up.
  {
    event: 'oauth.authorize.success',
    type: 'urn:qauth:event:authorization.completed:v1-rc.0',
    source: 'audit',
  },
  {
    event: 'oauth.authorize.failure',
    type: 'urn:qauth:event:authorization.failed:v1-rc.0',
    source: 'audit',
  },
  {
    event: 'oauth.stepup.required',
    type: 'urn:qauth:event:step_up.required:v1-rc.0',
    source: 'audit',
  },
  {
    event: 'oauth.stepup.elevation',
    type: 'urn:qauth:event:step_up.elevated:v1-rc.0',
    source: 'audit',
  },
  {
    event: 'oauth.consent.granted',
    type: 'urn:qauth:event:consent.granted:v1-rc.0',
    source: 'audit',
  },
  {
    event: 'oauth.consent.denied',
    type: 'urn:qauth:event:consent.denied:v1-rc.0',
    source: 'audit',
  },
  {
    event: 'oauth.consent.revoked',
    type: 'urn:qauth:event:consent.revoked:v1-rc.0',
    source: 'audit',
  },
  {
    event: 'oauth.consent.csrf_failure',
    type: 'urn:qauth:event:request.csrf_rejected:v1-rc.0',
    data: { form: 'consent' },
    source: 'audit',
  },
  {
    event: 'consents.revoke.csrf_failure',
    type: 'urn:qauth:event:request.csrf_rejected:v1-rc.0',
    data: { form: 'consent_revocation' },
    source: 'audit',
  },

  // The token, revocation, introspection and userinfo endpoints.
  {
    event: 'oauth.token.exchange.success',
    type: 'urn:qauth:event:token.issued:v1-rc.0',
    source: 'audit',
  },
  {
    event: 'oauth.token.exchange.failure',
    type: 'urn:qauth:event:token.request_failed:v1-rc.0',
    source: 'audit',
  },
  { event: 'oauth.revoke.success', type: 'urn:qauth:event:token.revoked:v1-rc.0', source: 'audit' },
  {
    event: 'oauth.revoke.failure',
    type: 'urn:qauth:event:token.revocation_failed:v1-rc.0',
    source: 'audit',
  },
  {
    event: 'oauth.introspect.success',
    type: 'urn:qauth:event:token.introspected:v1-rc.0',
    source: 'audit',
  },
  {
    event: 'oauth.introspect.failure',
    type: 'urn:qauth:event:token.introspection_failed:v1-rc.0',
    source: 'audit',
  },
  {
    event: 'oauth.userinfo.success',
    type: 'urn:qauth:event:userinfo.served:v1-rc.0',
    source: 'audit',
  },
  {
    event: 'oauth.userinfo.failure',
    type: 'urn:qauth:event:userinfo.request_failed:v1-rc.0',
    source: 'audit',
  },

  // Clients and API keys.
  {
    event: 'oauth.client.registered',
    type: 'urn:qauth:event:client.created:v1-rc.0',
    data: { registration: 'dynamic' },
    source: 'audit',
  },
  {
    event: 'oauth.client.created',
    type: 'urn:qauth:event:client.created:v1-rc.0',
    data: { registration: 'developer_api' },
    source: 'audit',
  },
  {
    event: 'oauth.client.updated',
    type: 'urn:qauth:event:client.updated:v1-rc.0',
    source: 'audit',
  },
  {
    event: 'oauth.client.deleted',
    type: 'urn:qauth:event:client.deleted:v1-rc.0',
    source: 'audit',
  },
  {
    event: 'oauth.client.secret_regenerated',
    type: 'urn:qauth:event:client.secret_rotated:v1-rc.0',
    source: 'audit',
  },
  {
    event: 'oauth.client.suspended',
    type: 'urn:qauth:event:client.suspended:v1-rc.0',
    source: 'audit',
  },
  {
    event: 'oauth.client.suspension_lifted',
    type: 'urn:qauth:event:client.suspension_lifted:v1-rc.0',
    source: 'audit',
  },
  { event: 'api_key.created', type: 'urn:qauth:event:api_key.created:v1-rc.0', source: 'audit' },
  { event: 'api_key.revoked', type: 'urn:qauth:event:api_key.revoked:v1-rc.0', source: 'audit' },

  // Wallet federation.
  {
    event: 'auth.wallet_link.success',
    type: 'urn:qauth:event:wallet.linked:v1-rc.0',
    source: 'audit',
  },
  {
    event: 'auth.wallet_link.failure',
    type: 'urn:qauth:event:wallet.link_failed:v1-rc.0',
    source: 'audit',
  },
  {
    event: 'auth.wallet_link.csrf_failure',
    type: 'urn:qauth:event:request.csrf_rejected:v1-rc.0',
    data: { form: 'wallet_link' },
    source: 'audit',
  },
  {
    event: 'oid4vp.response.received',
    type: 'urn:qauth:event:wallet.presentation_received:v1-rc.0',
    source: 'audit',
  },
];

const BY_EVENT: ReadonlyMap<string, LegacyEventMapping> = new Map(
  LEGACY_EVENT_MAP.map((mapping) => [mapping.event, mapping])
);

/** The mapping of one old event name, or `undefined` when the name is unknown. */
export function legacyEventMapping(event: string): LegacyEventMapping | undefined {
  return BY_EVENT.get(event);
}

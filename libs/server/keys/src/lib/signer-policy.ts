import type { SignerOperation } from './signer';
import { JWS_SIGNING_PURPOSES, type JwsSigningPurpose } from './signer-typ';

/**
 * Who may call which signer operation (ADR-019 Decision 9, issue #464).
 *
 * Every call to the signer names the role it is made for. In a single
 * deployment the code that calls it says so; the remote signer (#497) takes
 * the role from the caller's client certificate instead, and never accepts
 * `local` from a peer.
 */

/**
 * The roles that call the signer.
 *
 * - `local` — a caller inside the signer's own process. In a single deployment
 *   every role shares one process and one trust domain (ADR-019 Decision 9),
 *   so `local` may call every operation.
 * - `web` — the browser-facing role: authorize, the ceremony UI, end-session.
 * - `api` — the API role: token, introspection, revocation, userinfo.
 * - `delivery` — the role that sends events and webhooks (ADR-019 Decision 8).
 * - `admin` — the admin API.
 *
 * The names follow the deployment roles of `SERVICE_ROLES` (#495); `signer`
 * itself never calls the signer.
 */
export const SIGNER_CALLERS = Object.freeze(['local', 'web', 'api', 'delivery', 'admin'] as const);

/** A role that calls the signer. See {@link SIGNER_CALLERS}. */
export type SignerCaller = (typeof SIGNER_CALLERS)[number];

/** What one role may call. */
export interface SignerGrant {
  /** The purposes the role may sign with through `signJws`. */
  readonly signJws: readonly JwsSigningPurpose[];
  readonly signHybrid: boolean;
  readonly signWebhook: boolean;
  readonly signClientAssertion: boolean;
  readonly getCookieSecrets: boolean;
  readonly encrypt: boolean;
  /**
   * `true`: any `data_at_rest` ciphertext. A list: only ciphertexts whose
   * `context` starts with one of these prefixes, so a role that needs one kind
   * of stored secret cannot decrypt the others.
   */
  readonly decrypt: boolean | readonly string[];
  readonly getVerificationKeys: boolean;
  readonly getJwks: boolean;
  readonly getUpstreamJwks: boolean;
}

/** Public keys only: what every role may read. */
const PUBLIC_READS = { getVerificationKeys: true, getJwks: true, getUpstreamJwks: true } as const;

/**
 * The `context` prefix of a secret a delivery destination stores, such as an
 * SSF receiver's `Authorization` header (#410): the only `data_at_rest`
 * ciphertexts the `delivery` role may decrypt. Any other stored secret must
 * use a context outside it.
 */
export const DELIVERY_SECRET_CONTEXT_PREFIX = 'delivery:';

/**
 * The `context` prefix of a realm's mail transport secret, the SMTP password
 * or the Resend API key (`realm_secrets:mail.<field>`, #529): one of the two
 * kinds of `data_at_rest` ciphertext the `api` role may decrypt, for the
 * realm's mail sender. `@qauth-labs/server-realm-policy` makes the context
 * (`realmSecretContext`); this library may not import it, so both pin the
 * string in their tests.
 */
export const REALM_MAIL_SECRET_CONTEXT_PREFIX = 'realm_secrets:mail.';

/**
 * The `context` prefix of an upstream OpenID Provider's client secret
 * (`upstream-oidc:client-secret:<realm id>:<provider type>:<destination>`,
 * #601): the other kind of `data_at_rest` ciphertext the `api` role may
 * decrypt, so the host can open a provider's stored config for the code
 * exchange, as it already signs that provider's client assertions (#547).
 * `@qauth-labs/server-upstream-oidc` builds its contexts from this constant.
 */
export const UPSTREAM_CLIENT_SECRET_CONTEXT_PREFIX = 'upstream-oidc:client-secret:';

const NOTHING_ELSE = {
  signJws: [],
  signHybrid: false,
  signWebhook: false,
  signClientAssertion: false,
  getCookieSecrets: false,
  encrypt: false,
  decrypt: false,
} as const;

/**
 * The policy table: what each role may call.
 *
 * - `web` gets the cookie HMAC secrets, the one secret ADR-019 Decision 9 hands
 *   to a role outside the signer. It never signs a token.
 * - `api` signs access and ID tokens (`token_signing`, hybrid included), signs
 *   client assertions toward upstream providers (#547), and encrypts with the
 *   `data_at_rest` key. It decrypts only two kinds of stored secret: a realm's
 *   mail transport secret ({@link REALM_MAIL_SECRET_CONTEXT_PREFIX}), which
 *   its mail sender sends with (#529), and an upstream provider's client
 *   secret ({@link UPSTREAM_CLIENT_SECRET_CONTEXT_PREFIX}), which the code
 *   exchange with that provider sends (#601). Nothing else of the role
 *   decrypts.
 * - `delivery` signs Security Event Tokens and logout tokens
 *   (`event_signing`) and webhook messages (#547). It holds no secret: it
 *   sends the message to the signer and gets the signature header back. It
 *   may decrypt, never encrypt, and only a ciphertext whose `context` starts
 *   with {@link DELIVERY_SECRET_CONTEXT_PREFIX}: a destination's secret, such
 *   as an SSF receiver's `Authorization` header that the api role stored
 *   encrypted and that each push sends (#410).
 * - `admin` reads public keys. The key operations of the admin API (rotation
 *   and retirement, #544 and #551) add their own grants.
 * - Every role may read the realm's public keys, which hold no secret.
 *
 * A role that is not in this table may call nothing.
 */
export const SIGNER_POLICY: Readonly<Record<SignerCaller, SignerGrant>> = freezePolicy({
  local: {
    signJws: JWS_SIGNING_PURPOSES,
    signHybrid: true,
    signWebhook: true,
    signClientAssertion: true,
    getCookieSecrets: true,
    encrypt: true,
    decrypt: true,
    ...PUBLIC_READS,
  },
  web: { ...NOTHING_ELSE, getCookieSecrets: true, ...PUBLIC_READS },
  api: {
    ...NOTHING_ELSE,
    signJws: ['token_signing'],
    signHybrid: true,
    signClientAssertion: true,
    encrypt: true,
    decrypt: [REALM_MAIL_SECRET_CONTEXT_PREFIX, UPSTREAM_CLIENT_SECRET_CONTEXT_PREFIX],
    ...PUBLIC_READS,
  },
  delivery: {
    ...NOTHING_ELSE,
    signJws: ['event_signing'],
    signWebhook: true,
    decrypt: [DELIVERY_SECRET_CONTEXT_PREFIX],
    ...PUBLIC_READS,
  },
  admin: { ...NOTHING_ELSE, ...PUBLIC_READS },
});

function freezePolicy(
  policy: Record<SignerCaller, SignerGrant>
): Readonly<Record<SignerCaller, SignerGrant>> {
  for (const grant of Object.values(policy)) {
    Object.freeze(grant.signJws);
    if (Array.isArray(grant.decrypt)) Object.freeze(grant.decrypt);
    Object.freeze(grant);
  }
  return Object.freeze(policy);
}

/** Whether `value` is a role in {@link SIGNER_CALLERS}. */
export function isSignerCaller(value: unknown): value is SignerCaller {
  return typeof value === 'string' && (SIGNER_CALLERS as readonly string[]).includes(value);
}

/**
 * Whether `caller` may call `operation`. For `signJws`, `detail` names the
 * purpose to sign with, and the call is allowed only when the role's grant
 * lists it. For `decrypt`, `detail` is the ciphertext's `context`: a role
 * whose grant is a list of prefixes may decrypt only a context that starts
 * with one of them, and is refused when none is given. An unknown role,
 * operation or purpose is never allowed.
 */
export function isSignerCallAllowed(
  caller: unknown,
  operation: SignerOperation,
  detail?: string
): boolean {
  if (!isSignerCaller(caller)) return false;
  const grant: SignerGrant = SIGNER_POLICY[caller];
  if (!Object.hasOwn(grant, operation)) return false;
  if (operation === 'signJws') {
    return detail !== undefined && (grant.signJws as readonly string[]).includes(detail);
  }
  if (operation === 'decrypt' && Array.isArray(grant.decrypt)) {
    const context = detail;
    return (
      context !== undefined &&
      (grant.decrypt as readonly string[]).some((prefix) => context.startsWith(prefix))
    );
  }
  return grant[operation] === true;
}

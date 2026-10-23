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
  readonly getCookieSecrets: boolean;
  readonly encrypt: boolean;
  readonly decrypt: boolean;
  readonly getVerificationKeys: boolean;
  readonly getJwks: boolean;
}

/** Public keys only: what every role may read. */
const PUBLIC_READS = { getVerificationKeys: true, getJwks: true } as const;

const NOTHING_ELSE = {
  signJws: [],
  signHybrid: false,
  getCookieSecrets: false,
  encrypt: false,
  decrypt: false,
} as const;

/**
 * The policy table: what each role may call.
 *
 * - `web` gets the cookie HMAC secrets, the one secret ADR-019 Decision 9 hands
 *   to a role outside the signer. It never signs a token.
 * - `api` signs access and ID tokens (`token_signing`, hybrid included) and
 *   uses the `data_at_rest` key.
 * - `delivery` signs Security Event Tokens and logout tokens
 *   (`event_signing`). Webhook signing joins it with #547.
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
    encrypt: true,
    decrypt: true,
    ...PUBLIC_READS,
  },
  delivery: { ...NOTHING_ELSE, signJws: ['event_signing'], ...PUBLIC_READS },
  admin: { ...NOTHING_ELSE, ...PUBLIC_READS },
});

function freezePolicy(
  policy: Record<SignerCaller, SignerGrant>
): Readonly<Record<SignerCaller, SignerGrant>> {
  for (const grant of Object.values(policy)) {
    Object.freeze(grant.signJws);
    Object.freeze(grant);
  }
  return Object.freeze(policy);
}

/** Whether `value` is a role in {@link SIGNER_CALLERS}. */
export function isSignerCaller(value: unknown): value is SignerCaller {
  return typeof value === 'string' && (SIGNER_CALLERS as readonly string[]).includes(value);
}

/**
 * Whether `caller` may call `operation`. For `signJws`, `purpose` names the
 * purpose to sign with, and the call is allowed only when the role's grant
 * lists it. An unknown role, operation or purpose is never allowed.
 */
export function isSignerCallAllowed(
  caller: unknown,
  operation: SignerOperation,
  purpose?: string
): boolean {
  if (!isSignerCaller(caller)) return false;
  const grant: SignerGrant = SIGNER_POLICY[caller];
  if (!Object.hasOwn(grant, operation)) return false;
  if (operation === 'signJws') {
    return purpose !== undefined && (grant.signJws as readonly string[]).includes(purpose);
  }
  return grant[operation] === true;
}

/**
 * The versioned names of the account API v1 contract (ADR-019 Decision 7,
 * ADR-018 §5).
 *
 * The account API is one of the three API families. Its path prefix and its
 * token audience carry the same release candidate: until QAuth 1.0.0 the API
 * is served at `/account/v1-rc.<M>` to tokens whose only audience is
 * `urn:qauth:aud:account:v1-rc.<M>`, and a breaking change before 1.0.0
 * raises `<M>` for both. The release that ships 1.0.0 drops the suffix. The
 * auth server's own table (`apps/auth-server/src/app/api-conventions/families.ts`)
 * holds the same two values; a test there keeps them equal.
 */

/** The major version and its release-candidate number. */
export const ACCOUNT_API_MAJOR = 1;
export const ACCOUNT_API_RC = 0;

/** `v1-rc.0`: the version label of the path, the audience and the published files. */
export const ACCOUNT_API_VERSION = `v${ACCOUNT_API_MAJOR}-rc.${ACCOUNT_API_RC}` as const;

/** The path prefix every operation of this version is served under. */
export const ACCOUNT_API_PREFIX = `/account/${ACCOUNT_API_VERSION}`;

/** The only audience a token for this version may carry. */
export const ACCOUNT_API_AUDIENCE = `urn:qauth:aud:account:${ACCOUNT_API_VERSION}`;

/**
 * The scopes of the account API (#933), one per operation class: an operation
 * whose `x-qauth-class` is `read` needs `qauth:account:read`, one whose class
 * is `write` needs `qauth:account:write`. The two are independent: the write
 * scope does not reach a read. They sit in QAuth's reserved `qauth:` scope
 * namespace and carry no version: the audience does. The auth server's table
 * (`API_FAMILY_SCOPES` in `apps/auth-server/src/app/api-conventions/families.ts`)
 * holds the same values; a test there keeps them equal.
 */
export const ACCOUNT_API_SCOPES = Object.freeze({
  read: 'qauth:account:read',
  write: 'qauth:account:write',
} as const);

/**
 * How old a sign-in may be, in seconds, for an operation that needs fresh
 * authentication (ADR-017 Decision 8: "at most 5 minutes old").
 */
export const FRESH_AUTHENTICATION_MAX_AGE_SECONDS = 300;

/**
 * What an operation needs of the sign-in behind the token, as its
 * `x-qauth-fresh-authentication` says:
 *
 * - `none`: any sign-in the token's guard accepts;
 * - `strongest-factor`: a sign-in at most
 *   {@link FRESH_AUTHENTICATION_MAX_AGE_SECONDS} old (`auth_time`) whose `amr`
 *   holds the account's strongest bound factor: `pop` when a passkey is bound,
 *   else `otp` when TOTP is, else `pwd` (ADR-017 Decision 8, #663);
 * - `strongest-factor-or-recovery-code`: the same, or a sign-in of the same
 *   age that used a recovery code in place of a lost second factor. Only the
 *   operations that bind a new second factor after a lost one take it; a
 *   recovery code adds no `amr` value, so the guard finds it through the
 *   token's `sid`.
 */
export const FRESH_AUTHENTICATION_RULES = [
  'none',
  'strongest-factor',
  'strongest-factor-or-recovery-code',
] as const;

export type FreshAuthenticationRule = (typeof FRESH_AUTHENTICATION_RULES)[number];

/**
 * Whether an operation takes an act-chain token (RFC 8693 `act`), as its
 * `x-qauth-act-chain` says. ADR-019 Decision 7: an act-chain token never
 * counts as the person's fresh authentication, and the account API refuses it
 * on every operation that changes a credential, an identifier, the contact
 * address or a linked account, and on account deletion.
 */
export const ACT_CHAIN_RULES = ['accepted', 'refused'] as const;

export type ActChainRule = (typeof ACT_CHAIN_RULES)[number];

/** Where the docs site publishes the contract's document, from the site root. */
export const CONTRACT_SITE_PATH = `/account/${ACCOUNT_API_VERSION}/`;

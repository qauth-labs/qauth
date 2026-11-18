/**
 * What the signer lets the `admin` role have signed as an access token: an
 * act-chain token, and nothing else (ADR-019 Decision 7, issue #523).
 *
 * An admin who acts for a user gets an act-chain token: `sub` is the user,
 * `act` names the admin. The admin API mints it in the transaction of the
 * approved security operation that issues it, so the `admin` role asks the
 * signer for an access token of the `token_signing` key. That key signs every
 * access token of the realm, so the signer, not the role, holds what the role
 * asks for to the act-chain profile:
 *
 * - **Only these claims** ({@link ACT_CHAIN_TOKEN_CLAIMS}), besides the `iss`
 *   the signer adds: no `auth_time`, `amr` or `sid`, since an act-chain token
 *   never counts as the user's sign-in, and no claim an ID token or another
 *   grant carries.
 * - **The account API's audience alone**, {@link ACT_CHAIN_TOKEN_AUDIENCE}, as
 *   a single string, and **only account API scopes**
 *   ({@link ACT_CHAIN_TOKEN_SCOPES}).
 * - **One actor**: `act` holds the admin's `sub`, `iss` and `client_id` and no
 *   nested actor, and its `client_id` is the token's.
 * - **DPoP-bound**: `cnf` holds a `jkt` and nothing else.
 * - **Short-lived**: `iat` near the signer's clock and `exp` at most
 *   {@link ACT_CHAIN_TOKEN_MAX_LIFETIME_SECONDS} after it.
 *
 * So a node of the `admin` role, whatever its code does, has the signer sign
 * no token that a resource server, the token endpoint or a relying party
 * takes for an ordinary access token or for a sign-in of the user. Whether a
 * particular admin may act for a particular user is the auth server's
 * approval and the account API's per-call check, not the signer's.
 *
 * The audience and the scopes copy the auth server's account API values
 * (`apps/auth-server/src/app/api-conventions/families.ts`), which this
 * library cannot import; a test there keeps them equal.
 */

/** The account API's audience: the one `aud` an act-chain token carries. */
export const ACT_CHAIN_TOKEN_AUDIENCE = 'urn:qauth:aud:account:v1-rc.0';

/** The scopes an act-chain token may carry: the account API's. */
export const ACT_CHAIN_TOKEN_SCOPES: readonly string[] = Object.freeze([
  'qauth:account:read',
  'qauth:account:write',
]);

/** The longest an act-chain token may live, in seconds: ten minutes. */
export const ACT_CHAIN_TOKEN_MAX_LIFETIME_SECONDS = 600;

/** How far an act-chain token's `iat` may be from the signer's clock, in seconds. */
export const ACT_CHAIN_TOKEN_CLOCK_SKEW_SECONDS = 60;

/**
 * The claims an act-chain token carries, besides the `iss` the signer adds.
 * It is an allow-list: the key that signs it signs every access token.
 */
export const ACT_CHAIN_TOKEN_CLAIMS: readonly string[] = Object.freeze([
  'sub',
  'aud',
  'act',
  'cnf',
  'jti',
  'client_id',
  'scope',
  'token_use',
  'iat',
  'exp',
]);

/** The members of an act-chain token's `act`: the admin. */
const ACTOR_MEMBERS: readonly string[] = Object.freeze(['sub', 'iss', 'client_id']);

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}

/** Whether `value` holds exactly the members `names`, each a non-empty string. */
function holdsStringsExactly(value: Record<string, unknown>, names: readonly string[]): boolean {
  const keys = Object.keys(value);
  return (
    keys.length === names.length &&
    names.every((name) => Object.hasOwn(value, name) && isNonEmptyString(value[name]))
  );
}

/**
 * Why `claims` are not an act-chain token's, or `undefined` when they are.
 * The message names a claim, never a value.
 *
 * @param claims - the claims as the signer will sign them, without `iss`
 * @param nowSeconds - the signer's clock, in whole seconds
 */
export function actChainTokenClaimsProblem(
  claims: Readonly<Record<string, unknown>>,
  nowSeconds: number
): string | undefined {
  for (const claim of Object.keys(claims)) {
    if (!ACT_CHAIN_TOKEN_CLAIMS.includes(claim)) {
      return `An act-chain token carries only ${ACT_CHAIN_TOKEN_CLAIMS.join(', ')}; not '${claim}'`;
    }
  }
  for (const claim of ['sub', 'jti', 'client_id']) {
    if (!isNonEmptyString(claims[claim])) return `An act-chain token carries a '${claim}'`;
  }
  if (claims['aud'] !== ACT_CHAIN_TOKEN_AUDIENCE) {
    return "An act-chain token's 'aud' is the account API's audience alone";
  }
  if (claims['token_use'] !== 'access') return "An act-chain token's 'token_use' is 'access'";

  const act = claims['act'];
  if (!isPlainObject(act) || !holdsStringsExactly(act, ACTOR_MEMBERS)) {
    return "An act-chain token's 'act' holds the admin's sub, iss and client_id, and no other actor";
  }
  if (act['client_id'] !== claims['client_id']) {
    return "An act-chain token's 'act.client_id' is its 'client_id'";
  }
  const cnf = claims['cnf'];
  if (!isPlainObject(cnf) || !holdsStringsExactly(cnf, ['jkt'])) {
    return "An act-chain token is bound to a DPoP key: its 'cnf' holds a 'jkt' alone";
  }

  const scope = claims['scope'];
  const scopes = typeof scope === 'string' ? scope.split(' ') : [];
  if (
    scopes.length === 0 ||
    scopes.some((value) => !ACT_CHAIN_TOKEN_SCOPES.includes(value)) ||
    new Set(scopes).size !== scopes.length
  ) {
    return "An act-chain token's 'scope' names account API scopes only, each once";
  }

  const iat = claims['iat'];
  const exp = claims['exp'];
  if (!Number.isSafeInteger(iat) || !Number.isSafeInteger(exp)) {
    return "An act-chain token carries whole-second 'iat' and 'exp'";
  }
  const issued = iat as number;
  const expires = exp as number;
  if (Math.abs(issued - nowSeconds) > ACT_CHAIN_TOKEN_CLOCK_SKEW_SECONDS) {
    return "An act-chain token's 'iat' is the signer's time";
  }
  if (expires <= issued || expires - issued > ACT_CHAIN_TOKEN_MAX_LIFETIME_SECONDS) {
    return `An act-chain token lives at most ${ACT_CHAIN_TOKEN_MAX_LIFETIME_SECONDS} seconds`;
  }
  return undefined;
}

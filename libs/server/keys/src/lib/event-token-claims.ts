/**
 * What the signer lets an event token carry: a Security Event Token or a
 * logout token (issue #624).
 *
 * A logout token is signed with the keys of the ID tokens, which the realm
 * JWKS publishes (OpenID Connect Back-Channel Logout 1.0 §2.4, §2.6). A
 * verifier that reads that JWKS and skips the `typ` check, as RFC 9068 §4 and
 * RFC 8725 §3.11 forbid, would take a token those keys sign for another kind.
 * The delivery role asks for both kinds of event token, and it is the role
 * that talks to destinations on the internet; so the signer, not the role,
 * holds an event token to its kind:
 *
 * - **No grant.** Neither kind carries a claim a resource server or a client
 *   reads as an access token's or an ID token's grant: `scope`, `client_id`,
 *   `cnf`, `act`, `nonce`, `acr` and the like.
 * - **An `events` object**, which both kinds carry (RFC 8417 §2.2,
 *   Back-Channel Logout 1.0 §2.4).
 * - **A Security Event Token** carries no `sub` and no `exp`: QAuth's SETs
 *   name their subject in `sub_id` and never expire.
 * - **A logout token** carries the back-channel logout event alone, an `aud`,
 *   a `jti`, a `sub` or a `sid`, an `iat` near the signer's clock and an `exp`
 *   at most two minutes after it (Back-Channel Logout 1.0 §2.4, §4), and no
 *   other claim ({@link LOGOUT_TOKEN_CLAIMS}): a relying party that skips the
 *   `typ` check and reads, say, `email` from what it takes for an ID token
 *   finds none.
 */

/** The token types that are event tokens, whose claims the signer checks. */
export const EVENT_TOKEN_TYPS: readonly string[] = Object.freeze(['secevent+jwt', 'logout+jwt']);

/** Whether `typ` is an event token's type (see {@link EVENT_TOKEN_TYPS}). */
export function isEventTokenTyp(typ: string): boolean {
  return EVENT_TOKEN_TYPS.includes(typ);
}

/** The `events` member of a logout token (Back-Channel Logout 1.0 §2.4). */
export const LOGOUT_TOKEN_EVENT = 'http://schemas.openid.net/event/backchannel-logout';

/**
 * The claims a logout token may carry, besides the `iss` the signer adds
 * (Back-Channel Logout 1.0 §2.4). It is an allow-list: the key that signs
 * logout tokens signs ID tokens too.
 */
export const LOGOUT_TOKEN_CLAIMS: readonly string[] = Object.freeze([
  'aud',
  'iat',
  'exp',
  'jti',
  'events',
  'sub',
  'sid',
]);

/** The longest a logout token the signer signs may live, in seconds. */
export const LOGOUT_TOKEN_MAX_LIFETIME_SECONDS = 120;

/** How far a logout token's `iat` may be from the signer's clock, in seconds. */
export const EVENT_TOKEN_CLOCK_SKEW_SECONDS = 60;

/**
 * Claims no event token carries: what a resource server or a client reads as
 * the grant of an access token or an ID token.
 */
export const EVENT_TOKEN_REFUSED_CLAIMS: readonly string[] = Object.freeze([
  'scope',
  'scp',
  'client_id',
  'azp',
  'cnf',
  'act',
  'may_act',
  'nonce',
  'auth_time',
  'acr',
  'amr',
  'token_use',
  'roles',
  'groups',
  'entitlements',
]);

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}

/**
 * Why `claims` are not of the event token kind `typ` names, or `undefined`
 * when they are. The message names a claim, never a value.
 *
 * @param typ - `secevent+jwt` or `logout+jwt` ({@link isEventTokenTyp})
 * @param claims - the claims as the signer will sign them, without `iss`
 * @param nowSeconds - the signer's clock, in whole seconds
 */
export function eventTokenClaimsProblem(
  typ: string,
  claims: Readonly<Record<string, unknown>>,
  nowSeconds: number
): string | undefined {
  for (const claim of EVENT_TOKEN_REFUSED_CLAIMS) {
    if (Object.hasOwn(claims, claim)) return `An event token never carries '${claim}'`;
  }
  const events = claims['events'];
  if (!isPlainObject(events) || Object.keys(events).length === 0) {
    return "An event token carries a non-empty 'events' object";
  }

  if (typ !== 'logout+jwt') {
    for (const claim of ['sub', 'exp']) {
      if (Object.hasOwn(claims, claim)) {
        return `A Security Event Token never carries '${claim}'; it names its subject in 'sub_id'`;
      }
    }
    return undefined;
  }

  for (const claim of Object.keys(claims)) {
    if (!LOGOUT_TOKEN_CLAIMS.includes(claim)) {
      return `A logout token carries only ${LOGOUT_TOKEN_CLAIMS.join(', ')}; not '${claim}'`;
    }
  }
  const names = Object.keys(events);
  if (names.length !== 1 || names[0] !== LOGOUT_TOKEN_EVENT || !isPlainObject(events[names[0]])) {
    return "A logout token's 'events' holds the back-channel logout event alone, as an object";
  }
  if (!isNonEmptyString(claims['aud'])) return "A logout token's 'aud' is one client_id";
  if (!isNonEmptyString(claims['jti'])) return "A logout token carries a 'jti'";
  const sub = claims['sub'];
  const sid = claims['sid'];
  if (sub !== undefined && !isNonEmptyString(sub)) return "A logout token's 'sub' is a string";
  if (sid !== undefined && !isNonEmptyString(sid)) return "A logout token's 'sid' is a string";
  if (sub === undefined && sid === undefined) return "A logout token carries 'sub' or 'sid'";
  const iat = claims['iat'];
  const exp = claims['exp'];
  if (!Number.isSafeInteger(iat) || !Number.isSafeInteger(exp)) {
    return "A logout token carries whole-second 'iat' and 'exp'";
  }
  const issued = iat as number;
  const expires = exp as number;
  if (Math.abs(issued - nowSeconds) > EVENT_TOKEN_CLOCK_SKEW_SECONDS) {
    return "A logout token's 'iat' is the signer's time";
  }
  if (expires <= issued || expires - issued > LOGOUT_TOKEN_MAX_LIFETIME_SECONDS) {
    return `A logout token's 'exp' is at most ${LOGOUT_TOKEN_MAX_LIFETIME_SECONDS} seconds after its 'iat'`;
  }
  return undefined;
}

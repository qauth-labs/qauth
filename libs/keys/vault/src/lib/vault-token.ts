import { VaultAnswerError, VaultHttpError } from './errors';
import { readSecretFile } from './secret-file';
import { SYSTEM_CLOCK, type VaultClient, type VaultClock } from './vault-client';

/**
 * The Vault token the provider calls Transit with (ADR-019 Decision 9, #578):
 * how it is obtained, kept alive and replaced.
 *
 * - **Token file** (`KEK_VAULT_TOKEN_FILE`): the file is read at each login,
 *   and `auth/token/lookup-self` tells the token's remaining TTL and whether
 *   it is renewable. A Vault Agent sink that rewrites the file hands QAuth
 *   the new token at the next login.
 * - **AppRole** (`KEK_VAULT_ROLE_ID` and `KEK_VAULT_SECRET_ID_FILE`):
 *   `auth/<mount>/login` with the role ID and the secret ID, read from its
 *   file at each login.
 *
 * Renewal: once two thirds of a token's TTL have passed, the session renews
 * it (`auth/token/renew-self`), on a timer that does not hold the process
 * open. When a renewal no longer extends the token, because it reached its
 * maximum TTL, or the token is not renewable, the session logs in again
 * before the token expires: AppRole gets a new token, a token file is read
 * again. A renewal Vault cannot answer is tried again later, while the token
 * lasts. A token that has expired anyway, say after the process was
 * suspended, is replaced by a login at its next use.
 *
 * Refusal: when Vault refuses a call (403), the caller reports it with
 * {@link TokenSession.refused}. A token that still works was refused by its
 * policy: it is kept and the call fails. A token Vault no longer accepts is
 * dropped and the call is tried once more, after a new login. A revoked token
 * in a token file is refused again, and the call fails with
 * `KEK_ACCESS_DENIED`: nothing falls back to another credential.
 *
 * Tokens and secret IDs live only in this module's closures. They are never
 * logged, never put in an error and never returned from the provider.
 */

/** What a login gives. */
export interface VaultLogin {
  readonly token: string;
  /** The token's remaining lifetime in ms; `0` for a token that never expires. */
  readonly ttlMs: number;
  readonly renewable: boolean;
}

/** One way to log in to Vault. */
export interface VaultCredentials {
  readonly method: 'token' | 'approle';
  /** Log in. A Vault refusal or an unreadable file throws; the caller maps it. */
  login(client: VaultClient): Promise<VaultLogin>;
}

/** Hands out a valid token, renewing and replacing it. */
export interface TokenSession {
  /** A token that has not expired, logging in when there is none. */
  token(): Promise<string>;
  /**
   * Vault refused a call made with `token` (403). Ask Vault whether the token
   * itself still works (`auth/token/lookup-self`): when it does, the policy
   * refused the call and the token is kept, so a denied path never mints new
   * tokens; when it does not, the token is dropped and the next {@link token}
   * logs in again.
   *
   * @returns whether the call is worth one more try with {@link token}
   */
  refused(token: string): Promise<boolean>;
  /** Stop renewing and drop the token. */
  close(): void;
}

/** Seconds as Vault reports a TTL: a non-negative integer. */
function ttlSeconds(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : undefined;
}

/** The `auth` block of a login or renewal answer. */
function leaseOf(
  operation: 'approle-login' | 'token-renew-self',
  body: unknown
): { token: unknown; ttlMs: number; renewable: boolean } {
  const auth = (body as { auth?: unknown } | undefined)?.auth;
  if (typeof auth !== 'object' || auth === null) {
    throw new VaultAnswerError(operation, 'has no auth block');
  }
  const { client_token: token, lease_duration: lease, renewable } = auth as Record<string, unknown>;
  const seconds = ttlSeconds(lease);
  if (seconds === undefined || typeof renewable !== 'boolean') {
    throw new VaultAnswerError(operation, 'has no lease duration or renewable flag');
  }
  return { token, ttlMs: seconds * 1000, renewable };
}

/** A Vault token as it may appear in a header. */
function isToken(value: unknown): value is string {
  return typeof value === 'string' && /^[\x21-\x7e]{1,4096}$/.test(value);
}

/** Log in with the Vault token in `path`, which `variable` names. */
export function tokenFileCredentials(path: string, variable: string): VaultCredentials {
  return Object.freeze({
    method: 'token' as const,
    async login(client: VaultClient): Promise<VaultLogin> {
      const token = readSecretFile(path, variable);
      const answer = await client.send('token-lookup-self', {
        method: 'GET',
        path: 'auth/token/lookup-self',
        token,
      });
      const data = (answer.body as { data?: Record<string, unknown> } | undefined)?.data;
      const seconds = ttlSeconds(data?.['ttl']);
      if (seconds === undefined || typeof data?.['renewable'] !== 'boolean') {
        throw new VaultAnswerError('token-lookup-self', 'has no ttl or renewable flag');
      }
      // Vault reports the TTL in whole seconds, so a token in its last second
      // reads `ttl: 0`, as one that never expires does. Only the latter has no
      // expiry time; the former is held as expiring now.
      const expireTime = data['expire_time'];
      const neverExpires = seconds === 0 && (expireTime === null || expireTime === undefined);
      return {
        token,
        ttlMs: neverExpires ? 0 : Math.max(seconds * 1000, 1),
        renewable: data['renewable'],
      };
    },
  });
}

/** What {@link appRoleCredentials} needs. */
export interface AppRoleCredentialsOptions {
  readonly roleId: string;
  readonly secretIdFile: string;
  readonly secretIdVariable: string;
  /** The AppRole auth mount path. */
  readonly mount: string;
}

/** Log in with an AppRole role ID and the secret ID in a file. */
export function appRoleCredentials(options: AppRoleCredentialsOptions): VaultCredentials {
  return Object.freeze({
    method: 'approle' as const,
    async login(client: VaultClient): Promise<VaultLogin> {
      const secretId = readSecretFile(options.secretIdFile, options.secretIdVariable);
      const answer = await client.send('approle-login', {
        method: 'POST',
        path: `auth/${options.mount}/login`,
        body: { role_id: options.roleId, secret_id: secretId },
      });
      const lease = leaseOf('approle-login', answer.body);
      if (!isToken(lease.token)) throw new VaultAnswerError('approle-login', 'has no client token');
      return { token: lease.token, ttlMs: lease.ttlMs, renewable: lease.renewable };
    },
  });
}

/** Renew once this share of a token's remaining lifetime has passed. */
export const RENEW_AT_FRACTION = 2 / 3;

/** A token this close to its expiry is not handed out; a login replaces it first. */
export const EXPIRY_MARGIN_MS = 1_000;

/** The shortest wait before a renewal or a retry, in ms. */
const MIN_DELAY_MS = 500;
/** The longest wait before retrying a renewal Vault could not answer, in ms. */
const MAX_RETRY_DELAY_MS = 30_000;
/** Node's longest timer. */
const MAX_TIMER_MS = 2 ** 31 - 1;

/** A token the session holds. */
interface HeldToken {
  readonly token: string;
  /** Epoch ms; `null` for a token that never expires. */
  readonly expiresAt: number | null;
  readonly renewable: boolean;
}

/** What {@link createTokenSession} needs. */
export interface TokenSessionOptions {
  readonly client: VaultClient;
  readonly credentials: VaultCredentials;
  readonly clock?: VaultClock;
}

/** Keep a timer from holding the process open, when the clock's timers can be unreferenced. */
function unref(timer: unknown): void {
  if (typeof timer === 'object' && timer !== null && 'unref' in timer) {
    (timer as { unref(): void }).unref();
  }
}

/** The session over `credentials`. It logs in at the first {@link TokenSession.token}. */
export function createTokenSession(options: TokenSessionOptions): TokenSession {
  const { client, credentials } = options;
  const clock = options.clock ?? SYSTEM_CLOCK;
  let held: HeldToken | undefined;
  let loggingIn: Promise<HeldToken> | undefined;
  let timer: unknown;
  let closed = false;

  function clearTimer(): void {
    if (timer !== undefined) clock.clearTimeout(timer);
    timer = undefined;
  }

  function schedule(delayMs: number, run: () => Promise<void>): void {
    clearTimer();
    if (closed) return;
    timer = clock.setTimeout(
      () => {
        timer = undefined;
        // A background failure is never thrown: the next use of the token sees it.
        run().catch(() => undefined);
      },
      Math.min(MAX_TIMER_MS, Math.max(MIN_DELAY_MS, Math.floor(delayMs)))
    );
    unref(timer);
  }

  /** Arm the renewal of `token`, if it expires. */
  function scheduleRenewal(token: HeldToken): void {
    if (token.expiresAt === null) {
      clearTimer();
      return;
    }
    schedule((token.expiresAt - clock.now()) * RENEW_AT_FRACTION, () => refresh(token));
  }

  /** Try `token`'s renewal again later, while it lasts. */
  function retryLater(token: HeldToken): void {
    if (token.expiresAt === null) return;
    const remaining = token.expiresAt - clock.now();
    if (remaining <= EXPIRY_MARGIN_MS) return;
    schedule(Math.min(MAX_RETRY_DELAY_MS, remaining / 2), () => refresh(token));
  }

  function hold(login: VaultLogin): HeldToken {
    return Object.freeze({
      token: login.token,
      expiresAt: login.ttlMs > 0 ? clock.now() + login.ttlMs : null,
      renewable: login.renewable,
    });
  }

  /** Log in, once at a time. The renewal is armed only when the login extends what was held. */
  function login(): Promise<HeldToken> {
    loggingIn ??= (async () => {
      try {
        const previous = held;
        const fresh = hold(await credentials.login(client));
        if (closed) throw new Error('The Vault token session is closed');
        held = fresh;
        const extended =
          previous === undefined ||
          fresh.token !== previous.token ||
          fresh.expiresAt === null ||
          previous.expiresAt === null ||
          fresh.expiresAt > previous.expiresAt + EXPIRY_MARGIN_MS;
        if (extended) scheduleRenewal(fresh);
        else clearTimer();
        return fresh;
      } finally {
        loggingIn = undefined;
      }
    })();
    return loggingIn;
  }

  /** The renewal timer: renew `token`, or log in again before it expires. */
  async function refresh(token: HeldToken): Promise<void> {
    if (closed || held !== token) return;
    if (token.renewable) {
      try {
        const answer = await client.send('token-renew-self', {
          method: 'POST',
          path: 'auth/token/renew-self',
          token: token.token,
          body: {},
        });
        if (held !== token) return;
        const lease = leaseOf('token-renew-self', answer.body);
        const expiresAt = clock.now() + lease.ttlMs;
        if (
          lease.ttlMs > 0 &&
          token.expiresAt !== null &&
          expiresAt > token.expiresAt + EXPIRY_MARGIN_MS
        ) {
          held = Object.freeze({ token: token.token, expiresAt, renewable: lease.renewable });
          scheduleRenewal(held);
          return;
        }
        // The renewal did not extend the token: it is at its maximum TTL.
      } catch (error) {
        if (held !== token) return;
        if (!(error instanceof VaultHttpError) || (error.status !== 400 && error.status !== 403)) {
          retryLater(token);
          return;
        }
        // Vault refused the renewal: the token may be gone, or the policy may
        // lack renew-self. A login settles which.
      }
    }
    try {
      await login();
    } catch (error) {
      if (held !== token) return;
      // A refused login leaves the token in place until Vault refuses it too;
      // a login Vault could not answer is tried again while the token lasts.
      if (!(error instanceof VaultHttpError) || (error.status !== 400 && error.status !== 403)) {
        retryLater(token);
      }
    }
  }

  return Object.freeze({
    async token(): Promise<string> {
      if (closed) throw new Error('The Vault token session is closed');
      const current = held;
      if (
        current !== undefined &&
        (current.expiresAt === null || clock.now() < current.expiresAt - EXPIRY_MARGIN_MS)
      ) {
        return current.token;
      }
      return (await login()).token;
    },

    async refused(token: string): Promise<boolean> {
      // Another call replaced the token already: try again with the new one.
      if (held?.token !== token) return true;
      try {
        await client.send('token-lookup-self', {
          method: 'GET',
          path: 'auth/token/lookup-self',
          token,
        });
        return false;
      } catch (error) {
        if (!(error instanceof VaultHttpError) || error.status !== 403) return false;
      }
      if (held?.token === token) {
        held = undefined;
        clearTimer();
      }
      return true;
    },

    close(): void {
      closed = true;
      held = undefined;
      clearTimer();
    },
  });
}

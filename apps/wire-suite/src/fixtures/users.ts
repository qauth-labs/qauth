import { randomBytes, randomUUID } from 'node:crypto';

import { serverPath, wireConfig } from '../config';
import { waitForVerificationToken } from '../helpers/mail';

/**
 * Every user the wire suite creates is created here, and only here.
 *
 * Today that is `POST /auth/register`. ADR-017 replaces it with hosted sign-up,
 * and when that lands this file is the one place that changes; no suite calls
 * the registration route for a user it means to keep. A suite that signs a user
 * in takes the account from {@link createSignInAccount}.
 */

export interface WireUser {
  readonly email: string;
  readonly password: string;
}

/**
 * An address that is unique to this call and can never receive mail:
 * `example.com` is reserved by RFC 2606.
 */
export function uniqueEmail(): string {
  return `wire-${randomUUID()}@example.com`;
}

/** A password with 144 bits of entropy, far above any strength floor. */
export function strongPassword(): string {
  return `Wire-${randomBytes(18).toString('base64url')}`;
}

/**
 * Register a password account and return its credentials.
 *
 * The route answers every address with the same `202`, so the answer does not
 * prove an account exists; it proves the server accepted the request. The
 * account is unverified: with `REQUIRE_VERIFIED_ACCOUNT` on, the server's
 * default, it cannot sign in until its address is confirmed.
 *
 * @throws when the server does not answer `202`
 */
export async function createUser(
  overrides: Partial<WireUser> = {},
  baseUrl: string = wireConfig().baseUrl
): Promise<WireUser> {
  const user: WireUser = {
    email: overrides.email ?? uniqueEmail(),
    password: overrides.password ?? strongPassword(),
  };
  const response = await fetch(serverPath(baseUrl, '/auth/register'), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(user),
  });
  if (response.status !== 202) {
    throw new Error(
      `POST /auth/register answered ${response.status}, expected 202: ${await response.text()}`
    );
  }
  await response.body?.cancel();
  return user;
}

/**
 * Register an account that can sign in, and return its credentials.
 *
 * With `QAUTH_WIRE_MAIL_URL` set, the address is verified the way a person
 * verifies it: the token from the mail the target delivered to the mail sink,
 * then `POST /auth/verify` with the token and the password. Without it, the
 * account is left unverified, which signs in only on a target that does not
 * require verified accounts (`REQUIRE_VERIFIED_ACCOUNT=false`); on any other,
 * the sign-in helper names this setting when the server refuses the account.
 *
 * @throws when the registration or the verification is refused
 */
export async function createSignInAccount(
  baseUrl: string = wireConfig().baseUrl
): Promise<WireUser> {
  const user = await createUser({}, baseUrl);
  const { mailUrl } = wireConfig();
  if (mailUrl === undefined) return user;

  const token = await waitForVerificationToken(mailUrl, user.email);
  const response = await fetch(serverPath(baseUrl, '/auth/verify'), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ token, password: user.password }),
    redirect: 'manual',
  });
  if (response.status !== 200) {
    throw new Error(
      `POST /auth/verify answered ${response.status}, expected 200: ${await response.text()}`
    );
  }
  await response.body?.cancel();
  return user;
}

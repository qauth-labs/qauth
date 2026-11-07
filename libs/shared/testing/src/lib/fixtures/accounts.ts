import { randomUUID } from 'node:crypto';

/**
 * A primary credential for a test account that only needs to exist (#846):
 * `users.create` takes the credential that creates the account. Its type,
 * `test`, is no way to sign in, proves nothing and is no upstream identity,
 * so the account it creates signs in with nothing and is no verified owner;
 * its subject is unique, so each call creates another account.
 */
export function testPrimaryCredential(): {
  readonly providerType: string;
  readonly externalSub: string;
  readonly credentialData: Record<string, unknown>;
} {
  return { providerType: 'test', externalSub: randomUUID(), credentialData: {} };
}

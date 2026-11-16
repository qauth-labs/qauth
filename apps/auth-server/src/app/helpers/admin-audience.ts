/**
 * Which clients may hold the admin API's audience (ADR-019 Decision 7, issue
 * #522). Apart from `client-auth.ts` so the admin API's authority stage
 * (`admin-authority.ts`, `service-accounts.ts`) reads the rule without
 * loading the client authentication module and the environment it reads.
 */

/**
 * Whether a client may hold the admin API's audience at all: only one that
 * authenticates with `private_key_jwt`.
 *
 * An admin token reaches the admin API, so the client it is issued to must
 * prove a private key whose public half the operator registered, as a short,
 * single-use assertion. A shared secret (`client_secret_basic`,
 * `client_secret_post`) is a long-lived credential that copies; a public
 * client (`none`) proves nothing. Neither gets the admin audience, whatever
 * its `audience` lists, on any grant. The method is the client's registered
 * one: client authentication accepts no other (`authenticateClientRequest`),
 * so a `private_key_jwt` client authenticated with an assertion. A client
 * with no method recorded is not one.
 */
export function mayHoldAdminAudience(client: {
  readonly tokenEndpointAuthMethod?: string;
}): boolean {
  return client.tokenEndpointAuthMethod === 'private_key_jwt';
}

/**
 * A redirect-flow client's hosted flows (ADR-017 Decision 8, question 13;
 * issue #640).
 *
 * Signing in needs no flag: every redirect-flow client may send a person to
 * sign in. What a client may start beyond that is operator-set, never
 * self-asserted: `oauth_clients.hosted_flows`, which only the
 * `db:seed-oauth-clients` manifest and, later, a `qauth:admin:security`
 * operation write (ADR-019 Decision 7), as with the first-party profile. A
 * `native_backend` client keeps its own list in `first_party_policy.flows`.
 *
 * - `register`: the client may start registration with `prompt=create`. The
 *   realm's sign-up switch (`accounts.allowSignUp`) must allow it too: both
 *   are required.
 *
 * Reset and the verification of an account need no flag: the hosted pages
 * offer them whenever the hosted pages are on (ADR-017 phase F2a).
 */
import { z } from 'zod';

/** The flows an operator may list on a redirect-flow client. */
export const HOSTED_FLOWS = ['register'] as const;
export type HostedFlow = (typeof HOSTED_FLOWS)[number];

/**
 * The list as an operator writes it: known flows, none twice. Empty is
 * allowed and means the same as none.
 */
export const hostedFlowsSchema = z
  .array(z.enum(HOSTED_FLOWS))
  .refine((flows) => new Set(flows).size === flows.length, {
    message: 'hosted_flows lists a flow twice',
  });

/**
 * The hosted flows a stored client allows. Fails closed: a value that is not
 * a list of strings allows none, and a member this version does not know is
 * ignored, never read as another flow.
 */
export function hostedFlowsOf(client: { readonly hostedFlows?: unknown }): readonly HostedFlow[] {
  const stored = client.hostedFlows;
  if (!Array.isArray(stored)) return [];
  if (!stored.every((flow): flow is string => typeof flow === 'string')) return [];
  return HOSTED_FLOWS.filter((flow) => stored.includes(flow));
}

/** Whether a stored client allows the hosted flow `flow`. */
export function clientAllowsHostedFlow(
  client: { readonly hostedFlows?: unknown },
  flow: HostedFlow
): boolean {
  return hostedFlowsOf(client).includes(flow);
}

import { isEgressError } from '@qauth-labs/fastify-plugin-egress';
import { BACKCHANNEL_LOGOUT_EGRESS_PURPOSE } from '@qauth-labs/server-backchannel-logout';
import type { FastifyInstance } from 'fastify';

import { rejectRegistration } from './dynamic-client-registration';

/**
 * The address check of a `backchannel_logout_uri` a client registers itself
 * (OpenID Connect Back-Channel Logout 1.0 §2.2, issue #624; ADR-019
 * Decision 8): the egress client resolves the host and checks every address,
 * sending nothing. A URI a client registers never uses the deployment
 * allowlist (`source: 'client'`), so a private, loopback, link-local or other
 * non-public address is refused, even for a development client. Only an
 * admin sets a URI the allowlist may open. Delivery checks the addresses
 * again before every logout token.
 *
 * A host that does not resolve is refused as well, with the same answer: told
 * apart, the two would show a registrant which names resolve to private
 * addresses from QAuth's network.
 *
 * @param realmName - the realm the client is registered in, for the egress
 *   client's log line
 * @returns whether the destination passes
 */
export async function isRegistrableBackchannelLogoutDestination(
  fastify: FastifyInstance,
  uri: string,
  realmName?: string
): Promise<boolean> {
  try {
    await fastify.egress.validateDestination(uri, {
      purpose: BACKCHANNEL_LOGOUT_EGRESS_PURPOSE,
      source: 'client',
      ...(realmName === undefined ? {} : { realm: realmName }),
    });
    return true;
  } catch (error) {
    if (isEgressError(error)) return false;
    throw error;
  }
}

/** What a refused destination answers at dynamic registration. */
export const UNREACHABLE_BACKCHANNEL_LOGOUT_URI_DESCRIPTION =
  'backchannel_logout_uri must name a host that resolves, and only to public addresses';

/**
 * {@link isRegistrableBackchannelLogoutDestination} for dynamic registration:
 * a refused destination is `invalid_client_metadata` (RFC 7591 §3.2.2), and
 * nothing is stored.
 */
export async function assertRegistrableBackchannelLogoutDestination(
  fastify: FastifyInstance,
  uri: string,
  realmName: string
): Promise<void> {
  if (!(await isRegistrableBackchannelLogoutDestination(fastify, uri, realmName))) {
    rejectRegistration('invalid_client_metadata', UNREACHABLE_BACKCHANNEL_LOGOUT_URI_DESCRIPTION);
  }
}

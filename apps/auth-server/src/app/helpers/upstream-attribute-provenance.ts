import { UPSTREAM_PRESET_PROVENANCE } from '@qauth-labs/fastify-plugin-federation';
import type { FastifyInstance } from 'fastify';

/**
 * The `provenance` the upstream sign-in records on each attribute row of the
 * method of `type` (#671): {@link UPSTREAM_PRESET_PROVENANCE} when the plugin
 * loader built it from an upstream OpenID Connect preset, which claim
 * resolution then ranks with `oidc_*`, and `null` for any other method.
 *
 * Decided when the row is written, on the process that runs the sign-in and
 * so loaded the plugins, never when a claim is resolved: the `api` role,
 * which serves the token and userinfo endpoints, loads no plugin, and a type
 * that another package serves later does not re-rank the rows an earlier one
 * wrote. A process without the plugin runtime records none: a lower rank,
 * never a higher one.
 */
export function upstreamAttributeProvenance(
  fastify: Partial<Pick<FastifyInstance, 'authMethodPlugins'>>,
  type: string
): typeof UPSTREAM_PRESET_PROVENANCE | null {
  return fastify.authMethodPlugins?.ofType(type)?.kind === 'upstream-oidc-preset'
    ? UPSTREAM_PRESET_PROVENANCE
    : null;
}

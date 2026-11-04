import { EGRESS_PLUGIN_NAME } from '@qauth-labs/fastify-plugin-egress';
import {
  type BackchannelLogoutClientSource,
  createBackchannelLogoutRoute,
} from '@qauth-labs/server-backchannel-logout';
import type { DeliveryRoute } from '@qauth-labs/server-event-delivery';
import type { FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';

import packageJson from '../../package.json';

/** Back-channel logout, as the delivery role and the retention job use it. */
export interface BackchannelLogout {
  /** The delivery route that POSTs each client its logout token. */
  readonly deliveryRoute: DeliveryRoute;
}

/** What the app hands the plugin. */
export interface BackchannelLogoutPluginOptions {
  /**
   * The delivery role's view of the clients: the `backchannelLogoutClients`
   * repository. The app hands it over, so that the role's repositories stay
   * named in one place (`service-roles.ts`).
   */
  readonly clients: BackchannelLogoutClientSource;
}

declare module 'fastify' {
  interface FastifyInstance {
    /** OpenID Connect Back-Channel Logout 1.0 delivery (#624), in a process that delivers. */
    backchannelLogout: BackchannelLogout;
  }
}

/**
 * The back-channel logout delivery route's wiring (issue #624).
 *
 * It builds the route over the clients the app hands it and `fastify.egress`,
 * the egress client built with the deployment's allowlist, which the route
 * lets only a URI an admin set use. Register it after the egress plugin, in a
 * process that delivers: the roles that end sessions only queue the notices.
 */
export const backchannelLogoutPlugin = fp<BackchannelLogoutPluginOptions>(
  async (fastify: FastifyInstance, options) => {
    fastify.decorate(
      'backchannelLogout',
      Object.freeze({
        deliveryRoute: createBackchannelLogoutRoute({
          clients: options.clients,
          egress: fastify.egress,
        }),
      })
    );
  },
  {
    name: packageJson.name,
    dependencies: [EGRESS_PLUGIN_NAME],
  }
);

export default backchannelLogoutPlugin;

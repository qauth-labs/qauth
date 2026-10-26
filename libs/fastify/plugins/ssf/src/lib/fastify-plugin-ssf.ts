import { DATABASE_PLUGIN_NAME } from '@qauth-labs/fastify-plugin-db';
import { createEgressClient, type EgressClient, isEgressError } from '@qauth-labs/server-egress';
import type { DeliveryRoute } from '@qauth-labs/server-event-delivery';
import {
  createSsfDeliveryRoute,
  SSF_EGRESS_PURPOSE,
  ssfEventsSupported,
  SsfRequestError,
} from '@qauth-labs/server-ssf';
import type { FastifyInstance, FastifyPluginOptions } from 'fastify';
import fp from 'fastify-plugin';

import packageJson from '../../package.json';

/** The transmitter, as the routes and the delivery role use it. */
export interface SsfTransmitter {
  /** The SSF delivery route, for the delivery role and the retention job. */
  readonly deliveryRoute: DeliveryRoute;
  /** `events_supported`: the SSF events the transmitter can send. */
  readonly eventsSupported: readonly string[];
  /**
   * Check a stream's `endpoint_url` when a receiver registers it: the egress
   * client resolves it and checks every address, sending nothing. The push
   * route checks again at every delivery.
   *
   * @throws SsfRequestError when it is refused; the reason is logged, not returned
   */
  checkEndpoint(url: string): Promise<void>;
}

/** Options of {@link ssfPlugin}. */
export interface SsfPluginOptions extends FastifyPluginOptions {
  /** `SSF_TRANSMITTER_ENABLED`. Off: `fastify.ssf` is `null` and nothing else happens. */
  enabled: boolean;
  /**
   * The egress client. One is created with the server's logger unless set;
   * only a test that stands up its own network sets it.
   */
  egress?: Pick<EgressClient, 'request' | 'validateDestination'>;
}

declare module 'fastify' {
  interface FastifyInstance {
    /** The Shared Signals Framework transmitter (#410); `null` while SSF_TRANSMITTER_ENABLED is off. */
    ssf: SsfTransmitter | null;
  }
}

/**
 * The Shared Signals Framework transmitter's wiring (issue #410).
 *
 * With `enabled` off it decorates `fastify.ssf` with `null` and creates
 * nothing: no egress client, no route. On, it builds the push delivery route
 * over the `ssfStreams` repository and the egress client, for the app to hand
 * to the delivery role and the retention job. Register it after the database
 * plugin.
 *
 * @example
 * ```typescript
 * await fastify.register(ssfPlugin, { enabled: env.SSF_TRANSMITTER_ENABLED });
 * const routes = fastify.ssf ? [fastify.ssf.deliveryRoute] : [];
 * ```
 */
export const ssfPlugin = fp<SsfPluginOptions>(
  async (fastify: FastifyInstance, options: SsfPluginOptions) => {
    if (!options.enabled) {
      fastify.decorate('ssf', null);
      return;
    }
    const egress = options.egress ?? createEgressClient({ logger: fastify.log });
    const streams = fastify.repositories.ssfStreams;
    const transmitter: SsfTransmitter = Object.freeze({
      deliveryRoute: createSsfDeliveryRoute({ streams, egress }),
      eventsSupported: Object.freeze(ssfEventsSupported()),
      async checkEndpoint(url: string) {
        try {
          await egress.validateDestination(url, { purpose: SSF_EGRESS_PURPOSE });
        } catch (error) {
          if (!isEgressError(error)) throw error;
          // The reason stays in the server's log (the egress client logs it):
          // telling the receiver would let it map which names resolve to
          // private addresses.
          throw new SsfRequestError('endpoint_url is refused');
        }
      },
    });
    fastify.decorate('ssf', transmitter);
  },
  {
    name: packageJson.name,
    dependencies: [DATABASE_PLUGIN_NAME],
  }
);

export default ssfPlugin;

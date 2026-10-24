import type { Database } from '@qauth-labs/infra-db';
import type {
  DeliveryClock,
  DeliveryRoute,
  DeliverySettingsInput,
} from '@qauth-labs/server-event-delivery';
import type { Signer } from '@qauth-labs/server-keys';
import type { FastifyPluginOptions } from 'fastify';
import type { Registry } from 'prom-client';

/** Options of the delivery role's plugin (issue #460). */
export interface EventDeliveryPluginOptions extends FastifyPluginOptions {
  /**
   * The database the delivery role connects to: in a distributed deployment
   * as its own user (`eventDeliveryGrantStatements`), in a single one the
   * server's database.
   */
  db: Database;
  /** The signer role's signer. The role only ever gets a `delivery` handle of it. */
  signer: Signer;
  /** The delivery routes. None: the role does nothing. */
  routes?: readonly DeliveryRoute[];
  /** Where the role's metrics go: the `/metrics` registry. None: no metrics. */
  registry?: Registry;
  /** The role's settings; the rest keep their defaults. */
  settings?: DeliverySettingsInput;
  /** The role's clock, for a test that moves time by hand. */
  clock?: DeliveryClock;
  /** The jitter's random numbers, for a test. */
  random?: () => number;
}

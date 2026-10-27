import { createEventDeliveriesRepository } from '@qauth-labs/infra-db';
import {
  type DeliveryRole,
  resolveDeliverySettings,
  startDeliveryRole,
} from '@qauth-labs/server-event-delivery';
import type { FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';

import packageJson from '../../package.json';
import type { EventDeliveryPluginOptions } from '../types';
import { registerDeliveryMetrics } from './metrics';
import { deliverySignerHandle } from './signer-handle';

/**
 * The delivery role's wiring (ADR-019 Decision 8, issue #460): run the role
 * in-process, from the server's ready to its close.
 *
 * It builds the delivery queue on `options.db`, hands the role a `delivery`
 * handle of the signer (`deliverySignerHandle`), registers the role's
 * metrics on `options.registry`, starts the role in an `onReady` hook and
 * stops it in an `onClose` hook: `fastify.close()` waits for the attempts in
 * flight up to the role's shutdown limit, then releases the rest. Register it
 * after the database plugin, so the pool is still open while the role stops.
 *
 * With no route the role fans nothing out and claims nothing. A separate
 * entry point for the delivery role (the topology area) calls
 * `startDeliveryRole` itself, with the role's own database user.
 *
 * @example
 * ```typescript
 * await fastify.register(eventDeliveryPlugin, {
 *   db: fastify.db,
 *   signer: fastify.signer,
 *   routes: [],
 *   registry: fastify.metrics.registry,
 *   settings: { maxAttempts: 12 },
 * });
 * ```
 */
export const eventDeliveryPlugin = fp<EventDeliveryPluginOptions>(
  async (fastify: FastifyInstance, options: EventDeliveryPluginOptions) => {
    // Checked here, so a setting out of range fails the boot, not the ready hook.
    const settings = resolveDeliverySettings(options.settings);
    const routes = options.routes ?? [];
    const store = createEventDeliveriesRepository(options.db);
    const clock = options.clock;
    const now = () => (clock ? clock.now() : Date.now());

    let role: DeliveryRole | undefined;
    const metrics =
      options.registry === undefined
        ? undefined
        : registerDeliveryMetrics(options.registry, {
            store,
            kinds: routes.map((route) => route.kind),
            now,
            warn: (error, message) => fastify.log.warn({ err: error }, message),
            signerHeld: () => role?.signerHeld(),
          });

    fastify.addHook('onReady', async () => {
      role = startDeliveryRole({
        store,
        routes,
        signer: deliverySignerHandle(options.signer),
        log: fastify.log,
        ...(metrics === undefined ? {} : { metrics }),
        settings,
        ...(clock === undefined ? {} : { clock }),
        ...(options.random === undefined ? {} : { random: options.random }),
      });
    });
    fastify.addHook('onClose', async () => {
      await role?.stop();
    });
  },
  {
    name: packageJson.name,
  }
);

export default eventDeliveryPlugin;

# @qauth-labs/fastify-plugin-event-delivery

The delivery role's wiring ([ADR-019 Decision 8](../../../../docs/adr/019-deployment-topology-and-trust-boundaries.md),
issue #460): runs `startDeliveryRole` of `@qauth-labs/server-event-delivery` in-process, from the
server's ready to its close.

```typescript
import { eventDeliveryPlugin } from '@qauth-labs/fastify-plugin-event-delivery';

await fastify.register(eventDeliveryPlugin, {
  db: fastify.db, // the delivery role's own database user in a distributed deployment
  signer: fastify.signer, // the role gets only a `delivery` handle of it
  routes: [], // webhooks (#538) and SSF (#410) plug in here
  registry: fastify.metrics.registry,
  settings: { maxAttempts: 12 },
});
```

- **Queue.** The plugin builds the delivery queue (`createEventDeliveriesRepository` of
  `@qauth-labs/infra-db`) on `db`.
- **Signer handle.** `deliverySignerHandle(signer)` calls the signer as the `delivery` caller:
  webhook signatures and `event_signing` tokens, nothing else (`SIGNER_POLICY`).
- **Lifecycle.** The role starts in an `onReady` hook and stops in an `onClose` hook:
  `fastify.close()` waits for the attempts in flight up to the role's shutdown limit, then releases
  the rest. Register the plugin after the database plugin.
- **Metrics.** With a `registry`: `qauth_events_pending{kind}`, `qauth_events_delivery_lag_seconds`
  and `qauth_events_delivery_attempts_total{kind,result}` (`delivered`, `retry`, `failed`).

`pnpm nx run fastify-plugin-event-delivery:test-integration` runs the acceptance suite of #460
against Postgres: a worker that died after its claim, two workers, retries on a fake clock, a
destination that is down, and the metrics.

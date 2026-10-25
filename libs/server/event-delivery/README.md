# @qauth-labs/server-event-delivery

The delivery role ([ADR-019 Decision 8](../../../docs/adr/019-deployment-topology-and-trust-boundaries.md)):
a worker that hands every event to every destination whose filter matches it, **at least once**
and with the event's own id. Webhooks (#538) and Shared Signals Framework streams (#410) plug in
as routes.

> **Status:** the role and its queue are complete. The auth server starts the role in-process
> (`@qauth-labs/fastify-plugin-event-delivery`); its one route so far is the SSF route of
> `@qauth-labs/server-ssf` (#410), present while `SSF_TRANSMITTER_ENABLED` is on. With no route the
> role does nothing.

## Usage

```typescript
import { startDeliveryRole, type DeliveryRoute } from '@qauth-labs/server-event-delivery';

const webhooks: DeliveryRoute = {
  kind: 'webhook',
  // Every enabled destination, before each fan-out.
  async destinations() {
    return [{ id: subscription.id, realmId: subscription.realmId, types: subscription.types }];
  },
  // One attempt. A throw counts as a failed attempt that is retried.
  async deliver(delivery, event, { signer }) {
    const body = JSON.stringify(event);
    const timestamp = Math.floor(Date.now() / 1000);
    const signature = await signer.signWebhook({
      realmId: delivery.realmId,
      subscriptionId: delivery.destinationId,
      id: event.id,
      timestamp,
      body,
    });
    const res = await egress.request({ method: 'POST', url, body /* … */ });
    return res.status < 300
      ? { ok: true, statusCode: res.status }
      : { ok: false, statusCode: res.status, errorClass: 'http_status' };
  },
};

const role = startDeliveryRole({ store, routes: [webhooks], signer, log, metrics });
// At shutdown:
await role.stop();
```

- **`store`** is the delivery queue: `createEventDeliveriesRepository` of `@qauth-labs/infra-db`,
  connected as the delivery role's own database user (`eventDeliveryGrantStatements`).
- **`signer`** is the handle the signer role gives the delivery role (`deliverySignerHandle` in
  `@qauth-labs/fastify-plugin-event-delivery`). It signs webhook messages and event tokens, and
  decrypts a destination's stored secret, such as an SSF receiver's `Authorization` header; the
  role never sees a key.

## How it works

Every `pollIntervalMs` the role asks each route for its destinations and fans the new events out
to them, one delivery row per destination and event. It claims due deliveries into its free slots
(`concurrency`), destination by destination in turn and at most `maxInFlightPerDestination` of
one destination at a time, so a stalled destination never holds every slot. Each attempt has a
time limit (`attemptTimeoutMs`); its outcome is recorded as delivered, retried later, or failed
for good after `maxAttempts`.

- **At least once.** A claim leases its row for `leaseMs`. A worker that dies leaves the row to
  come due again when the lease runs out, and the event is delivered again with the same id; a
  receiver drops the duplicate. Order is not kept across retries: receivers order by `time` or by
  the stream position.
- **Retries.** Exponential backoff with jitter (`retry`): 30 seconds, doubling, at most 6 hours,
  less up to 20%, by default; 12 attempts by default. A route marks a refusal no retry can change
  with `retry: false`, and the delivery ends `failed` at once. A failed delivery stays in the queue.
- **A failing listing.** When a route's `destinations()` throws, nothing is fanned out that cycle,
  so no destination misses an event because its route could not be asked.
- **Stopping.** `stop()` claims nothing more, waits for the attempts in flight up to
  `shutdownTimeoutMs`, then aborts the rest and releases their leases, so another node takes them
  at once.
- **Clock.** Every time is the role's clock (`clock`), which a test can drive.

## No keys

The role holds no private key and loads none (ADR-019 Decision 9). This library depends only on
the shared layer: the Nx constraint for `type:event-delivery` in `.oxlintrc.json` refuses any
other workspace library, and `key-isolation.test.ts` walks every import path from the library's
source and fails on one that reaches key custody, the config library, core-crypto, server-jwt,
the signer's wiring or `jose`.

## Metrics

The role counts attempts through `metrics.attempt(kind, result)`; the auth server publishes them
as `qauth_events_delivery_attempts_total{kind,result}`, beside `qauth_events_pending{kind}` and
`qauth_events_delivery_lag_seconds`.

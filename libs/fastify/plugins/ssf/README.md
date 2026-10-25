# @qauth-labs/fastify-plugin-ssf

The Shared Signals Framework transmitter's wiring (issue #410).

```typescript
import { ssfPlugin } from '@qauth-labs/fastify-plugin-ssf';

await fastify.register(ssfPlugin, { enabled: env.SSF_TRANSMITTER_ENABLED });
const routes = fastify.ssf ? [fastify.ssf.deliveryRoute] : [];
```

- **Off** (`enabled: false`, the default deployment): `fastify.ssf` is `null`, and the plugin creates
  no egress client and no route.
- **On**: `fastify.ssf.deliveryRoute` is the push route of `@qauth-labs/server-ssf` over the
  `ssfStreams` repository and an egress client; the app hands it to the delivery role and the
  retention job. `fastify.ssf.checkEndpoint(url)` checks a stream's `endpoint_url` at registration
  and throws `SsfRequestError` (a `400`) when the egress client refuses it.

It re-exports `@qauth-labs/server-ssf`, which the app may not import itself. Register it after the
database plugin.

`src/testing/egress-network.ts` re-exports the egress client's fixture network for a suite that
pushes to local HTTPS receivers by mocking the egress transport module.

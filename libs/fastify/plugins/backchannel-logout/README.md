# @qauth-labs/fastify-plugin-backchannel-logout

The wiring of OpenID Connect Back-Channel Logout 1.0 delivery (issue #624).

```typescript
import { backchannelLogoutPlugin } from '@qauth-labs/fastify-plugin-backchannel-logout';

await fastify.register(backchannelLogoutPlugin, {
  clients: fastify.repositories.backchannelLogoutClients,
});
const routes = [fastify.backchannelLogout.deliveryRoute];
```

`fastify.backchannelLogout.deliveryRoute` is the route of `@qauth-labs/server-backchannel-logout`
over the clients the app hands the plugin (the `backchannelLogoutClients` repository) and
`fastify.egress`, the egress client the egress plugin built with the deployment's allowlist: only a
URI an admin set may use it. The app hands the route to the delivery role and the retention job, in
a process that delivers.

It re-exports `@qauth-labs/server-backchannel-logout`, which the app may not import itself.
Register it after the egress plugin.

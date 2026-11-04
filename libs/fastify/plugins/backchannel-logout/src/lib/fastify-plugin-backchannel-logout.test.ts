import { EGRESS_PLUGIN_NAME } from '@qauth-labs/fastify-plugin-egress';
import { BACKCHANNEL_LOGOUT_DELIVERY_KIND } from '@qauth-labs/server-backchannel-logout';
import Fastify, { type FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { backchannelLogoutPlugin } from './fastify-plugin-backchannel-logout';

const apps: FastifyInstance[] = [];

afterEach(async () => {
  await Promise.all(apps.splice(0).map((app) => app.close()));
});

const CLIENT = {
  id: '0192a000-0000-7000-8000-0000000000cc',
  realmId: '0192a000-0000-7000-8000-000000000001',
  clientId: 'rp',
};

async function build(options: { egress?: boolean } = {}) {
  const app = Fastify({ logger: false });
  apps.push(app);
  const clients = {
    listDestinations: vi.fn(async () => [CLIENT]),
    findForDelivery: vi.fn(async () => undefined),
  };
  if (options.egress !== false) {
    await app.register(
      fp(
        async (instance) => {
          instance.decorate('egress', { request: vi.fn() } as never);
        },
        { name: EGRESS_PLUGIN_NAME }
      )
    );
  }
  await app.register(backchannelLogoutPlugin, { clients });
  await app.ready();
  return { app, clients };
}

describe('backchannelLogoutPlugin (#624)', () => {
  it('builds the delivery route over the clients the app hands it', async () => {
    const { app, clients } = await build();

    const route = app.backchannelLogout.deliveryRoute;
    expect(route.kind).toBe(BACKCHANNEL_LOGOUT_DELIVERY_KIND);
    expect(await route.destinations()).toEqual([
      expect.objectContaining({ id: CLIENT.id, realmId: CLIENT.realmId }),
    ]);
    expect(clients.listDestinations).toHaveBeenCalledTimes(1);
  });

  it('refuses to register without the egress plugin, whose allowlist the route needs', async () => {
    await expect(build({ egress: false })).rejects.toThrow(EGRESS_PLUGIN_NAME);
  });
});

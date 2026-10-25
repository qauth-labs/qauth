import { DATABASE_PLUGIN_NAME } from '@qauth-labs/fastify-plugin-db';
import { SsfRequestError } from '@qauth-labs/server-ssf';
import Fastify, { type FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ssfPlugin, type SsfPluginOptions } from './fastify-plugin-ssf';

const apps: FastifyInstance[] = [];

afterEach(async () => {
  await Promise.all(apps.splice(0).map((app) => app.close()));
});

async function build(options: SsfPluginOptions): Promise<FastifyInstance> {
  const app = Fastify({ logger: false });
  apps.push(app);
  await app.register(
    fp(
      async (instance) => {
        instance.decorate('repositories', {
          ssfStreams: {
            listDestinations: vi.fn(async () => []),
            findForDelivery: vi.fn(async () => undefined),
          },
        } as never);
      },
      { name: DATABASE_PLUGIN_NAME }
    )
  );
  await app.register(ssfPlugin, options);
  await app.ready();
  return app;
}

describe('ssfPlugin', () => {
  it('decorates null and builds nothing while the switch is off', async () => {
    const app = await build({ enabled: false });
    expect(app.ssf).toBeNull();
  });

  it('builds the push route and offers no event before EVT-11 maps one', async () => {
    const app = await build({ enabled: true });
    expect(app.ssf?.deliveryRoute.kind).toBe('ssf');
    expect(app.ssf?.eventsSupported).toEqual([]);
    expect(await app.ssf?.deliveryRoute.destinations()).toEqual([]);
  });

  it('refuses an endpoint on a private address with the real egress client', async () => {
    const app = await build({ enabled: true });
    for (const url of ['https://10.0.0.7/events', 'https://127.0.0.1/events', 'https://[::1]/']) {
      await expect(app.ssf?.checkEndpoint(url)).rejects.toThrow(
        new SsfRequestError('endpoint_url is refused')
      );
    }
    await expect(app.ssf?.checkEndpoint('http://receiver.example/')).rejects.toThrow(
      'endpoint_url is refused'
    );
  });

  it('checks an endpoint through the egress client it is given', async () => {
    const egress = {
      request: vi.fn(),
      validateDestination: vi.fn(async (url: string | URL) => ({
        url: String(url),
        host: 'receiver.example',
        addresses: ['93.184.215.14'],
      })),
    };
    const app = await build({ enabled: true, egress: egress as never });
    await app.ssf?.checkEndpoint('https://receiver.example/events');
    expect(egress.validateDestination).toHaveBeenCalledWith('https://receiver.example/events', {
      purpose: 'ssf_push',
    });
  });

  it('lets an unexpected failure of the check through', async () => {
    const egress = {
      request: vi.fn(),
      validateDestination: vi.fn(async () => {
        throw new Error('boom');
      }),
    };
    const app = await build({ enabled: true, egress });
    await expect(app.ssf?.checkEndpoint('https://receiver.example/')).rejects.toThrow('boom');
  });
});

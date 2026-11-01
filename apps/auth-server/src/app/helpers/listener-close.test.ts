import Fastify from 'fastify';
import { describe, expect, it } from 'vitest';

import { closeWithApp } from './listener-close';

/** The app's further listeners close together (#496, #511). */

const wait = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

describe('closeWithApp', () => {
  it('closes every listener at once when the app closes, so the slowest bounds the whole', async () => {
    const app = Fastify({ logger: false });
    const closed: string[] = [];
    closeWithApp(app, async () => {
      await wait(300);
      closed.push('admin');
    });
    closeWithApp(app, async () => {
      await wait(300);
      closed.push('internal');
    });
    await app.ready();

    const started = Date.now();
    await app.close();
    expect(Date.now() - started).toBeLessThan(550);
    expect(closed.sort()).toEqual(['admin', 'internal']);
  });

  it('closes them before the app plugins close', async () => {
    const app = Fastify({ logger: false });
    const order: string[] = [];
    app.addHook('onClose', async () => {
      order.push('app');
    });
    closeWithApp(app, async () => {
      await wait(50);
      order.push('listener');
    });
    await app.ready();
    await app.close();
    expect(order).toEqual(['listener', 'app']);
  });

  it('lets every close settle before it reports the first failure', async () => {
    const app = Fastify({ logger: false });
    let other = false;
    closeWithApp(app, async () => {
      throw new Error('the admin listener did not close');
    });
    closeWithApp(app, async () => {
      await wait(50);
      other = true;
    });
    await app.ready();
    await expect(app.close()).rejects.toThrow('the admin listener did not close');
    expect(other).toBe(true);
  });
});

import type { FastifyInstance } from 'fastify';
import { describe, expect, it, vi } from 'vitest';

import { createBackgroundTasks } from './background-tasks';

function fastifyStub() {
  const hooks: { onClose?: () => Promise<unknown> } = {};
  const fastify = {
    addHook: (name: string, hook: () => Promise<unknown>) => {
      if (name === 'onClose') hooks.onClose = hook;
    },
    log: { error: vi.fn() },
  };
  return { fastify: fastify as unknown as FastifyInstance, hooks, log: fastify.log };
}

/** A task the test settles by hand, like a slow mail provider. */
function deferred() {
  const control: { resolve?: () => void; reject?: (error: Error) => void } = {};
  const promise = new Promise<void>((resolve, reject) => {
    control.resolve = resolve;
    control.reject = reject;
  });
  return { promise, control };
}

/** 'pending' if `promise` has not settled within a few ticks. */
async function settledSoon(promise: Promise<unknown>): Promise<string> {
  return Promise.race([
    promise.then(
      () => 'settled',
      () => 'settled'
    ),
    new Promise<string>((resolve) => setTimeout(() => resolve('pending'), 50)),
  ]);
}

describe('createBackgroundTasks', () => {
  it('returns before the task settles, and starts it', async () => {
    const { fastify } = fastifyStub();
    const tasks = createBackgroundTasks(fastify);
    const { promise, control } = deferred();
    const task = vi.fn(() => promise);

    tasks.run(task, 'failed');
    await Promise.resolve();
    await Promise.resolve();

    expect(task).toHaveBeenCalledOnce();
    control.resolve?.();
  });

  it('holds onClose until a running task settles', async () => {
    const { fastify, hooks } = fastifyStub();
    const tasks = createBackgroundTasks(fastify);
    const { promise, control } = deferred();

    tasks.run(() => promise, 'failed');
    if (!hooks.onClose) throw new Error('No onClose hook registered');
    const closing = hooks.onClose();

    expect(await settledSoon(closing)).toBe('pending');
    control.resolve?.();
    await expect(closing).resolves.toBeUndefined();
  });

  it('logs a failed task and does not fail onClose', async () => {
    const { fastify, hooks, log } = fastifyStub();
    const tasks = createBackgroundTasks(fastify);
    const { promise, control } = deferred();

    tasks.run(() => promise, 'Failed to send mail');
    if (!hooks.onClose) throw new Error('No onClose hook registered');
    const closing = hooks.onClose();
    control.reject?.(new Error('smtp down'));

    await expect(closing).resolves.toBeUndefined();
    expect(log.error).toHaveBeenCalledWith(expect.any(Error), 'Failed to send mail');
  });

  it('forgets a settled task, so onClose has nothing left to wait for', async () => {
    const { fastify, hooks } = fastifyStub();
    const tasks = createBackgroundTasks(fastify);

    tasks.run(async () => undefined, 'failed');
    await new Promise((resolve) => setTimeout(resolve, 0));
    if (!hooks.onClose) throw new Error('No onClose hook registered');

    expect(await settledSoon(hooks.onClose())).toBe('settled');
  });
});

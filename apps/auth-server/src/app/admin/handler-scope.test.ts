import type { FastifyInstance } from 'fastify';
import { describe, expect, it, vi } from 'vitest';

import { adminHandlerRepositories, runInAdminHandler } from './handler-scope';

type Repositories = FastifyInstance['repositories'];

/** A repository whose method calls another of its own without a transaction. */
function fixtureRepositories() {
  const calls: string[] = [];
  const users = {
    table: 'users',
    async findById(realmId: string, id: string, tx?: object) {
      calls.push(`findById:${realmId}:${id}:${tx === undefined ? 'pool' : 'tx'}`);
      return { id };
    },
    async touch(realmId: string, id: string, tx?: object) {
      // Its own method, called on itself: not checked again.
      await this.findById(realmId, id);
      calls.push(`touch:${tx === undefined ? 'pool' : 'tx'}`);
    },
  };
  const audit = {
    async append(tx: object, entry: string) {
      calls.push(`append:${entry}:${tx === undefined ? 'pool' : 'tx'}`);
    },
  };
  // A repository this process does not load, as the database plugin refuses it.
  const repositories = new Proxy({ users, audit } as Record<string, unknown>, {
    get(target, property, receiver) {
      if (property === 'realmKeys') {
        throw new Error('The realmKeys repository is not loaded in this process');
      }
      return Reflect.get(target, property, receiver);
    },
  });
  return { calls, raw: users, repositories: repositories as unknown as Repositories };
}

interface FixtureView {
  users: {
    table: string;
    findById(realmId: string, id: string, tx?: object): Promise<{ id: string }>;
    touch(realmId: string, id: string, tx?: object): Promise<void>;
  };
  audit: { append(tx: object, entry: string): Promise<void> };
  realmKeys: unknown;
}

function guardedView(repositories: Repositories): FixtureView {
  return adminHandlerRepositories(repositories) as unknown as FixtureView;
}

describe('the repositories of an admin handler (#517, the #887 review)', () => {
  it('works as the repositories do outside an admin handler', async () => {
    const { calls, repositories } = fixtureRepositories();
    const view = guardedView(repositories);

    await view.users.findById('r', 'u');
    expect(calls).toEqual(['findById:r:u:pool']);
    expect(view.users.table).toBe('users');
  });

  it("refuses, inside a handler, a call that does not pass the handler's transaction, before it runs", async () => {
    const { calls, repositories } = fixtureRepositories();
    const view = guardedView(repositories);
    const tx = {};

    await runInAdminHandler(tx, async () => {
      expect(() => view.users.findById('r', 'u')).toThrow(
        'An admin handler reaches the database only through adminTransaction(request): repositories.users.findById was called without it'
      );
      // Another transaction, such as a savepoint of it, is not the handler's.
      expect(() => view.users.findById('r', 'u', {})).toThrow(/repositories\.users\.findById/);
      // After an await too: the scope follows the handler's async calls.
      await Promise.resolve();
      expect(() => view.audit.append({}, 'row')).toThrow(/repositories\.audit\.append/);
    });
    expect(calls).toEqual([]);
  });

  it("runs, inside a handler, a call that passes the handler's transaction wherever its argument is", async () => {
    const { calls, repositories } = fixtureRepositories();
    const view = guardedView(repositories);
    const tx = {};

    await runInAdminHandler(tx, async () => {
      await view.users.findById('r', 'u', tx);
      await view.audit.append(tx, 'row');
      // Run on the repository itself: its own call without the transaction
      // is the repository's, not the handler's.
      await view.users.touch('r', 'u', tx);
    });
    expect(calls).toEqual(['findById:r:u:tx', 'append:row:tx', 'findById:r:u:pool', 'touch:tx']);
  });

  it('ends the scope with the handler, and keeps it per async context', async () => {
    const { calls, repositories } = fixtureRepositories();
    const view = guardedView(repositories);
    const tx = {};
    let release: () => void = () => undefined;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });

    const handler = runInAdminHandler(tx, async () => {
      await held;
      expect(() => view.users.findById('r', 'in-handler')).toThrow();
    });
    // Another request, outside any handler, at the same time.
    await view.users.findById('r', 'beside');
    release();
    await handler;
    await view.users.findById('r', 'after');
    expect(calls).toEqual(['findById:r:beside:pool', 'findById:r:after:pool']);
  });

  it('reads a repository when it is used, so one this process does not load fails as it does there', () => {
    const { repositories } = fixtureRepositories();
    const view = guardedView(repositories);

    expect(() => view.realmKeys).toThrow('The realmKeys repository is not loaded in this process');
    expect('users' in view).toBe(true);
  });

  it('guards a method replaced on the repository, such as a spy', async () => {
    const { raw, repositories } = fixtureRepositories();
    const view = guardedView(repositories);
    const spy = vi.spyOn(raw, 'findById').mockResolvedValue({ id: 'spied' });
    const tx = {};

    await expect(view.users.findById('r', 'u')).resolves.toEqual({ id: 'spied' });
    await runInAdminHandler(tx, async () => {
      expect(() => view.users.findById('r', 'u')).toThrow(/repositories\.users\.findById/);
      await expect(view.users.findById('r', 'u', tx)).resolves.toEqual({ id: 'spied' });
    });
    expect(spy).toHaveBeenCalledTimes(2);
  });
});

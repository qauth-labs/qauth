import { AsyncLocalStorage } from 'node:async_hooks';

import type { FastifyInstance } from 'fastify';

/**
 * WHERE AN ADMIN HANDLER REACHES THE DATABASE (#517, the second point of the
 * #887 review).
 *
 * The handler of an admin route runs inside the transaction its audit row
 * commits in, and holds that one connection of the shared pool for its whole
 * run. A repository call that does not pass it, `adminTransaction(request)`,
 * takes a second connection, so enough admin calls at once could exhaust the
 * pool the public listener serves from, and commits on its own, outside the
 * audited transaction. The pipeline runs each handler in a scope that holds
 * its transaction ({@link runInAdminHandler}), and the admin listener's
 * `repositories` ({@link adminHandlerRepositories}) refuse, inside that scope,
 * every call that does not pass it: the call throws, so the handler fails, its
 * transaction rolls back, and the call is `failed`.
 *
 * Outside a handler, in the stages before it and the audit row after it, the
 * repositories work as everywhere else.
 */

type Repositories = FastifyInstance['repositories'];

/** The transaction of the admin handler that runs, in its async context. */
const handlerTransactions = new AsyncLocalStorage<object>();

/**
 * Run `run`, the handler of an admin route, in the scope of `transaction`:
 * the scope ends when `run` returns, and the promise it returns keeps it until
 * it settles.
 */
export function runInAdminHandler<T>(transaction: object, run: () => T): T {
  return handlerTransactions.run(transaction, run);
}

/**
 * The repositories of the admin listener: `repositories`, each method of
 * which refuses, inside an admin handler, a call that does not pass the
 * handler's transaction among its arguments. A savepoint of it is another
 * transaction, so it is refused too. Each method runs on its own repository,
 * so a repository's calls to its own methods are not checked again. A
 * repository is read from `repositories` when it is first used, so one this
 * process does not load still fails as it does there.
 */
export function adminHandlerRepositories(repositories: Repositories): Repositories {
  const views = new WeakMap<object, object>();
  return new Proxy(repositories, {
    get(target, property, receiver) {
      const repository: unknown = Reflect.get(target, property, receiver);
      if (typeof repository !== 'object' || repository === null) return repository;
      let view = views.get(repository);
      if (view === undefined) {
        view = guardedRepository(String(property), repository);
        views.set(repository, view);
      }
      return view;
    },
  });
}

/** `repository`, whose methods refuse a call without the handler's transaction. */
function guardedRepository(name: string, repository: object): object {
  const methods = new WeakMap<(...args: unknown[]) => unknown, (...args: unknown[]) => unknown>();
  return new Proxy(repository, {
    get(target, property) {
      const value: unknown = Reflect.get(target, property, target);
      if (typeof value !== 'function') return value;
      const method = value as (...args: unknown[]) => unknown;
      let guarded = methods.get(method);
      if (guarded === undefined) {
        guarded = function guardedRepositoryCall(...args: unknown[]): unknown {
          const transaction = handlerTransactions.getStore();
          if (transaction !== undefined && !args.includes(transaction)) {
            throw new Error(
              `An admin handler reaches the database only through adminTransaction(request): repositories.${name}.${String(property)} was called without it`
            );
          }
          return Reflect.apply(method, target, args);
        };
        methods.set(method, guarded);
      }
      return guarded;
    },
  });
}

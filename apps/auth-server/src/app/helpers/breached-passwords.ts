import {
  type BreachCheckOutcome,
  type BreachCheckResult,
  type BreachedPasswordCheck,
  createBreachedPasswordChecker,
  createBreachRangeLookup,
  createRealmBreachCheck,
  createReloadableBreachList,
  type RealmBreachListSetting,
  type ReloadableBreachList,
} from '@qauth-labs/fastify-plugin-sign-in-engine';
import type { FastifyInstance } from 'fastify';

import type { RealmRow } from './request-realm';

declare module 'fastify' {
  interface FastifyInstance {
    /**
     * The deployment's breach list (#635, ADR-020 §3): the operator's local
     * list and the k-anonymity range lookup, checked as each realm's
     * `password.breachListSource` says.
     */
    breachedPasswords: ServerBreachedPasswords;
  }
}

/** The breach check of a process: one checker, one local list in memory, for every realm. */
export interface ServerBreachedPasswords {
  /**
   * Check `password`, in the form the credential stores (NFC for a new
   * password), against `realm`'s breach list. Never throws for a list or
   * lookup problem: that is `failed`, counted and logged here, and the caller
   * records the event and lets the password through.
   */
  check(realm: RealmRow, password: string): Promise<BreachCheckResult>;
  /** The sign-in engine's port: the same check, the realm read by its id. */
  readonly engine: BreachedPasswordCheck;
}

/** What the deployment provides: `BREACHED_PASSWORD_LIST_PATH` and `BREACHED_PASSWORD_RANGE_URL`. */
export interface BreachedPasswordsConfig {
  readonly listPath?: string;
  readonly rangeUrl?: string;
}

/**
 * Build the process's breach check (#635).
 *
 * - With `listPath`, the local list is loaded now, at boot, and again on each
 *   `SIGHUP`, without a restart. A load that fails is logged and keeps the
 *   list in use (none, at boot): every check of a realm whose source is
 *   `local` then fails as `list_not_loaded`, which never blocks a sign-in.
 * - With `rangeUrl`, the range lookup goes through `fastify.egress` (ADR-019
 *   Decision 8), as an operator destination, with the realm's name.
 * - Every result but `off` is counted on `qauth_breached_password_checks_total`;
 *   a failed one is logged as a warning too, never with the password.
 *
 * @throws TypeError when `rangeUrl` is not an acceptable range URL (the env
 *   schema refuses one first)
 */
export async function createServerBreachedPasswords(
  fastify: FastifyInstance,
  config: BreachedPasswordsConfig
): Promise<ServerBreachedPasswords> {
  const localList =
    config.listPath === undefined ? undefined : createReloadableBreachList(config.listPath);
  const rangeLookup =
    config.rangeUrl === undefined
      ? undefined
      : createBreachRangeLookup({ egress: fastify.egress, url: config.rangeUrl });
  const checker = createBreachedPasswordChecker({
    ...(localList === undefined ? {} : { localList }),
    ...(rangeLookup === undefined ? {} : { rangeLookup }),
    onResult: (result) => recordBreachCheck(fastify, result),
  });

  if (localList !== undefined) {
    await reloadBreachList(fastify, localList, 'boot');
    const onSighup = () => {
      void reloadBreachList(fastify, localList, 'SIGHUP');
    };
    process.on('SIGHUP', onSighup);
    fastify.addHook('onClose', async () => {
      process.off('SIGHUP', onSighup);
    });
  }

  const settingOf = (realm: RealmRow): RealmBreachListSetting => ({
    source: fastify.policyStore.ofRealm(realm).policies.password.breachListSource,
    name: realm.name,
  });

  return Object.freeze({
    async check(realm: RealmRow, password: string): Promise<BreachCheckResult> {
      const { source, name } = settingOf(realm);
      return checker.check({ source, password, realm: name });
    },
    engine: createRealmBreachCheck({
      checker,
      settingOf: async (realmId) => {
        const realm = await fastify.repositories.realms.findById(realmId);
        if (realm === undefined) throw new Error('breach check for a realm that does not exist');
        return settingOf(realm);
      },
    }),
  });
}

/** Load the local list again, and log what happened. Never rejects. */
async function reloadBreachList(
  fastify: FastifyInstance,
  list: ReloadableBreachList,
  trigger: 'boot' | 'SIGHUP'
): Promise<void> {
  const result = await list.reload();
  if (result.loaded) {
    fastify.log.info({ trigger, size: result.size }, 'breached-password list loaded');
  } else {
    // The message names a line number at most, never a line's content.
    fastify.log.error(
      { trigger, err: { name: result.error.name, message: result.error.message } },
      list.current() === null
        ? 'breached-password list did not load: checks of a local-list realm fail open'
        : 'breached-password list did not load: the list loaded before stays in use'
    );
  }
}

/** Count one check, and log a failed one. */
function recordBreachCheck(fastify: FastifyInstance, result: BreachCheckOutcome): void {
  if (fastify.hasDecorator('metrics')) {
    fastify.metrics.breachedPasswordChecks.inc({
      source: result.source,
      result: result.kind,
      reason: result.kind === 'failed' ? result.reason : '',
    });
  }
  if (result.kind === 'failed') {
    fastify.log.warn(
      { source: result.source, reason: result.reason },
      'breached-password check failed: the password is taken as not listed'
    );
  }
}

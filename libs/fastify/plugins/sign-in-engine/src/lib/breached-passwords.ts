import type {
  BreachCheckResult,
  BreachedPasswordChecker,
} from '@qauth-labs/server-breached-passwords';
import type { BreachCheckVerdict, BreachedPasswordCheck } from '@qauth-labs/server-sign-in-engine';

// What the auth server builds its breach check from (#635), from the library
// it may not import.
export {
  type BreachCheckOutcome,
  type BreachCheckResult,
  type BreachedPasswordChecker,
  type BreachListReloadResult,
  createBreachedPasswordChecker,
  createBreachRangeLookup,
  createReloadableBreachList,
  type ReloadableBreachList,
} from '@qauth-labs/server-breached-passwords';

/** What a realm's breach check reads of the realm: its source, and its name for the egress client. */
export interface RealmBreachListSetting {
  /** `password.breachListSource`. */
  readonly source: 'off' | 'local' | 'k_anonymity';
  /** The realm's name: the egress allowlist entries naming it apply to an internal mirror. */
  readonly name: string;
}

/** The engine's verdict for one of the checker's results. */
export function breachVerdictOf(result: BreachCheckResult): BreachCheckVerdict {
  switch (result.kind) {
    case 'off':
      return { kind: 'off' };
    case 'listed':
      return { kind: 'listed' };
    case 'not_listed':
      return { kind: 'not_listed' };
    case 'failed':
      return { kind: 'failed', failure: result.reason };
  }
}

/**
 * The sign-in engine's breach check (#635) over the deployment's checker:
 * each check reads the realm's `password.breachListSource` through
 * `settingOf`, then asks the checker. A realm `settingOf` cannot find throws,
 * which the engine counts as a failed check (`unavailable`): a failed check
 * never blocks a sign-in.
 */
export function createRealmBreachCheck(deps: {
  readonly checker: BreachedPasswordChecker;
  readonly settingOf: (realmId: string) => Promise<RealmBreachListSetting>;
}): BreachedPasswordCheck {
  return Object.freeze({
    async check({ realmId, password }: { readonly realmId: string; readonly password: string }) {
      const { source, name } = await deps.settingOf(realmId);
      return breachVerdictOf(await deps.checker.check({ source, password, realm: name }));
    },
  });
}

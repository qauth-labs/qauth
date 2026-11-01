import {
  fromStore,
  type IdentifierDigest,
  type LadderHook,
  type LadderVerdict,
  type PasswordHardAction,
} from '@qauth-labs/server-sign-in-engine';

import type { HardActionArming } from './password-hard-action';

/**
 * THE FAILURE LADDER FOR THE LEGACY LOGIN ROUTES (#615). `/ui/login` and
 * `/auth/login` check a password outside the sign-in engine; while they
 * exist they reserve and count on the engine's ladder, beside their own lock,
 * so guesses at one account add up across every surface, and they apply its
 * hard action. The order is the engine's password step's:
 *
 * 1. `reserve` before the credential is read: an attempt inside the wait is
 *    refused, neither verified nor counted; any error of the digest or of the
 *    store rejects with `SignInStoreUnavailableError`, and the route refuses
 *    the round before any credential is checked.
 * 2. One verification, then `failed` or `succeeded`. They never throw and
 *    never change the answer: the attempt is counted already, so a settle
 *    that fails is logged and leaves it counted.
 */

/** Where the gate reports what it cannot settle. */
export interface PasswordAttemptsLog {
  error(details: Record<string, unknown>, message: string): void;
}

/** What {@link createPasswordAttempts} needs: the ports the engine's password step uses. */
export interface PasswordAttemptsDependencies {
  readonly identifierDigest: IdentifierDigest;
  readonly ladder: LadderHook;
  readonly hardAction: PasswordHardAction;
  /** Whether the hard action is armed: the credential lookup honours a disabled mark only then. */
  readonly hardActionArmed: HardActionArming;
  readonly log: PasswordAttemptsLog;
}

/** One reserved attempt at a password. */
export interface ReservedPasswordAttempt {
  readonly kind: 'reserved';
  /**
   * The password was refused. `account` names the account the hard action
   * would disable: an account that exists and is enabled, whose password is
   * usable, else `null`. It is called only when the failure counted at the
   * ladder's hard ceiling, so a wrong password costs no further read.
   */
  failed(account: () => Promise<{ readonly userId: string } | null>): Promise<void>;
  /**
   * The password proved the account: its counter is cleared, and a disabled
   * mark the lookup ignored (the hard action unarmed) is cleared too.
   */
  succeeded(account: { readonly userId: string; readonly ignoredMark: boolean }): Promise<void>;
}

/** The ladder's verdict on an attempt. */
export type PasswordAttempt =
  | { readonly kind: 'wait'; readonly retryAfterSeconds: number }
  | ReservedPasswordAttempt;

/** The ladder, as the legacy login routes use it. */
export interface PasswordAttempts {
  /**
   * Reserve an attempt at the password of `identifier` (normalised) in the
   * realm, from `endUserIp` (the client address key, for the known-IP
   * exemption).
   *
   * @throws SignInStoreUnavailableError when the digest or the store fails: refuse the round
   */
  reserve(input: {
    readonly realmId: string;
    readonly identifier: string;
    readonly endUserIp?: string;
  }): Promise<PasswordAttempt>;
  /** Whether the hard action is armed in the realm; rejects on error, so the caller fails closed. */
  readonly hardActionArmed: HardActionArming;
}

/** The legacy login routes' gate onto the failure ladder. */
export function createPasswordAttempts(deps: PasswordAttemptsDependencies): PasswordAttempts {
  const report = (realmId: string, what: string, error: unknown) => {
    try {
      deps.log.error({ realmId, err: error }, `sign-in ladder: ${what} failed`);
    } catch {
      // A log that fails must not change the password's answer either.
    }
  };

  async function reserve(input: {
    readonly realmId: string;
    readonly identifier: string;
    readonly endUserIp?: string;
  }): Promise<PasswordAttempt> {
    const { realmId, identifier, endUserIp } = input;
    const identifierHmac = await fromStore('identifierDigest', () =>
      deps.identifierDigest({ realmId, identifier })
    );
    const reservation: LadderVerdict = await fromStore('ladder', () =>
      deps.ladder.reserve({
        realmId,
        identifierHmac,
        factor: 'password',
        ...(endUserIp === undefined ? {} : { endUserIp }),
      })
    );
    if (reservation.kind === 'wait') {
      return Object.freeze({ kind: 'wait', retryAfterSeconds: reservation.retryAfterSeconds });
    }
    let settled = false;
    const once = () => {
      if (settled) throw new Error('sign-in ladder: an attempt settled twice');
      settled = true;
    };
    return Object.freeze({
      kind: 'reserved',
      async failed(account) {
        once();
        let ceilingReached: boolean;
        try {
          ceilingReached = (await reservation.settle('failure'))?.ceilingReached === true;
        } catch (error) {
          report(realmId, 'settling a failure', error);
          return;
        }
        if (!ceilingReached) return;
        try {
          const target = await account();
          if (target !== null) {
            await deps.hardAction.ceilingReached({ realmId, userId: target.userId, identifier });
          }
        } catch (error) {
          report(realmId, 'the hard action', error);
        }
      },
      async succeeded({ userId, ignoredMark }) {
        once();
        try {
          await reservation.settle('success');
        } catch (error) {
          report(realmId, 'settling a success', error);
        }
        if (!ignoredMark) return;
        try {
          await deps.hardAction.clearIgnoredMark({ realmId, userId, identifier });
        } catch (error) {
          report(realmId, 'clearing an ignored mark', error);
        }
      },
    } satisfies ReservedPasswordAttempt);
  }

  return Object.freeze({ reserve, hardActionArmed: deps.hardActionArmed });
}

import type {
  PasswordAttempt,
  PasswordAttempts,
  ReservedPasswordAttempt,
} from '@qauth-labs/fastify-plugin-sign-in-engine';
import { type Mock, vi } from 'vitest';

/**
 * TEST SUPPORT — `fastify.passwordAttempts` (#615) for a login route's unit
 * test: every attempt is reserved unless a test says otherwise, the hard
 * action is unarmed, and each reservation is kept so a test can see how the
 * route settled it. The ladder's own rules are tested in
 * `@qauth-labs/fastify-plugin-sign-in-engine`.
 */
export interface FakePasswordAttempts extends PasswordAttempts {
  readonly reserve: Mock<PasswordAttempts['reserve']>;
  readonly hardActionArmed: Mock<PasswordAttempts['hardActionArmed']>;
  /** Every reservation handed out, in order. */
  readonly reserved: FakeReservation[];
  /**
   * Whether a failure counts at the ladder's hard ceiling: only then does
   * `failed` ask the route for the account, as the real gate does. Off by
   * default.
   */
  atCeiling: boolean;
}

/** One reservation, with how the route settled it. */
export interface FakeReservation extends ReservedPasswordAttempt {
  readonly failed: Mock<ReservedPasswordAttempt['failed']>;
  readonly succeeded: Mock<ReservedPasswordAttempt['succeeded']>;
  /** What the route named as the account at the hard ceiling, once `failed` asked it. */
  account?: { readonly userId: string } | null;
}

/** A fake gate: every attempt reserved, the hard action unarmed, no failure at the ceiling. */
export function createFakePasswordAttempts(): FakePasswordAttempts {
  const reserved: FakeReservation[] = [];
  const reserve = vi.fn<PasswordAttempts['reserve']>(async (): Promise<PasswordAttempt> => {
    const reservation: FakeReservation = {
      kind: 'reserved',
      failed: vi.fn(async (account) => {
        if (gate.atCeiling) reservation.account = await account();
      }),
      succeeded: vi.fn(async () => undefined),
    };
    reserved.push(reservation);
    return reservation;
  });
  const gate: FakePasswordAttempts = {
    reserve,
    hardActionArmed: vi.fn<PasswordAttempts['hardActionArmed']>(async () => false),
    reserved,
    atCeiling: false,
  };
  return gate;
}

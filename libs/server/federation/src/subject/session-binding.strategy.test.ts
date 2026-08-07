import { describe, expect, it, vi } from 'vitest';

import { validatedFixtureCredential } from '../../testing/subject-resolution.fixture';
import { createSessionBindingStrategy } from './session-binding.strategy';
import type { SubjectAccountLookup, SubjectResolutionContext } from './subject-resolution.types';

/**
 * `session-binding` (#300, ADR-009 §5) — the LINKING strategy.
 *
 * It answers "may this credential be attached to the account already in this
 * session?", not "which account is this?". So the assertions here are mostly
 * about what it does NOT do.
 */

/** A lookup that fails the test if it is ever consulted. */
function forbiddenLookup(): SubjectAccountLookup & { readonly calls: number[] } {
  const calls: number[] = [];
  return {
    calls,
    async byAssertedIdentifier() {
      calls.push(1);
      return [];
    },
    async byWalletSubject() {
      calls.push(1);
      return [];
    },
  };
}

function contextOf(
  lookup: SubjectAccountLookup,
  overrides: Partial<SubjectResolutionContext> = {}
): SubjectResolutionContext {
  return { realmId: 'realm-1', lookup, ...overrides };
}

describe('createSessionBindingStrategy (ADR-009 §5)', () => {
  it('resolves to the account the session already authenticated', async () => {
    const credential = await validatedFixtureCredential();

    await expect(
      createSessionBindingStrategy().resolve(
        credential,
        contextOf(forbiddenLookup(), { authenticatedUserId: 'user-7' })
      )
    ).resolves.toEqual({ kind: 'matched', userId: 'user-7' });
  });

  it('performs no account lookup at all — there is nothing to look up', async () => {
    // No candidate set means no ambiguity, no enumeration surface and no
    // `no-match`. The session either carries a user or it does not.
    const credential = await validatedFixtureCredential();
    const lookup = forbiddenLookup();

    await createSessionBindingStrategy().resolve(
      credential,
      contextOf(lookup, { authenticatedUserId: 'user-7', assertedIdentifier: 'alice@example.com' })
    );

    expect(lookup.calls).toEqual([]);
  });

  it.each([
    ['no session', undefined],
    ['an empty user id', ''],
    ['a non-string user id', 42],
  ])('refuses %s, and never reports no-match', async (_label, authenticatedUserId) => {
    // `no-match` is the one outcome a caller may turn into an enrolment. An
    // unauthenticated caller presenting a credential must never be a route to
    // creating or claiming an account — that is why linking is session-bound in
    // the first place (ADR-009 §1's second bootstrap case).
    const credential = await validatedFixtureCredential();

    const outcome = await createSessionBindingStrategy().resolve(
      credential,
      contextOf(forbiddenLookup(), {
        authenticatedUserId: authenticatedUserId as unknown as string | undefined,
      })
    );

    expect(outcome).toEqual({ kind: 'rejected' });
  });

  it('ignores an asserted identifier — the session decides, not the user input', async () => {
    const credential = await validatedFixtureCredential();

    await expect(
      createSessionBindingStrategy().resolve(
        credential,
        contextOf(forbiddenLookup(), {
          authenticatedUserId: 'user-7',
          assertedIdentifier: 'victim@example.com',
        })
      )
    ).resolves.toEqual({ kind: 'matched', userId: 'user-7' });
  });

  it('derives no external_sub — #238 owns the column value', async () => {
    // ADR-009 establishes the credential carries no stable subject; the linked
    // row's `external_sub` is the account's own identifier, read from the
    // session by the linking flow.
    const credential = await validatedFixtureCredential();

    expect(
      createSessionBindingStrategy().deriveExternalSub(
        credential,
        contextOf(forbiddenLookup(), { authenticatedUserId: 'user-7' })
      )
    ).toBeNull();
  });

  it('takes no configuration and holds no state between calls', async () => {
    const credential = await validatedFixtureCredential();
    const strategy = createSessionBindingStrategy();
    const onLookupError = vi.fn();

    await expect(
      strategy.resolve(
        credential,
        contextOf(forbiddenLookup(), { authenticatedUserId: 'user-a', onLookupError })
      )
    ).resolves.toEqual({ kind: 'matched', userId: 'user-a' });
    await expect(
      strategy.resolve(
        credential,
        contextOf(forbiddenLookup(), { authenticatedUserId: 'user-b', onLookupError })
      )
    ).resolves.toEqual({ kind: 'matched', userId: 'user-b' });
    expect(onLookupError).not.toHaveBeenCalled();
  });
});

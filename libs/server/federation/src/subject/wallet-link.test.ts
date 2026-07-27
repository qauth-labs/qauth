import { InvalidConfigurationError } from '@qauth-labs/shared-errors';
import { describe, expect, it, vi } from 'vitest';

import { validatedFixtureCredential } from '../../testing/subject-resolution.fixture';
import { readWalletBinding } from '../providers/wallet-credential-data';
import { createAssertedLookupStrategy } from './asserted-lookup.strategy';
import { createIssuerScopedClaimStrategy } from './issuer-scoped-claim.strategy';
import { deriveIssuerScopedSubject, deriveWalletBinding } from './subject-binding';
import type { SubjectAccountCandidate, SubjectAccountLookup } from './subject-resolution.types';
import type { SubjectResolutionConfig } from './subject-resolution-strategies';
import { prepareWalletLink, type WalletLinkContext } from './wallet-link';

/**
 * Account linking (#238, ADR-004 / ADR-009 §5) — attaching a wallet credential
 * to an account the user is ALREADY authenticated as.
 *
 * Every credential here is real: issued with a real signature, presented with a
 * real Key Binding JWT, and run through #234's validator. The claims a test
 * makes about refusals are therefore claims about credentials that are valid in
 * every respect — which is the only version worth making, since a validated
 * credential is exactly what an attacker would bring.
 */

const REALM = 'realm-1';
const OWNER = 'user-owner';
const OWNER_IDENTIFIER = 'owner@example.com';
const BINDING_CLAIMS = ['birth_date', 'family_name', 'given_name'];
const SUBJECT_CLAIM = 'personal_administrative_number';
const TEST_ISSUER = 'https://issuer.example.com';

const ASSERTED_LOOKUP: SubjectResolutionConfig = Object.freeze({
  strategy: 'asserted-lookup' as const,
  bindingClaims: BINDING_CLAIMS,
});

const ISSUER_SCOPED: SubjectResolutionConfig = Object.freeze({
  strategy: 'issuer-scoped-claim' as const,
  subjectClaim: SUBJECT_CLAIM,
  issuers: [TEST_ISSUER],
  fallback: { bindingClaims: BINDING_CLAIMS },
});

interface LookupTables {
  readonly wallet?: Record<string, readonly SubjectAccountCandidate[]>;
  readonly throws?: boolean;
}

function lookupOf(tables: LookupTables = {}): SubjectAccountLookup & {
  readonly walletCalls: string[][];
} {
  const walletCalls: string[][] = [];
  return {
    walletCalls,
    async byAssertedIdentifier() {
      // Linking never resolves an account from the presentation, so this half of
      // the port must stay untouched — asserted below.
      throw new Error('byAssertedIdentifier must not be called while linking');
    },
    async byWalletSubject(realmId, externalSub) {
      walletCalls.push([realmId, externalSub]);
      if (tables.throws) throw new Error('account store unavailable');
      return tables.wallet?.[externalSub] ?? [];
    },
  };
}

function contextOf(
  lookup: SubjectAccountLookup,
  overrides: Partial<WalletLinkContext> = {}
): WalletLinkContext {
  return {
    realmId: REALM,
    authenticatedUserId: OWNER,
    accountIdentifier: OWNER_IDENTIFIER,
    lookup,
    onLookupError: () => undefined,
    ...overrides,
  };
}

describe('prepareWalletLink — the session is the authority (ADR-009 §5)', () => {
  it('plans a wallet row for the authenticated account', async () => {
    const credential = await validatedFixtureCredential();
    const outcome = await prepareWalletLink(credential, ASSERTED_LOOKUP, contextOf(lookupOf()));

    expect(outcome).toMatchObject({
      kind: 'linkable',
      userId: OWNER,
      externalSub: OWNER_IDENTIFIER,
      subjectSource: 'asserted-lookup',
    });
  });

  it.each([
    ['absent', undefined],
    ['empty', ''],
    ['not a string', 42 as unknown as string],
  ] as const)(
    'refuses when the authenticated user id is %s — a presentation alone may never create a link',
    async (_label, userId) => {
      // The whole point of `session-binding`: without a session there is no
      // account to bind to, and treating the presentation as one would be the
      // takeover ADR-009 §1's second bootstrap case exists to prevent.
      const credential = await validatedFixtureCredential();

      const outcome = await prepareWalletLink(
        credential,
        ASSERTED_LOOKUP,
        contextOf(lookupOf(), { authenticatedUserId: userId as string })
      );

      expect(outcome).toEqual({ kind: 'rejected' });
    }
  );

  it('never looks an account up from the presentation', async () => {
    // `byAssertedIdentifier` throws in the fixture. Reaching it at all would
    // mean linking had started resolving an account from attacker-supplied
    // material instead of binding to the session.
    const credential = await validatedFixtureCredential();
    const outcome = await prepareWalletLink(credential, ASSERTED_LOOKUP, contextOf(lookupOf()));

    expect(outcome.kind).toBe('linkable');
  });

  it('takes external_sub from the ACCOUNT, not from anything the credential says', async () => {
    // ADR-009 §1: a linked wallet credential's `external_sub` is "the same
    // column PasswordProvider fills". If it came from the credential, a later
    // password login and a later wallet login would key on different values.
    const credential = await validatedFixtureCredential({
      claims: { given_name: 'Alice', family_name: 'Doe', birth_date: '1990-01-01' },
    });

    const outcome = await prepareWalletLink(
      credential,
      ASSERTED_LOOKUP,
      contextOf(lookupOf(), { accountIdentifier: '  Owner@Example.COM  ' })
    );

    // Normalized the same way `PasswordProvider` normalizes it, so the two rows
    // cannot disagree about what "the same account" means.
    expect(outcome).toMatchObject({ kind: 'linkable', externalSub: OWNER_IDENTIFIER });
  });

  it.each([
    ['blank', '   '],
    ['not a string', null as unknown as string],
    ['over-long', `${'a'.repeat(320)}@example.com`],
  ] as const)('refuses an unusable account identifier (%s)', async (_label, identifier) => {
    const credential = await validatedFixtureCredential();

    const outcome = await prepareWalletLink(
      credential,
      ASSERTED_LOOKUP,
      contextOf(lookupOf(), { accountIdentifier: identifier as string })
    );

    expect(outcome).toEqual({ kind: 'rejected' });
  });
});

describe('prepareWalletLink — the binding is what makes the link worth anything', () => {
  it('stores a binding the asserted-lookup strategy later accepts', async () => {
    // The acceptance criterion in one test: what linking WRITES is what a later
    // login CHECKS. Anything less makes the link a row that proves nothing.
    const credential = await validatedFixtureCredential();
    const outcome = await prepareWalletLink(credential, ASSERTED_LOOKUP, contextOf(lookupOf()));

    if (outcome.kind !== 'linkable') {
      expect.fail(`expected a write plan, got ${outcome.kind}`);
    }

    const stored = readWalletBinding(outcome.credentialData);
    expect(stored).toBe(deriveWalletBinding(credential, BINDING_CLAIMS));

    const login = await createAssertedLookupStrategy({ bindingClaims: BINDING_CLAIMS }).resolve(
      credential,
      {
        realmId: REALM,
        assertedIdentifier: outcome.externalSub,
        lookup: {
          async byAssertedIdentifier() {
            return [{ userId: outcome.userId, walletBinding: stored }];
          },
          async byWalletSubject() {
            return [];
          },
        },
      }
    );

    expect(login).toEqual({ kind: 'matched', userId: OWNER });
  });

  it('refuses a credential whose binding claims were withheld', async () => {
    // Selective disclosure means a holder may present a credential carrying
    // none of the configured binding claims. Linking it would write a row no
    // later presentation could ever match — so it is refused at link time,
    // where the user can be told, rather than at some future login.
    const credential = await validatedFixtureCredential({ claims: { nickname: 'ali' } });

    const outcome = await prepareWalletLink(credential, ASSERTED_LOOKUP, contextOf(lookupOf()));

    expect(outcome).toEqual({ kind: 'rejected' });
  });

  it('records the VALIDATED issuer and the credential type, not the asserted ones', async () => {
    const credential = await validatedFixtureCredential();
    const outcome = await prepareWalletLink(credential, ASSERTED_LOOKUP, contextOf(lookupOf()));

    if (outcome.kind !== 'linkable') expect.fail('expected a write plan');

    expect(outcome.credentialData.issuer).toBe(credential.issuer.identifier);
    expect(outcome.credentialData.vct).toBe(credential.credentialType);
  });

  it('refuses a credential whose issuer is not a branded ValidatedIssuer', async () => {
    // `as unknown as ValidatedIssuer` exists, and so do JSON round-trips. ADR-009
    // §2 makes the rule absolute, so it is enforced where the key is built.
    const credential = await validatedFixtureCredential();
    const forged = {
      ...credential,
      issuer: { identifier: TEST_ISSUER, keyResolution: 'issuer-metadata' },
    } as unknown as typeof credential;

    const outcome = await prepareWalletLink(forged, ASSERTED_LOOKUP, contextOf(lookupOf()));

    expect(outcome).toEqual({ kind: 'rejected' });
  });

  it('refuses when the credential carries no usable credential type', async () => {
    const credential = await validatedFixtureCredential();
    const broken = { ...credential, credentialType: '' } as unknown as typeof credential;

    const outcome = await prepareWalletLink(broken, ASSERTED_LOOKUP, contextOf(lookupOf()));

    expect(outcome).toEqual({ kind: 'rejected' });
  });

  it('throws on an unusable binding-claim configuration rather than linking unbound', async () => {
    // An operator error, not an attacker-reachable outcome — so it throws the
    // same InvalidConfigurationError the strategies throw. Degrading to a link
    // with no binding is ADR-009 §1's bypass arrived at through configuration.
    const credential = await validatedFixtureCredential();

    await expect(
      prepareWalletLink(
        credential,
        { strategy: 'asserted-lookup', bindingClaims: [] },
        contextOf(lookupOf())
      )
    ).rejects.toBeInstanceOf(InvalidConfigurationError);
  });
});

describe('#238 AC3 — after linking, either credential resolves to the SAME account', () => {
  it('keys the wallet row on the identifier the password credential already owns', async () => {
    // The acceptance criterion, end to end and with real cryptography. The
    // account store below is what `user_credentials` would hold after the link:
    //
    //   (realm, 'password', 'owner@example.com') → user-owner   [no binding]
    //   (realm, 'wallet',   'owner@example.com') → user-owner   [binding]
    //
    // ADR-009 §1 puts the wallet row's `external_sub` in "the same column
    // PasswordProvider fills", so both rows key on ONE identifier — which is
    // what makes a later wallet login land on the account the password login
    // lands on, and therefore mint a token with the identical `sub`.
    const credential = await validatedFixtureCredential();
    const plan = await prepareWalletLink(credential, ASSERTED_LOOKUP, contextOf(lookupOf()));

    if (plan.kind !== 'linkable') expect.fail('expected a write plan');

    // The password credential's `external_sub` — `normalizeEmail` of the
    // registered address — unchanged by linking.
    expect(plan.externalSub).toBe(OWNER_IDENTIFIER);

    const stored = readWalletBinding(plan.credentialData);
    const accountStore: SubjectAccountLookup = {
      async byAssertedIdentifier(_realmId, identifier) {
        if (identifier !== OWNER_IDENTIFIER) return [];
        return [
          // The password row: an account with NO wallet binding, which on its
          // own is ADR-009's second bootstrap case and a refusal.
          { userId: OWNER, walletBinding: null },
          // The row linking just planned.
          { userId: plan.userId, walletBinding: stored },
        ];
      },
      async byWalletSubject() {
        return [];
      },
    };

    const walletLogin = await createAssertedLookupStrategy({
      bindingClaims: BINDING_CLAIMS,
    }).resolve(credential, {
      realmId: REALM,
      assertedIdentifier: OWNER_IDENTIFIER,
      lookup: accountStore,
    });

    // Same `users.id` the password credential belongs to. `sub` is that id, so
    // the two logins are the same subject downstream.
    expect(walletLogin).toEqual({ kind: 'matched', userId: OWNER });
  });

  it('still refuses that same account BEFORE the link — linking is what changes the answer', async () => {
    // The control. Without the linked row the identical credential, asserting
    // the identical account, is refused — so the test above is passing because
    // of the link, not because `asserted-lookup` accepts anything.
    const credential = await validatedFixtureCredential();

    const beforeLinking = await createAssertedLookupStrategy({
      bindingClaims: BINDING_CLAIMS,
    }).resolve(credential, {
      realmId: REALM,
      assertedIdentifier: OWNER_IDENTIFIER,
      lookup: {
        async byAssertedIdentifier() {
          return [{ userId: OWNER, walletBinding: null }];
        },
        async byWalletSubject() {
          return [];
        },
      },
    });

    expect(beforeLinking).toEqual({ kind: 'rejected' });
  });
});

describe('prepareWalletLink — conflict detection is strategy-scoped (ADR-009 Negative)', () => {
  const SUBJECT_CLAIMS = {
    given_name: 'Alice',
    family_name: 'Doe',
    birth_date: '1990-01-01',
    [SUBJECT_CLAIM]: 'EMP-00042',
  };

  it('keys external_sub on (validated issuer, claim) under issuer-scoped-claim', async () => {
    const credential = await validatedFixtureCredential({ claims: SUBJECT_CLAIMS });
    const outcome = await prepareWalletLink(credential, ISSUER_SCOPED, contextOf(lookupOf()));

    expect(outcome).toMatchObject({
      kind: 'linkable',
      subjectSource: 'issuer-scoped-claim',
      externalSub: deriveIssuerScopedSubject(credential, SUBJECT_CLAIM),
    });
  });

  it('rejects linking a wallet whose stable subject is bound to a DIFFERENT account', async () => {
    // #238's conditional acceptance criterion, in the one configuration where it
    // is enforceable at all.
    const credential = await validatedFixtureCredential({ claims: SUBJECT_CLAIMS });
    const subject = deriveIssuerScopedSubject(credential, SUBJECT_CLAIM) as string;

    const outcome = await prepareWalletLink(
      credential,
      ISSUER_SCOPED,
      contextOf(
        lookupOf({ wallet: { [subject]: [{ userId: 'someone-else', walletBinding: 'wb1:x' }] } })
      )
    );

    expect(outcome).toEqual({ kind: 'conflict' });
  });

  it('permits re-linking the same wallet to the SAME account', async () => {
    const credential = await validatedFixtureCredential({ claims: SUBJECT_CLAIMS });
    const subject = deriveIssuerScopedSubject(credential, SUBJECT_CLAIM) as string;

    const outcome = await prepareWalletLink(
      credential,
      ISSUER_SCOPED,
      contextOf(lookupOf({ wallet: { [subject]: [{ userId: OWNER, walletBinding: 'wb1:x' }] } }))
    );

    expect(outcome).toMatchObject({ kind: 'linkable', userId: OWNER });
  });

  it('never reports a conflict under asserted-lookup — there is no key to detect one with', async () => {
    // ADR-009's Negative consequence, asserted rather than assumed: with
    // `external_sub` holding an account identifier there is no stable per-wallet
    // value, so the store is not even consulted. A check that looked like
    // duplicate detection here would report uniqueness that does not exist.
    const credential = await validatedFixtureCredential();
    const lookup = lookupOf({
      wallet: { [OWNER_IDENTIFIER]: [{ userId: 'other', walletBinding: null }] },
    });

    const outcome = await prepareWalletLink(credential, ASSERTED_LOOKUP, contextOf(lookup));

    expect(outcome.kind).toBe('linkable');
    expect(lookup.walletCalls).toEqual([]);
  });

  it('falls back to the account identifier when the issuer is not opted in', async () => {
    const credential = await validatedFixtureCredential({
      claims: SUBJECT_CLAIMS,
      issuer: 'https://other-issuer.example.com',
    });

    const outcome = await prepareWalletLink(credential, ISSUER_SCOPED, contextOf(lookupOf()));

    expect(outcome).toMatchObject({
      kind: 'linkable',
      subjectSource: 'asserted-lookup',
      externalSub: OWNER_IDENTIFIER,
    });
  });

  it('falls back to the account identifier when the subject claim was withheld', async () => {
    // ADR-009 §2: the holder may refuse even a mandatory attribute, so the
    // fallback is structural. A link that failed here would make the deployment
    // depend on a disclosure it cannot compel.
    const credential = await validatedFixtureCredential();

    const outcome = await prepareWalletLink(credential, ISSUER_SCOPED, contextOf(lookupOf()));

    expect(outcome).toMatchObject({
      kind: 'linkable',
      subjectSource: 'asserted-lookup',
      externalSub: OWNER_IDENTIFIER,
    });
  });

  it('refuses — never links — when the account store cannot answer the conflict question', async () => {
    // Writing the row anyway would resolve the conflict in the attacker's
    // favour, from a deployment that is merely degraded.
    const credential = await validatedFixtureCredential({ claims: SUBJECT_CLAIMS });
    const onLookupError = vi.fn();

    const outcome = await prepareWalletLink(
      credential,
      ISSUER_SCOPED,
      contextOf(lookupOf({ throws: true }), { onLookupError })
    );

    expect(outcome).toEqual({ kind: 'rejected' });
    expect(onLookupError).toHaveBeenCalledTimes(1);
  });

  it.each([
    ['a null candidate', [null as unknown as SubjectAccountCandidate]],
    ['a candidate with no user id', [{ userId: '', walletBinding: null }]],
  ] as const)('refuses when the store returns %s', async (_label, rows) => {
    const credential = await validatedFixtureCredential({ claims: SUBJECT_CLAIMS });
    const subject = deriveIssuerScopedSubject(credential, SUBJECT_CLAIM) as string;

    const outcome = await prepareWalletLink(
      credential,
      ISSUER_SCOPED,
      contextOf(lookupOf({ wallet: { [subject]: rows as readonly SubjectAccountCandidate[] } }))
    );

    expect(outcome).toEqual({ kind: 'rejected' });
  });

  it('stores a binding the issuer-scoped fallback can still check later', async () => {
    // The fallback's entitlement check has to be as strong as the primary key,
    // because the holder may withhold the subject claim on the very next login.
    const credential = await validatedFixtureCredential({ claims: SUBJECT_CLAIMS });
    const outcome = await prepareWalletLink(credential, ISSUER_SCOPED, contextOf(lookupOf()));

    if (outcome.kind !== 'linkable') expect.fail('expected a write plan');

    const stored = readWalletBinding(outcome.credentialData) as string;

    const withheld = await validatedFixtureCredential({
      claims: { given_name: 'Alice', family_name: 'Doe', birth_date: '1990-01-01' },
    });
    const fallbackLogin = await createIssuerScopedClaimStrategy({
      subjectClaim: SUBJECT_CLAIM,
      issuers: [TEST_ISSUER],
      fallback: { bindingClaims: BINDING_CLAIMS },
    }).resolve(withheld, {
      realmId: REALM,
      assertedIdentifier: OWNER_IDENTIFIER,
      lookup: {
        async byAssertedIdentifier() {
          return [{ userId: OWNER, walletBinding: stored }];
        },
        async byWalletSubject() {
          return [];
        },
      },
    });

    expect(fallbackLogin).toEqual({ kind: 'matched', userId: OWNER });
  });
});

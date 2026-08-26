import { describe, expect, it } from 'vitest';

import { assertAttestingIssuersUsable } from './attesting-issuers';

/**
 * The refusal class, obtained from a known-bad call rather than imported.
 *
 * `@qauth-labs/shared-errors` is not a dependency of this plugin — it reaches
 * the module under test transitively, through `server-federation` — and adding
 * it just so a test can name a class would make the dependency graph lie about
 * what this package needs. Same reasoning as `wallet-credential-verification.test.ts`.
 */
const REFUSAL_CLASS = (() => {
  try {
    assertAttestingIssuersUsable({ 'not-a-url': 'iso_18045_high' } as never);
    throw new Error('expected a malformed issuer identity to be refused');
  } catch (caught) {
    return (caught as Error).constructor as new (...args: never[]) => Error;
  }
})();

/**
 * The boot-time agreement gate for `OID4VP_ATTESTING_ISSUERS` (#308/#379).
 *
 * `server-config` validates each key with `z.url({ protocol: /^https$/ })`;
 * the runtime reduces the SAME key with `canonicalizeIssuerIdentifier`, which
 * additionally refuses userinfo, a query string and a fragment. The values below
 * are exactly the ones that pass the first rule set and fail the second — the
 * gap this gate closes.
 *
 * Why it must be a BOOT failure: the resolver that would notice is built lazily
 * at the first presentation, and its throw is caught on the request path and
 * rendered as the same uniform refusal a forged credential gets. Without this
 * gate the deployment starts clean and then silently resolves every credential
 * from that ecosystem to `assurance: 'none'` — so an entry demanding hardware
 * key storage grants `'low'` to a wallet that satisfies it.
 */
describe('assertAttestingIssuersUsable — schema-valid but runtime-unusable (#308/#379)', () => {
  it.each([
    ['a query string', 'https://pid.issuer.example?tenant=a'],
    ['a fragment', 'https://pid.issuer.example#frag'],
    ['userinfo', 'https://user:pw@pid.issuer.example'],
  ])('refuses the boot on an issuer identity carrying %s', (_label, issuer) => {
    // Each of these satisfies `z.url({ protocol: /^https$/ })`, so the env
    // schema already let it through — this is the second rule set running.
    expect(() => assertAttestingIssuersUsable({ [issuer]: 'iso_18045_high' })).toThrow(
      REFUSAL_CLASS
    );
  });

  it('refuses a grade this build does not order', () => {
    expect(() =>
      assertAttestingIssuersUsable({
        'https://pid.issuer.example': 'iso_18045_beyond-high',
      } as never)
    ).toThrow(REFUSAL_CLASS);
  });

  it('accepts a canonicalizable identity, so a correct deployment still boots', () => {
    expect(() =>
      assertAttestingIssuersUsable({ 'https://pid.issuer.example': 'iso_18045_high' })
    ).not.toThrow();
  });

  it.each([
    ['not configured', undefined],
    ['explicitly null', null],
    ['an empty map', {}],
  ])(
    'starts when the variable is %s — nothing recorded is the fail-closed default',
    (_l, value) => {
      expect(() => assertAttestingIssuersUsable(value)).not.toThrow();
    }
  );

  it('names the offending value in details rather than in the message', () => {
    // Same discipline as `assertTrustedIssuersUsable`: the message is stable
    // operator copy; the operator-written value travels on `details`.
    const error: Error | undefined = (() => {
      try {
        assertAttestingIssuersUsable({ 'https://pid.issuer.example?x=1': 'iso_18045_high' });
        return undefined;
      } catch (caught) {
        return caught as Error;
      }
    })();

    expect(error).toBeInstanceOf(REFUSAL_CLASS);
    expect(error?.message).not.toContain('?x=1');
  });
});

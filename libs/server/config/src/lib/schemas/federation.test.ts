import { describe, expect, it } from 'vitest';

import { type FederationEnv, federationEnvSchema } from './federation';

describe('federationEnvSchema (WALLET_FEDERATION_ENABLED — #232)', () => {
  it('is off by default when unset (epic #231 is incomplete)', () => {
    expect(federationEnvSchema.parse({}).WALLET_FEDERATION_ENABLED).toBe(false);
  });

  it.each([
    ['true', true],
    ['1', true],
    ['false', false],
    ['0', false],
  ])('coerces %s to %s', (raw, expected) => {
    expect(
      federationEnvSchema.parse({ WALLET_FEDERATION_ENABLED: raw }).WALLET_FEDERATION_ENABLED
    ).toBe(expected);
  });

  it.each(['yes', 'TRUE', 'on', ''])(
    'rejects the unrecognized value %o at parse time (never silently truthy)',
    (raw) => {
      expect(() => federationEnvSchema.parse({ WALLET_FEDERATION_ENABLED: raw })).toThrow();
    }
  );

  it('exposes a plain object shape so auth-server can spread it into its env schema', () => {
    // A `.superRefine()`/`.transform()`-wrapped schema has no `.shape`, which
    // would break `z.object({ ...federationEnvSchema.shape })` in env.ts. Both
    // fields wrap themselves (`.transform()`, `z.preprocess()`), which is fine;
    // this asserts neither wrapper has been hoisted up to the object.
    expect(Object.keys(federationEnvSchema.shape)).toEqual([
      'WALLET_FEDERATION_ENABLED',
      'OID4VP_VERIFIER_PROFILE',
    ]);
  });
});

describe('federationEnvSchema (OID4VP_VERIFIER_PROFILE — #299)', () => {
  it('is undefined when unset — absence means "refuse wallet flows", not a default', () => {
    // Unlike WALLET_FEDERATION_ENABLED, this has NO default. `haip-1.0` is not a
    // stricter `oid4vp-1.0-base`, so neither is safe to assume (#296 LOCKED).
    expect(federationEnvSchema.parse({}).OID4VP_VERIFIER_PROFILE).toBeUndefined();
  });

  it.each(['oid4vp-1.0-base', 'haip-1.0'])('accepts the shipped profile id %s', (raw) => {
    expect(
      federationEnvSchema.parse({ OID4VP_VERIFIER_PROFILE: raw }).OID4VP_VERIFIER_PROFILE
    ).toBe(raw);
  });

  it.each(['oid4vp', 'haip', 'HAIP-1.0', 'oid4vp-1.0', 'haip-1.1'])(
    'rejects %o at parse time so a typo fails the boot',
    (raw) => {
      // The dangerous alternative is a typo parsing to `undefined` and reading as
      // a deliberate opt-out, which would look identical to "not configured".
      expect(() => federationEnvSchema.parse({ OID4VP_VERIFIER_PROFILE: raw })).toThrow();
    }
  );

  it.each([
    ['an empty string', ''],
    ['spaces', '   '],
    ['a tab', '\t'],
    ['a newline', '\n'],
  ])('reads %s as unset rather than throwing', (_label, raw) => {
    // `parseEnv` parses the WHOLE composed auth-server env in one `.parse()` at
    // module import, so throwing here would take the process down before it
    // listens — password login and /token included — for a deployment with no
    // interest in wallet federation. A blank value is what an absent variable
    // looks like once compose expands `${OID4VP_VERIFIER_PROFILE:-}`, which is
    // this repo's own default form, so it must land where omission lands.
    expect(
      federationEnvSchema.parse({ OID4VP_VERIFIER_PROFILE: raw }).OID4VP_VERIFIER_PROFILE
    ).toBeUndefined();
  });

  it('still rejects a whitespace-padded profile id (blank is unset, not a trimmer)', () => {
    // Tolerating blanks must not turn into tolerating sloppiness: ' haip-1.0 '
    // is a stated intent that this schema cannot honour verbatim, so it fails
    // loudly instead of being silently normalised into a posture choice.
    expect(() => federationEnvSchema.parse({ OID4VP_VERIFIER_PROFILE: ' haip-1.0 ' })).toThrow();
  });

  it('narrows to the profile id union — the blank-tolerance wrapper must not widen the type', () => {
    // Compile-time assertion, pinned to the EXPORTED type rather than to this
    // call site (a call site can be steered by the contextual type; consumers
    // only ever see `FederationEnv`). If `z.preprocess` had widened the output to
    // `string`/`unknown` this stops compiling — the signal we want, because every
    // downstream `switch` on the profile id would silently lose exhaustiveness
    // and a newly added profile could fall through unhandled.
    const parsed: FederationEnv = federationEnvSchema.parse({
      OID4VP_VERIFIER_PROFILE: 'haip-1.0',
    });
    const profileId: 'oid4vp-1.0-base' | 'haip-1.0' | undefined = parsed.OID4VP_VERIFIER_PROFILE;
    expect(profileId).toBe('haip-1.0');
  });

  it('stays orthogonal to the enable flag — either may be set without the other', () => {
    const parsed = federationEnvSchema.parse({ OID4VP_VERIFIER_PROFILE: 'oid4vp-1.0-base' });
    expect(parsed.WALLET_FEDERATION_ENABLED).toBe(false);
    expect(parsed.OID4VP_VERIFIER_PROFILE).toBe('oid4vp-1.0-base');
  });
});

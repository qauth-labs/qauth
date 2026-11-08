import { describe, expect, it } from 'vitest';

import { EXPERIMENTAL_ITEMS } from './items';

/*
 * The checks of the registry against the repository (the decision records,
 * the docs pages and the evidence paths) live in the `docs-checks` project
 * (apps/docs-checks), beside the files they read (#1044).
 */

describe('the experimental-feature registry', () => {
  // The task list of #476: the six items of ADR-018 §4, the unbuilt ones
  // marked `built: false`.
  it('lists the six items of ADR-018 §4', () => {
    expect(EXPERIMENTAL_ITEMS.map((item) => item.id)).toEqual([
      'fipa-challenge-endpoint',
      'node-first-party',
      'oid4vp-1.0-base',
      'attestation-client-auth',
      'pass-through-leg',
      'plugin-api',
    ]);
  });

  it('marks only the oid4vp-1.0-base verifier profile and the plugin API as built', () => {
    expect(EXPERIMENTAL_ITEMS.filter((item) => item.built).map((item) => item.id)).toEqual([
      'oid4vp-1.0-base',
      'plugin-api',
    ]);
  });

  it('marks no item stable', () => {
    expect(EXPERIMENTAL_ITEMS.filter((item) => item.stable)).toEqual([]);
  });

  it('switches the pilot on with OID4VP_VERIFIER_PROFILE=oid4vp-1.0-base under wallet sign-in', () => {
    const pilot = EXPERIMENTAL_ITEMS.find((item) => item.id === 'oid4vp-1.0-base');
    expect(pilot).toMatchObject({
      surface: 'server',
      switchKey: 'OID4VP_VERIFIER_PROFILE',
      switchValue: 'oid4vp-1.0-base',
      requires: ['WALLET_FEDERATION_ENABLED=true'],
    });
  });

  // #477: the members ADR-017 §11 plans for its experimental items. Each is
  // the name its spec registers.
  it.each([
    ['fipa-challenge-endpoint', ['authorization_challenge_endpoint']],
    [
      'attestation-client-auth',
      [
        'client_attestation_signing_alg_values_supported',
        'client_attestation_pop_signing_alg_values_supported',
      ],
    ],
  ])('lists the discovery members of %s', (id, members) => {
    const item = EXPERIMENTAL_ITEMS.find((candidate) => candidate.id === id);
    expect(item?.discoveryMembers).toEqual(members);
  });
});

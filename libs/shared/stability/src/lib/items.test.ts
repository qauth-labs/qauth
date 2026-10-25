import { existsSync, readFileSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';

import { describe, expect, it } from 'vitest';

import { EXPERIMENTAL_ITEMS } from './items';
import { missingEvidencePaths, repositoryPathCheck } from './status';

const REPO_ROOT = resolve(__dirname, '..', '..', '..', '..', '..');

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

  it('marks only the oid4vp-1.0-base verifier profile as built', () => {
    expect(EXPERIMENTAL_ITEMS.filter((item) => item.built).map((item) => item.id)).toEqual([
      'oid4vp-1.0-base',
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

  it('documents the pilot on the wallet sign-in page', () => {
    const pilot = EXPERIMENTAL_ITEMS.find((item) => item.id === 'oid4vp-1.0-base');
    expect(pilot?.docsPage).toBe('/integrate/wallet-login/');
    expect(
      existsSync(join(REPO_ROOT, 'apps/docs-site/src/content/docs/integrate/wallet-login.md'))
    ).toBe(true);
  });

  // Where a decision record already names an item's switch, the registry uses
  // that name, so the area that builds the item does not invent another.
  it.each([
    ['fipa-challenge-endpoint', 'docs/adr/017-first-party-login.md', 'FIRST_PARTY_LOGIN_ENABLED'],
    ['pass-through-leg', 'docs/adr/016-agent-platform-bindings.md', 'PASS_THROUGH_LEG_ENABLED'],
  ])('names the switch of %s as its record does', (id, adr, key) => {
    const item = EXPERIMENTAL_ITEMS.find((candidate) => candidate.id === id);
    expect(item?.adr).toBe(adr);
    expect(item?.switchKey).toBe(key);
    expect(readFileSync(join(REPO_ROOT, adr), 'utf8')).toContain(`\`${key}\``);
  });

  it.each(EXPERIMENTAL_ITEMS.map((item) => [item.id, item.adr] as const))(
    '%s links a decision record that exists (%s)',
    (_id, adr) => {
      expect(existsSync(join(REPO_ROOT, adr))).toBe(true);
    }
  );

  it('names, in ADR-018 §4, every record the items link', () => {
    const adr018 = readFileSync(join(REPO_ROOT, 'docs/adr/018-1-0-scope-and-stability.md'), 'utf8');
    const section = adr018.slice(
      adr018.indexOf('### 4. Experimental in 1.0'),
      adr018.indexOf('### 5. The stability contract')
    );
    expect(section).toContain('ADR-017');
    expect(section).toContain('ADR-016 §4');
    expect(section).toContain('`oid4vp-1.0-base`');
    expect(section).toContain('`/first-party` subpath of `@qauth-labs/node`');
    expect(section).toContain('draft-ietf-oauth-attestation-based-client-auth');
    expect(section).toContain('The plugin API');
  });

  // Evidence is a link or a path that must exist (#476): a file, and a
  // section of it when one is named. The same check the script runs.
  it('names only files and sections that exist as evidence', () => {
    const pathExists = repositoryPathCheck({
      isFile: (path) =>
        existsSync(join(REPO_ROOT, path)) && statSync(join(REPO_ROOT, path)).isFile(),
      readText: (path) => readFileSync(join(REPO_ROOT, path), 'utf8'),
    });
    expect(
      EXPERIMENTAL_ITEMS.flatMap((item) =>
        missingEvidencePaths(item, pathExists).map((missing) => `${item.id} ${missing}`)
      )
    ).toEqual([]);
  });
});

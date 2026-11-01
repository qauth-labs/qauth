import { describe, expect, it } from 'vitest';

import { PolicyDefinitionError } from './field';
import { createPolicyStore, type RealmPolicyStorage } from './policy-store';
import { defaultsFromEnv } from './realm-policies';
import { type PolicySchemaUpgrade, REALM_POLICY_UPGRADES, upgradePathsTo } from './upgrades';
import {
  compareSchemaVersions,
  FIRST_REALM_POLICY_SCHEMA_VERSION,
  REALM_POLICY_SCHEMA_VERSION,
} from './version';

/**
 * The upgrades of stored realm policies (#908): the order of schema versions,
 * the rules an upgrade list is held to, and the contract that QAuth's own
 * list reads every version a release stored.
 */

const identity = (document: Record<string, unknown>) => document;
const step = (from: string, to: string): PolicySchemaUpgrade => ({ from, to, upgrade: identity });

describe('compareSchemaVersions', () => {
  it('puts a release candidate before its release, and a release before the next candidates', () => {
    const ordered = ['1-rc.0', '1-rc.1', '1-rc.2', '1-rc.10', '1', '2-rc.0', '2', '10-rc.3', '10'];
    for (const [index, version] of ordered.entries()) {
      for (const [other, otherVersion] of ordered.entries()) {
        expect(Math.sign(compareSchemaVersions(version, otherVersion))).toBe(
          Math.sign(index - other)
        );
      }
    }
  });

  it('refuses what is not a policy schema version', () => {
    for (const value of ['v1', '1-rc', '1-rc.01', '01', '1.0', '']) {
      expect(() => compareSchemaVersions(value, '1')).toThrow(TypeError);
      expect(() => compareSchemaVersions('1', value)).toThrow(TypeError);
    }
  });
});

describe('upgradePathsTo', () => {
  it('gives each older version the upgrades that lead from it to the target, in order', () => {
    const first = step('1-rc.0', '1-rc.1');
    const second = step('1-rc.1', '1-rc.3');
    const third = step('1-rc.3', '1');

    const paths = upgradePathsTo([third, first, second], '1');

    expect([...paths.keys()].sort()).toEqual(['1-rc.0', '1-rc.1', '1-rc.3']);
    expect(paths.get('1-rc.0')?.map((entry) => entry.to)).toEqual(['1-rc.1', '1-rc.3', '1']);
    expect(paths.get('1-rc.3')?.map((entry) => entry.to)).toEqual(['1']);
    // A version no release stored, between two that were, has no path.
    expect(paths.get('1-rc.2')).toBeUndefined();
  });

  it('has nothing to do with no upgrades', () => {
    expect(upgradePathsTo([], '1-rc.0').size).toBe(0);
  });

  it('refuses an upgrade list a store could not read every version with', () => {
    const refused: [string, PolicySchemaUpgrade[], string][] = [
      ['a version that is not one', [step('v1', '1-rc.1')], '1-rc.1'],
      ['a target that is not one', [step('1-rc.0', 'next')], '1-rc.1'],
      ['an upgrade that stays', [step('1-rc.1', '1-rc.1')], '1-rc.1'],
      ['an upgrade that goes back', [step('1-rc.1', '1-rc.0')], '1-rc.1'],
      ['an upgrade past the target', [step('1-rc.0', '1-rc.2')], '1-rc.1'],
      ['two upgrades from one version', [step('1-rc.0', '1-rc.1'), step('1-rc.0', '1')], '1'],
      ['a path that stops short', [step('1-rc.0', '1-rc.1')], '1-rc.2'],
      [
        'an upgrade with no function',
        [{ from: '1-rc.0', to: '1-rc.1' } as unknown as PolicySchemaUpgrade],
        '1-rc.1',
      ],
    ];
    for (const [, upgrades, target] of refused) {
      expect(() => upgradePathsTo(upgrades, target)).toThrow(PolicyDefinitionError);
    }
  });

  it('keeps a copy, so changing an upgrade later changes no path', () => {
    const upgrade = step('1-rc.0', '1-rc.1');
    const paths = upgradePathsTo([upgrade], '1-rc.1');

    (upgrade as { to: string }).to = '1-rc.0';

    expect(paths.get('1-rc.0')?.[0].to).toBe('1-rc.1');
    expect(Object.isFrozen(paths.get('1-rc.0'))).toBe(true);
  });
});

describe('REALM_POLICY_UPGRADES (contract, #908)', () => {
  it('leads from the first stored schema version to this release’s', () => {
    // A release that changes REALM_POLICY_SCHEMA_VERSION appends the upgrade
    // from the version before it (version.ts says what else it ships).
    // Without it, every realm a release stored is refused from then on.
    const paths = upgradePathsTo(REALM_POLICY_UPGRADES, REALM_POLICY_SCHEMA_VERSION);

    if (FIRST_REALM_POLICY_SCHEMA_VERSION === REALM_POLICY_SCHEMA_VERSION) {
      expect(REALM_POLICY_UPGRADES).toEqual([]);
    } else {
      expect(paths.get(FIRST_REALM_POLICY_SCHEMA_VERSION)?.at(-1)?.to).toBe(
        REALM_POLICY_SCHEMA_VERSION
      );
    }
    for (const upgrade of REALM_POLICY_UPGRADES) {
      expect(
        compareSchemaVersions(upgrade.from, FIRST_REALM_POLICY_SCHEMA_VERSION)
      ).toBeGreaterThanOrEqual(0);
    }
  });

  it('is what a store over the default registry reads with', () => {
    const storage = {} as RealmPolicyStorage<never, never>;

    expect(() => createPolicyStore({ storage, seeds: defaultsFromEnv({}) })).not.toThrow();
    expect(Object.isFrozen(REALM_POLICY_UPGRADES)).toBe(true);
  });
});

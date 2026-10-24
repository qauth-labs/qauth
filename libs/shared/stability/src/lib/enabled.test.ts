import { describe, expect, it } from 'vitest';

import {
  enabledExperimentalItems,
  experimentalBootWarning,
  experimentalDocsUrl,
  type ExperimentalSwitches,
  headingAnchor,
  serverSwitchKeys,
} from './enabled';
import { sampleItem } from './fixtures';
import { EXPERIMENTAL_ITEMS } from './items';

interface Config {
  readonly profile?: string;
  readonly wallet?: boolean;
}

const SWITCHES: ExperimentalSwitches<Config> = {
  'oid4vp-1.0-base': (config) => config.wallet === true && config.profile === 'oid4vp-1.0-base',
};

const ids = (config: Config) => enabledExperimentalItems(config, SWITCHES).map((item) => item.id);

describe('enabledExperimentalItems', () => {
  it('lists an item whose switch is on', () => {
    expect(ids({ wallet: true, profile: 'oid4vp-1.0-base' })).toEqual(['oid4vp-1.0-base']);
  });

  it.each([
    ['nothing is set', {}],
    ['the profile is the stable one', { wallet: true, profile: 'haip-1.0' }],
    ['wallet sign-in is off', { wallet: false, profile: 'oid4vp-1.0-base' }],
  ])('lists nothing when %s', (_label, config) => {
    expect(ids(config)).toEqual([]);
  });

  it('never lists an item that is not built, or an SDK item, whatever the switches say', () => {
    const items = [
      sampleItem({ id: 'unbuilt', built: false }),
      sampleItem({
        id: 'in-an-sdk',
        surface: 'sdk',
        switchKey: '@qauth-labs/node/sample',
        switchValue: null,
      }),
    ];
    const always = { 'oid4vp-1.0-base': () => true, unbuilt: () => true, 'in-an-sdk': () => true };
    expect(enabledExperimentalItems({}, always, items)).toEqual([]);
  });

  it('keeps registry order', () => {
    const items = [sampleItem({ id: 'b-item' }), sampleItem({ id: 'a-item' })];
    const switches = { 'oid4vp-1.0-base': () => true, 'a-item': () => true, 'b-item': () => true };
    expect(enabledExperimentalItems({}, switches, items).map((item) => item.id)).toEqual([
      'b-item',
      'a-item',
    ]);
  });
});

describe('experimentalBootWarning', () => {
  // The task list of #476: one warn line per enabled item, with the item id,
  // "may change in a minor release", and a docs link.
  it('names the item, says it may change in a minor release, and links its docs section', () => {
    const pilot = EXPERIMENTAL_ITEMS.find((item) => item.id === 'oid4vp-1.0-base');
    if (pilot === undefined) throw new Error('the pilot is not registered');

    expect(experimentalBootWarning(pilot)).toEqual({
      id: 'oid4vp-1.0-base',
      docs: 'https://docs.qauth.dev/reference/experimental-features/#oid4vp-10-base',
      message:
        'Experimental feature oid4vp-1.0-base is on. It may change in a minor release, ' +
        'without a deprecation window. See ' +
        'https://docs.qauth.dev/reference/experimental-features/#oid4vp-10-base',
    });
  });
});

describe('the docs link', () => {
  it.each([
    ['oid4vp-1.0-base', 'oid4vp-10-base'],
    ['plugin-api', 'plugin-api'],
  ])('of %s ends in the anchor Starlight gives its heading, #%s', (id, anchor) => {
    expect(headingAnchor(id)).toBe(anchor);
    expect(experimentalDocsUrl({ id })).toBe(
      `https://docs.qauth.dev/reference/experimental-features/#${anchor}`
    );
  });
});

describe('serverSwitchKeys', () => {
  it('lists the switch key of every server item, built or not, and no SDK import path', () => {
    expect([...serverSwitchKeys()].sort()).toEqual([
      'FIRST_PARTY_LOGIN_ENABLED',
      'OID4VP_VERIFIER_PROFILE',
      'PASS_THROUGH_LEG_ENABLED',
    ]);
  });
});

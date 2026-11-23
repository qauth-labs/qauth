/**
 * The status feed a release carries (`export.mts`). The committed feature
 * list is read too, so an entry that would break the release's feed fails
 * here first, in the unit suite.
 */
import { describe, expect, it } from 'vitest';

import type { FeatureStatus } from '../../apps/docs-site/src/lib/status.ts';
import { FEATURE_STATUS } from '../../apps/docs-site/src/lib/status.ts';
import { buildSiteStatus, SITE_STATUS_FORMAT, siteStatusProblems } from './export.mts';

const entry = (overrides: Partial<FeatureStatus>): FeatureStatus => ({
  id: 'passkey-sign-in',
  feature: 'Passkey sign-in',
  state: 'shipped',
  summary: 'Built.',
  ...overrides,
});

describe('the committed feature list', () => {
  it('makes a sound feed', () => {
    expect(siteStatusProblems(FEATURE_STATUS)).toEqual([]);
  });

  it('builds the feed a release attaches', () => {
    const feed = buildSiteStatus('0.2.10', FEATURE_STATUS);
    expect(feed.format).toBe(SITE_STATUS_FORMAT);
    expect(feed.version).toBe('0.2.10');
    expect(feed.features.map((feature) => feature.id)).toEqual(
      FEATURE_STATUS.map((feature) => feature.id)
    );
  });
});

describe('siteStatusProblems', () => {
  it('refuses an id that is not kebab-case', () => {
    expect(siteStatusProblems([entry({ id: 'Passkey_Sign_In' })])).toEqual([
      'Passkey_Sign_In: id is not kebab-case',
    ]);
  });

  it('refuses an id used twice', () => {
    expect(siteStatusProblems([entry({}), entry({ feature: 'Other' })])).toEqual([
      'passkey-sign-in: id is used twice',
    ]);
  });

  it('refuses a planned entry that names no tracking issue after "Open:"', () => {
    expect(
      siteStatusProblems([entry({ state: 'planned', summary: 'Planned for 1.0 (#673).' })])
    ).toEqual(['passkey-sign-in: a planned entry names its tracking issue after "Open:"']);
    expect(
      siteStatusProblems([
        entry({ state: 'planned', summary: 'Planned. Open: the plugin (#673).' }),
      ])
    ).toEqual([]);
  });
});

describe('buildSiteStatus', () => {
  it('publishes the id, the name, the state and the flag, and not the summary', () => {
    const feed = buildSiteStatus('1.0.0-rc.2', [
      entry({ state: 'partial', flag: { name: 'WEBAUTHN_ENABLED', default: 'off' } }),
      entry({ id: 'api-keys', feature: 'API keys' }),
    ]);
    expect(feed).toEqual({
      format: 'qauth-status/1-rc.0',
      version: '1.0.0-rc.2',
      features: [
        {
          id: 'passkey-sign-in',
          name: 'Passkey sign-in',
          state: 'partial',
          flag: { name: 'WEBAUTHN_ENABLED', default: 'off' },
        },
        { id: 'api-keys', name: 'API keys', state: 'shipped' },
      ],
    });
  });

  it('refuses a version that is not X.Y.Z or X.Y.Z-rc.N', () => {
    for (const version of ['v0.2.10', '0.2', '1.0.0-beta.1', '']) {
      expect(() => buildSiteStatus(version, [entry({})])).toThrow(/is not X\.Y\.Z/);
    }
  });

  it('refuses an unsound list', () => {
    expect(() => buildSiteStatus('0.2.10', [entry({}), entry({})])).toThrow(/id is used twice/);
  });
});

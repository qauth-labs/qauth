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

  it.each(['planned', 'partial'] as const)(
    'refuses a %s entry that lists no open issue after "Open:"',
    (state) => {
      const refusal =
        `passkey-sign-in: a ${state} entry lists its open work with an issue, after "Open:" (#N); ` +
        'if none is left, the feature is shipped';
      // An issue outside the open-work list, or open work with no issue, is not enough.
      expect(siteStatusProblems([entry({ state, summary: 'Built (#651).' })])).toEqual([refusal]);
      expect(
        siteStatusProblems([entry({ state, summary: 'Built (#651). Open: provider icons.' })])
      ).toEqual([refusal]);
      expect(
        siteStatusProblems([entry({ state, summary: 'Built (#651). Open: the screens (#652).' })])
      ).toEqual([]);
    }
  );

  it('lets a shipped entry name no open work', () => {
    expect(siteStatusProblems([entry({ summary: 'Built (#651).' })])).toEqual([]);
  });
});

describe('buildSiteStatus', () => {
  it('publishes the id, the name, the state and the flag, and not the summary', () => {
    const feed = buildSiteStatus('1.0.0-rc.2', [
      entry({
        state: 'partial',
        summary: 'Built (#651). Open: the screens (#652).',
        flag: { name: 'WEBAUTHN_ENABLED', default: 'off' },
      }),
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

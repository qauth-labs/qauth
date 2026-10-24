import type { ConditionEvidence, ExperimentalItem } from './item';

/**
 * Registry entries for this library's tests. Not exported from the package.
 */

export const none: ConditionEvidence = { evidence: [] };

/** A built server item with nothing proven, valid as it stands. */
export const sampleItem = (overrides: Partial<ExperimentalItem> = {}): ExperimentalItem => ({
  id: 'sample-feature',
  title: 'A sample feature',
  description: 'A feature for this test.',
  adr: 'docs/adr/018-1-0-scope-and-stability.md',
  surface: 'server',
  switchKey: 'SAMPLE_FEATURE_ENABLED',
  switchValue: 'true',
  requires: [],
  spec: { name: 'A sample draft', url: 'https://example.com/sample', status: 'draft' },
  built: true,
  stable: false,
  conditions: {
    'spec-final': none,
    'external-beta': none,
    'external-audit': none,
    'conformance-tests': none,
  },
  ...overrides,
});

/** Evidence for all four conditions, on a Final spec. */
export const PROVEN: Pick<ExperimentalItem, 'spec' | 'conditions'> = {
  spec: { name: 'A sample final', url: 'https://example.com/final', status: 'final' },
  conditions: {
    'spec-final': { evidence: ['https://example.com/final'] },
    'external-beta': { evidence: ['#900'] },
    'external-audit': { evidence: ['docs/adr/018-1-0-scope-and-stability.md#8-assurance'] },
    'conformance-tests': { evidence: ['RFC 9449'] },
  },
};

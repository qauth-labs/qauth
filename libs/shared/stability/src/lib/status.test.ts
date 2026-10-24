import { describe, expect, it } from 'vitest';

import { none, PROVEN, sampleItem } from './fixtures';
import { EXPERIMENTAL_ITEMS } from './items';
import {
  describeSwitch,
  mayBecomeStable,
  missingEvidencePaths,
  renderPromotionStatus,
  stableCheckFailures,
} from './status';

const everythingExists = () => true;
const nothingExists = () => false;

describe('stableCheckFailures', () => {
  it('passes the registry', () => {
    expect(stableCheckFailures(EXPERIMENTAL_ITEMS, everythingExists)).toEqual([]);
  });

  it('fails a stable item with a condition that lacks evidence', () => {
    const item = sampleItem({
      stable: true,
      ...PROVEN,
      conditions: { ...PROVEN.conditions, 'conformance-tests': none },
    });
    expect(stableCheckFailures([item], everythingExists)).toEqual([
      'sample-feature: stable, but condition conformance-tests has no evidence',
    ]);
  });

  it('passes a stable item with evidence for all four conditions', () => {
    expect(
      stableCheckFailures([sampleItem({ stable: true, ...PROVEN })], everythingExists)
    ).toEqual([]);
  });

  it('fails a stable item whose evidence names a path that does not exist', () => {
    expect(stableCheckFailures([sampleItem({ stable: true, ...PROVEN })], nothingExists)).toEqual([
      'sample-feature: stable, but the evidence of external-audit: docs/adr/018-1-0-scope-and-stability.md#8-assurance does not exist',
    ]);
  });

  it('checks the file of a path, not its section', () => {
    const seen: string[] = [];
    missingEvidencePaths(sampleItem(PROVEN), (path) => {
      seen.push(path);
      return true;
    });
    expect(seen).toEqual(['docs/adr/018-1-0-scope-and-stability.md']);
  });
});

describe('mayBecomeStable', () => {
  it('holds for a built item that is not stable yet and has evidence for every condition', () => {
    expect(mayBecomeStable(sampleItem(PROVEN), everythingExists)).toBe(true);
  });

  it.each([
    ['a condition lacks evidence', sampleItem()],
    ['it is not built', sampleItem({ ...PROVEN, built: false })],
    ['it is stable already', sampleItem({ ...PROVEN, stable: true })],
  ])('does not hold when %s', (_label, item) => {
    expect(mayBecomeStable(item, everythingExists)).toBe(false);
  });

  it('does not hold when a path evidence does not exist', () => {
    expect(mayBecomeStable(sampleItem(PROVEN), nothingExists)).toBe(false);
  });
});

describe('describeSwitch', () => {
  it.each([
    [
      'oid4vp-1.0-base',
      'OID4VP_VERIFIER_PROFILE=oid4vp-1.0-base, with WALLET_FEDERATION_ENABLED=true',
    ],
    ['node-first-party', '@qauth-labs/node/first-party'],
    ['plugin-api', 'none named yet'],
  ])('describes the switch of %s', (id, text) => {
    const item = EXPERIMENTAL_ITEMS.find((candidate) => candidate.id === id);
    if (item === undefined) throw new Error(`${id} is not registered`);
    expect(describeSwitch(item)).toBe(text);
  });
});

describe('renderPromotionStatus', () => {
  const output = renderPromotionStatus(EXPERIMENTAL_ITEMS, everythingExists);

  // The task list of #476: the script prints the four conditions per item.
  it.each(EXPERIMENTAL_ITEMS.map((item) => [item.id] as const))(
    'prints the four conditions of %s',
    (id) => {
      const block = output.split('\n\n').find((part) => part.startsWith(`${id}: `)) ?? '';
      expect(block).toMatch(/\[[ x]\] 1\. The spec it implements is an RFC or a Final/);
      expect(block).toMatch(/\[[ x]\] 2\. It has seen external use in a beta\./);
      expect(block).toMatch(/\[[ x]\] 3\. The external audit covered it\./);
      expect(block).toMatch(/\[[ x]\] 4\. Conformance tests exist for it\./);
    }
  );

  it('ticks a condition with evidence and lists the evidence under it', () => {
    expect(output).toContain(
      '  [x] 1. The spec it implements is an RFC or a Final specification.\n' +
        '        https://openid.net/specs/openid-4-verifiable-presentations-1_0.html\n'
    );
  });

  it('names the items that may become stable, or none', () => {
    expect(output.trimEnd().split('\n').at(-1)).toBe('May become stable: none.');
    expect(renderPromotionStatus([sampleItem(PROVEN)], everythingExists)).toContain(
      'May become stable: sample-feature.'
    );
  });

  it('marks evidence that names a missing path', () => {
    expect(renderPromotionStatus([sampleItem(PROVEN)], nothingExists)).toContain(
      'docs/adr/018-1-0-scope-and-stability.md#8-assurance (does not exist)'
    );
  });
});

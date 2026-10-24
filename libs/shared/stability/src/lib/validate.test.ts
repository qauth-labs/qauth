import { describe, expect, it } from 'vitest';

import { none, PROVEN, sampleItem } from './fixtures';
import type { ExperimentalItem } from './item';
import { EXPERIMENTAL_ITEMS } from './items';
import { missingEvidence, registryShapeProblems, validateExperimentalRegistry } from './validate';

describe('validateExperimentalRegistry', () => {
  it('passes the registry', () => {
    expect(validateExperimentalRegistry(EXPERIMENTAL_ITEMS)).toEqual([]);
  });

  it('passes a valid item', () => {
    expect(validateExperimentalRegistry([sampleItem()])).toEqual([]);
  });

  // The acceptance criteria of #476: a duplicate id, a missing ADR link, and a
  // built item with no switch key each fail the registry.
  it('fails on a duplicate id', () => {
    expect(validateExperimentalRegistry([sampleItem(), sampleItem()])).toEqual([
      'sample-feature: registered twice',
    ]);
  });

  it.each([
    ['empty', ''],
    ['blank', '  '],
    ['missing', undefined as unknown as string],
  ])('fails on an ADR link that is %s', (_label, adr) => {
    expect(validateExperimentalRegistry([sampleItem({ adr })])).toEqual([
      'sample-feature: the ADR link is missing',
    ]);
  });

  it('fails on an ADR link that is not a decision record path', () => {
    expect(
      validateExperimentalRegistry([sampleItem({ adr: 'https://docs.qauth.dev/adr/018' })])
    ).toEqual(['sample-feature: the ADR link must be a docs/adr/NNN-<name>.md path']);
  });

  it('fails on a built item with no switch key', () => {
    expect(
      validateExperimentalRegistry([sampleItem({ switchKey: null, switchValue: null })])
    ).toEqual(['sample-feature: a built item needs a switch key']);
  });

  it('accepts an item that is not built and has no switch key yet', () => {
    expect(
      validateExperimentalRegistry([
        sampleItem({ built: false, switchKey: null, switchValue: null }),
      ])
    ).toEqual([]);
  });

  it.each([
    ['an id with capitals', { id: 'Sample' }, 'the id must be lower-case'],
    ['an id with a space', { id: 'sample feature' }, 'the id must be lower-case'],
    ['no title', { title: '' }, 'the title is missing'],
    ['no description', { description: ' ' }, 'the description is missing'],
    ['a lower-case server switch', { switchKey: 'sample_enabled' }, 'a configuration key'],
    ['a server switch with no value', { switchValue: null }, 'needs the value'],
    [
      'an SDK switch that is not an import path',
      { surface: 'sdk', switchKey: 'SAMPLE', switchValue: null },
      'an @qauth-labs/... import path',
    ],
    [
      'an SDK switch with a value',
      { surface: 'sdk', switchKey: '@qauth-labs/node/sample', switchValue: 'true' },
      'has no value',
    ],
    ['a required setting with no value', { requires: ['OTHER_ENABLED'] }, 'KEY=value'],
    [
      'an unknown surface on an item with no switch',
      { built: false, surface: 'cli', switchKey: null, switchValue: null },
      'the surface must be server or sdk',
    ],
    [
      'a spec URL over http',
      { spec: { name: 'x', url: 'http://example.com', status: 'draft' } },
      'an https link',
    ],
    [
      'an unknown spec status',
      { spec: { name: 'x', url: 'https://example.com', status: 'proposed' } },
      'the spec status must be one of draft, rfc, final',
    ],
    ['a stable item that is not built', { built: false, stable: true, ...PROVEN }, 'not built'],
  ] as const)('fails on %s', (_label, overrides, message) => {
    const problems = validateExperimentalRegistry([
      sampleItem(overrides as Partial<ExperimentalItem>),
    ]);
    expect(problems).toHaveLength(1);
    expect(problems[0]).toContain(message);
  });

  it('fails on evidence of no known form', () => {
    const item = sampleItem({
      conditions: { ...sampleItem().conditions, 'external-beta': { evidence: ['a beta ran'] } },
    });
    expect(validateExperimentalRegistry([item])).toEqual([
      'sample-feature: condition external-beta: "a beta ran" is not an RFC number, an issue, an https link or a repository path',
    ]);
  });

  it('fails on a missing condition and on an unknown one', () => {
    const conditions = {
      'spec-final': none,
      'external-beta': none,
      'external-audit': none,
      'conformance-suite': none,
    } as unknown as ExperimentalItem['conditions'];
    expect(validateExperimentalRegistry([sampleItem({ conditions })])).toEqual([
      'sample-feature: there is no promotion condition conformance-suite',
      'sample-feature: condition conformance-tests is missing; write it with no evidence',
    ]);
  });

  it('ties condition spec-final to the spec status', () => {
    expect(
      validateExperimentalRegistry([
        sampleItem({ conditions: { ...PROVEN.conditions, 'external-beta': none } }),
      ])
    ).toEqual(['sample-feature: condition spec-final has evidence, but the spec is a draft']);
    expect(
      validateExperimentalRegistry([
        sampleItem({ spec: { name: 'x', url: 'https://example.com', status: 'rfc' } }),
      ])
    ).toEqual(['sample-feature: the spec is rfc, so condition spec-final needs evidence']);
  });

  it('fails on a stable item with a condition that has no evidence', () => {
    const item = sampleItem({
      stable: true,
      ...PROVEN,
      conditions: { ...PROVEN.conditions, 'external-audit': none },
    });
    expect(validateExperimentalRegistry([item])).toEqual([
      'sample-feature: stable, but condition external-audit has no evidence',
    ]);
  });

  it('passes a stable item with evidence for all four conditions', () => {
    expect(validateExperimentalRegistry([sampleItem({ stable: true, ...PROVEN })])).toEqual([]);
  });
});

describe('the docs anchor of an item', () => {
  it('fails on two ids that give the same anchor', () => {
    expect(
      validateExperimentalRegistry([
        sampleItem({ id: 'oid4vp-1.0-base' }),
        sampleItem({ id: 'oid4vp-10-base' }),
      ])
    ).toEqual([
      'oid4vp-10-base: its docs anchor #oid4vp-10-base is the anchor of oid4vp-1.0-base too',
    ]);
  });

  it.each(['items', 'becoming-stable', 'what-experimental-means'])(
    'fails on the id %s, which a heading of the page already takes',
    (id) => {
      expect(validateExperimentalRegistry([sampleItem({ id })])).toEqual([
        `${id}: its docs anchor #${id} is taken by a heading of the docs page`,
      ]);
    }
  );
});

describe('registryShapeProblems', () => {
  it('passes the registry', () => {
    expect(registryShapeProblems(EXPERIMENTAL_ITEMS)).toEqual([]);
  });

  it('fails on something that is not an array', () => {
    expect(registryShapeProblems({ items: [] })).toEqual([
      'the registry must be an array of items',
    ]);
  });

  it('names every field of the wrong type', () => {
    expect(registryShapeProblems([{}])).toEqual([
      'item 1: id must be a string',
      'item 1: title must be a string',
      'item 1: description must be a string',
      'item 1: surface must be a string',
      'item 1: switchKey must be a string or null',
      'item 1: switchValue must be a string or null',
      'item 1: requires must be an array of strings',
      'item 1: built must be true or false',
      'item 1: stable must be true or false',
      'item 1: spec must have a name, a url and a status, each a string',
      'item 1: conditions must be an object',
    ]);
  });

  // In JSON, "false" is a string, and a string is truthy.
  it('fails on stable written as a string', () => {
    const item = { ...sampleItem(), stable: 'false' };
    expect(registryShapeProblems([item])).toEqual(['sample-feature: stable must be true or false']);
  });

  it('fails on a condition with no evidence array', () => {
    const item = {
      ...sampleItem(),
      conditions: { ...sampleItem().conditions, 'external-beta': {} },
    };
    expect(registryShapeProblems([item])).toEqual([
      'sample-feature: condition external-beta must hold an evidence array of strings and an optional note',
    ]);
  });

  it('runs first in validateExperimentalRegistry, so a malformed item never reaches the rules', () => {
    expect(validateExperimentalRegistry([{ id: 'x' } as unknown as ExperimentalItem])).toEqual(
      registryShapeProblems([{ id: 'x' }])
    );
  });
});

describe('missingEvidence', () => {
  it('lists the conditions with no evidence, in ADR-018 order', () => {
    expect(missingEvidence(sampleItem())).toEqual([
      'spec-final',
      'external-beta',
      'external-audit',
      'conformance-tests',
    ]);
    expect(
      missingEvidence(
        sampleItem({ ...PROVEN, conditions: { ...PROVEN.conditions, 'external-beta': none } })
      )
    ).toEqual(['external-beta']);
    expect(missingEvidence(sampleItem(PROVEN))).toEqual([]);
  });
});

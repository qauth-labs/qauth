import { describe, expect, it } from 'vitest';

import { experimentalSurfaceProblem } from './openapi-export-surface';

describe('experimentalSurfaceProblem', () => {
  const BUILT = ['oid4vp-1.0-base', 'sample-feature'];

  it('accepts a default surface that turns no item on', () => {
    expect(experimentalSurfaceProblem('default', [], BUILT)).toBeNull();
  });

  it('refuses a default surface that turns an item on', () => {
    expect(experimentalSurfaceProblem('default', ['oid4vp-1.0-base'], BUILT)).toBe(
      'the default surface turns experimental items on: oid4vp-1.0-base'
    );
  });

  it('accepts a maximal surface that turns every built item on', () => {
    expect(experimentalSurfaceProblem('maximal', [...BUILT], BUILT)).toBeNull();
  });

  it('refuses a maximal surface that leaves a built item off, naming each', () => {
    expect(experimentalSurfaceProblem('maximal', [], BUILT)).toBe(
      'the maximal surface leaves experimental items off: oid4vp-1.0-base, sample-feature'
    );
    expect(experimentalSurfaceProblem('maximal', ['sample-feature'], BUILT)).toBe(
      'the maximal surface leaves experimental items off: oid4vp-1.0-base'
    );
  });
});

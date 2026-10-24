import { describe, expect, it } from 'vitest';

import { isRouteSurface, ROUTE_SURFACES, routeSurfaceProblem } from './route-surface';

describe('route surfaces (#486)', () => {
  it('has the four classes the realm resolver knows', () => {
    expect(ROUTE_SURFACES).toEqual(['browser', 'api', 'meta', 'none']);
    for (const surface of ROUTE_SURFACES) expect(isRouteSurface(surface)).toBe(true);
    for (const value of ['public', 'BROWSER', '', undefined, null, 1]) {
      expect(isRouteSurface(value)).toBe(false);
    }
  });

  it('fails a route with no surface class, naming the route', () => {
    expect(routeSurfaceProblem({ method: 'GET', url: '/ui/new-page' })).toBe(
      "Route GET /ui/new-page has no config.surface; set one of 'browser', 'api', 'meta', 'none'"
    );
    expect(routeSurfaceProblem({ method: 'POST', url: '/x', config: {} })).toMatch(
      /^Route POST \/x has no config\.surface/
    );
  });

  it('fails a route whose surface is not a class', () => {
    expect(
      routeSurfaceProblem({ method: ['GET', 'HEAD'], url: '/x', config: { surface: 'public' } })
    ).toMatch(/^Route GET,HEAD \/x has an unknown config\.surface/);
  });

  it('passes a classified route', () => {
    for (const surface of ROUTE_SURFACES) {
      expect(routeSurfaceProblem({ method: 'GET', url: '/x', config: { surface } })).toBe(
        undefined
      );
    }
  });
});

/**
 * The flag surfaces `openapi-export.ts` exports the API under, and the check
 * of each one's experimental items (ADR-018 §5, #477). Kept apart from the
 * exporter, which boots the app when it loads, so the check has unit tests.
 */

/** Which feature switches the exported app boots with (see `openapi-export.ts`). */
export type FlagSurface = 'default' | 'maximal';

/**
 * Why the environment of `surface` cannot be exported, or `null` when it can.
 *
 * The default surface is what a deployment serves with every switch off, so
 * it turns no experimental item on. The maximal surface turns on every item
 * the server has a switch for, or an item's routes would be missing from both
 * documents and the stable-surface check could not require their tag.
 *
 * @param enabled the items the surface's environment turns on
 * @param builtServerItems the items the server has a switch for
 */
export function experimentalSurfaceProblem(
  surface: FlagSurface,
  enabled: readonly string[],
  builtServerItems: readonly string[]
): string | null {
  if (surface === 'default') {
    return enabled.length === 0
      ? null
      : `the default surface turns experimental items on: ${enabled.join(', ')}`;
  }
  const off = builtServerItems.filter((id) => !enabled.includes(id));
  return off.length === 0
    ? null
    : `the maximal surface leaves experimental items off: ${off.join(', ')}`;
}

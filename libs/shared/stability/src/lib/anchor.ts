/**
 * Heading anchors, as the docs site renders them. The boot warning links an
 * item's section by its anchor, and a `path#section` evidence names one.
 */

/**
 * The heading anchor Starlight renders for an ASCII heading, as its slugger
 * computes it: `oid4vp-1.0-base` becomes `oid4vp-10-base`,
 * `8. Assurance before 1.0` becomes `8-assurance-before-10`.
 */
export function headingAnchor(text: string): string {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9 _-]/g, '')
    .replace(/ /g, '-');
}

/** The headings of the experimental features page above its items, in order. */
export const PAGE_HEADINGS = ['What experimental means', 'Becoming stable', 'Items'] as const;

/** The anchors of the page's own headings, which no item id may take. */
export const RESERVED_ANCHORS: ReadonlySet<string> = new Set(PAGE_HEADINGS.map(headingAnchor));

/**
 * The heading anchors of a Markdown document. Fenced code is skipped, a link
 * in a heading counts as its text, and a repeated heading gets the `-1`, `-2`
 * suffixes the slugger gives it.
 */
export function markdownHeadingAnchors(markdown: string): ReadonlySet<string> {
  const anchors = new Set<string>();
  const seen = new Map<string, number>();
  let fenced = false;
  for (const line of markdown.split(/\r?\n/)) {
    if (/^\s*(```|~~~)/.test(line)) {
      fenced = !fenced;
      continue;
    }
    const heading = fenced ? null : /^#{1,6}\s+(.*?)\s*#*\s*$/.exec(line);
    if (heading === null) continue;
    const text = heading[1].replace(/\[([^\]]*)\]\([^)]*\)/g, '$1');
    const base = headingAnchor(text);
    const count = seen.get(base) ?? 0;
    seen.set(base, count + 1);
    anchors.add(count === 0 ? base : `${base}-${count}`);
  }
  return anchors;
}

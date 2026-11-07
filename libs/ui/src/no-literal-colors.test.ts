import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';

import { describe, expect, it } from 'vitest';

/** Tailwind's own palette. A component names a token (`bg-card`), never one of these. */
const LITERAL =
  /\b(?:bg|text|border|ring|ring-offset|outline|fill|stroke|from|via|to|divide|placeholder|decoration|shadow|accent|caret)-(?:slate|gray|zinc|neutral|stone|red|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink|rose|white|black)(?:-\d{2,3})?\b/g;

function sources(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return sources(path);
    return /\.(tsx?|css)$/.test(entry.name) && !/\.test\.tsx?$/.test(entry.name) ? [path] : [];
  });
}

describe('libs/ui', () => {
  it('uses no literal Tailwind colour utility', () => {
    const found = sources(__dirname).flatMap((file) =>
      [...readFileSync(file, 'utf8').matchAll(LITERAL)].map(
        (m) => `${relative(__dirname, file)}: ${m[0]}`
      )
    );
    expect(found).toEqual([]);
  });
});

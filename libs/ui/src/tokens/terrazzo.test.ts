import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

import { defineConfig, parse } from '@terrazzo/parser';
import { describe, expect, it } from 'vitest';

import { COLOR_TOKENS, oklchCss } from './read-tokens';

/**
 * The token file is also Terrazzo's input: delurio's kit for libs/ui (#561) compiles it with
 * Terrazzo. This proves Terrazzo reads it without an error and sees the same light and dark values
 * libs/ui generates its own CSS from.
 */
describe('the token file under Terrazzo', () => {
  it('parses, with both modes on every colour', async () => {
    const file = join(__dirname, 'tokens.json');
    const config = defineConfig({}, { cwd: pathToFileURL(`${__dirname}/`) });
    const { tokens } = await parse(
      [{ filename: pathToFileURL(file), src: readFileSync(file, 'utf8') }],
      { config, logger: undefined }
    );

    for (const token of COLOR_TOKENS) {
      const parsed = tokens[token.path];
      expect(parsed, token.path).toBeDefined();
      expect(Object.keys(parsed?.mode ?? {}).sort(), token.path).toEqual(['.', 'dark', 'light']);
      const dark = parsed?.mode['dark']?.$value as { components: number[]; alpha?: number };
      expect(
        oklchCss({
          l: dark.components[0] ?? NaN,
          c: dark.components[1] ?? NaN,
          h: dark.components[2] ?? NaN,
          alpha: dark.alpha ?? 1,
        }),
        token.path
      ).toBe(oklchCss(token.dark));
    }
  });
});

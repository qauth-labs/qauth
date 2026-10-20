import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

import { describe, expect, it } from 'vitest';

import { CONFIG_KEY_REGISTRY } from './keys';

/**
 * `.env.example` is where an operator starts, so every stable key appears in
 * it: set, or commented out with an example value.
 */

const ENV_EXAMPLE = readFileSync(
  join(resolve(__dirname, '../../../../../..'), '.env.example'),
  'utf8'
);

describe('.env.example', () => {
  it.each(CONFIG_KEY_REGISTRY.filter((key) => key.tier === 'stable').map((key) => key.name))(
    'shows the stable key %s',
    (name) => {
      expect(ENV_EXAMPLE).toMatch(new RegExp(`^(# )?${name}=`, 'm'));
    }
  );
});

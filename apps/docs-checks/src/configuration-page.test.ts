import { join } from 'node:path';

import {
  CONFIG_KEY_REGISTRY,
  CONFIGURATION_PAGE_PATH,
  renderConfigurationPage,
} from '@qauth-labs/server-config';
import { describe, expect, it } from 'vitest';

import { formatAs, REPO_ROOT } from './workspace';

/**
 * The configuration key registry of `@qauth-labs/server-config` against the
 * docs site. The library's own tests check what the page renders; this one
 * checks the committed page.
 */

const PAGE_PATH = join(REPO_ROOT, CONFIGURATION_PAGE_PATH);

describe('the configuration page', () => {
  // This test is the generator: when the registry changes,
  // `pnpm nx test docs-checks -- -u` rewrites the page, and without `-u` the
  // test fails until the committed page matches.
  it('is what the registry renders (regenerate with `pnpm nx test docs-checks -- -u`)', async () => {
    const page = formatAs(PAGE_PATH, renderConfigurationPage(CONFIG_KEY_REGISTRY));
    await expect(page).toMatchFileSnapshot(PAGE_PATH);
  });
});

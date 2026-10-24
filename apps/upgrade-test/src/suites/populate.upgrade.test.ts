import { describe, expect, it } from 'vitest';

import { upgradeConfig } from '../config';
import { writeScenario } from '../helpers/scenario';
import { readState, writeState } from '../state';

/**
 * Step 1 of the upgrade test, against the BASELINE release: write the
 * scenario's data through its HTTP API and save what the verify step needs.
 */
describe('populate the baseline release', () => {
  it('registers users, creates clients, runs the code flow with PKCE, consents and mints an API key', async () => {
    const { baseUrl, databaseUrl, statePath, mailUrl } = upgradeConfig();
    const state = await writeScenario(baseUrl, databaseUrl, mailUrl);
    writeState(statePath, state);
    expect(readState(statePath)).toEqual(state);
  });
});

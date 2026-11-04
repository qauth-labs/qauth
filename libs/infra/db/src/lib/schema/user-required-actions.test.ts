/**
 * The closed sets of `user_required_actions` (#635): the lists the code
 * exports are the ones the issue names, and the CHECKs the table declares are
 * built from them.
 */
import { getTableConfig } from 'drizzle-orm/pg-core';
import { describe, expect, it } from 'vitest';

import {
  USER_REQUIRED_ACTION_SOURCES,
  USER_REQUIRED_ACTIONS,
  userRequiredActions,
} from './user-required-actions';

describe('user_required_actions (#635)', () => {
  it('names the four actions and the two sources', () => {
    expect([...USER_REQUIRED_ACTIONS]).toEqual([
      'update_password',
      'setup_mfa',
      'setup_passkey',
      'complete_profile',
    ]);
    expect([...USER_REQUIRED_ACTION_SOURCES]).toEqual(['admin', 'user_report']);
  });

  it('declares one row per user and action, and the CHECKs on both closed sets', () => {
    const config = getTableConfig(userRequiredActions);
    expect(config.name).toBe('user_required_actions');
    const unique = config.indexes.find(
      (index) => index.config.name === 'idx_user_required_actions_user_action_unique'
    );
    expect(unique?.config.unique).toBe(true);
    expect(unique?.config.columns.map((column) => (column as { name: string }).name)).toEqual([
      'user_id',
      'action',
    ]);
    expect(config.checks.map((check) => check.name).sort()).toEqual([
      'user_required_actions_action_known',
      'user_required_actions_source_known',
    ]);
  });
});

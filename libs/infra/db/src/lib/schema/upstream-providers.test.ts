/**
 * The shape of `realm_upstream_providers` (#639): one provider per type in a
 * realm, and the CHECKs the table declares.
 */
import { getTableConfig } from 'drizzle-orm/pg-core';
import { describe, expect, it } from 'vitest';

import { realmUpstreamProviders } from './upstream-providers';

describe('realm_upstream_providers (#639)', () => {
  const config = getTableConfig(realmUpstreamProviders);

  it('declares one provider per type in a realm', () => {
    expect(config.name).toBe('realm_upstream_providers');
    const unique = config.indexes.find(
      (index) => index.config.name === 'idx_realm_upstream_providers_realm_type_unique'
    );
    expect(unique?.config.unique).toBe(true);
    expect(unique?.config.columns.map((column) => (column as { name: string }).name)).toEqual([
      'realm_id',
      'type',
    ]);
  });

  it('declares the CHECKs on the type, the name and the config', () => {
    expect(config.checks.map((check) => check.name).sort()).toEqual([
      'realm_upstream_providers_config_object',
      'realm_upstream_providers_display_name_length',
      'realm_upstream_providers_type_form',
    ]);
  });
});

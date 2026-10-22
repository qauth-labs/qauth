import { describe, expect, it } from 'vitest';

import {
  DEFAULT_KEY_ROTATION_PERIOD_DAYS,
  getKeyPurpose,
  isKeyPurpose,
  KEY_ALGORITHM_KINDS,
  KEY_ALGORITHMS,
  KEY_PURPOSES,
  type KeyPurposeDefinition,
  STANDARD_REALM_KEY_PURPOSES,
} from './key-purposes';

/** ADR-019 Decision 9's list, with the two purposes added on 2026-10-10 and ADR-014/016's pair. */
const ADR_019_PURPOSES = [
  'token_signing',
  'event_signing',
  'federation_entity',
  'trust_anchor',
  'oid4vp_request_signing',
  'oid4vp_response_encryption',
  'data_at_rest',
  'cookie_hmac',
  'webhook_signing',
  'upstream_client_assertion',
  'agent_upstream_identity',
  'agent_wrap',
];

/** `realm_keys.purpose` and `realm_keys.algorithm` are varchar(64) and varchar(32). */
const PURPOSE_COLUMN_LENGTH = 64;
const ALGORITHM_COLUMN_LENGTH = 32;

const entries = Object.entries(KEY_PURPOSES) as [string, KeyPurposeDefinition][];

describe('KEY_PURPOSES', () => {
  it('holds exactly the purposes of ADR-019 Decision 9', () => {
    expect(Object.keys(KEY_PURPOSES).sort()).toEqual([...ADR_019_PURPOSES].sort());
  });

  describe.each(entries)('%s', (name, definition) => {
    it('has a description, a kind, algorithms, a scoped flag, a published flag and a rotation default', () => {
      expect(typeof definition.description).toBe('string');
      expect(definition.description.length).toBeGreaterThan(0);
      expect(['signing', 'encryption', 'symmetric']).toContain(definition.kind);
      expect(Array.isArray(definition.algorithms)).toBe(true);
      expect(definition.algorithms.length).toBeGreaterThan(0);
      expect(typeof definition.scoped).toBe('boolean');
      expect(typeof definition.published).toBe('boolean');
      expect(definition.rotation).toBeDefined();
      if (definition.rotation.mode === 'automatic') {
        expect(Number.isInteger(definition.rotation.periodDays)).toBe(true);
        expect(definition.rotation.periodDays).toBeGreaterThan(0);
      } else {
        expect(definition.rotation).toEqual({ mode: 'manual' });
      }
    });

    it('lists only known algorithms of its own kind, without repeats', () => {
      for (const algorithm of definition.algorithms) {
        expect(KEY_ALGORITHMS).toContain(algorithm);
        expect(KEY_ALGORITHM_KINDS[algorithm]).toBe(definition.kind);
      }
      expect(new Set(definition.algorithms).size).toBe(definition.algorithms.length);
    });

    it('defaults to one of its algorithms', () => {
      expect(definition.algorithms).toContain(definition.defaultAlgorithm);
    });

    it('is never published when it is symmetric', () => {
      if (definition.kind === 'symmetric') expect(definition.published).toBe(false);
    });

    it('names a hybrid companion only among its own algorithms, beside an EdDSA default', () => {
      if (definition.hybridCompanion === undefined) return;
      expect(definition.algorithms).toContain(definition.hybridCompanion);
      expect(definition.defaultAlgorithm).toBe('EdDSA');
      expect(definition.hybridCompanion).not.toBe(definition.defaultAlgorithm);
    });

    it('fits the purpose and algorithm columns of realm_keys', () => {
      expect(name.length).toBeLessThanOrEqual(PURPOSE_COLUMN_LENGTH);
      expect(name).toMatch(/^[a-z][a-z0-9_]*$/);
      for (const algorithm of definition.algorithms) {
        expect(algorithm.length).toBeLessThanOrEqual(ALGORITHM_COLUMN_LENGTH);
      }
    });

    it('cannot be changed at run time', () => {
      expect(Object.isFrozen(definition)).toBe(true);
      expect(Object.isFrozen(definition.algorithms)).toBe(true);
    });
  });

  it('cannot gain or lose a purpose at run time', () => {
    expect(Object.isFrozen(KEY_PURPOSES)).toBe(true);
  });

  it('scopes webhook signing, upstream client assertions and upstream app identities, and nothing else', () => {
    const scoped = entries.filter(([, definition]) => definition.scoped).map(([name]) => name);
    expect(scoped.sort()).toEqual([
      'agent_upstream_identity',
      'upstream_client_assertion',
      'webhook_signing',
    ]);
  });

  it('pairs only token signing for hybrid signing, with ML-DSA-65 (ADR-005)', () => {
    const hybrid = entries.filter(([, definition]) => definition.hybridCompanion !== undefined);
    expect(hybrid.map(([name, definition]) => [name, definition.hybridCompanion])).toEqual([
      ['token_signing', 'ML-DSA-65'],
    ]);
  });

  it('keeps the trust anchor, and only it, to federation-operator deployments', () => {
    const operatorOnly = entries
      .filter(([, definition]) => definition.federationOperatorOnly === true)
      .map(([name]) => name);
    expect(operatorOnly).toEqual(['trust_anchor']);
  });

  it('rotates every automatic purpose on the 90-day default', () => {
    for (const [, definition] of entries) {
      if (definition.rotation.mode === 'automatic') {
        expect(definition.rotation.periodDays).toBe(DEFAULT_KEY_ROTATION_PERIOD_DAYS);
      }
    }
    expect(DEFAULT_KEY_ROTATION_PERIOD_DAYS).toBe(90);
  });

  it('rotates manually every purpose whose key or public half a party outside the deployment holds', () => {
    const manual = entries
      .filter(([, definition]) => definition.rotation.mode === 'manual')
      .map(([name]) => name);
    expect(manual.sort()).toEqual([
      'agent_upstream_identity',
      'federation_entity',
      'oid4vp_request_signing',
      'trust_anchor',
      'upstream_client_assertion',
      'webhook_signing',
    ]);
  });

  it('pins the algorithms the wire depends on', () => {
    expect(KEY_PURPOSES.oid4vp_request_signing.algorithms).toEqual(['ES256']);
    expect(KEY_PURPOSES.oid4vp_response_encryption.algorithms).toEqual(['ECDH-ES']);
    expect(KEY_PURPOSES.token_signing.defaultAlgorithm).toBe('EdDSA');
    expect(KEY_PURPOSES.token_signing.algorithms).toContain('RS256');
  });
});

describe('STANDARD_REALM_KEY_PURPOSES', () => {
  it('names the four keys every new realm gets', () => {
    expect(STANDARD_REALM_KEY_PURPOSES).toEqual([
      'token_signing',
      'event_signing',
      'cookie_hmac',
      'data_at_rest',
    ]);
  });

  it('names only unscoped purposes any deployment may create', () => {
    for (const purpose of STANDARD_REALM_KEY_PURPOSES) {
      const definition = getKeyPurpose(purpose);
      expect(definition.scoped).toBe(false);
      expect(definition.federationOperatorOnly).not.toBe(true);
    }
  });
});

describe('isKeyPurpose', () => {
  it('accepts every registered purpose', () => {
    for (const name of ADR_019_PURPOSES) expect(isKeyPurpose(name)).toBe(true);
  });

  it('refuses unknown names and inherited object members', () => {
    for (const name of ['', 'TOKEN_SIGNING', 'token-signing', 'constructor', 'toString']) {
      expect(isKeyPurpose(name)).toBe(false);
    }
  });
});

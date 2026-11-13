import { describe, expect, it } from 'vitest';

import { readConfiguredEnv } from './configured-env';
import { CONFIG_KEY_REGISTRY } from './keys';
import { refuseRemovedKeys, REMOVED_CONFIG_KEYS, RemovedConfigKeyError } from './removed';

/*
 * Removed configuration keys (issue #481). CIMD_ALLOW_PRIVATE_ADDRESSES and
 * ID_JAG_ALLOW_PRIVATE_ADDRESSES turned the SSRF guard off; the egress
 * allowlist (EGRESS_ALLOWLIST_PATH) and the test-only egress client replace
 * them. A deployment that still sets one must not boot believing it applies.
 */

const SWITCHES = ['CIMD_ALLOW_PRIVATE_ADDRESSES', 'ID_JAG_ALLOW_PRIVATE_ADDRESSES'] as const;

describe('refuseRemovedKeys', () => {
  it.each(SWITCHES.flatMap((name) => ['true', 'false', '1'].map((value) => [name, value])))(
    '%s=%s stops the boot with a message that names the replacement',
    (name, value) => {
      const refuse = () => refuseRemovedKeys({ [name]: value });
      expect(refuse).toThrow(RemovedConfigKeyError);
      expect(refuse).toThrow(`${name} was removed in 0.2.0 and is set.`);
      expect(refuse).toThrow('EGRESS_ALLOWLIST_PATH');
      expect(refuse).toThrow(`Unset ${name}.`);
    }
  );

  it('names every removed key that is set, at once', () => {
    let error: unknown;
    try {
      refuseRemovedKeys({
        CIMD_ALLOW_PRIVATE_ADDRESSES: 'true',
        ID_JAG_ALLOW_PRIVATE_ADDRESSES: 'true',
      });
    } catch (err) {
      error = err;
    }
    expect(error).toBeInstanceOf(RemovedConfigKeyError);
    expect((error as RemovedConfigKeyError).keys).toEqual([...SWITCHES]);
  });

  it.each(['', '   '])(
    'treats a blank value (%j) as unset, as docker-compose forwards one',
    (value) => {
      expect(() =>
        refuseRemovedKeys({
          CIMD_ALLOW_PRIVATE_ADDRESSES: value,
          ID_JAG_ALLOW_PRIVATE_ADDRESSES: value,
        })
      ).not.toThrow();
    }
  );

  it('runs before the schema, in readConfiguredEnv', () => {
    expect(() =>
      readConfiguredEnv(CONFIG_KEY_REGISTRY, { ID_JAG_ALLOW_PRIVATE_ADDRESSES: 'true' })
    ).toThrow('ID_JAG_ALLOW_PRIVATE_ADDRESSES was removed in 0.2.0');
  });
});

/*
 * PQC_SELF_CONTAINED_ACK (issue #875) acknowledged PQC_TOKEN_DELIVERY=
 * self-contained, which the server never built: hybrid tokens were delivered
 * by reference whatever it said. A deployment that still sets it must learn
 * that the setting it relies on did nothing.
 */
describe('refuseRemovedKeys (PQC_SELF_CONTAINED_ACK)', () => {
  it.each(['true', 'false', '1', '0'])(
    'PQC_SELF_CONTAINED_ACK=%s stops the boot, naming the delivery that applies',
    (value) => {
      const refuse = () => refuseRemovedKeys({ PQC_SELF_CONTAINED_ACK: value });
      expect(refuse).toThrow(RemovedConfigKeyError);
      expect(refuse).toThrow('PQC_SELF_CONTAINED_ACK was removed in 0.3.0 and is set.');
      expect(refuse).toThrow('PQC_TOKEN_DELIVERY=reference');
      expect(refuse).toThrow('Unset PQC_SELF_CONTAINED_ACK.');
    }
  );

  it('treats a blank value as unset, as docker-compose forwards one', () => {
    expect(() => refuseRemovedKeys({ PQC_SELF_CONTAINED_ACK: '' })).not.toThrow();
  });

  it('runs before the schema, in readConfiguredEnv', () => {
    expect(() =>
      readConfiguredEnv(CONFIG_KEY_REGISTRY, { PQC_SELF_CONTAINED_ACK: 'true' })
    ).toThrow('PQC_SELF_CONTAINED_ACK was removed in 0.3.0');
  });
});

describe('REMOVED_CONFIG_KEYS', () => {
  it('names no key the registry still reads, under its name or an old one', () => {
    const read = new Set(
      CONFIG_KEY_REGISTRY.flatMap((key) => [key.name, ...key.aliases.map((alias) => alias.name)])
    );
    for (const { name } of REMOVED_CONFIG_KEYS) {
      expect(read.has(name)).toBe(false);
    }
  });

  it('holds the two private-address switches and the self-contained acknowledgement', () => {
    expect(REMOVED_CONFIG_KEYS.map(({ name }) => name)).toEqual([
      ...SWITCHES,
      'PQC_SELF_CONTAINED_ACK',
    ]);
  });
});

import { describe, expect, it } from 'vitest';

import {
  CREDENTIAL_STATUS,
  MAX_DECOMPRESSED_STATUS_LIST_BYTES,
  MAX_ENCODED_STATUS_LIST_BYTES,
  STATUS_LIST_BIT_WIDTHS,
  STATUS_LIST_TOKEN_MEDIA_TYPE,
  STATUS_LIST_TOKEN_TYP,
  TOKEN_STATUS_LIST_DRAFT,
} from './status-list-spec';

describe('Token Status List version pin (#297)', () => {
  it('pins the HAIP §9.4 revision in an isolated constant', () => {
    // HAIP 1.0 §9.4 normatively references draft-14 and says to prefer it over
    // later finals. Changing this without changing the wire handling is a
    // silent conformance break, which is why the pin is asserted rather than
    // merely present.
    expect(TOKEN_STATUS_LIST_DRAFT).toBe('draft-ietf-oauth-status-list-14');
  });

  it('uses the specified media type and token type', () => {
    expect(STATUS_LIST_TOKEN_TYP).toBe('statuslist+jwt');
    expect(STATUS_LIST_TOKEN_MEDIA_TYPE).toBe('application/statuslist+jwt');
  });

  it('permits exactly the four bit widths draft-14 §4.1 allows', () => {
    expect([...STATUS_LIST_BIT_WIDTHS]).toEqual([1, 2, 4, 8]);
    // Every width divides 8, which is what keeps a lookup inside one byte.
    for (const width of STATUS_LIST_BIT_WIDTHS) expect(8 % width).toBe(0);
  });

  it('numbers the registered status values per draft-14 §7.1', () => {
    expect(CREDENTIAL_STATUS.VALID).toBe(0x00);
    expect(CREDENTIAL_STATUS.INVALID).toBe(0x01);
    expect(CREDENTIAL_STATUS.SUSPENDED).toBe(0x02);
  });

  it('bounds decompression on both sides of the inflate', () => {
    expect(MAX_ENCODED_STATUS_LIST_BYTES).toBeGreaterThan(0);
    expect(MAX_DECOMPRESSED_STATUS_LIST_BYTES).toBeGreaterThan(MAX_ENCODED_STATUS_LIST_BYTES);
  });
});

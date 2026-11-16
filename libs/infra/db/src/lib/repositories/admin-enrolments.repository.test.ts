import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { adminEnrolmentTokenHash } from './admin-enrolments.repository';

const BASE64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

describe('adminEnrolmentTokenHash (#602)', () => {
  it('hashes the 32 bytes of a token in its one canonical form', () => {
    const bytes = Buffer.alloc(32, 0xfb);
    const token = bytes.toString('base64url');
    expect(token).toHaveLength(43);
    expect(adminEnrolmentTokenHash(token)).toEqual(createHash('sha256').update(bytes).digest());
  });

  it('names no hash for another length, padding or alphabet', () => {
    const bytes = Buffer.alloc(32, 0xfb);
    for (const other of [
      '',
      bytes.toString('base64'),
      `${bytes.toString('base64url')}=`,
      Buffer.alloc(31).toString('base64url'),
      Buffer.alloc(33).toString('base64url'),
      `${bytes.toString('base64url').slice(0, 42)}+`,
    ]) {
      expect(adminEnrolmentTokenHash(other), other).toBeUndefined();
    }
  });

  it('names no hash for a second spelling of the same bytes', () => {
    // The last of 43 characters carries two unused bits: flipping one keeps
    // the bytes and changes the text, which must not name the same row.
    const bytes = Buffer.alloc(32, 0xfb);
    const token = bytes.toString('base64url');
    const last = BASE64URL.indexOf(token.at(-1) as string);
    const sibling = `${token.slice(0, -1)}${BASE64URL[last ^ 1]}`;
    expect(Buffer.from(sibling, 'base64url')).toEqual(bytes);
    expect(adminEnrolmentTokenHash(sibling)).toBeUndefined();
  });
});

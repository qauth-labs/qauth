import { describe, expect, it } from 'vitest';

import { passwordSha1 } from './digest';

describe('passwordSha1', () => {
  it('is the SHA-1 of the UTF-8 bytes, 40 upper-case hex characters, as breach corpora index it', () => {
    // Vectors computed apart, with `printf '%s' … | sha1sum`.
    expect(passwordSha1('password')).toBe('5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8');
    expect(passwordSha1('pässwörd')).toBe('F517DDF1D32A112FF1AD55C66D1B12CB38E7E8F7');
    expect(passwordSha1('')).toBe('DA39A3EE5E6B4B0D3255BFEF95601890AFD80709');
  });

  it('hashes the password as given: the caller picks the form', () => {
    expect(passwordSha1('café')).not.toBe(passwordSha1('café'));
  });
});

import { describe, expect, it } from 'vitest';

import { tableCell } from './docs-page';

describe('tableCell', () => {
  it('escapes a pipe', () => {
    expect(tableCell('a|b')).toBe('a\\|b');
  });

  it('escapes the backslash before an escaped pipe, so the cell does not end there', () => {
    expect(tableCell('a\\|b')).toBe('a\\\\\\|b');
  });

  it('escapes a lone backslash', () => {
    expect(tableCell('C:\\path')).toBe('C:\\\\path');
  });

  it('flattens newlines and the whitespace around them', () => {
    expect(tableCell('one\n  two')).toBe('one two');
    expect(tableCell('one \n \n two')).toBe('one two');
  });

  it('keeps whitespace with no newline', () => {
    expect(tableCell('one  two\tthree')).toBe('one  two\tthree');
  });

  it('reads a long run of spaces in linear time', () => {
    const spaces = ' '.repeat(200_000);
    expect(tableCell(`a${spaces}b`)).toBe(`a${spaces}b`);
  });
});

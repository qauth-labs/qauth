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

  it('flattens newlines', () => {
    expect(tableCell('one\n  two')).toBe('one two');
  });
});

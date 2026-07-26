/**
 * Vendored from `@react-email/body@0.3.0` (resend/react-email), MIT licensed.
 * See `../LICENSE` and `../README.md`. Changed from upstream: this header and
 * the explicit `react` type import (upstream relied on a global React type).
 */
import type * as React from 'react';

export const marginProperties: (keyof React.CSSProperties)[] = [
  'margin',
  'marginTop',
  'marginBottom',
  'marginRight',
  'marginLeft',
  'marginInline',
  'marginBlock',
  'marginBlockStart',
  'marginBlockEnd',
  'marginInlineStart',
  'marginInlineEnd',
];

export const paddingProperties: (keyof React.CSSProperties)[] = [
  'padding',
  'paddingTop',
  'paddingBottom',
  'paddingRight',
  'paddingLeft',
  'paddingInline',
  'paddingBlock',
  'paddingBlockStart',
  'paddingBlockEnd',
  'paddingInlineStart',
  'paddingInlineEnd',
];

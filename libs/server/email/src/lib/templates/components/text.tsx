/**
 * Vendored from `@react-email/text@0.1.6` (resend/react-email), MIT licensed.
 * See `./LICENSE` and `./README.md`. Changed from upstream: this header and the
 * import path of `compute-margins`.
 */
import * as React from 'react';

import { computeMargins } from './utils/compute-margins';

export type TextProps = Readonly<React.ComponentPropsWithoutRef<'p'>>;

export const Text = React.forwardRef<HTMLParagraphElement, TextProps>(
  ({ style, ...props }, ref) => {
    /**
     * we do this clunky way of spreading these default margins because
     * if we were to simply spread, the ordering of the margins would be lost
     *
     * ex:
     * ```js
     * { ...{ marginTop: '16px', marginBottom: '16px' }, ...{ marginTop: '24px' } }
     * // would result in
     * { marginTop: '24px', marginBottom: '16px' }
     * // not the expected
     * { marginBottom: '16px', marginTop: '24px' }
     * ```
     */
    const defaultMargins: React.CSSProperties = {};
    if (style?.marginTop === undefined) {
      defaultMargins.marginTop = '16px';
    }
    if (style?.marginBottom === undefined) {
      defaultMargins.marginBottom = '16px';
    }
    const margins = computeMargins({
      ...defaultMargins,
      ...style,
    });

    return (
      <p
        {...props}
        ref={ref}
        style={{
          fontSize: '14px',
          lineHeight: '24px',
          ...style,
          ...margins,
        }}
      />
    );
  }
);

Text.displayName = 'Text';

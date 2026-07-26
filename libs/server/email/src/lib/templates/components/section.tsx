/**
 * Vendored from `@react-email/section@0.0.17` (resend/react-email), MIT licensed.
 * See `./LICENSE` and `./README.md`. Changed from upstream: this header only.
 */
import * as React from 'react';

export type SectionProps = Readonly<React.ComponentPropsWithoutRef<'table'>>;

export const Section = React.forwardRef<HTMLTableElement, SectionProps>(
  ({ children, style, ...props }, ref) => {
    return (
      <table
        align="center"
        width="100%"
        border={0}
        cellPadding="0"
        cellSpacing="0"
        role="presentation"
        {...props}
        ref={ref}
        style={style}
      >
        <tbody>
          <tr>
            <td>{children}</td>
          </tr>
        </tbody>
      </table>
    );
  }
);

Section.displayName = 'Section';

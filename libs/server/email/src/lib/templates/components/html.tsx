/**
 * Vendored from `@react-email/html@0.0.12` (resend/react-email), MIT licensed.
 * See `./LICENSE` and `./README.md`. Changed from upstream: this header only.
 */
import * as React from 'react';

export type HtmlProps = Readonly<React.ComponentPropsWithoutRef<'html'>>;

export const Html = React.forwardRef<HTMLHtmlElement, HtmlProps>(
  ({ children, lang = 'en', dir = 'ltr', ...props }, ref) => (
    <html {...props} dir={dir} lang={lang} ref={ref}>
      {children}
    </html>
  )
);

Html.displayName = 'Html';

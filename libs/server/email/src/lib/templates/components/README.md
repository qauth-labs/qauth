# Vendored React Email components

These components are vendored from [`resend/react-email`](https://github.com/resend/react-email),
copied verbatim from the original TypeScript sources of the individual
`@react-email/*` packages that `@react-email/components@1.0.12` re-exported.

## Why they are vendored

`@react-email/components` is deprecated on npm across its entire recent version
range (see issue #333). Upstream consolidated the ~20 split packages into the
single `react-email` package, whose _runtime_ dependencies include a bundler
(`esbuild`), a WebSocket server (`socket.io`), a syntax highlighter (`prismjs`)
and a file watcher — roughly +46 MB and +80 packages. The auth-server image
installs rather than bundles (`apps/auth-server/Dockerfile`), so all of that
would ship into production. Vendoring the eight primitives we actually use keeps
today's authoring ergonomics at the runtime weight of depending on
`@react-email/render` alone.

## Provenance

| Component   | Upstream package         | Version |
| ----------- | ------------------------ | ------- |
| `Body`      | `@react-email/body`      | 0.3.0   |
| `Button`    | `@react-email/button`    | 0.2.1   |
| `Container` | `@react-email/container` | 0.0.16  |
| `Head`      | `@react-email/head`      | 0.0.13  |
| `Html`      | `@react-email/html`      | 0.0.12  |
| `Preview`   | `@react-email/preview`   | 0.0.14  |
| `Section`   | `@react-email/section`   | 0.0.17  |
| `Text`      | `@react-email/text`      | 0.1.6   |

Each file carries the same provenance header. The only edits made to the
upstream sources are import-path adjustments, those headers, and formatting
applied by the repository's Prettier configuration. The verification email
renders byte-for-byte identically before and after the migration in both HTML
and `plainText` modes; `components.test.tsx` and `verification-email.test.tsx`
pin the markup so a later edit to these files cannot change it silently.

## Licence

Upstream is MIT-licensed, Copyright (c) Resend. See `LICENSE` in this directory
for the full text; it applies to every file here.

## Updating

There is no update channel: these are ours now. If upstream fixes an
email-client compatibility bug worth taking, port it by hand and bump the
version recorded above and in the file header.

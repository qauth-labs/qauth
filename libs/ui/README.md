# @qauth-labs/ui

QAuth's design system for its own front-ends: the developer portal now, the ceremony app, the
account console and the admin console next (ADR-020).

## Overview

`@qauth-labs/ui` is QAuth's design system: the design tokens, the theme stylesheets built from
them, and the React primitives styled with them.

- **Tokens** — `src/tokens/tokens.json`, in the
  [Design Tokens Community Group](https://www.designtokens.org/) format (2025.10). Colours for
  light and dark, the fonts and type scale, spacing, radius, the focus ring and motion. It is the
  one source of every value; nothing else holds a colour or a size of its own.
- **Stylesheets** — `theme.css` (the tokens as CSS custom properties) and `tailwind-theme.css`
  (the Tailwind v4 theme on top of them) are generated from the tokens. `base.css` sets the page's
  colours and fonts, and `fonts.css` loads the self-hosted fonts.
- **Brand settings** — `applyBrand(brand)` checks a realm's brand settings and returns the theme
  stylesheet with them applied.
- **Primitives** — `Button`, the `Card` family, `Input`, `Label` and `FormField`.

The visual language is the qauth.dev website's: square corners, flat surfaces with hairline
edges, DM Sans for text, Instrument Serif for page and section headings, JetBrains Mono for code.
The interactive components that come next (#556) are built on React Aria Components
([ADR-020 §6](../../docs/adr/020-ui-surfaces-and-acceptance-criteria.md)) with these tokens.

All components forward standard DOM props and accept a `className` that is merged with the
component's base styles (via `clsx` + `tailwind-merge`), so callers can override or extend
styling without fighting specificity. `Card*`, `Input`, and `Label` forward refs.

## Using it in an app

A Tailwind v4 app imports the design system right after Tailwind:

```css
@import 'tailwindcss';
@import '@qauth-labs/ui/styles.css';
```

That brings the fonts, the theme, the Tailwind theme, the base rules, the `dark:` variant, and an
`@source` for the library's components, so the app needs no `@source` line for them.

A page with no Tailwind (the auth server's `/ui` pages) links `theme.css`, `base.css` and
`fonts.css` and styles its own elements with the variables: `var(--background)`,
`var(--muted-foreground)`, `var(--font-sans)`, `var(--radius-control)`.

### Light and dark

The theme follows the system's `prefers-color-scheme`. `data-theme="light"` or
`data-theme="dark"` on the root element overrides it, and on any other element fixes that subtree
to one mode. `color-scheme` follows, so form controls and scrollbars match.

## Tokens

| Group            | CSS variables                                                                                | Tailwind                                      |
| ---------------- | -------------------------------------------------------------------------------------------- | --------------------------------------------- |
| `color.surface`  | `--background`, `--card`, `--popover`, `--muted`, `--secondary`, `--accent`, `--*-surface`   | `bg-background`, `bg-card`, …                 |
| `color.text`     | `--foreground`, `--body`, `--muted-foreground`, `--primary-text`, `--*-foreground`           | `text-foreground`, `text-body`, …             |
| `color.primary`  | `--primary`, `--primary-hover`, `--primary-foreground`                                       | `bg-primary`, `text-primary-foreground`       |
| `color.brand`    | `--highlight` (the brand accent)                                                             | `text-highlight`                              |
| `color.feedback` | `--destructive`, `--success`                                                                 | `text-destructive`, `bg-success-surface`      |
| `color.line`     | `--border`, `--input`, `--ring`                                                              | `border-border`, `border-input`, `ring-ring`  |
| `font.*`         | `--font-sans`, `--font-display`, `--font-mono`, `--font-weight-*`, `--text-*`, `--leading-*` | `font-display`, `text-sm`, `leading-snug`     |
| `space.unit`     | `--spacing`                                                                                  | `p-4`, `gap-2`, …                             |
| `radius.*`       | `--radius-control`, `--radius-surface`, `--radius-full` (control and surface are 0: square)  | `rounded-control`, `rounded-surface`          |
| `focus.*`        | `--focus-ring-width`, `--focus-ring-offset`                                                  | —                                             |
| `motion.*`       | `--duration-fast`, `--duration-normal` (0ms under reduced motion), `--ease-standard`         | `duration-(--duration-fast)`, `ease-standard` |

Colour names follow the design system's (shadcn's) names, so the website and these apps share
them. `accent` is the hover and selected fill; the brand
accent is `highlight`.

**Contrast.** Each text colour declares, under `$extensions["dev.qauth.ui"].contrast`, the
backgrounds it is drawn on and its floor: 4.5:1 for text, 3:1 for a control's edge and the focus
ring (WCAG 2.2, 1.4.3 and 1.4.11). A test checks every pair in light and dark.

**Changing a token.** Edit `tokens.json`, then run `pnpm nx test ui -u` to regenerate
`theme.css` and `tailwind-theme.css`. CI fails when the checked-in files differ from the tokens.

## Brand settings

Only four inputs may change a token:

| Setting    | Value                           | Checked                                                                                   |
| ---------- | ------------------------------- | ----------------------------------------------------------------------------------------- |
| `primary`  | `#rrggbb`, or `{ light, dark }` | its text (`primary-foreground`) reaches 4.5:1 on it, and on its hover shade, in each mode |
| `accent`   | `#rrggbb`, or `{ light, dark }` | it reaches 4.5:1 as text on the page, cards and muted fills, in each mode                 |
| `font`     | `'qauth'` or `'system'`         | one of the self-hosted or system fonts in `BRAND_FONTS`; it sets text and headings        |
| `darkMode` | `true` (default) or `false`     | `false` leaves the dark set out, so the pages stay light whatever the system prefers      |

The logo, per-locale strings and links are data, not tokens.

```ts
import { applyBrand, BrandError } from '@qauth-labs/ui';

try {
  const css = applyBrand({ primary: '#1d4ed8', darkMode: false });
  // Serve `css` in place of theme.css.
} catch (error) {
  if (error instanceof BrandError) console.log(error.issues); // every problem at once
}
```

`applyBrand` refuses any value that contains `url(`, `;`, `{` or `}`, a colour not written
`#rrggbb`, a font outside the list, and a setting it does not know. Links and text buttons use
the primary colour where it reaches 4.5:1 on the page in that mode, and the text colour where it
does not. The result is plain CSS text: serve it as a stylesheet, in place of `theme.css`, never
beside it.

## Installation

This library is part of the QAuth monorepo and is automatically available to
other projects within the workspace.

```tsx
import { Button, Card, CardHeader, CardTitle, Input, Label, FormField } from '@qauth-labs/ui';
```

## Usage

### Button

```tsx
import { Button } from '@qauth-labs/ui';

<Button onClick={handleSave}>Save</Button>
<Button variant="outline" size="sm">Cancel</Button>
<Button variant="link">Learn more</Button>
<Button disabled>Submitting…</Button>
```

`ButtonProps` extends `React.ButtonHTMLAttributes<HTMLButtonElement>` and adds:

- `variant?: 'default' | 'secondary' | 'outline' | 'ghost' | 'destructive' | 'link'` (default `'default'`)
- `size?: 'default' | 'sm' | 'lg'` (default `'default'`)

### Card

```tsx
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@qauth-labs/ui';

<Card>
  <CardHeader>
    <CardTitle>Register an application</CardTitle>
    <CardDescription>Create OAuth client credentials.</CardDescription>
  </CardHeader>
  <CardContent>{/* … */}</CardContent>
</Card>;
```

Each `Card*` component is a `forwardRef` wrapper over the matching HTML element
(`div`/`h3`/`p`) and accepts that element's standard attributes plus `className`.

### Input and Label

```tsx
import { Input, Label } from '@qauth-labs/ui';

<Label htmlFor="email">Email</Label>
<Input id="email" type="email" placeholder="you@example.com" />

// Error state: set aria-invalid to drive the red focus/border styling.
<Input id="email" aria-invalid="true" />
```

`InputProps` is `InputHTMLAttributes<HTMLInputElement>`; `LabelProps` is
`LabelHTMLAttributes<HTMLLabelElement>`. Both forward refs.

### FormField

A layout wrapper that renders a `Label`, the control you pass as `children`, and
either an error or helper message beneath it. When `error` is set it takes
precedence over `helperText` and renders in the error color.

```tsx
import { FormField, Input } from '@qauth-labs/ui';

<FormField label="Email" htmlFor="email" error={errors.email} helperText="We'll never share it.">
  <Input id="email" type="email" aria-invalid={errors.email ? 'true' : undefined} />
</FormField>;
```

`FormFieldProps`:

- `label: string`
- `htmlFor: string`
- `error?: string`
- `helperText?: string`
- `children: ReactNode`

## API

| Export                                                              | Kind      | Notes                                             |
| ------------------------------------------------------------------- | --------- | ------------------------------------------------- |
| `Button`                                                            | component | `variant` / `size` + all button attributes        |
| `ButtonProps`                                                       | type      | Props for `Button`                                |
| `Card`, `CardHeader`, `CardTitle`, `CardDescription`, `CardContent` | component | `forwardRef` element wrappers                     |
| `Input`                                                             | component | `forwardRef`; `aria-invalid` drives error styling |
| `InputProps`                                                        | type      | `= InputHTMLAttributes<HTMLInputElement>`         |
| `Label`                                                             | component | `forwardRef`                                      |
| `LabelProps`                                                        | type      | `= LabelHTMLAttributes<HTMLLabelElement>`         |
| `FormField`                                                         | component | Label + control + error/helper wrapper            |
| `FormFieldProps`                                                    | type      | Props for `FormField`                             |
| `buttonVariants`                                                    | function  | The button's classes, for a link styled as one    |
| `applyBrand`, `BrandError`, `BRAND_FONTS`                           | function  | A realm's brand stylesheet; see Brand settings    |
| `themeCss`, `tailwindThemeCss`                                      | function  | The generators of the two theme files             |
| `COLOR_TOKENS`, `STATIC_TOKENS`, `contrastFailures`                 | data      | The tokens, flattened, and the contrast check     |

## Development

### Running unit tests

```bash
pnpm nx test ui
```

`pnpm nx test ui -u` regenerates `src/styles/theme.css` and `src/styles/tailwind-theme.css` from
the tokens.

## License

Apache-2.0

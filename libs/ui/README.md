# @qauth-labs/ui

Shared React UI primitives for QAuth front-ends (the developer portal and other
in-repo apps). A small set of unstyled-by-convention, Tailwind-styled building
blocks with consistent props and `className` overrides.

## Overview

`@qauth-labs/ui` provides headless-ish React primitives styled with Tailwind CSS:

- **Button** — variant/size-aware button
- **Card** family — `Card`, `CardHeader`, `CardTitle`, `CardDescription`, `CardContent`
- **Input** — text input with `aria-invalid` error styling
- **Label** — form label
- **FormField** — label + control + error/helper-text wrapper

All components forward standard DOM props and accept a `className` that is merged
with the component's base styles (via `clsx` + `tailwind-merge`), so callers can
override or extend styling without fighting specificity. `Card*`, `Input`, and
`Label` forward refs.

> **Peer requirements:** React and a Tailwind CSS build are expected in the
> consuming app (the component class names assume Tailwind is processing them).

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

- `variant?: 'default' | 'outline' | 'ghost' | 'link'` (default `'default'`)
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

## Development

### Running unit tests

```bash
pnpm nx test ui
```

## License

Apache-2.0

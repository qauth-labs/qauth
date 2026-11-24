# QAuth colour tokens

Source of truth: `libs/ui/src/tokens/tokens.json` (DTCG 2025.10). Generated CSS: `libs/ui/src/styles/theme.css` (vars) and `tailwind-theme.css` (`--color-*`). Hex values are sRGB conversions of the OKLCH tokens (gamut-clipped); OKLCH is canonical.

## surface

| Token | Light OKLCH | Light hex | Dark OKLCH | Dark hex | Contrast floor | Purpose |
|---|---|---|---|---|---|---|
| `--background` | `oklch(1 0 0)` | `#ffffff` | `oklch(0.113 0.004 260)` | `#040506` | — | The page. |
| `--card` | `oklch(1 0 0)` | `#ffffff` | `oklch(0.138 0.005 260)` | `#08090b` | — | A card or panel on the page. |
| `--popover` | `oklch(1 0 0)` | `#ffffff` | `oklch(0.138 0.005 260)` | `#08090b` | — | A menu, popover or dialog. |
| `--muted` | `oklch(0.97 0.001 106.424)` | `#f5f5f4` | `oklch(0.2 0.005 260)` | `#151618` | — | A quiet fill: a code block, a table header, a disabled field. |
| `--secondary` | `oklch(0.967 0.001 286.375)` | `#f4f4f5` | `oklch(0.274 0.006 286.033)` | `#27272a` | — | The secondary button. |
| `--accent` | `oklch(0.97 0.001 106.424)` | `#f5f5f4` | `oklch(0.2 0.005 260)` | `#151618` | — | The hover and selected fill of a menu item or ghost button. Not the brand accent: that is color.brand.highlight. |
| `--destructive-surface` | `oklch(0.97 0.015 27.325)` | `#fff2f0` | `oklch(0.22 0.05 22.216)` | `#2e1010` | — | The fill behind an error message or destructive action. |
| `--success-surface` | `oklch(0.97 0.02 149.214)` | `#ecf9ee` | `oklch(0.22 0.05 149.214)` | `#06210d` | — | The fill behind a success message. |
| `--warning-surface` | `oklch(0.97 0.03 85)` | `#fef4df` | `oklch(0.24 0.05 70)` | `#2e1a01` | — | The fill behind a warning. |
| `--scrim` | `oklch(0 0 0 / 0.4)` | `#00000066` | `oklch(0 0 0 / 0.6)` | `#00000099` | — | The shade behind a modal dialog. |

## text

| Token | Light OKLCH | Light hex | Dark OKLCH | Dark hex | Contrast floor | Purpose |
|---|---|---|---|---|---|---|
| `--foreground` | `oklch(0.147 0.004 49.25)` | `#0c0a09` | `oklch(0.97 0.002 90)` | `#f5f5f4` | ≥4.5:1 on background, card, popover, muted | Headings and primary text. |
| `--card-foreground` | `oklch(0.147 0.004 49.25)` | `#0c0a09` | `oklch(0.97 0.002 90)` | `#f5f5f4` | ≥4.5:1 on card | Text on a card. |
| `--popover-foreground` | `oklch(0.147 0.004 49.25)` | `#0c0a09` | `oklch(0.97 0.002 90)` | `#f5f5f4` | ≥4.5:1 on popover | Text in a menu, popover or dialog. |
| `--secondary-foreground` | `oklch(0.21 0.006 285.885)` | `#18181b` | `oklch(0.985 0 0)` | `#fafafa` | ≥4.5:1 on secondary, accent | Text on the secondary button. |
| `--accent-foreground` | `oklch(0.216 0.006 56.043)` | `#1c1917` | `oklch(0.97 0.002 90)` | `#f5f5f4` | ≥4.5:1 on accent | Text on the hover and selected fill. |
| `--body` | `oklch(0.42 0.013 58)` | `#534b46` | `oklch(0.75 0.008 90)` | `#b0aea8` | ≥4.5:1 on background, card, muted | Running text: softer than foreground, stronger than muted. |
| `--muted-foreground` | `oklch(0.53 0.013 58.071)` | `#726a65` | `oklch(0.62 0.008 90)` | `#888681` | ≥4.5:1 on background, card, popover, muted | Secondary text: hints, captions, placeholders. Light 0.53 (the design system's 0.553 was 4.4:1 on muted). |
| `--primary-text` | `oklch(0.5 0.15 38)` | `#a73b15` | `oklch(0.72 0.12 45)` | `#e28b63` | ≥4.5:1 on background, card, muted | The brand colour as text: links and text buttons. The fill itself is too dark for text in dark mode. |

## primary

| Token | Light OKLCH | Light hex | Dark OKLCH | Dark hex | Contrast floor | Purpose |
|---|---|---|---|---|---|---|
| `--primary` | `oklch(0.54 0.15 38)` | `#b44723` | `oklch(0.54 0.15 38)` | `#b44723` | — | The brand colour as a fill: the primary button. |
| `--primary-hover` | `oklch(0.49 0.14 38)` | `#9f3c1a` | `oklch(0.49 0.14 38)` | `#9f3c1a` | — | The primary button under the pointer. Darker, so its text keeps its contrast. |
| `--primary-foreground` | `oklch(0.98 0.016 73.684)` | `#fff7ed` | `oklch(0.98 0.016 73.684)` | `#fff7ed` | ≥4.5:1 on primary, primary-hover | Text on the primary fill. |

## brand

| Token | Light OKLCH | Light hex | Dark OKLCH | Dark hex | Contrast floor | Purpose |
|---|---|---|---|---|---|---|
| `--highlight` | `oklch(0.5 0.1324 194.77)` | `#00797a` | `oklch(0.75 0.15 195)` | `#00cacb` | ≥4.5:1 on background, card, muted | The brand accent: emphasis, badges, the selected state. Light 0.5 (the design system's 0.7766 was 1.9:1 on white). |

## feedback

| Token | Light OKLCH | Light hex | Dark OKLCH | Dark hex | Contrast floor | Purpose |
|---|---|---|---|---|---|---|
| `--destructive` | `oklch(0.55 0.22 27.325)` | `#d40c18` | `oklch(0.704 0.191 22.216)` | `#ff6467` | ≥4.5:1 on background, card, muted, destructive-surface | Errors and destructive actions. Light 0.55 (0.577 was 4.4:1 on muted). |
| `--success` | `oklch(0.52 0.17 149.214)` | `#008229` | `oklch(0.648 0.223 149.214)` | `#00b033` | ≥4.5:1 on background, card, success-surface | Success messages. |
| `--warning` | `oklch(0.5 0.11 65)` | `#8d5406` | `oklch(0.82 0.13 80)` | `#f0ba59` | ≥4.5:1 on background, card, warning-surface | Warnings: a secret shown once, a deprecated grant. |

## line

| Token | Light OKLCH | Light hex | Dark OKLCH | Dark hex | Contrast floor | Purpose |
|---|---|---|---|---|---|---|
| `--border` | `oklch(0.923 0.003 48.717)` | `#e7e5e4` | `oklch(1 0 0 / 0.08)` | `#ffffff14` | — | Dividers and card edges. Decorative, so no contrast floor. |
| `--input` | `oklch(0.62 0.003 48.717)` | `#888684` | `oklch(0.5 0.008 90)` | `#65635e` | ≥3:1 on background, card | The edge of a text field, checkbox or select: 3:1, as WCAG 1.4.11 asks of a control's boundary (the design system's was 1.2:1). |
| `--ring` | `oklch(0.5 0.1324 194.77)` | `#00797a` | `oklch(0.75 0.15 195)` | `#00cacb` | ≥3:1 on background, card, muted | The focus outline: the teal accent, so focus stands out from the primary orange and the greys. 3:1 or more against what it sits on (WCAG 1.4.11): 4.9:1 on white, 10:1 on the dark page. |

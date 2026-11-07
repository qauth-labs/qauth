/**
 * THE /ui PAGES' OWN RULES (#472), the last part of their stylesheet
 * (`ui-assets.ts`), after the design system's `theme.css` and `base.css`.
 *
 * The page layout, the card, the form controls, the buttons, the links and the
 * notices every server-rendered page shares. A page that needs more (the
 * sign-in page's divider, the consent screen's client details) adds it in its
 * own inline `<style>`, under the request's style nonce, with the same tokens.
 *
 * The look is the design system's (`libs/ui`): square corners, flat cards with
 * a hairline edge and no shadow, DM Sans for text and Instrument Serif for the
 * page heading (`base.css` sets both faces). Every colour, font, radius and
 * duration is a token of `theme.css`, in light and dark, and every text colour
 * is drawn on a surface `tokens.json` checks it against. The one literal colour
 * is the QR code box's white: see `.qr`.
 *
 * These rules are unlayered, so they win over `base.css`, which is in the
 * `base` layer. None sets `outline`: base.css draws the focus ring on every
 * control, as an outline that also shows in forced-colors mode.
 */
export const UI_PAGE_CSS = `/* The /ui pages' own rules (apps/auth-server/src/app/helpers/ui-page-css.ts). */
*,
::before,
::after {
  box-sizing: border-box;
}

html {
  -webkit-text-size-adjust: 100%;
  text-size-adjust: 100%;
}

body {
  margin: 0;
  min-height: 100vh;
  min-height: 100dvh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 1.5rem 1rem;
  font-size: var(--text-sm);
  line-height: var(--leading-normal);
}

.card {
  width: 100%;
  max-width: 26.25rem;
  padding: 2rem;
  background-color: var(--card);
  color: var(--card-foreground);
  border: 1px solid var(--border);
  border-radius: var(--radius-surface);
}

h1 {
  margin: 0 0 1rem;
  font-size: 1.75rem;
  line-height: var(--leading-tight);
  color: var(--foreground);
  overflow-wrap: break-word;
}

p,
ul,
ol {
  margin: 0 0 0.75rem;
  color: var(--body);
  overflow-wrap: break-word;
}

strong {
  font-weight: var(--font-weight-semibold);
}

p > strong,
li > strong {
  color: var(--foreground);
}

a {
  color: var(--primary-text);
  text-decoration-line: underline;
  text-decoration-thickness: 1px;
  text-underline-offset: 0.2em;
}

a:hover {
  text-decoration-thickness: 2px;
}

code {
  padding: 0.0625rem 0.375rem;
  border-radius: var(--radius-control);
  background-color: var(--muted);
  color: var(--foreground);
  font-size: 0.875em;
  overflow-wrap: anywhere;
}

label {
  display: block;
  margin-top: 1rem;
  font-weight: var(--font-weight-medium);
  color: var(--foreground);
}

/* A field and a button are the same height, 40px, wherever they sit together. */
input[type='text'],
input[type='email'],
input[type='password'] {
  display: block;
  width: 100%;
  height: 2.5rem;
  margin-top: 0.375rem;
  padding: 0 0.75rem;
  border: 1px solid var(--input);
  border-radius: var(--radius-control);
  background-color: transparent;
  color: var(--foreground);
  font: inherit;
  /* 16px on a phone, so the browser does not zoom in when the field takes focus. */
  font-size: var(--text-base);
  transition: border-color var(--duration-fast) var(--ease-standard);
}

@media (min-width: 48rem) {
  input[type='text'],
  input[type='email'],
  input[type='password'] {
    font-size: var(--text-sm);
  }
}

input:focus-visible {
  border-color: var(--ring);
}

input[aria-invalid='true'] {
  border-color: var(--destructive);
}

input[type='checkbox'] {
  flex: none;
  width: 1rem;
  height: 1rem;
  margin: 0;
  accent-color: var(--primary);
}

button,
.alt-action {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 100%;
  min-height: 2.5rem;
  padding: 0.5rem 1rem;
  border: 1px solid transparent;
  border-radius: var(--radius-control);
  font: inherit;
  font-weight: var(--font-weight-medium);
  line-height: var(--leading-tight);
  text-align: center;
  cursor: pointer;
  transition:
    background-color var(--duration-fast) var(--ease-standard),
    border-color var(--duration-fast) var(--ease-standard);
}

button {
  margin-top: 1.5rem;
  background-color: var(--primary);
  color: var(--primary-foreground);
}

button:hover {
  background-color: var(--primary-hover);
}

button:disabled {
  cursor: not-allowed;
  opacity: 0.5;
}

button:disabled:hover {
  background-color: var(--primary);
}

/* The other choice: an outline button, or a link drawn as one. */
button.secondary,
.alt-action {
  border-color: var(--input);
  background-color: transparent;
  color: var(--foreground);
}

button.secondary:hover,
.alt-action:hover {
  background-color: var(--muted);
}

button.secondary {
  margin-top: 0.75rem;
}

.alt-action {
  margin-top: 1rem;
  text-decoration: none;
}

.footer-link {
  display: block;
  margin-top: 1.25rem;
  text-align: center;
}

.hint {
  margin: 0.375rem 0 0;
  color: var(--muted-foreground);
}

.error,
.status {
  padding: 0.625rem 0.75rem;
  border-radius: var(--radius-control);
}

.error {
  margin: 0 0 1rem;
  background-color: var(--destructive-surface);
  color: var(--destructive);
}

.status {
  margin: 1rem 0 0;
  background-color: var(--muted);
  color: var(--body);
}

details {
  margin-top: 1.5rem;
}

summary {
  color: var(--primary-text);
  cursor: pointer;
}

.qr {
  width: 15rem;
  max-width: 100%;
  margin: 1.25rem auto;
  padding: 0.5rem;
  border: 1px solid var(--border);
  /* White in both modes, never a token: a scanner reads dark modules on a light ground. */
  background-color: #fff;
}

.qr svg {
  display: block;
}

@media (max-width: 30rem) {
  body {
    padding: 1rem 0.75rem;
  }

  .card {
    padding: 1.5rem 1.25rem;
  }
}
`;

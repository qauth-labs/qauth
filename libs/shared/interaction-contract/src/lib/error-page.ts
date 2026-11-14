import { CEREMONY_PAGE_PREFIX } from './identifiers';

/**
 * THE CEREMONY APP'S ERROR PAGE (#1106; ADR-019 Decisions 5 and 6, ADR-020
 * §3).
 *
 * Some endings leave no interaction for a ceremony page to read: the
 * callback of an upstream provider whose interaction expired, moved on or
 * belongs to another browser, and the pages an RP-initiated logout ends on.
 * A realm may name a page of its ceremony app for them, its
 * `ceremonyApp.errorPage` policy: a path on the realm origin under `/ui/`,
 * which the ceremony app serves as it serves `/ui/interaction/{id}`. With it
 * set, the auth server answers `303 See Other` to that path with the query
 * below, and renders no page of its own; without it, the auth server renders
 * its own page, as before.
 *
 * Every refusal that leaves an interaction live goes back to that
 * interaction's ceremony page instead, as its step's `error`.
 */

/** The codes the error page is sent, with what each means. */
export const ERROR_PAGE_CODES = {
  interaction_expired:
    'An upstream provider sent the browser back for a sign-in with no interaction left to continue: it expired or ended, it moved on, or the browser is not the one that started it. Nothing was signed in, and nothing went to the client.',
  logout_refused:
    'An app’s sign-out request was refused: it named a return URI the app did not register, a client that is not the ID token hint’s audience, or a client that may not be used. Nothing was signed out.',
  logout_finished:
    'A sign-out ended with no app the browser is sent back to: `signed_out` says whether this browser now holds no session of the realm, and `host`, when present, names the app the person would go back to, which the browser is not sent to because the operator did not set the app up.',
} as const;

/** A code of {@link ERROR_PAGE_CODES}. */
export type ErrorPageCode = keyof typeof ERROR_PAGE_CODES;

/** The members of the error page's query, with what each holds. */
export const ERROR_PAGE_PARAMETERS = {
  code: 'Always: one of the codes. A page that does not know a code shows a general message.',
  trace_id:
    'The id the server logged the request that sent the browser here under, as a problem document’s `trace_id` (ADR-019 Decision 7): the page shows it, so an operator can find the request. Absent when that id is not one a `trace_id` can carry.',
  signed_out:
    'With `logout_finished`: `true` when this browser holds no session of the realm, `false` when it is still signed in (the person chose to stay).',
  host: 'With `logout_finished` and `signed_out=true`, at most: the host of the app’s registered return URI, in ASCII form, for a web app the operator did not set up. Text to show, never a link.',
} as const;

/** A member of the error page's query. */
export type ErrorPageParameter = keyof typeof ERROR_PAGE_PARAMETERS;

/** The rules a page that serves the error page follows. */
export const ERROR_PAGE_RULES: readonly string[] = [
  `The page is a path of the ceremony app on the realm origin, under \`/ui/\` as \`${CEREMONY_PAGE_PREFIX}{interactionId}\` is. The realm names it in its \`ceremonyApp.errorPage\` policy; the policy takes nothing but such a path, so the auth server never sends the browser to another origin from it.`,
  'Every member of the query is display data, as anyone can write the same URL. The page trusts nothing navigational from it (ADR-019 Decision 5): it never builds a link or a redirect from `host` or any other member, and it shows each as text. It changes nothing and asks for nothing, so a forged query can only show a wrong message.',
  'The page reads no interaction: there is none to read, and no step to answer. The person’s way on is their own, such as going back to the app they came from; the realm’s brand `help` link says where to get help.',
];

/**
 * The error page as the published document and the docs page describe it:
 * what it is for, its query and its rules, in Markdown.
 */
export function errorPageDescription(): string {
  const code = (value: string) => `\`${value}\``;
  return [
    `Some endings leave no interaction for a ceremony page to read: an upstream provider's callback for an interaction that expired, moved on or belongs to another browser, and the pages an RP-initiated logout ends on (#1106). A realm may name its ceremony app's error page for them, in its ${code('ceremonyApp.errorPage')} policy. With it set, the auth server answers ${code('303 See Other')} to that path with the query below and renders no page; without it, it renders its own page. A refusal that leaves the interaction live goes back to the interaction's ceremony page instead, as its step's ${code('error')} with the refusing request's ${code('trace_id')}.`,
    [
      '| Code | Meaning |',
      '| ---- | ------- |',
      ...Object.entries(ERROR_PAGE_CODES).map(
        ([name, meaning]) => `| ${code(name)} | ${meaning} |`
      ),
    ].join('\n'),
    [
      '| Query member | Holds |',
      '| ------------ | ----- |',
      ...Object.entries(ERROR_PAGE_PARAMETERS).map(
        ([name, holds]) => `| ${code(name)} | ${holds} |`
      ),
    ].join('\n'),
    ERROR_PAGE_RULES.map((rule) => `- ${rule}`).join('\n'),
  ].join('\n\n');
}

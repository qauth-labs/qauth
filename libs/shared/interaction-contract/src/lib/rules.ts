import {
  FLOW_COOKIE_NAME,
  INTERACTION_API_PREFIX,
  INTERACTION_OPENAPI_PATH,
  WALLET_RETURN_PREFIX,
} from './identifiers';

/**
 * The rules the Interaction API follows, in words. The OpenAPI document's
 * `info.description` and the docs page both render these lists, and a test
 * checks that each sentence appears in both, so the two cannot drift apart.
 */

/** The rules of ADR-019 Decision 6 that every operation shows. */
export const API_RULES: readonly string[] = [
  `Browser-facing and same-origin. A page calls the API on the realm origin it was served from. A flow cookie (\`${FLOW_COOKIE_NAME}\`) and a CSRF value protect it, and the server sends no CORS headers.`,
  'Typed data from the auth server’s own records, never HTML. Every string a response carries is an enum, a constant or a bounded value with a pattern. A display value has no markup bracket, no control, format, private-use or unassigned character, no line separator, and no space at either end.',
  'No URL carries `return_to`, a redirect or a client parameter. A page reads one opaque interaction id from its own URL, and the client, the redirect target and everything else it shows come from the API.',
  'The interaction id alone reads the current step, with no personal data. Personal data, such as the account chooser’s list, needs the flow cookie. Answering a step or cancelling the interaction needs the flow cookie, the step’s CSRF value and a same-origin request.',
  'Every operation answers with `Cache-Control: no-store`.',
];

/** The versioning rules (ADR-018 §5, ADR-019 Decision 6, ADR-017 Decision 3). */
export const VERSIONING_RULES: readonly string[] = [
  `The path carries the major version. Until QAuth 1.0.0 it is a release candidate, \`/interaction/v1-rc.<M>\` (today \`${INTERACTION_API_PREFIX}\`), and nothing about it is promised: a breaking change raises \`<M>\`. The release that ships 1.0.0 serves \`/interaction/v1\`.`,
  'Within a major version, changes are additive only: new operations, new steps, new optional request members, new response members, and new values of an extensible set (step names, problem codes, fonts).',
  'A client ignores response members it does not know, and a page shows its error page for a step it does not know. A request with a member the operation does not declare is refused.',
  'Removing or renaming a member, changing a type, tightening validation, changing a status code, removing an operation or a step, and adding to a closed set, such as a step’s errors, need a new major version.',
  'A successor major version is served beside the previous one for at least 12 months, and the previous one stays until the next major release of QAuth.',
  'A step is named `urn:qauth:ia:<name>:v1-rc.<M>` until 1.0.0 and `urn:qauth:ia:<name>:v1` from then on, with the same release candidate as the path. QAuth never renames a step; if a registry of standard step names appears, its names are added beside QAuth’s.',
];

/** What the reserved prefix is for. */
export const RESERVED_PREFIX_RULE = `The prefix \`${WALLET_RETURN_PREFIX}\` is reserved for the wallet return leg (ADR-013). No operation of this document is served under it.`;

/** Where the auth server serves the document. */
export const DOCUMENT_PATH_RULE = `The auth server serves this document at \`${INTERACTION_OPENAPI_PATH}\`.`;

import {
  ACCOUNT_API_AUDIENCE,
  ACCOUNT_API_PREFIX,
  ACCOUNT_API_SCOPES,
  FRESH_AUTHENTICATION_MAX_AGE_SECONDS,
} from './identifiers';
import { SECURITY_LOG_DEFAULT_RETENTION_DAYS } from './security-log';

/**
 * The rules the account API follows, in words. The OpenAPI document's
 * `info.description` and the docs page both render these lists, and a test
 * checks that each sentence appears in both, so the two cannot drift apart.
 */

const MAX_AGE = FRESH_AUTHENTICATION_MAX_AGE_SECONDS;

/** Who calls the API, and with what token (ADR-019 Decision 7). */
export const TOKEN_RULES: readonly string[] = [
  `The callers are backends, such as the account console’s, that hold a person’s access token whose only audience is \`${ACCOUNT_API_AUDIENCE}\`, sent as a Bearer token or, while the server’s DPoP support is on, a DPoP-bound one. No cookie authenticates a call, and the server sends no CORS headers. Each operation names the audience in \`x-qauth-audience\`.`,
  'The token’s subject is an enabled user of the request’s realm, and every operation acts on that user’s own account only. A resource of another account answers `not_found`, as one that does not exist.',
  `Each operation names the permission it needs in \`x-qauth-permission\` and its class in \`x-qauth-class\`. The token needs the account scope of that class: \`${ACCOUNT_API_SCOPES.read}\` for a \`read\` operation, \`${ACCOUNT_API_SCOPES.write}\` for a \`write\` one. The two are independent, so a caller that reads and writes asks for both. A token without it gets 403 \`forbidden\` with \`WWW-Authenticate: Bearer realm="OAuth", error="insufficient_scope", scope="<the scope>"\`, or, for a request in the \`DPoP\` scheme, \`WWW-Authenticate: DPoP error="insufficient_scope", scope="<the scope>", algs="<the proof algorithms>"\`, before any other rule of the operation. QAuth issues these scopes only to a client whose audience an operator set to \`${ACCOUNT_API_AUDIENCE}\`.`,
];

/** The fresh-authentication challenge (ADR-017 Decision 8, RFC 9470 §3). */
export const FRESH_AUTHENTICATION_RULES_TEXT: readonly string[] = [
  `An operation whose \`x-qauth-fresh-authentication\` is \`strongest-factor\` needs a sign-in at most ${MAX_AGE} seconds old (the token’s \`auth_time\`) whose \`amr\` holds the account’s strongest bound factor: \`pop\` when a passkey is bound, else \`otp\` when an authenticator app is, else \`pwd\`.`,
  '`strongest-factor-or-recovery-code` also accepts a sign-in of the same age that used a recovery code in place of a lost second factor. Only the two halves of a rebind after a lost factor take it (ADR-017 Decision 8): removing a passkey or the authenticator app, and binding a new authenticator app.',
  `Otherwise the operation answers 401 \`insufficient_user_authentication\` (RFC 9470 §3) with the challenge \`WWW-Authenticate: Bearer error="insufficient_user_authentication", max_age="${MAX_AGE}"\` when the sign-in is too old, or \`max_age="0"\` when it is recent but lacks the strongest factor. The problem document carries the same \`max_age\`. The caller sends the person to the authorization endpoint with that \`max_age\`, and repeats the call with the new token. That sign-in ends with the account’s strongest bound factor, since a sign-in completes only once the transaction has proved it (ADR-017, the downgrade rule).`,
];

/** The act-chain rule (ADR-019 Decision 7). */
export const ACT_CHAIN_RULES_TEXT: readonly string[] = [
  'An act-chain token (RFC 8693 `act`: an admin or an agent acting for the person) never counts as the person’s fresh authentication.',
  'An operation whose `x-qauth-act-chain` is `refused` answers an act-chain token with 403 `delegated_token_refused`, before any fresh-authentication check, so a delegated caller never gets a challenge it cannot meet. Every operation that changes a credential, an identifier, the contact address or a linked account refuses one, and so do deleting the account and reporting a sign-in as not the person’s.',
];

/** The shape rules every operation follows (`reference/api-conventions` on the docs site). */
export const API_RULES: readonly string[] = [
  'Typed data from the auth server’s own records, never HTML. Every string a response carries is an enum, a constant or a bounded value with a pattern. A display value has no markup bracket, no control, format, private-use or unassigned character, no line separator, and no space at either end, and `x-qauth-display` says where it comes from.',
  'A request takes no unbounded text: a value the person types, such as a profile value or a passkey’s name, is a bounded display value too. A password is the one exception: it takes any character, appears only in a request (`writeOnly`) and is never shown.',
  'Every error is an RFC 9457 problem document (`application/problem+json`) with a stable `code` and a `trace_id`, and no prose: no `detail`, no `instance`, and field errors as reason codes. Each error response lists the codes it may carry in `x-qauth-problem-codes`, a closed list per operation.',
  'A list pages by cursor: `limit` (1 to 200, default 50) and `cursor`, the opaque `nextCursor` of the previous page, which is `null` on the last page.',
  'An update is a JSON Merge Patch (RFC 7396, `application/merge-patch+json`) sent with `If-Match`, the `ETag` of the resource’s last read. A stale value answers 412 `precondition_failed`, a missing one 428 `precondition_required`.',
  'Every answer carries `Cache-Control: no-store`.',
  `The security log keeps an entry for ${SECURITY_LOG_DEFAULT_RETENTION_DAYS} days by default, a realm setting. Its \`kind\` is a closed list, built from QAuth’s events through an allow list.`,
];

/** The versioning rules (ADR-018 §5, ADR-019 Decision 7). */
export const VERSIONING_RULES: readonly string[] = [
  `The path and the audience carry the major version. Until QAuth 1.0.0 it is a release candidate, \`/account/v1-rc.<M>\` and \`urn:qauth:aud:account:v1-rc.<M>\` (today \`${ACCOUNT_API_PREFIX}\`), and nothing about it is promised: a breaking change raises \`<M>\` for both. The release that ships 1.0.0 serves \`/account/v1\`.`,
  'Within a major version, changes are additive only: new operations, new optional request members, new response members, and new values of an extensible set (problem codes, field error reasons, password rejection reasons, profile field types, security notices).',
  'A client ignores response members it does not know, and treats a problem code it does not know by its HTTP status. A request with a member the operation does not declare is refused.',
  'The published schemas close response objects (`additionalProperties: false`) to describe this version exactly. A later version may add members, so a client must not validate responses strictly against an older schema, and ignores the members it does not know.',
  'Removing or renaming a member, changing a type, tightening validation, changing a status code, removing an operation, changing what an operation asks of the token (`x-qauth-fresh-authentication`, `x-qauth-act-chain`) and adding to a closed set, such as the security log’s kinds, need a new major version.',
  'A successor major version is served beside the previous one for at least 12 months, and the previous one stays until the next major release of QAuth.',
];

/** What the auth server serves today, and what the account API replaces. */
export const STATUS_RULES: readonly string[] = [
  `This document is the contract, published before the implementation. The auth server serves fifteen of its operations today: \`account.consents.list\` and \`account.consents.delete\`, \`account.linkedAccounts.list\` and \`account.linkedAccounts.delete\`, \`account.signInMethods.get\` and \`account.password.change\`, \`account.passkeys.list\`, \`account.passkeys.get\`, \`account.passkeys.update\` and \`account.passkeys.delete\`, \`account.totp.enrollment.create\`, \`account.totp.enrollment.confirm\` and \`account.totp.delete\`, and \`account.recoveryCodes.get\` and \`account.recoveryCodes.regenerate\`; the others arrive with the account console’s backend. The served operations still answer errors with the auth server’s general problem document, which may carry \`detail\` and \`errors[].message\`; the implementation of this contract narrows them to its problem document. It also narrows what the two consent operations send beyond that: \`client_name\` is the name the client registered, which no display rule has checked; and the path accepts an id in capital letters.`,
  '`GET /consents` and `DELETE /consents/{id}`, which the hosted UI calls with the session cookie and an `X-CSRF-Token` header, are deprecated aliases of `account.consents.list` and `account.consents.delete`. They are removed when the account console replaces the hosted UI’s consents page.',
  '`GET /api/consents` and `DELETE /api/consents/{id}`, deprecated for `/developer/v1-rc.0/consents`, list and revoke a person’s consents with a developer-audience token. A person’s consents move from the developer portal to the account console (ADR-020 §3), so `account.consents.*` is what the console calls. Retiring the developer family’s consent operations is a change of that family’s own contract.',
];

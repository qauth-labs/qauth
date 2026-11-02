import { assetSchema, clientDisplaySchema } from './client-display';
import {
  ACCOUNT_API_AUDIENCE,
  ACCOUNT_API_PREFIX,
  ACCOUNT_API_VERSION,
  FRESH_AUTHENTICATION_MAX_AGE_SECONDS,
} from './identifiers';
import {
  ACCOUNT_OPERATIONS,
  ACCOUNT_TAGS,
  type AccountOperation,
  EXAMPLE_TRACE_ID,
  operationErrors,
} from './operations';
import {
  ACCOUNT_PROBLEM_CODES,
  type AccountProblemCodeName,
  problemTypeUri,
  STATUS_TITLES,
} from './problems';
import {
  ACT_CHAIN_RULES_TEXT,
  API_RULES,
  FRESH_AUTHENTICATION_RULES_TEXT,
  STATUS_RULES,
  TOKEN_RULES,
  VERSIONING_RULES,
} from './rules';
import { type JsonSchema } from './schema-kit';
import {
  addressChangeConfirmRequestSchema,
  addressChangeRequestSchema,
  addressChangeSchema,
  addressesSchema,
  clientReferenceSchema,
  consentSchema,
  CURSOR_SCHEMA,
  deletionPreviewSchema,
  deletionRequestSchema,
  deviceSchema,
  endAllSessionsRequestSchema,
  fieldErrorSchema,
  groupSchema,
  locationSchema,
  noticePreferenceSchema,
  notificationPreferencesSchema,
  PAGES,
  passkeyPatchSchema,
  passkeySchema,
  passwordChangeRequestSchema,
  problemSchema,
  profileFieldSchema,
  profilePatchSchema,
  profileSchema,
  recoveryCodeSetSchema,
  recoveryCodeStatusSchema,
  ref,
  securityLogEntrySchema,
  securityLogKindSchema,
  sessionSchema,
  signInMethodsSchema,
  totpConfirmRequestSchema,
  totpConfirmResultSchema,
  totpEnrollmentSchema,
  uuid,
} from './schemas';
import { SECURITY_LOG_KINDS } from './security-log';

/**
 * The account API v1 contract as one OpenAPI 3.1 document (#588). Pure:
 * `artifacts.ts` serialises it, the export script writes it, and the typed
 * client (`libs/shared/account-client`) is generated from the written file.
 *
 * Every operation of `operations.ts` becomes one operation here, with:
 *
 * - `x-qauth-audience`: the only audience its token may carry;
 * - `x-qauth-fresh-authentication`: `none`, `strongest-factor` or
 *   `strongest-factor-or-recovery-code` (`identifiers.ts`);
 * - `x-qauth-act-chain`: `accepted` or `refused`;
 * - `x-qauth-class`, `x-qauth-permission` and `x-qauth-stability`, as every
 *   API family operation (`reference/api-conventions` on the docs site);
 * - its error responses, each naming the codes it may carry
 *   (`x-qauth-problem-codes`) with one example per code;
 * - one example request (its parameters and body) and one example response.
 */

export type OpenApiDocument = { readonly [key: string]: unknown };

/** The OpenAPI version, the one the auth server's own export declares. */
export const OPENAPI_VERSION = '3.1.0';

/** The security requirement of every operation: a Bearer token, or a DPoP-bound one. */
export const ACCOUNT_SECURITY = [{ bearerAuth: [] }, { dpopAuth: [] }] as const;

const NO_STORE = { 'Cache-Control': { $ref: '#/components/headers/CacheControl' } };

// ---------------------------------------------------------------------------
// Problem examples
// ---------------------------------------------------------------------------

/** The members a code's document carries beyond the five every document has. */
const PROBLEM_EXAMPLE_MEMBERS: Partial<Record<AccountProblemCodeName, Record<string, unknown>>> = {
  validation_error: { errors: [{ pointer: '/limit', reason: 'too_long' }] },
  unprocessable_content: { errors: [{ pointer: '/fields/department', reason: 'read_only' }] },
  weak_password: { reasons: ['too_short', 'breached'] },
  insufficient_user_authentication: { max_age: FRESH_AUTHENTICATION_MAX_AGE_SECONDS },
};

/** An example problem document of `code`. */
export function problemExample(code: AccountProblemCodeName): Record<string, unknown> {
  const entry = ACCOUNT_PROBLEM_CODES[code];
  return {
    type: problemTypeUri(code),
    title: entry.title,
    status: entry.status,
    code,
    trace_id: EXAMPLE_TRACE_ID,
    ...PROBLEM_EXAMPLE_MEMBERS[code],
  };
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

/** The headers of an error response with `status`. */
function errorHeaders(status: number) {
  return {
    ...NO_STORE,
    ...(status === 401 ? { 'WWW-Authenticate': { $ref: '#/components/headers/Challenge' } } : {}),
    ...(status === 403
      ? { 'WWW-Authenticate': { $ref: '#/components/headers/ScopeChallenge' } }
      : {}),
    ...(status === 429 ? { 'Retry-After': { $ref: '#/components/headers/RetryAfter' } } : {}),
  };
}

/** The error responses of `operation`, each naming the codes it may carry. */
function errorResponses(operation: AccountOperation) {
  return Object.fromEntries(
    operationErrors(operation).map(([status, codes]) => [
      String(status),
      {
        description: `${STATUS_TITLES[status]}: ${codes.map((code) => `\`${code}\``).join(' or ')}.`,
        'x-qauth-problem-codes': codes,
        headers: errorHeaders(status),
        content: {
          'application/problem+json': {
            schema: ref('Problem'),
            examples: Object.fromEntries(
              codes.map((code) => [code, { $ref: `#/components/examples/${code}` }])
            ),
          },
        },
      },
    ])
  );
}

function successResponse(operation: AccountOperation) {
  const { success, example } = operation;
  const headers = {
    ...NO_STORE,
    ...(success.etag ? { ETag: { $ref: '#/components/headers/ETag' } } : {}),
  };
  return {
    [String(success.status)]: {
      description: success.description,
      headers,
      ...(success.schema === undefined
        ? {}
        : {
            content: {
              'application/json': {
                schema: ref(success.schema),
                example: example.response,
              },
            },
          }),
    },
  };
}

/** The query parameters of a list: the page size, the cursor and the list's filters. */
function listParameters(operation: AccountOperation) {
  if (operation.list === undefined) return [];
  const query = operation.example.query ?? {};
  return [
    {
      name: 'limit',
      in: 'query',
      required: false,
      description: 'How many items a page holds at most.',
      schema: { type: 'integer', minimum: 1, maximum: 200, default: 50 },
      ...('limit' in query ? { example: query['limit'] } : {}),
    },
    {
      name: 'cursor',
      in: 'query',
      required: false,
      description:
        'Where the page starts: the previous page’s `nextCursor`. Absent for the first page.',
      schema: CURSOR_SCHEMA,
      ...('cursor' in query ? { example: query['cursor'] } : {}),
    },
    ...(operation.list.filters ?? []).map((filter) => ({
      name: filter,
      in: 'query',
      required: false,
      description: 'List only the entries of this kind.',
      schema: ref('SecurityLogKind'),
      ...(filter in query ? { example: query[filter] } : {}),
    })),
  ];
}

function parameters(operation: AccountOperation) {
  const path = Object.entries(operation.pathParameters ?? {}).map(([name, description]) => ({
    name,
    in: 'path',
    required: true,
    description,
    schema: uuid(description),
    example: operation.example.pathParams?.[name],
  }));
  const ifMatch = operation.conditional
    ? [
        {
          name: 'If-Match',
          in: 'header',
          required: true,
          description:
            'The `ETag` of the resource’s last read. A stale value answers 412, a missing one 428.',
          schema: { type: 'string', minLength: 2, maxLength: 128, pattern: '^(?:W/)?"[!#-~]*"$' },
          example: operation.example.ifMatch,
        },
      ]
    : [];
  return [...path, ...listParameters(operation), ...ifMatch];
}

function requestBody(operation: AccountOperation) {
  const { body, example } = operation;
  if (body === undefined) return {};
  return {
    requestBody: {
      required: body.required,
      content: {
        [body.mediaType]: { schema: ref(body.schema), example: example.body },
      },
    },
  };
}

const FRESH_AUTHENTICATION_TEXT = {
  none: 'no fresh authentication',
  'strongest-factor': `fresh authentication with the account’s strongest factor (at most ${FRESH_AUTHENTICATION_MAX_AGE_SECONDS} seconds old)`,
  'strongest-factor-or-recovery-code': `fresh authentication with the account’s strongest factor or a recovery code (at most ${FRESH_AUTHENTICATION_MAX_AGE_SECONDS} seconds old)`,
} as const;

/** The sentence every operation's description ends with: what it asks of the token. */
export function tokenSentence(operation: AccountOperation): string {
  return `Token: audience \`${ACCOUNT_API_AUDIENCE}\`; ${
    FRESH_AUTHENTICATION_TEXT[operation.freshAuthentication]
  }; an act-chain token is ${operation.actChain}.`;
}

function operationObject(operation: AccountOperation) {
  const declared = parameters(operation);
  return {
    operationId: operation.id,
    summary: operation.summary,
    description: `${operation.description}\n\n${tokenSentence(operation)}`,
    tags: [operation.tag],
    security: ACCOUNT_SECURITY,
    'x-qauth-stability': 'stable',
    'x-qauth-class': operation.class,
    'x-qauth-permission': operation.permission,
    'x-qauth-audience': ACCOUNT_API_AUDIENCE,
    'x-qauth-fresh-authentication': operation.freshAuthentication,
    'x-qauth-act-chain': operation.actChain,
    ...(declared.length === 0 ? {} : { parameters: declared }),
    ...requestBody(operation),
    responses: { ...successResponse(operation), ...errorResponses(operation) },
  };
}

function paths() {
  const result: Record<string, Record<string, unknown>> = {};
  for (const operation of ACCOUNT_OPERATIONS) {
    const path = `${ACCOUNT_API_PREFIX}${operation.path}`;
    result[path] = { ...result[path], [operation.method]: operationObject(operation) };
  }
  return result;
}

// ---------------------------------------------------------------------------
// The document
// ---------------------------------------------------------------------------

const bullets = (lines: readonly string[]) => lines.map((line) => `- ${line}`).join('\n');

/** `info.description`: what the API is, its rules and its versioning rules. */
export function documentDescription(): string {
  return [
    'The account API is how a signed-in person manages their own account (ADR-019 Decision 7): the profile, the sign-in methods, the sessions, the security log, the addresses, the connected apps, the notices and deleting the account. The account console calls it from its backend, with the person’s access token.',
    `## Status\n\n${bullets(STATUS_RULES)}`,
    `## Tokens\n\n${bullets(TOKEN_RULES)}`,
    `## Fresh authentication\n\n${bullets(FRESH_AUTHENTICATION_RULES_TEXT)}`,
    `## Act-chain tokens\n\n${bullets(ACT_CHAIN_RULES_TEXT)}`,
    `## Rules\n\n${bullets(API_RULES)}`,
    `## Versioning\n\n${bullets(VERSIONING_RULES)}`,
  ].join('\n\n');
}

/** `SecurityLogKind`, with what each kind means and the events it is built from. */
function securityLogKindComponent(): JsonSchema {
  const lines = Object.entries(SECURITY_LOG_KINDS).map(
    ([kind, entry]) =>
      `\`${kind}\`: ${entry.description} From ${entry.sources.map((source) => `\`${source.event}\``).join(' and ')}.`
  );
  return {
    ...securityLogKindSchema,
    description: `${String(securityLogKindSchema['description'])}\n\n${bullets(lines)}`,
  };
}

/** Build the document. Deterministic: the same contract gives the same bytes. */
export function buildAccountOpenApi(): OpenApiDocument {
  return {
    openapi: OPENAPI_VERSION,
    info: {
      title: 'QAuth Account API',
      version: ACCOUNT_API_VERSION,
      description: documentDescription(),
      license: { name: 'Apache-2.0', identifier: 'Apache-2.0' },
    },
    servers: [
      {
        url: '/',
        description:
          'The auth server’s origin for the realm, the issuer’s. A caller’s backend calls it server to server.',
      },
    ],
    tags: Object.entries(ACCOUNT_TAGS).map(([name, description]) => ({ name, description })),
    paths: paths(),
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
          description: `An access token (RFC 9068) whose only audience is \`${ACCOUNT_API_AUDIENCE}\` and whose subject is a user of the realm.`,
        },
        dpopAuth: {
          type: 'http',
          scheme: 'DPoP',
          description:
            'The same access token, bound to a key (RFC 9449), with a `DPoP` proof of the request. Accepted while the server’s DPoP support is on.',
        },
      },
      headers: {
        CacheControl: {
          description: 'Every answer is `no-store`.',
          schema: { type: 'string', const: 'no-store' },
        },
        ETag: {
          description:
            'The version of the resource. An update sends it back in `If-Match` (RFC 9110 §13.1.1).',
          schema: { type: 'string', minLength: 2, maxLength: 128, pattern: '^(?:W/)?"[!#-~]*"$' },
        },
        RetryAfter: {
          description: 'How many seconds to wait before trying again.',
          schema: { type: 'integer', minimum: 0 },
        },
        Challenge: {
          description: `The challenge (RFC 6750 §3): \`Bearer realm="OAuth"\` without a token, with \`error="invalid_token"\` for a refused one, and \`Bearer error="insufficient_user_authentication", max_age="${FRESH_AUTHENTICATION_MAX_AGE_SECONDS}"\` (or \`max_age="0"\`) when fresh authentication is needed (RFC 9470 §3). A DPoP-bound token gets the same under the \`DPoP\` scheme.`,
          schema: { type: 'string', minLength: 1, maxLength: 1024, pattern: '^[!-~][ -~]*$' },
        },
        ScopeChallenge: {
          description:
            'With `forbidden`: the `insufficient_scope` challenge, whose `scope` names the scopes the operation needs (RFC 6750 §3.1). Absent with the other codes.',
          schema: { type: 'string', minLength: 1, maxLength: 1024, pattern: '^[!-~][ -~]*$' },
        },
      },
      schemas: {
        Problem: problemSchema,
        FieldError: fieldErrorSchema,
        Profile: profileSchema,
        ProfileField: profileFieldSchema,
        Group: groupSchema,
        ProfilePatch: profilePatchSchema,
        SignInMethods: signInMethodsSchema,
        PasswordChangeRequest: passwordChangeRequestSchema,
        Passkey: passkeySchema,
        PasskeyPage: PAGES.PasskeyPage,
        PasskeyPatch: passkeyPatchSchema,
        TotpEnrollment: totpEnrollmentSchema,
        TotpConfirmRequest: totpConfirmRequestSchema,
        TotpConfirmResult: totpConfirmResultSchema,
        RecoveryCodeSet: recoveryCodeSetSchema,
        RecoveryCodeStatus: recoveryCodeStatusSchema,
        Session: sessionSchema,
        SessionPage: PAGES.SessionPage,
        Device: deviceSchema,
        Location: locationSchema,
        EndAllSessionsRequest: endAllSessionsRequestSchema,
        SecurityLogKind: securityLogKindComponent(),
        SecurityLogEntry: securityLogEntrySchema,
        SecurityLogPage: PAGES.SecurityLogPage,
        ClientReference: clientReferenceSchema,
        Addresses: addressesSchema,
        AddressChangeRequest: addressChangeRequestSchema,
        AddressChange: addressChangeSchema,
        AddressChangeConfirmRequest: addressChangeConfirmRequestSchema,
        Consent: consentSchema,
        ConsentPage: PAGES.ConsentPage,
        ClientDisplay: clientDisplaySchema,
        Asset: assetSchema,
        DeletionPreview: deletionPreviewSchema,
        DeletionRequest: deletionRequestSchema,
        NotificationPreferences: notificationPreferencesSchema,
        NoticePreference: noticePreferenceSchema,
      },
      examples: Object.fromEntries(
        (Object.keys(ACCOUNT_PROBLEM_CODES) as AccountProblemCodeName[]).map((code) => [
          code,
          { summary: ACCOUNT_PROBLEM_CODES[code].title, value: problemExample(code) },
        ])
      ),
    },
  };
}

/** The document, built once. */
export const ACCOUNT_OPENAPI: OpenApiDocument = buildAccountOpenApi();

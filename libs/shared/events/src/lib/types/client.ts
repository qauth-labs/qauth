import { z } from 'zod';

import { defineEventType } from '../definition';
import { extensibleEnum } from '../envelope';
import { FIRST_RELEASE, scopeList } from './fields';

/**
 * OAuth clients and their API keys. The client is the subject, as its
 * `client_id`; an API key event's subject is the key, and its client is the
 * envelope's `client`.
 */

export const CLIENT_REGISTRATIONS = ['dynamic', 'developer_api'] as const;

export const clientCreated = defineEventType({
  name: 'client.created',
  version: 1,
  rc: 0,
  description:
    'An OAuth client was created: by RFC 7591 dynamic registration, or by a developer through the developer API.',
  category: 'user',
  severity: 'info',
  since: FIRST_RELEASE,
  subject: 'client',
  data: z.strictObject({
    registration: extensibleEnum(CLIENT_REGISTRATIONS).describe(
      '`dynamic`: RFC 7591 dynamic client registration. `developer_api`: a developer created it. The set may grow in a minor release.'
    ),
    isPublic: z.boolean().describe('Whether the client is public, with no client authentication.'),
    isAgent: z
      .boolean()
      .optional()
      .describe('Whether the client registered as an agent (ADR-007 §2).'),
    grantTypes: z
      .array(z.string().min(1).max(255))
      .max(32)
      .describe('The grant types the client may use.'),
    scopes: scopeList('The scopes the client may request.').optional(),
    authMethod: z
      .string()
      .min(1)
      .max(64)
      .optional()
      .describe('How the client authenticates at the token endpoint, such as `private_key_jwt`.'),
  }),
});

export const clientUpdated = defineEventType({
  name: 'client.updated',
  version: 1,
  rc: 0,
  description: "A developer changed a client's settings.",
  category: 'user',
  severity: 'info',
  since: FIRST_RELEASE,
  subject: 'client',
  data: z.strictObject({
    fields: z
      .array(z.string().min(1).max(64))
      .max(64)
      .describe('The names of the settings that changed. Never their values.'),
  }),
});

export const clientDeleted = defineEventType({
  name: 'client.deleted',
  version: 1,
  rc: 0,
  description: 'A developer deleted a client.',
  category: 'user',
  severity: 'info',
  since: FIRST_RELEASE,
  subject: 'client',
  data: z.strictObject({}),
});

export const clientSecretRotated = defineEventType({
  name: 'client.secret_rotated',
  version: 1,
  rc: 0,
  description: "A developer replaced a client's secret. The old secret stopped working.",
  category: 'user',
  severity: 'info',
  since: FIRST_RELEASE,
  subject: 'client',
  data: z.strictObject({}),
});

export const clientSuspended = defineEventType({
  name: 'client.suspended',
  version: 1,
  rc: 0,
  description:
    'An operator suspended a client: it can no longer obtain tokens until the suspension is lifted.',
  category: 'admin',
  severity: 'warning',
  since: FIRST_RELEASE,
  subject: 'client',
  data: z.strictObject({}),
});

export const clientSuspensionLifted = defineEventType({
  name: 'client.suspension_lifted',
  version: 1,
  rc: 0,
  description: "An operator lifted a client's suspension.",
  category: 'admin',
  severity: 'info',
  since: FIRST_RELEASE,
  subject: 'client',
  data: z.strictObject({}),
});

export const apiKeyCreated = defineEventType({
  name: 'api_key.created',
  version: 1,
  rc: 0,
  description: 'A developer created an API key for a client.',
  category: 'user',
  severity: 'info',
  since: FIRST_RELEASE,
  subject: 'api_key',
  data: z.strictObject({}),
});

export const apiKeyRevoked = defineEventType({
  name: 'api_key.revoked',
  version: 1,
  rc: 0,
  description: 'A developer revoked an API key. It stopped working.',
  category: 'user',
  severity: 'info',
  since: FIRST_RELEASE,
  subject: 'api_key',
  data: z.strictObject({}),
});

export const CLIENT_EVENT_TYPES = [
  clientCreated,
  clientUpdated,
  clientDeleted,
  clientSecretRotated,
  clientSuspended,
  clientSuspensionLifted,
  apiKeyCreated,
  apiKeyRevoked,
] as const;

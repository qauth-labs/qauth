import { z } from 'zod';

import { defineEventType } from '../definition';
import { extensibleEnum } from '../envelope';
import { CAEP_CREDENTIAL_CHANGE } from '../ssf-mapping';
import { count, FIRST_RELEASE, scopeList } from './fields';

/**
 * OAuth clients and their API keys. The client is the subject, as its
 * `client_id`; an API key event's subject is the key, and its client is the
 * envelope's `client`.
 */

export const CLIENT_REGISTRATIONS = ['dynamic', 'developer_api'] as const;

/**
 * Why a client's suspension and deletion have no SSF event: no standard event
 * is about a client.
 */
const NO_CLIENT_STATE_EVENT =
  'No CAEP 1.0 or RISC 1.0 event describes a client’s suspension or deletion: RISC `account-disabled` is about an account a person signs in to.';

/**
 * The CAEP `credential_type` of a client's credentials. CAEP 1.0 §3.3.1 lists
 * the credentials a person authenticates with and allows any other type the
 * transmitter and the receiver agree on; these two are QAuth's.
 */
const CLIENT_SECRET_CREDENTIAL = 'client-secret';
const API_KEY_CREDENTIAL = 'api-key';

/**
 * Why a client's credential change goes to that client's own stream only, and
 * names `admin`: a client id is no secret, so any receiver could add another
 * client as a subject and watch its credentials change. A developer managing
 * a client's credentials acts as its administrator, not as an end user.
 */
const OWN_CREDENTIALS_NOTE =
  'Sent only to the stream of the client whose credential changed, never to another receiver that added that client: a receiver learns of its own credentials only. A developer managing a client acts as its administrator, so `initiating_entity` is `admin`.';

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
  security: true,
  ssf: 'none',
  ssfNote: NO_CLIENT_STATE_EVENT,
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
  security: true,
  ssf: {
    event: CAEP_CREDENTIAL_CHANGE,
    clientOnly: true,
    initiatingEntity: 'admin',
    members: {
      credential_type: { value: CLIENT_SECRET_CREDENTIAL },
      change_type: { value: 'update' },
    },
  },
  ssfNote: OWN_CREDENTIALS_NOTE,
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
  security: true,
  ssf: 'none',
  ssfNote: NO_CLIENT_STATE_EVENT,
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
  security: true,
  ssf: 'none',
  ssfNote: NO_CLIENT_STATE_EVENT,
});

/**
 * The first-party profiles of ADR-017 Decision 2, as an event names them.
 * ADR-017 phase F4 adds `native_attested`.
 */
export const CLIENT_FIRST_PARTY_PROFILES = ['web_redirect', 'native_backend'] as const;

/** The flows a `native_backend` client's policy may allow. */
export const CLIENT_FIRST_PARTY_FLOWS = ['login', 'register', 'reset'] as const;

const firstPartyProfile = (description: string) =>
  extensibleEnum(CLIENT_FIRST_PARTY_PROFILES).nullable().describe(description);

export const clientFirstPartyChanged = defineEventType({
  name: 'client.first_party_changed',
  version: 1,
  rc: 0,
  description:
    "An operator set, changed or removed a client's first-party profile (ADR-017 Decision 2), its policy or its written reason. Removing the profile revoked every refresh token family of the client in the same transaction.",
  category: 'admin',
  severity: 'warning',
  since: FIRST_RELEASE,
  subject: 'client',
  data: z.strictObject({
    from: firstPartyProfile(
      '`web_redirect` or `native_backend`: the profile before the change, or `null` when the client was not first party. The set may grow in a minor release.'
    ),
    to: firstPartyProfile(
      'The profile after the change, or `null` when it was removed. The set may grow in a minor release.'
    ),
    flows: z
      .array(extensibleEnum(CLIENT_FIRST_PARTY_FLOWS))
      .min(1)
      .max(16)
      .optional()
      .describe(
        "A `native_backend` client's flows after the change: `login`, `register`, `reset`. Absent for any other profile."
      ),
    pkceRequired: z
      .boolean()
      .optional()
      .describe(
        "Whether a `native_backend` client's policy requires PKCE at the authorization challenge endpoint after the change. `false` is a deviation the operator chose for this client. Absent for any other profile."
      ),
    writtenReason: z
      .string()
      .min(1)
      .max(1000)
      .optional()
      .describe(
        'The reason the operator wrote for the profile, as stored with the client. Absent when the profile was removed.'
      ),
    revokedTokenCount: count(
      'How many refresh tokens the removal revoked: every live token of every family of the client. `0` when the profile was set or changed.'
    ),
  }),
  security: true,
  ssf: 'none',
  ssfNote:
    'No CAEP 1.0 or RISC 1.0 event describes a change of trust in a client. The tokens the removal revoked were the client’s, not a person’s session.',
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
  security: true,
  ssf: {
    event: CAEP_CREDENTIAL_CHANGE,
    // The key is the client's credential: the SET is about the client.
    subject: 'client',
    clientOnly: true,
    initiatingEntity: 'admin',
    members: {
      credential_type: { value: API_KEY_CREDENTIAL },
      change_type: { value: 'create' },
    },
  },
  ssfNote: OWN_CREDENTIALS_NOTE,
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
  security: true,
  ssf: {
    event: CAEP_CREDENTIAL_CHANGE,
    subject: 'client',
    clientOnly: true,
    initiatingEntity: 'admin',
    members: {
      credential_type: { value: API_KEY_CREDENTIAL },
      change_type: { value: 'revoke' },
    },
  },
  ssfNote: OWN_CREDENTIALS_NOTE,
});

export const CLIENT_EVENT_TYPES = [
  clientCreated,
  clientUpdated,
  clientDeleted,
  clientSecretRotated,
  clientSuspended,
  clientSuspensionLifted,
  clientFirstPartyChanged,
  apiKeyCreated,
  apiKeyRevoked,
] as const;

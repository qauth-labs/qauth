import { z } from 'zod';

/**
 * One active consent, as the account API (`/account/v1-rc.0/consents`) and
 * the developer API (`/developer/v1-rc.0/consents`) show it (#524): the grant
 * a user gave a client, in the API conventions' representation. The client is
 * named by its OAuth `client_id`, which may be a URL (a Client ID Metadata
 * Document client), and by its `client_name`.
 *
 * The deprecated `/api/consents` and `/consents` keep their own shape.
 */
export const familyConsentSchema = z.object({
  id: z.uuid(),
  client_id: z.string(),
  client_name: z.string(),
  scopes: z.array(z.string()),
  grantedAt: z.iso.datetime(),
});

export type FamilyConsent = z.infer<typeof familyConsentSchema>;

/** The path parameters of one consent. */
export const consentParamsSchema = z.object({ consentId: z.uuid() });

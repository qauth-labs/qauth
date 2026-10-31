import { z } from 'zod';

import { groupDocsLink } from '../docs';
import { ordered, policyField } from '../field';

const link = groupDocsLink('registration');

/**
 * An OAuth scope token (RFC 6749 §3.3) outside QAuth's reserved `qauth:`
 * namespace, in any case (#507, `isReservedQauthScope` in
 * `@qauth-labs/shared-validation`; the realm row's CHECK
 * `realms_dynamic_registration_scopes_not_qauth` refuses the same).
 */
const OPEN_SCOPE_PATTERN = /^(?![qQ][aA][uU][tT][hH]:)[\x21\x23-\x5B\x5D-\x7E]+$/;

/** A DNS label: 1 to 63 letters, digits and inner hyphens. */
const LABEL = '[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?';

/**
 * A host a CIMD `client_id` URL may have, or `*.` and a parent domain of such
 * hosts: at least two labels, the last of them not all digits, so neither a
 * bare top-level domain (`com`, `*.com`) nor an IPv4 literal is one; an IPv6
 * literal has characters no label has.
 *
 * Upper-case letters match too. The type lower-cases a domain before this
 * check, so it never sees one, but the JSON Schema of the input views shows
 * this pattern to a writer, who may send one.
 */
const TRUSTED_DOMAIN_PATTERN = new RegExp(`^(?:\\*\\.)?(?:${LABEL}\\.)+(?![0-9]+$)${LABEL}$`);

/**
 * Client registration (`registration`, #514; read from the realm row by
 * #534): dynamic client registration (RFC 7591) and Client ID Metadata
 * Documents (CIMD).
 *
 * Each loosening changes who can receive a token (ADR-019 Decision 7,
 * `token-content`): a scope added to what a dynamically registered client may
 * hold, CIMD switched on, the trust policy widened to any HTTPS host, or a
 * domain added to the allowlist. The trusted domains name hosts of the
 * realm's environment, so a sandbox promotion leaves them out unless they are
 * selected.
 */
export const REGISTRATION_POLICY_GROUP = {
  dynamicRegistrationAllowedScopes: policyField(
    z.array(z.string().max(255).regex(OPEN_SCOPE_PATTERN)).max(100),
    {
      seedEnv: 'DEFAULT_DYNAMIC_REGISTRATION_SCOPES',
      default: ['openid', 'profile', 'email', 'offline_access'],
      direction: 'subset-is-stricter',
      securityWhen: 'loosening',
      effects: ['token-content'],
      secret: false,
      environmentBound: false,
      doc: {
        summary:
          'The scopes a dynamically registered client may hold; a scope outside the list is dropped from the registration, and no scope of the reserved qauth: namespace can be listed.',
        link,
      },
    }
  ),
  cimd: {
    enabled: policyField(z.boolean(), {
      seedEnv: 'CIMD_ENABLED',
      default: true,
      direction: 'false-is-stricter',
      securityWhen: 'loosening',
      effects: ['token-content'],
      secret: false,
      environmentBound: false,
      doc: {
        summary:
          'Whether an HTTPS URL is accepted as a client_id, its metadata fetched from that URL (Client ID Metadata Documents).',
        link,
      },
    }),
    trustPolicy: policyField(z.enum(['accept-any-https', 'allowlist']), {
      seedEnv: 'CIMD_TRUST_POLICY',
      default: 'accept-any-https',
      direction: ordered(['accept-any-https', 'allowlist']),
      securityWhen: 'loosening',
      effects: ['token-content'],
      secret: false,
      environmentBound: false,
      doc: {
        summary:
          'Which hosts a metadata-document client_id may have: any HTTPS host, or only the trusted domains.',
        link,
      },
    }),
    trustedDomains: policyField(
      z.array(z.string().max(253).toLowerCase().regex(TRUSTED_DOMAIN_PATTERN)).max(100),
      {
        seedEnv: 'CIMD_TRUSTED_DOMAINS',
        default: [],
        direction: 'subset-is-stricter',
        securityWhen: 'loosening',
        effects: ['token-content'],
        secret: false,
        environmentBound: true,
        doc: {
          summary:
            'The hosts the allowlist policy accepts, stored in lower case; an entry `*.example.com` accepts every subdomain of `example.com` but not `example.com` itself.',
          link,
        },
      }
    ),
  },
} as const;

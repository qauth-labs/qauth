import { z } from 'zod';

import { groupDocsLink } from '../docs';
import { policyField } from '../field';

/**
 * A path the ceremony app serves on the realm origin: under `/ui/` (ADR-019
 * Decision 5), one to eight segments of RFC 3986 unreserved characters, none
 * of which starts with a dot, so no segment is `.` or `..`. It has no scheme,
 * no host, no `//`, no backslash, no percent-encoding, no query and no
 * fragment, so a browser resolves it against the realm origin and nowhere
 * else, and a proxy routes it as written.
 */
export const CEREMONY_APP_PAGE_PATTERN = /^\/ui(?:\/[A-Za-z0-9_~-][A-Za-z0-9._~-]{0,63}){1,8}$/;

/** The longest such path. */
export const CEREMONY_APP_PAGE_MAX_LENGTH = 256;

/**
 * The ceremony app (`ceremonyApp`, #1106; ADR-019 Decisions 5 and 6, ADR-020
 * §3): what the auth server needs to know of the realm's ceremony app beyond
 * the Interaction API.
 *
 * `errorPage` names the ceremony app's page for the endings that leave no
 * interaction to read: an upstream provider's callback for an interaction
 * that expired, moved on or belongs to another browser, and the pages an
 * RP-initiated logout ends on. With it set, the auth server answers `303` to
 * it with `code` and `trace_id` (and, for a logout, `signed_out` and `host`)
 * instead of rendering a page of its own; `null`, the default, keeps the
 * auth server's own pages. It is a path on the realm origin, never a URL, so
 * it cannot send the browser to another origin.
 *
 * `CEREMONY_APP_ERROR_PAGE` seeds it (#1118): a new realm's, and that of a
 * realm whose stored policies lack it. QAuth 0.2.4 added the field with no
 * key, so every realm it booted stored `null`; the schema upgrade to 1-rc.2
 * (`CEREMONY_APP_ERROR_PAGE_FILL_UPGRADE`) drops that `null`, so the first
 * boot of 0.2.5 fills it from the key, once, an admin's deliberate `null`
 * included. A value this field refuses stops the boot, naming the key. The
 * seed is the only way to name the page for a deployment that runs no admin
 * listener, which has no admin API to update the policy with.
 *
 * Neither value is stricter, and no change of it has an effect of ADR-019
 * Decision 7's closed list: it changes which page of the realm's own
 * ceremony app, part of the realm's trusted computing base, shows an
 * ending, as the brand's strings change what a page says. So every change is
 * a write.
 */
export const CEREMONY_APP_POLICY_GROUP = {
  errorPage: policyField(
    z
      .string()
      .max(CEREMONY_APP_PAGE_MAX_LENGTH)
      .regex(CEREMONY_APP_PAGE_PATTERN, {
        message:
          'is a path on the realm origin under /ui/, of unreserved characters, with no query or fragment',
      })
      .nullable(),
    {
      seedEnv: 'CEREMONY_APP_ERROR_PAGE',
      default: null,
      direction: 'opaque',
      securityWhen: 'never',
      effects: [],
      secret: false,
      environmentBound: false,
      doc: {
        summary:
          'The path on the realm origin, under `/ui/`, of the ceremony app’s page for the endings that leave no interaction to show (a provider callback whose sign-in has ended, the logout’s own pages), or null to keep the auth server’s own pages.',
        link: groupDocsLink('ceremonyApp'),
      },
    }
  ),
} as const;

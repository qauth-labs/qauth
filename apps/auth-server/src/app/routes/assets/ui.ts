import type { FastifyInstance } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { realmRateLimitKey } from '../../helpers/realm-rate-limit';
import { UI_ASSET_NAME, UI_ASSET_NAME_MAX_LENGTH, uiAsset } from '../../helpers/ui-assets';

/**
 * THE SERVER-RENDERED PAGES' STYLESHEET AND FONTS (#472):
 * `GET /assets/ui/<file>`.
 *
 * Serves the files `helpers/ui-assets.ts` built when it loaded: the one
 * stylesheet every page links and the woff2 files it names. Each name carries
 * a hash of its content, so a cache may keep the answer for a year without
 * asking again (`immutable`); a new stylesheet or font comes under a new
 * name. A name of another shape is refused by the schema (400), and a
 * well-formed name outside the set is the app's 404, as an unknown path is:
 * the name is only a key of that set, never part of a path on disk.
 *
 * Under `/assets/ui/`, not `/ui/`: some of the pages that link these files
 * are outside `/ui/` (the verification and mailed-pass pages, end-session,
 * the authorization-error page), and `/ui/*` belongs to the ceremony app
 * once a reverse proxy splits the two (ADR-019 Decision 5). A `meta` route,
 * like the discovery documents: it carries nothing of the realm and answers
 * on its primary and endpoint hosts, on a process with the `api` role.
 *
 * Its own rate-limit bucket ({@link ASSET_RATE_LIMIT}): a cold page view
 * fetches the stylesheet and a few fonts, and they must not spend the global
 * bucket the sign-in and consent pages share. Browsers keep the files, so
 * a client comes back for them only after a release changes one.
 *
 * Not part of the API, so it is hidden from the OpenAPI document: only the
 * pages link these files, and their names change whenever a file does. The
 * path is a constant for the same reason as the admin listener's document
 * route; the docs site's endpoint-coverage guard, which reads paths written
 * as string literals, therefore does not list it either.
 */

/** The route's path under the `/assets` prefix. */
const ASSET_PATH = '/ui/:file';

/** A year: the name changes with the content, so the answer never goes stale. */
const IMMUTABLE = 'public, max-age=31536000, immutable';

/**
 * The asset route's own bucket, per client address and realm: 1000 files a
 * minute, some 200 cold page views from behind one address, apart from the
 * global bucket.
 */
export const ASSET_RATE_LIMIT = { max: 1000, timeWindowMs: 60_000 } as const;

export default async function (fastify: FastifyInstance) {
  fastify.withTypeProvider<ZodTypeProvider>().get(
    ASSET_PATH,
    {
      schema: {
        hide: true,
        params: z.object({
          file: z.string().max(UI_ASSET_NAME_MAX_LENGTH).regex(UI_ASSET_NAME),
        }),
      },
      config: {
        surface: 'meta',
        rateLimit: {
          max: ASSET_RATE_LIMIT.max,
          timeWindow: ASSET_RATE_LIMIT.timeWindowMs,
          keyGenerator: realmRateLimitKey,
        },
      },
    },
    async (request, reply) => {
      const asset = uiAsset(request.params.file);
      if (asset === undefined) return reply.callNotFound();
      reply.header('Content-Type', asset.contentType);
      reply.header('Cache-Control', IMMUTABLE);
      return reply.send(asset.body);
    }
  );
}
